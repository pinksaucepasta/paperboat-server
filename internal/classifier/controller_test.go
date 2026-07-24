package classifier

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

type failingProvider struct {
	calls      int
	candidates []Candidate
}

func (p *failingProvider) Classify(_ context.Context, candidates []Candidate) (Response, error) {
	p.calls++
	p.candidates = append([]Candidate(nil), candidates...)
	return Response{}, errors.New("provider unavailable")
}

func TestControllerProviderFailureLeavesUnknownPathPending(t *testing.T) {
	store := openClassifierTestDB(t)
	ctx := context.Background()
	userID := "classifier_failure_" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	if _, err := store.SQL().ExecContext(ctx, `
		INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
		VALUES ($1, $2, $3, 'active') ON CONFLICT (id) DO NOTHING
	`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.audit_events WHERE resource_id=$1`, userID)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=$1`, userID)
	})

	provider := &failingProvider{}
	controller := NewController(store, provider, config.Classifier{
		MaxCandidates: 4, RequestsPerMinute: 10, RetryLimit: 2,
		RetryBackoff: time.Millisecond, CacheTTL: time.Hour,
		ModelRevision: "model-1", Revision: "classifier-1",
	}, "policy-1", audit.NewWriter(store))
	candidate := Candidate{
		Path: ".config/unknown-tool/settings.json", FileType: "file", Size: 42,
		ChangeFrequency: "changed", LocationClass: "xdg_config",
		Siblings: []Sibling{{Name: "defaults.json", FileType: "file"}},
	}
	result, err := controller.Classify(ctx, userID, []Candidate{candidate})
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 3 {
		t.Fatalf("provider calls = %d, want 3", provider.calls)
	}
	if len(result.Results) != 1 || !result.Results[0].Pending ||
		result.Results[0].Decision != Uncertain ||
		result.Results[0].ReasonCode != "provider_unavailable" ||
		result.Health != "unavailable" {
		t.Fatalf("result = %#v", result)
	}
	payload, err := json.Marshal(provider.candidates)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"content", "absolute_path", "credential", "secret_value"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("provider payload leaked forbidden field %q: %s", forbidden, payload)
		}
	}
	var failures int
	if err := store.SQL().QueryRowContext(ctx, `
		SELECT count(*) FROM paperboat.audit_events
		WHERE event_type='config_sync.classification_failed' AND resource_id=$1
	`, userID).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != 1 {
		t.Fatalf("failure audit count = %d, want 1", failures)
	}
}

func openClassifierTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run classifier PostgreSQL integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	return store
}
