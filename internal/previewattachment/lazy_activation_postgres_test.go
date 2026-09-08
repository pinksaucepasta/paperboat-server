package previewattachment_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/lazyaccess"
	"github.com/pinksaucepasta/paperboat-server/internal/previewattachment"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
)

// This fixture supplies the remote ready observation. Creation, attachment
// persistence, final activation publication, lookup and stop use real SQL paths;
// actual origin/carrier readiness is covered by the connected daemon test.
type readyLazyDispatch struct {
	database *db.DB
	fixture  previewattachment.LazyActivationFixture
}

func (d readyLazyDispatch) Dispatch(ctx context.Context, r previewv1.DispatchRequest) (previewv1.DispatchOutcome, error) {
	a := d.fixture.Attachment(r.PreviewID, r.OperationID, r.OwnerSessionID)
	a.Endpoint, a.AccessMode = r.Endpoint, r.AccessMode
	a.Target = previewattachment.Target{Scheme: r.Target.Scheme, Address: r.Target.Address}
	a.LeaseGeneration = uint64(r.ExpectedGeneration)
	a.ExpiresAt = r.LeaseDeadline
	if err := previewattachment.ApplyLazyReadyFixture(ctx, d.database, a); err != nil {
		return previewv1.DispatchOutcome{}, err
	}
	return previewv1.DispatchOutcome{Schema: previewv1.Schema, Kind: previewv1.PreviewDispatchKind, PreviewID: r.PreviewID, OperationID: r.OperationID, State: "accepted", Generation: r.ExpectedGeneration}, nil
}

func TestLazyActivationReadyPostgres(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}

	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if os.Getenv("PAPERBOAT_TEST_SCHEMA_READY") != "1" {
		if err = db.Migrate(ctx, database); err != nil {
			t.Fatal(err)
		}
	}
	f, err := previewattachment.NewLazyActivationFixture(ctx, database, fmt.Sprint(time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, q := range []string{
			`DELETE FROM lazy_activations WHERE policy_id IN (SELECT id FROM lazy_access_policies WHERE account_id=$1)`,
			`DELETE FROM lazy_access_policies WHERE account_id=$1`,
			`DELETE FROM lazy_runtime_owners WHERE account_id=$1`,
			`DELETE FROM lazy_environment_identities WHERE environment_id IN (SELECT environment_id FROM user_machines WHERE user_id=$1)`,
			`DELETE FROM preview_leases WHERE account_id=$1`,
			`DELETE FROM user_machines WHERE user_id=$1`,
			`DELETE FROM operations WHERE account_id=$1`,
			// Immutable audit records retain their actor until the isolated DB is dropped.
			`DELETE FROM users WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM audit_events WHERE actor_user_id=$1)`,
		} {
			if _, err = database.SQL().ExecContext(cleanup, q, f.AccountID); err != nil {
				t.Error("cleanup:", err)
			}
		}
		if _, err = database.SQL().ExecContext(cleanup, `DELETE FROM control_tunnel_nodes WHERE id=$1`, f.NodeID); err != nil {
			t.Error("cleanup:", err)
		}
	}()
	policies, err := lazyaccess.NewService(database, "preview.example.test")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := policies.Upsert(ctx, f.AccountID, lazyaccess.UpsertRequest{MachineID: f.MachineID, Target: lazyaccess.Target{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "private", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	store, err := previewtunnelstore.New(database)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := previewv1.NewService(store, previewv1.Config{EndpointDomain: "preview.example.test", CursorKey: make([]byte, 32), Dispatcher: readyLazyDispatch{database: database, fixture: f}})
	if err != nil {
		t.Fatal(err)
	}
	// Exercise one ordinary explicit lease before timing the first lazy request
	// on a running server. This warms the real driver's statement descriptions
	// across the WAN test DB without changing production query mode or deadlines.
	authority := previewtunnelapi.RequestContext{Actor: previewtunnelapi.Actor{AccountID: f.AccountID, ActorID: f.AccountID, Role: "user", Scopes: []string{"previews:read", "previews:write"}}, RequestID: "ready_" + f.Suffix, CorrelationID: "ready_" + f.Suffix}
	warmEnd := time.Now().UTC().Add(5 * time.Minute)
	warm, err := leases.Create(ctx, authority, previewv1.CreateRequest{OwnerDeviceID: f.MachineID, OwnerSessionID: "warm_" + f.Suffix, Target: previewv1.Target{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "private", ExpiresAt: &warmEnd, IdempotencyKey: "warm_" + f.Suffix})
	if err != nil {
		t.Fatal("explicit warm lease:", err)
	}
	warmView, err := leases.Get(ctx, authority, warm.Preview.ID)
	if err != nil {
		t.Fatal(err)
	}
	warmGeneration, err := previewtunnelapi.ParseIfMatch(map[string][]string{"If-Match": {warmView.ETag}}, previewv1.Kind, warm.Preview.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = leases.Stop(ctx, authority, warm.Preview.ID, previewv1.MutationRequest{ExpectedGeneration: warmGeneration, IdempotencyKey: "warm_stop_" + f.Suffix}); err != nil {
		t.Fatal(err)
	}
	activator := lazyaccess.Activator{DB: database, Leases: leases}
	boot := lazyaccess.RuntimeObservation{Schema: "paperboat.lazy-runtime/v1", BootID: "boot_ready_" + f.Suffix, InstallationGeneration: 1, StartedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if err = activator.RecordLazyRuntimeObservation(ctx, f.EnvironmentID, f.MachineID, boot); err != nil {
		t.Fatal(err)
	}
	request := lazyaccess.ActivationRequest{PolicyID: policy.ID, PolicyGeneration: policy.Generation, OwnerAccountID: f.AccountID, AuthorityDeadline: time.Now().Add(5 * time.Minute), Check: func(context.Context) error { return nil }}
	var wg sync.WaitGroup
	results := make(chan string, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); id, err := activator.Activate(ctx, request); results <- id; errs <- err }()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first string
	for id := range results {
		if id == "" || first != "" && first != id {
			t.Fatal("coalesced activation returned different leases")
		}
		first = id
	}
	got, err := leases.Get(ctx, authority, first)
	if err != nil || got.Preview.State != "ready" || got.Preview.Endpoint != "https://"+policy.Hostname {
		t.Fatalf("ready lease: %+v %v", got.Preview, err)
	}
	var count int
	if err = database.SQL().QueryRowContext(ctx, `SELECT count(*) FROM preview_leases WHERE endpoint=$1`, got.Preview.Endpoint).Scan(&count); err != nil || count != 1 {
		t.Fatalf("coalesced lease count: %d %v", count, err)
	}
	generation, err := previewtunnelapi.ParseIfMatch(map[string][]string{"If-Match": {got.ETag}}, previewv1.Kind, first)
	if err != nil {
		t.Fatal(err)
	}
	// The idle owner releases the ordinary lease; the reservation and policy survive.
	if _, err = leases.Stop(ctx, authority, first, previewv1.MutationRequest{ExpectedGeneration: generation, IdempotencyKey: "idle_" + f.Suffix}); err != nil {
		t.Fatal(err)
	}
	if err = activator.RecordLazyRuntimeObservation(ctx, f.EnvironmentID, f.MachineID, boot); err != nil {
		t.Fatal(err)
	}
	next, err := activator.Activate(ctx, request)
	if err != nil || next == "" || next == first {
		t.Fatalf("idle reactivation: %q %v", next, err)
	}
	got, err = leases.Get(ctx, authority, next)
	if err != nil || got.Preview.State != "ready" || got.Preview.Endpoint != "https://"+policy.Hostname {
		t.Fatalf("reactivated endpoint: %+v %v", got.Preview, err)
	}
}
