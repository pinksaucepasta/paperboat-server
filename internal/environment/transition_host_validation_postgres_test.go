package environment

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

func TestPostgresTransitionInventoryRejectsClientOnlyHostBinding(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run the transition host-capability proof")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(dsn), "_test") {
		t.Fatal("PAPERBOAT_TEST_DATABASE_DSN must name an isolated *_test database")
	}
	vectorRaw, err := os.ReadFile("../../testdata/contracts/environment-e2ee-v1/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RootPublic string `json:"root_public"`
		Authority  string `json:"authority"`
	}
	if err := json.Unmarshal(vectorRaw, &vector); err != nil {
		t.Fatal(err)
	}
	rootRaw, _ := base64.RawURLEncoding.DecodeString(vector.RootPublic)
	authorityRaw, _ := base64.RawURLEncoding.DecodeString(vector.Authority)
	rootID, err := peeridentity.RootFingerprint(ed25519.PublicKey(rootRaw))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ParseAuthority(authorityRaw, peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{{KeyID: "aek_" + rootID, PublicKey: ed25519.PublicKey(rootRaw)}}})
	if err != nil {
		t.Fatal(err)
	}
	hostID := ""
	for _, binding := range authority.Bindings {
		if binding.SubjectKind == 3 {
			hostID = binding.SubjectID
			break
		}
	}
	if hostID == "" {
		t.Fatal("shared authority has no host binding")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	_, _ = store.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, authority.AccountID)
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, authority.AccountID)
	})
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$2,$3,'active')`, authority.AccountID, "workos_env_client_only", "env-client-only@canary.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,setup_mode,setup_roles) VALUES($1,$2,'env_client_only','Client only','linux','amd64','/client','online','released','client',ARRAY[]::text[])`, hostID, authority.AccountID); err != nil {
		t.Fatal(err)
	}
	err = store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, inventoryErr := requiredScopeInventoryTx(ctx, tx, authority.AccountID, authority)
		return inventoryErr
	})
	if !errors.Is(err, ErrMachineNotHost) {
		t.Fatalf("transition inventory error=%v, want ErrMachineNotHost", err)
	}
}
