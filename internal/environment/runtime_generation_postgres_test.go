package environment

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

type environmentRuntimeRoots struct{ root peeridentity.AccountRoot }

func (r environmentRuntimeRoots) Root(context.Context, string) (peeridentity.AccountRoot, error) {
	return r.root, nil
}

func TestPostgresRuntimeSuspendsReinstalledHostAndOnlyRoutesRevocationToRetiredKey(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run the runtime reinstall/revocation proof")
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
	roots := peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{{KeyID: "aek_" + rootID, PublicKey: ed25519.PublicKey(rootRaw)}}}
	authority, err := ParseAuthority(authorityRaw, roots)
	if err != nil {
		t.Fatal(err)
	}
	var host Binding
	retiredKeyID := ""
	for _, binding := range authority.Bindings {
		if binding.SubjectKind == 3 {
			host = binding
		} else if binding.SubjectKind == 1 {
			retiredKeyID = binding.RecipientKeyID
		}
	}
	if host.SubjectID == "" || retiredKeyID == "" || retiredKeyID == host.RecipientKeyID {
		t.Fatal("shared authority lacks distinct host and manager recipient fixtures")
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
	accountID, environmentID := authority.AccountID, "env_runtime_generation"
	_, _ = store.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, accountID)
	t.Cleanup(func() { _, _ = store.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, accountID) })
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$2,$3,'active')`, accountID, "workos_env_runtime_generation", "env-runtime-generation@canary.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,setup_mode,setup_roles,installation_generation) VALUES($1,$2,$3,'Reinstalled ENV host','linux','amd64','/host','online','released','host',ARRAY['host'],$4)`, host.SubjectID, accountID, environmentID, int64(host.SubjectGeneration+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_authority_roots(account_id,key_id,public_key) VALUES($1,$2,$3)`, accountID, roots.Keys[0].KeyID, []byte(roots.Keys[0].PublicKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_authorities(account_id,generation,authority_id,operation_id,envelope) VALUES($1,$2,$3,$4,$5)`, accountID, int64(authority.Generation), authority.ID, authority.OperationID, authorityRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_authority_heads(account_id,generation,authority_id) VALUES($1,$2,$3)`, accountID, int64(authority.Generation), authority.ID); err != nil {
		t.Fatal(err)
	}
	service := NewService(store, nil, environmentRuntimeRoots{root: roots})
	observation := Observation{
		Schema: ObservationSchema, ObservationSeq: 1, HostRecipientKeyID: host.RecipientKeyID,
		Authority: &AuthorityRef{Generation: int64(authority.Generation), AuthorityID: authority.ID}, State: "pending", ObservedAt: time.Unix(1788134400, 0).UTC(),
	}
	result, err := service.RecordEnvironmentObservation(ctx, environmentID, host.SubjectID, &observation)
	if err != nil {
		t.Fatal(err)
	}
	if result.Bundle == nil || result.Bundle.RevocationOnly || result.Bundle.AuthorizationBootstrap != nil || result.Bundle.GlobalManifest != nil || result.Bundle.MachineManifest != nil {
		t.Fatalf("reinstalled host received ENV ciphertext or incorrect revocation state: %#v", result.Bundle)
	}
	var observations int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.environment_observations WHERE machine_id=$1`, host.SubjectID).Scan(&observations); err != nil || observations != 0 {
		t.Fatalf("stale-generation observation persisted: count=%d err=%v", observations, err)
	}

	observation.ObservationSeq++
	observation.HostRecipientKeyID = retiredKeyID
	result, err = service.RecordEnvironmentObservation(ctx, environmentID, host.SubjectID, &observation)
	if err != nil {
		t.Fatal(err)
	}
	if result.Bundle == nil || !result.Bundle.RevocationOnly || result.Bundle.AuthorizationBootstrap != nil || result.Bundle.GlobalManifest != nil || result.Bundle.MachineManifest != nil {
		t.Fatalf("retired recipient did not receive revocation-only metadata: %#v", result.Bundle)
	}
}
