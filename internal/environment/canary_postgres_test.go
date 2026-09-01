package environment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

func TestPostgresOpaqueCanaryNeverAppearsInServerSurfaces(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run the ENV E2EE canary storage proof")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(dsn), "_test") {
		t.Fatal("PAPERBOAT_TEST_DATABASE_DSN must name an isolated *_test database")
	}
	vectorRaw, err := os.ReadFile("../../../testdata/contracts/environment-e2ee-v1/vectors.json")
	if err != nil {
		t.Skip("shared Paperboat ENV E2EE vector is unavailable")
	}
	var vector struct {
		RootPublic         string            `json:"root_public"`
		Authority          string            `json:"authority"`
		SetManifest        string            `json:"set_manifest"`
		Expected           map[string]string `json:"expected_values"`
		HostRecipientKeyID string            `json:"host_recipient_key_id"`
	}
	if json.Unmarshal(vectorRaw, &vector) != nil {
		t.Fatal("invalid shared ENV E2EE vector")
	}
	rootRaw, _ := base64.RawURLEncoding.DecodeString(vector.RootPublic)
	authorityRaw, _ := base64.RawURLEncoding.DecodeString(vector.Authority)
	manifestRaw, _ := base64.RawURLEncoding.DecodeString(vector.SetManifest)
	rootID, _ := peeridentity.RootFingerprint(ed25519.PublicKey(rootRaw))
	authorityDocument, err := ParseAuthority(authorityRaw, peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{{KeyID: "aek_" + rootID, PublicKey: ed25519.PublicKey(rootRaw)}}})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseManifest(manifestRaw, authorityDocument)
	if err != nil {
		t.Fatal(err)
	}
	canary := []byte(vector.Expected["APP_TOKEN"])
	if len(canary) == 0 || bytes.Contains(manifestRaw, canary) {
		t.Fatal("shared vector does not provide an encrypted canary")
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
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	accountID, machineID, scopeID := "envcanaryuser_"+suffix, "envcanarymachine_"+suffix, "envcanaryscope_"+suffix
	defer store.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, accountID) //nolint:errcheck -- test cleanup
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$2,$3,'active')`, accountID, "workos_"+suffix, suffix+"@canary.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,setup_mode,setup_roles) VALUES($1,$2,$3,'ENV canary','linux','amd64','/canary','online','released','host',ARRAY['host'])`, machineID, accountID, "env_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_scopes(id,account_id,scope,scope_state,version,key_epoch,authority_generation,authority_id,manifest_id) VALUES($1,$2,'global','active',$3,$4,$5,$6,$7)`, scopeID, accountID, int64(manifest.Version), int64(manifest.KeyEpoch), int64(authorityDocument.Generation), authorityDocument.ID, manifest.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_scope_manifests(scope_id,version,key_epoch,authority_generation,authority_id,operation_id,manifest_id,envelope) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, scopeID, int64(manifest.Version), int64(manifest.KeyEpoch), int64(authorityDocument.Generation), authorityDocument.ID, manifest.OperationID, manifest.ID, manifestRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_observations(machine_id,account_id,host_recipient_key_id,observation_seq,state,observed_at,received_at) VALUES($1,$2,$3,1,'pending',now(),now())`, machineID, accountID, vector.HostRecipientKeyID); err != nil {
		t.Fatal(err)
	}
	if err := audit.NewWriter(store).Write(ctx, audit.Event{ActorUserID: accountID, ActorType: audit.ActorUser, EventType: "environment_manifest.set", ResourceType: "environment_manifest", ResourceID: scopeID, IdempotencyKey: "environment-canary:" + suffix, Metadata: map[string]any{"scope": "global", "changed_names": manifest.ChangedNames, "manifest_id": manifest.ID}}); err != nil {
		t.Fatal(err)
	}

	httpBody, _ := json.Marshal(map[string]any{"schema": "paperboat.environment-manifest-mutation/v1", "expected_version": manifest.PreviousVersion, "operation_id": manifest.OperationID, "envelope": vector.SetManifest})
	var databaseRows, auditRows string
	for _, query := range []string{
		`SELECT COALESCE(jsonb_agg(to_jsonb(t))::text,'') FROM paperboat.environment_scopes t WHERE account_id=$1`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(t))::text,'') FROM paperboat.environment_scope_manifests t WHERE scope_id=$1`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(t))::text,'') FROM paperboat.environment_observations t WHERE account_id=$1`,
	} {
		var part string
		arg := any(accountID)
		if strings.Contains(query, "scope_id=$1") {
			arg = scopeID
		}
		if scanErr := store.SQL().QueryRowContext(ctx, query, arg).Scan(&part); scanErr != nil {
			t.Fatal(scanErr)
		}
		databaseRows += part
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(t))::text,'') FROM paperboat.audit_events t WHERE resource_id=$1`, scopeID).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	for _, surface := range [][]byte{httpBody, []byte(databaseRows), []byte(auditRows)} {
		if bytes.Contains(surface, canary) {
			t.Fatal("plaintext ENV canary crossed HTTP, database, observation, or audit storage")
		}
	}
}
