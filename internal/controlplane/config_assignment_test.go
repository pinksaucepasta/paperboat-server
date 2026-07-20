package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

func TestConfigAssignmentOwnershipConcurrencyAndBYODConsent(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	userA, userB := "cfg_a_"+suffix, "cfg_b_"+suffix
	env := "cfg_env_" + suffix
	for _, user := range []string{userA, userB} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active') ON CONFLICT (id) DO NOTHING`, user, "workos_"+user, user+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET owner_user_id=EXCLUDED.owner_user_id, desired_state='active'`, env, "workspace_"+suffix, userA); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root) VALUES ($1,$2,$3,'BYOD','linux','arm64','/workspace')`, "cfg_machine_"+suffix, userA, env); err != nil {
		t.Fatal(err)
	}
	service := NewConfigAssignmentService(store, nil)
	repoA, err := service.ConnectRepository(ctx, userA, "github", "repo-a", "A")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConnectRepository(ctx, userB, "github", "repo-b", "B"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Assignment(ctx, userB, env); !errors.Is(err, ErrAssignmentForbidden) {
		t.Fatalf("cross-user assignment error = %v", err)
	}
	assignment, err := service.Assign(ctx, userA, env, repoA.ID, "warning-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if assignment.ConsentState != "pending" || assignment.Version != 1 {
		t.Fatalf("assignment = %#v", assignment)
	}
	if _, err := service.AcceptConsent(ctx, userA, env, "warning-wrong", assignment.Version); !errors.Is(err, ErrAssignmentConflict) {
		t.Fatalf("wrong warning error = %v", err)
	}
	accepted, err := service.AcceptConsent(ctx, userA, env, "warning-1", assignment.Version)
	if err != nil || accepted.ConsentState != "accepted" {
		t.Fatalf("accepted = %#v, %v", accepted, err)
	}
	if err := service.Clear(ctx, userA, env, assignment.Version); !errors.Is(err, ErrAssignmentConflict) {
		t.Fatalf("stale clear error = %v", err)
	}
	if err := service.Clear(ctx, userA, env, accepted.Version); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := store.SQL().QueryRowContext(ctx, `SELECT consent_state FROM paperboat.control_config_assignments WHERE environment_id=$1`, env).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "revoked" {
		t.Fatalf("consent state = %q", state)
	}
}

func TestConfigCredentialIsBoundReplaySafeAndRevokedWithAssignment(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	suffix := strings.ReplaceAll(t.Name(), "/", "_")
	user, environmentID := "cfg_credential_user_"+suffix, "cfg_credential_env_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, user, "workos_"+user, user+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3)`, environmentID, "workspace_"+suffix, user); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root) VALUES ($1,$2,$3,'BYOD','linux','arm64','/workspace')`, "cfg_credential_machine_"+suffix, user, environmentID); err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", ed25519.SeedSize)))
	signer, err := mint.New([]mint.Key{{ID: "config-test", PrivateKey: privateKey}}, "config-test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := NewEnrollmentService(store, signer, nil, "https://api.example.test", "config-credential-encryption-key")
	enrollment.clock = func() time.Time { return now }
	grant, err := enrollment.Issue(ctx, user, "config-enrollment-01", environmentID, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	helperPrivate := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", ed25519.SeedSize)))
	identity, err := enrollment.Exchange(ctx, grant.Credential, helperPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	assignments := NewConfigAssignmentService(store, nil)
	assignments.clock = func() time.Time { return now }
	repository, err := assignments.ConnectRepository(ctx, user, "github", "config-repo", "Config")
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := assignments.Assign(ctx, user, environmentID, repository.ID, "warning-7", 0)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err = assignments.AcceptConsent(ctx, user, environmentID, "warning-7", assignment.Version)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{}`)
	bodyHash := sha256.Sum256(body)
	proofClaims := HelperProofClaims{HelperID: identity.HelperID, EnvironmentID: environmentID, OperationID: "config-credential-operation-01", Method: "POST", Path: "/v1/config/credentials", BodySHA256: base64.RawURLEncoding.EncodeToString(bodyHash[:]), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	payload, _ := json.Marshal(proofClaims)
	proof, _ := json.Marshal(helperProofEnvelope{Algorithm: "EdDSA", Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(helperPrivate, payload))})
	credentials := NewConfigCredentialService(store, signer, "https://api.example.test", "config-credential-encryption-key")
	credentials.clock = func() time.Time { return now }
	issued, err := credentials.Issue(ctx, identity.Credential, proof, body, "POST", "/v1/config/credentials")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := signer.VerifyCredential(issued.Credential, "https://api.example.test", "config_sync", now)
	if err != nil || claims.AssignmentID != assignment.ID || claims.WarningRevision != "warning-7" || claims.HelperID != identity.HelperID {
		t.Fatalf("claims = %#v, %v", claims, err)
	}
	replay, err := credentials.Issue(ctx, identity.Credential, proof, body, "POST", "/v1/config/credentials")
	if err != nil || replay.Credential != issued.Credential {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	replacement, err := assignments.Assign(ctx, user, environmentID, repository.ID, "warning-8", assignment.Version)
	if err != nil || replacement.ID == assignment.ID {
		t.Fatalf("replacement = %#v, %v", replacement, err)
	}
	if _, err := credentials.Issue(ctx, identity.Credential, proof, body, "POST", "/v1/config/credentials"); !errors.Is(err, ErrConfigCredentialReplay) {
		t.Fatalf("replaced assignment replay error = %v", err)
	}
	if err := assignments.Clear(ctx, user, environmentID, replacement.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.Issue(ctx, identity.Credential, proof, body, "POST", "/v1/config/credentials"); !errors.Is(err, ErrConfigCredentialReplay) {
		t.Fatalf("revoked replay error = %v", err)
	}
	edge := NewEdgeService(store, "edge-control-test")
	edge.clock = func() time.Time { return now }
	document, err := edge.Revocations(ctx)
	if err != nil || !containsString(document.JTIs, claims.JTI) {
		t.Fatalf("revocation document = %#v, %v", document, err)
	}
	if err := edge.RevokeSigningKey(ctx, user, "revoke-signing-key-01", "config-test", "compromise", now); err != nil {
		t.Fatal(err)
	}
	if err := edge.RevokeSigningKey(ctx, user, "revoke-signing-key-01", "config-test", "compromise", now.Add(time.Minute)); err != nil {
		t.Fatalf("exact signing-key revocation replay = %v", err)
	}
	if err := edge.RevokeSigningKey(ctx, user, "revoke-signing-key-01", "other-key", "compromise", now); !errors.Is(err, ErrUsageOperationConflict) {
		t.Fatalf("signing-key revocation conflict = %v", err)
	}
	if err := edge.RevokeSigningKey(ctx, user, "revoke-signing-key-02", "config-test", "confirmed compromise", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var persistedRevokedAt time.Time
	if err := store.SQL().QueryRowContext(ctx, `SELECT revoked_at FROM paperboat.control_signing_key_revocations WHERE key_id='config-test'`).Scan(&persistedRevokedAt); err != nil || !persistedRevokedAt.Equal(now) {
		t.Fatalf("persisted signing key revocation = %v, %v", persistedRevokedAt, err)
	}
	document, err = edge.Revocations(ctx)
	if err != nil || !containsString(document.KeyIDs, "config-test") {
		t.Fatalf("signing key revocation document = %#v, %v", document, err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestConfigAssignmentHostedDoesNotRequireConsent(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_")
	user := "cfg_hosted_" + suffix
	env := "cfg_hosted_env_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active') ON CONFLICT (id) DO NOTHING`, user, "workos_"+user, user+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET owner_user_id=EXCLUDED.owner_user_id, desired_state='active'`, env, "workspace_"+suffix, user); err != nil {
		t.Fatal(err)
	}
	service := NewConfigAssignmentService(store, nil)
	repo, err := service.ConnectRepository(ctx, user, "gitlab", "repo", "Hosted")
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := service.Assign(ctx, user, env, repo.ID, "", 0)
	if err != nil || assignment.ConsentState != "not_required" {
		t.Fatalf("assignment = %#v, %v", assignment, err)
	}
}
