package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

func TestHelperEnrollmentExchangeIsSingleUseAndKeyBound(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	environmentID := "env_enrollment_" + strings.ReplaceAll(t.Name(), "/", "_")
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ('usr_test','workos_enrollment','enrollment@example.test','active') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,'usr_test') ON CONFLICT (id) DO UPDATE SET owner_user_id='usr_test'`, environmentID, "workspace_test"); err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := mint.New([]mint.Key{{ID: "enrollment-test", PrivateKey: privateKey}}, "enrollment-test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := NewEnrollmentService(store, signer, nil, "https://api.example.test", "enrollment-test-encryption-key")
	service.clock = func() time.Time { return now }
	operationKey := "issue:" + environmentID
	grant, err := service.Issue(ctx, "usr_test", operationKey, environmentID, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.Issue(ctx, "usr_test", operationKey, environmentID, 5*time.Minute)
	if err != nil || replay != grant {
		t.Fatalf("issuance replay = %#v, %v; want %#v", replay, err, grant)
	}
	if _, err := service.Issue(ctx, "usr_test", operationKey, environmentID, 6*time.Minute); !errors.Is(err, ErrUsageOperationConflict) {
		t.Fatalf("conflicting issuance error = %v", err)
	}
	var ciphertext []byte
	if err := store.SQL().QueryRowContext(ctx, `SELECT grant_ciphertext FROM paperboat.control_helper_enrollments WHERE id=$1`, grant.EnrollmentID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ciphertext), grant.Credential) {
		t.Fatal("stored enrollment grant contains plaintext credential")
	}
	helperPrivate := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", ed25519.SeedSize)))
	helperPublic := helperPrivate.Public().(ed25519.PublicKey)
	identity, err := service.Exchange(ctx, grant.Credential, helperPublic)
	if err != nil {
		t.Fatal(err)
	}
	if identity.EnvironmentID != environmentID || identity.HelperID != grant.HelperID || identity.Credential == "" {
		t.Fatalf("identity = %#v", identity)
	}
	claims, err := signer.VerifyCredential(identity.Credential, "https://api.example.test", "helper_identity", now)
	thumbprint := sha256.Sum256(helperPublic)
	if err != nil || claims.HelperID != grant.HelperID || claims.KeyThumbprint != "sha256:"+base64.RawURLEncoding.EncodeToString(thumbprint[:]) {
		t.Fatalf("identity claims = %#v, %v", claims, err)
	}
	if _, err := service.Exchange(ctx, grant.Credential, helperPublic); !errors.Is(err, ErrEnrollmentUsed) {
		t.Fatalf("replay error = %v", err)
	}
	renewNow := now.Add(50 * time.Minute)
	service.clock = func() time.Time { return renewNow }
	renewBody := []byte(`{"operation_id":"helper-renew-operation-01"}`)
	renewHash := sha256.Sum256(renewBody)
	renewClaims := HelperProofClaims{HelperID: identity.HelperID, EnvironmentID: environmentID, OperationID: "helper-renew-operation-01", Method: "POST", Path: "/v1/helpers/renew", BodySHA256: base64.RawURLEncoding.EncodeToString(renewHash[:]), IssuedAt: renewNow, ExpiresAt: renewNow.Add(time.Minute)}
	renewPayload, _ := json.Marshal(renewClaims)
	renewProof, _ := json.Marshal(helperProofEnvelope{Algorithm: "EdDSA", Payload: base64.RawURLEncoding.EncodeToString(renewPayload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(helperPrivate, renewPayload))})
	renewed, err := service.Renew(ctx, identity.Credential, renewProof, renewBody)
	if err != nil || renewed.Credential == identity.Credential || !renewed.ExpiresAt.After(identity.ExpiresAt) {
		t.Fatalf("renewed identity = %#v, %v", renewed, err)
	}
	renewedReplay, err := service.Renew(ctx, identity.Credential, renewProof, renewBody)
	if err != nil || renewedReplay != renewed {
		t.Fatalf("renewal replay = %#v, %v", renewedReplay, err)
	}
	var renewalCiphertext []byte
	if err := store.SQL().QueryRowContext(ctx, `SELECT identity_ciphertext FROM paperboat.hosted_helper_identity_renewals WHERE helper_id=$1`, identity.HelperID).Scan(&renewalCiphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(renewalCiphertext, []byte(renewed.Credential)) {
		t.Fatal("stored renewal contains plaintext credential")
	}
	replacement, err := service.ReplaceHelper(ctx, "usr_test", "replace-helper-01", environmentID, grant.HelperID, "default")
	if err != nil || replacement.ConnectorGeneration != 2 {
		t.Fatalf("replacement = %#v, %v", replacement, err)
	}
	replacementReplay, err := service.ReplaceHelper(ctx, "usr_test", "replace-helper-01", environmentID, grant.HelperID, "default")
	if err != nil || replacementReplay != replacement {
		t.Fatalf("replacement replay = %#v, %v", replacementReplay, err)
	}
	if _, err := service.ReplaceHelper(ctx, "usr_test", "replace-helper-02", environmentID, grant.HelperID, "default"); !errors.Is(err, ErrUsageOperationConflict) {
		t.Fatalf("replacement conflict = %v", err)
	}
}

func TestHelperEnrollmentRejectsExpiredCredentialBeforeMutation(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	environmentID := "env_expired_enrollment"
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ('usr_test','workos_enrollment','enrollment@example.test','active') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,'workspace_test','usr_test') ON CONFLICT (id) DO UPDATE SET owner_user_id='usr_test'`, environmentID); err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", ed25519.SeedSize)))
	signer, err := mint.New([]mint.Key{{ID: "enrollment-test", PrivateKey: privateKey}}, "enrollment-test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := NewEnrollmentService(store, signer, nil, "https://api.example.test", "enrollment-test-encryption-key")
	service.clock = func() time.Time { return now }
	grant, err := service.Issue(ctx, "usr_test", "issue:"+environmentID, environmentID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return now.Add(2 * time.Minute) }
	helperPublic := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", ed25519.SeedSize))).Public().(ed25519.PublicKey)
	if _, err := service.Exchange(ctx, grant.Credential, helperPublic); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("expired exchange error = %v", err)
	}
}

func TestEnsureBootGrantReplacesExpiredGrantAndStopsAfterEnrollment(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	environmentID := "env_boot_grant_" + strings.ReplaceAll(t.Name(), "/", "_")
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ('usr_test','workos_boot_grant','boot-grant@example.test','active') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$1,'usr_test')`, environmentID); err != nil {
		t.Fatal(err)
	}
	signer, err := mint.New([]mint.Key{{ID: "boot-grant-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("b", ed25519.SeedSize)))}}, "boot-grant-test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := NewEnrollmentService(store, signer, nil, "https://api.example.test", "boot-grant-encryption-key")
	service.clock = func() time.Time { return now }
	first, err := service.EnsureBootGrant(ctx, "usr_test", "hosted-create:"+environmentID, environmentID, time.Minute)
	if err != nil || first.Credential == "" {
		t.Fatalf("first grant = %#v, %v", first, err)
	}
	service.clock = func() time.Time { return now.Add(2 * time.Minute) }
	replacement, err := service.EnsureBootGrant(ctx, "usr_test", "hosted-create:"+environmentID, environmentID, time.Minute)
	if err != nil || replacement.Credential == "" || replacement.EnrollmentID == first.EnrollmentID {
		t.Fatalf("replacement grant = %#v, %v", replacement, err)
	}
	var firstState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.control_helper_enrollments WHERE id=$1`, first.EnrollmentID).Scan(&firstState); err != nil || firstState != "revoked" {
		t.Fatalf("first grant state = %q, %v", firstState, err)
	}
	helperKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", ed25519.SeedSize)))
	if _, err := service.Exchange(ctx, replacement.Credential, helperKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	afterEnrollment, err := service.EnsureBootGrant(ctx, "usr_test", "hosted-create:"+environmentID, environmentID, time.Minute)
	if err != nil || afterEnrollment.Credential != "" {
		t.Fatalf("post-enrollment grant = %#v, %v", afterEnrollment, err)
	}
}

func TestEnsureBootGrantConcurrentCallsReplayOneGrant(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	environmentID := "env_boot_concurrent_" + strings.ReplaceAll(t.Name(), "/", "_")
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ('usr_test','workos_boot_concurrent','boot-concurrent@example.test','active') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$1,'usr_test')`, environmentID); err != nil {
		t.Fatal(err)
	}
	signer, err := mint.New([]mint.Key{{ID: "boot-concurrent-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", ed25519.SeedSize)))}}, "boot-concurrent-test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := NewEnrollmentService(store, signer, nil, "https://api.example.test", "boot-concurrent-encryption-key")
	service.clock = func() time.Time { return time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC) }
	const callers = 8
	grants := make(chan EnrollmentGrant, callers)
	errs := make(chan error, callers)
	var start sync.WaitGroup
	start.Add(1)
	for range callers {
		go func() {
			start.Wait()
			grant, err := service.EnsureBootGrant(ctx, "usr_test", "hosted-create:"+environmentID, environmentID, time.Minute)
			grants <- grant
			errs <- err
		}()
	}
	start.Done()
	var enrollmentID string
	for range callers {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		grant := <-grants
		if enrollmentID == "" {
			enrollmentID = grant.EnrollmentID
		} else if grant.EnrollmentID != enrollmentID {
			t.Fatalf("grant IDs differ: %q and %q", enrollmentID, grant.EnrollmentID)
		}
	}
	var pending int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.control_helper_enrollments WHERE environment_id=$1 AND state='pending' AND revoked_at IS NULL`, environmentID).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("pending enrollments=%d err=%v", pending, err)
	}
}

func TestConnectorAdmissionBindsProofGenerationNodeAndReplay(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	suffix := strings.ReplaceAll(t.Name(), "/", "_")
	environmentID := "env_admission_" + suffix
	seedUsageScope(t, store, suffix)
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ('usr_test','workos_admission','admission@example.test','active') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_environments SET owner_user_id='usr_test' WHERE id=$1`, "env_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET state='ready',ready=true,endpoint_host='edge.example.test',endpoint_tcp_port=26022,endpoint_quic_port=26023,last_heartbeat_at=$2 WHERE id=$1`, "node_"+suffix, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,'workspace_test','usr_test')`, environmentID); err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("a", ed25519.SeedSize)))
	signer, err := mint.New([]mint.Key{{ID: "admission-test", PrivateKey: privateKey}}, "admission-test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := NewEnrollmentService(store, signer, nil, "https://api.example.test", "admission-encryption-key")
	enrollment.clock = func() time.Time { return now }
	grant, err := enrollment.Issue(ctx, "usr_test", "admission-enroll-01", environmentID, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	helperPrivate := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", ed25519.SeedSize)))
	identity, err := enrollment.Exchange(ctx, grant.Credential, helperPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port) VALUES ($1,$2,'helper_https_wss',$3,'127.0.0.1',8080)`, "route_admission_"+suffix, environmentID, "admission-"+strings.ToLower(strings.ReplaceAll(suffix, "_", "-"))+".example.test"); err != nil {
		t.Fatal(err)
	}
	// Bind the connector generation to the ready node after enrollment.
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_connector_generations SET edge_node_id=$2,state='pending' WHERE environment_id=$1`, environmentID, "node_"+suffix); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"operation_id":"admission-operation-01","environment_id":"` + environmentID + `","helper_id":"` + identity.HelperID + `","edge_pool":"default","protocol_version":"1.0"}`)
	bodyHash := sha256.Sum256(body)
	proofClaims := HelperProofClaims{HelperID: identity.HelperID, EnvironmentID: environmentID, OperationID: "admission-operation-01", Method: "POST", Path: "/v1/connectors/admission", BodySHA256: base64.RawURLEncoding.EncodeToString(bodyHash[:]), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	payload, _ := json.Marshal(proofClaims)
	proof, _ := json.Marshal(helperProofEnvelope{Algorithm: "EdDSA", Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(helperPrivate, payload))})
	edge := NewEdgeService(store, "edge-control-credential-01234567890123456789")
	edge.SetClock(func() time.Time { return now })
	edge.SetCredentialIssuer(signer, "https://api.example.test", "admission-encryption-key")
	admission, err := edge.IssueConnectorAdmission(ctx, identity.Credential, proof, body, "default", "POST", "/v1/connectors/admission")
	if err != nil || admission.OperationID != "admission-operation-01" || admission.EdgePool != "default" || admission.ProtocolVersion != "1.0" || admission.EdgeNodeID != "node_"+suffix || admission.EdgeEndpoint.Port != 26022 || len(admission.Routes) != 1 || admission.Routes[0].RouteID != "route_admission_"+suffix {
		t.Fatalf("admission = %#v, %v", admission, err)
	}
	wire, err := json.Marshal(admission)
	if err != nil || bytes.Contains(wire, []byte(`"expires_at"`)) || bytes.Contains(wire, []byte(`"tcp_port"`)) || bytes.Contains(wire, []byte(`"quic_port"`)) {
		t.Fatalf("admission wire = %s, %v", wire, err)
	}
	if _, err := signer.VerifyCredential(admission.Credential, "https://api.example.test", "connector_admission", now); err != nil {
		t.Fatalf("admission credential = %v", err)
	}
	replay, err := edge.IssueConnectorAdmission(ctx, identity.Credential, proof, body, "default", "POST", "/v1/connectors/admission")
	if err != nil || replay.Credential != admission.Credential {
		t.Fatalf("admission replay = %#v, %v", replay, err)
	}
	next := now.Add(time.Minute)
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET last_heartbeat_at=$2 WHERE id=$1`, "node_"+suffix, next); err != nil {
		t.Fatal(err)
	}
	edge.SetClock(func() time.Time { return next })
	nextBody := []byte(`{"operation_id":"admission-operation-02","environment_id":"` + environmentID + `","helper_id":"` + identity.HelperID + `","edge_pool":"default","protocol_version":"1.0"}`)
	nextHash := sha256.Sum256(nextBody)
	nextClaims := HelperProofClaims{HelperID: identity.HelperID, EnvironmentID: environmentID, OperationID: "admission-operation-02", Method: "POST", Path: "/v1/connectors/admission", BodySHA256: base64.RawURLEncoding.EncodeToString(nextHash[:]), IssuedAt: next, ExpiresAt: next.Add(time.Minute)}
	nextPayload, _ := json.Marshal(nextClaims)
	nextProof, _ := json.Marshal(helperProofEnvelope{Algorithm: "EdDSA", Payload: base64.RawURLEncoding.EncodeToString(nextPayload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(helperPrivate, nextPayload))})
	renewed, err := edge.IssueConnectorAdmission(ctx, identity.Credential, nextProof, nextBody, "default", "POST", "/v1/connectors/admission")
	if err != nil || renewed.OperationID != "admission-operation-02" || renewed.Credential == admission.Credential {
		t.Fatalf("admission replacement = %#v, %v", renewed, err)
	}
}
