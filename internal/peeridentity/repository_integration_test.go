package peeridentity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestSQLRepositoryBootstrapsRootAndCertificateAtomically(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run peer identity repository integration tests")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
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
	now := time.Now().UTC().Truncate(time.Second)
	suffix := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_")) + strings.ReplaceAll(now.Format("150405.000000000"), ".", "")
	userID, clientID := "peer_root_user_"+suffix, "peer_root_cli_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'peer root test','desktop','test',ARRAY['projects:connect'],'active',$4,$4)`, clientID, userID, "client_"+suffix, now); err != nil {
		t.Fatal(err)
	}
	repository, err := NewSQLRepository(store, audit.NewWriter(store))
	if err != nil {
		t.Fatal(err)
	}
	service, _ := NewService(repository)
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	raw := signedFixture(t, rootPrivate, userID, RoleCLI, clientID, 1, 1, now, now.Add(time.Hour))
	rootFingerprint := sha256.Sum256(rootPublic)
	request := BootstrapRequest{RegisterRequest: RegisterRequest{OperationID: "operation_bootstrap_" + suffix, UserID: userID, KeyID: keyIDForFingerprint(rootFingerprint), Certificate: raw, Expected: Expected{AccountID: userID, Role: RoleCLI, EndpointID: clientID, Generation: 1, Serial: 1}, ExpectedRootFingerprint: rootFingerprint, ExpectedCertificateFingerprint: sha256.Sum256(raw), ExpectedIssuedAt: now, ExpectedExpiresAt: now.Add(time.Hour), Now: now}, CLIClientSessionID: clientID, RootPublicKey: rootPublic}
	first, err := service.Bootstrap(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.Bootstrap(ctx, request)
	if err != nil || replay.Fingerprint != first.Fingerprint {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	otherPublic, otherPrivate, _ := ed25519.GenerateKey(nil)
	otherRaw := signedFixture(t, otherPrivate, userID, RoleCLI, clientID, 1, 1, now, now.Add(time.Hour))
	conflict := request
	conflict.OperationID = "operation_bootstrap_conflict_" + suffix
	conflict.RootPublicKey = otherPublic
	conflict.Certificate = otherRaw
	otherFingerprint := sha256.Sum256(otherPublic)
	conflict.ExpectedRootFingerprint = otherFingerprint
	conflict.KeyID = keyIDForFingerprint(otherFingerprint)
	conflict.ExpectedCertificateFingerprint = sha256.Sum256(otherRaw)
	if _, err := service.Bootstrap(ctx, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting root error=%v", err)
	}
	var roots, certificates int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.account_e2ee_roots WHERE user_id=$1`, userID).Scan(&roots); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_endpoint_certificates WHERE user_id=$1`, userID).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if roots != 1 || certificates != 1 {
		t.Fatalf("roots=%d certificates=%d", roots, certificates)
	}
}

func TestSQLRepositoryFreshBootstrapAddsDeviceKeyToExistingAccount(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run peer identity repository integration tests")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
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
	now := time.Now().UTC().Truncate(time.Second)
	suffix := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_")) + strings.ReplaceAll(now.Format("150405.000000000"), ".", "")
	userID := "peer_fresh_user_" + suffix
	firstClientID, freshClientID := "peer_first_cli_"+suffix, "peer_fresh_cli_"+suffix
	machineID := "peer_fresh_machine_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	firstPublic, _, _ := ed25519.GenerateKey(nil)
	firstFingerprint := sha256.Sum256(firstPublic)
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.account_e2ee_roots (user_id,public_key,fingerprint) VALUES ($1,$2,$3)`, userID, firstPublic, firstFingerprint[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.account_e2ee_keys (key_id,user_id,public_key,fingerprint,generation) VALUES ($1,$2,$3,$4,1)`, keyIDForFingerprint(firstFingerprint), userID, firstPublic, firstFingerprint[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,online,public_identity_key,setup_mode) VALUES ($1,$2,$3,'fresh-device','windows','amd64','C:\\Users\\Test','offline',false,$4,'host')`, machineID, userID, "env_"+suffix, "identity_"+suffix); err != nil {
		t.Fatal(err)
	}
	for _, clientID := range []string{firstClientID, freshClientID} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at,user_machine_id,fresh_e2ee_bootstrap) VALUES ($1,$2,$3,'fresh root test','desktop','windows',ARRAY['projects:connect'],'active',$4,$4,$5,$6)`, clientID, userID, "client_"+clientID, now, machineID, clientID == freshClientID); err != nil {
			t.Fatal(err)
		}
	}
	repository, err := NewSQLRepository(store, audit.NewWriter(store))
	if err != nil {
		t.Fatal(err)
	}
	service, _ := NewService(repository)
	freshPublic, freshPrivate, _ := ed25519.GenerateKey(nil)
	raw := signedFixture(t, freshPrivate, userID, RoleCLI, freshClientID, 1, 1, now, now.Add(time.Hour))
	freshFingerprint := sha256.Sum256(freshPublic)
	request := BootstrapRequest{RegisterRequest: RegisterRequest{OperationID: "operation_fresh_bootstrap_" + suffix, UserID: userID, KeyID: keyIDForFingerprint(freshFingerprint), Certificate: raw, Expected: Expected{AccountID: userID, Role: RoleCLI, EndpointID: freshClientID, Generation: 1, Serial: 1}, ExpectedRootFingerprint: freshFingerprint, ExpectedCertificateFingerprint: sha256.Sum256(raw), ExpectedIssuedAt: now, ExpectedExpiresAt: now.Add(time.Hour), Now: now}, CLIClientSessionID: freshClientID, RootPublicKey: freshPublic, AllowRootReplacement: true}
	result, err := service.Bootstrap(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyID != keyIDForFingerprint(freshFingerprint) {
		t.Fatalf("key id=%q", result.KeyID)
	}
	var activeKeys, freshCertificates int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.account_e2ee_keys WHERE user_id=$1 AND revoked_at IS NULL`, userID).Scan(&activeKeys); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_endpoint_certificates WHERE user_id=$1 AND endpoint_id=$2 AND revoked_at IS NULL`, userID, freshClientID).Scan(&freshCertificates); err != nil {
		t.Fatal(err)
	}
	if activeKeys != 2 || freshCertificates != 1 {
		t.Fatalf("active keys=%d fresh certificates=%d", activeKeys, freshCertificates)
	}
}

func TestSQLRepositoryCLIEndpointEnrollmentReplaysOnlyBoundActiveRequests(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run peer identity repository integration tests")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
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
	now := time.Now().UTC().Truncate(time.Second)
	suffix := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_")) + strings.ReplaceAll(now.Format("150405.000000000"), ".", "")
	userID, otherUserID, orphanUserID, revokedUserID := "peer_cli_user_"+suffix, "peer_cli_other_"+suffix, "peer_cli_orphan_"+suffix, "peer_cli_revoked_"+suffix
	for _, userID := range []string{userID, otherUserID, orphanUserID, revokedUserID} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	otherRootPublic, _, _ := ed25519.GenerateKey(nil)
	revokedRootPublic, _, _ := ed25519.GenerateKey(nil)
	for _, value := range []struct {
		userID string
		public ed25519.PublicKey
	}{
		{userID: userID, public: rootPublic},
		{userID: otherUserID, public: otherRootPublic},
		{userID: revokedUserID, public: revokedRootPublic},
	} {
		fingerprint := sha256.Sum256(value.public)
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.account_e2ee_roots (user_id,public_key,fingerprint) VALUES ($1,$2,$3)`, value.userID, value.public, fingerprint[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.account_e2ee_keys (key_id,user_id,public_key,fingerprint,generation) VALUES ($1,$2,$3,$4,1)`, keyIDForFingerprint(fingerprint), value.userID, value.public, fingerprint[:]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.account_e2ee_roots SET revoked_at=GREATEST(now(),created_at),updated_at=GREATEST(now(),created_at) WHERE user_id=$1`, revokedUserID); err != nil {
		t.Fatal(err)
	}
	repository, err := NewSQLRepository(store, audit.NewWriter(store))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	request := CLIEndpointRequest{OperationID: "operation_cli_enrollment_" + suffix, UserID: userID, EndpointID: "peer_cli_endpoint_" + suffix, Generation: 1, NoisePublicKey: [32]byte{1}, QUICPublicKey: [32]byte{2}, Now: now}
	first, err := service.RequestCLIEndpoint(ctx, request)
	if err != nil || first.State != "pending" || first.Role != RoleCLI {
		t.Fatalf("first request=%+v err=%v", first, err)
	}
	replay, err := service.RequestCLIEndpoint(ctx, request)
	if err != nil || replay.ID != first.ID || replay.State != "pending" {
		t.Fatalf("pending replay=%+v err=%v", replay, err)
	}
	conflict := request
	conflict.NoisePublicKey[0]++
	if _, err := service.RequestCLIEndpoint(ctx, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("request hash conflict=%v", err)
	}
	wrongAccount := request
	wrongAccount.UserID = otherUserID
	if _, err := service.RequestCLIEndpoint(ctx, wrongAccount); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong account conflict=%v", err)
	}

	raw := signedFixture(t, rootPrivate, userID, RoleCLI, request.EndpointID, 1, 1, now, now.Add(time.Hour))
	fingerprint := sha256.Sum256(raw)
	rootFingerprint := sha256.Sum256(rootPublic)
	if _, err := service.Register(ctx, RegisterRequest{OperationID: "operation_cli_certificate_" + suffix, UserID: userID, KeyID: keyIDForFingerprint(rootFingerprint), Certificate: raw, Expected: Expected{AccountID: userID, Role: RoleCLI, EndpointID: request.EndpointID, Generation: 1, Serial: 1}, ExpectedRootFingerprint: rootFingerprint, ExpectedCertificateFingerprint: fingerprint, ExpectedIssuedAt: now, ExpectedExpiresAt: now.Add(time.Hour), Now: now}); err != nil {
		t.Fatal(err)
	}
	fulfilledReplay, err := service.RequestCLIEndpoint(ctx, request)
	if err != nil || fulfilledReplay.ID != first.ID || fulfilledReplay.State != "fulfilled" {
		t.Fatalf("fulfilled replay=%+v err=%v", fulfilledReplay, err)
	}
	var requests, certificates int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_endpoint_enrollment_requests WHERE operation_key=$1`, request.OperationID).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_endpoint_certificates WHERE user_id=$1 AND endpoint_id=$2`, userID, request.EndpointID).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || certificates != 1 {
		t.Fatalf("requests=%d certificates=%d", requests, certificates)
	}

	orphanRequest := request
	orphanRequest.OperationID += "_orphan"
	orphanRequest.UserID = orphanUserID
	orphanRequest.EndpointID += "_orphan"
	if _, err := service.RequestCLIEndpoint(ctx, orphanRequest); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("orphan account root error=%v", err)
	}
	var orphanRequests int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_endpoint_enrollment_requests WHERE user_id=$1`, orphanUserID).Scan(&orphanRequests); err != nil {
		t.Fatal(err)
	}
	if orphanRequests != 0 {
		t.Fatalf("orphan requests=%d", orphanRequests)
	}

	revokedRequest := orphanRequest
	revokedRequest.OperationID += "_revoked"
	revokedRequest.UserID = revokedUserID
	revokedRequest.EndpointID += "_revoked"
	if _, err := service.RequestCLIEndpoint(ctx, revokedRequest); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revoked account root error=%v", err)
	}
}
