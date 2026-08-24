package peeridentity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"sync"
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
	request := BootstrapRequest{RegisterRequest: RegisterRequest{OperationID: "operation_bootstrap_" + suffix, UserID: userID, Certificate: raw, Expected: Expected{AccountID: userID, Role: RoleCLI, EndpointID: clientID, Generation: 1, Serial: 1}, ExpectedRootFingerprint: sha256.Sum256(rootPublic), ExpectedCertificateFingerprint: sha256.Sum256(raw), ExpectedIssuedAt: now, ExpectedExpiresAt: now.Add(time.Hour), Now: now}, CLIClientSessionID: clientID, RootPublicKey: rootPublic}
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
	conflict.ExpectedRootFingerprint = sha256.Sum256(otherPublic)
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

func TestSQLRepositoryCLIEnrollmentLifecycleUsesServerTimeAndAccountScope(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run peer identity repository integration tests")
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
	userID, otherUserID := "peer_lifecycle_user_"+suffix, "peer_lifecycle_other_"+suffix
	for _, value := range []string{userID, otherUserID} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, value, "workos_"+value, value+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	otherRoot, _, _ := ed25519.GenerateKey(nil)
	for _, value := range []struct {
		userID string
		public ed25519.PublicKey
	}{{userID, rootPublic}, {otherUserID, otherRoot}} {
		fingerprint := sha256.Sum256(value.public)
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.account_e2ee_roots (user_id,public_key,fingerprint) VALUES ($1,$2,$3)`, value.userID, value.public, fingerprint[:]); err != nil {
			t.Fatal(err)
		}
	}
	repository, err := NewSQLRepository(store, audit.NewWriter(store))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	rootFingerprint := sha256.Sum256(rootPublic)
	register := func(request CLIEndpointRequest, serial uint64, issuedAt, registerAt time.Time) error {
		raw := signedFixture(t, rootPrivate, userID, RoleCLI, request.EndpointID, 1, serial, issuedAt, registerAt.Add(time.Hour))
		fingerprint := sha256.Sum256(raw)
		_, err := service.Register(ctx, RegisterRequest{OperationID: "certificate_" + request.OperationID, UserID: userID, Certificate: raw, Expected: Expected{AccountID: userID, Role: RoleCLI, EndpointID: request.EndpointID, Generation: 1, Serial: serial}, ExpectedRootFingerprint: rootFingerprint, ExpectedCertificateFingerprint: fingerprint, ExpectedIssuedAt: issuedAt, ExpectedExpiresAt: registerAt.Add(time.Hour), Now: registerAt})
		return err
	}
	newRequest := func(label string, at time.Time) (CLIEndpointRequest, EndpointEnrollmentRequest) {
		request := CLIEndpointRequest{OperationID: "operation_" + label + "_" + suffix, UserID: userID, EndpointID: "endpoint_" + label + "_" + suffix, Generation: 1, NoisePublicKey: [32]byte{1}, QUICPublicKey: [32]byte{2}, Now: at}
		value, err := service.RequestCLIEndpoint(ctx, request)
		if err != nil {
			t.Fatalf("create %s: %v", label, err)
		}
		return request, value
	}

	expiring, expiringValue := newRequest("expiry", now)
	if err := register(expiring, 1, now.Add(time.Minute), now.Add(6*time.Minute)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("late approval error=%v, want unavailable", err)
	}
	expired, err := service.EndpointRequest(ctx, userID, expiringValue.ID, now.Add(6*time.Minute))
	if err != nil || expired.State != "expired" {
		t.Fatalf("expired status=%+v err=%v", expired, err)
	}
	if _, err := service.EndpointRequest(ctx, otherUserID, expiringValue.ID, now.Add(6*time.Minute)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cross-account status error=%v", err)
	}

	_, denyValue := newRequest("deny", now.Add(10*time.Minute))
	denyOperation := "deny_operation_" + suffix
	denied, err := service.DenyEndpointRequest(ctx, denyOperation, userID, denyValue.ID, now.Add(11*time.Minute))
	if err != nil || denied.State != "denied" {
		t.Fatalf("denied=%+v err=%v", denied, err)
	}
	replay, err := service.DenyEndpointRequest(ctx, denyOperation, userID, denyValue.ID, now.Add(12*time.Minute))
	if err != nil || replay.ID != denied.ID || replay.State != "denied" {
		t.Fatalf("denial replay=%+v err=%v", replay, err)
	}
	if _, err := service.DenyEndpointRequest(ctx, denyOperation+"_other", userID, denyValue.ID, now.Add(12*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting denial error=%v", err)
	}
	if _, err := service.DenyEndpointRequest(ctx, "deny_wrong_account_"+suffix, otherUserID, denyValue.ID, now.Add(12*time.Minute)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cross-account denial error=%v", err)
	}

	_, concurrentValue := newRequest("concurrent", now.Add(20*time.Minute))
	concurrentOperation := "deny_concurrent_" + suffix
	var wait sync.WaitGroup
	errorsByCall := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, err := service.DenyEndpointRequest(ctx, concurrentOperation, userID, concurrentValue.ID, now.Add(21*time.Minute))
			if err == nil && value.State != "denied" {
				err = errors.New("concurrent denial returned non-denied state")
			}
			errorsByCall <- err
		}()
	}
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent idempotent denial: %v", err)
		}
	}

	revokedRequest, revokedValue := newRequest("revoke", now.Add(30*time.Minute))
	issuedAt := now.Add(31 * time.Minute)
	if err := register(revokedRequest, 2, issuedAt, issuedAt); err != nil {
		t.Fatalf("register revoke fixture: %v", err)
	}
	if _, err := service.Revoke(ctx, "revoke_operation_"+suffix, userID, revokedRequest.EndpointID, 1, 2, "endpoint_removed", now.Add(32*time.Minute)); err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}
	status, err := service.EndpointRequest(ctx, userID, revokedValue.ID, now.Add(32*time.Minute))
	if err != nil || status.State != "revoked" {
		t.Fatalf("revoked request status=%+v err=%v", status, err)
	}
	revokedReplay, replayErr := service.RequestCLIEndpoint(ctx, revokedRequest)
	if !errors.Is(replayErr, ErrConflict) && (replayErr != nil || revokedReplay.State != "revoked") {
		t.Fatalf("revoked certificate replay=%+v err=%v, want revoked or conflict", revokedReplay, replayErr)
	}

	expiredCertificateRequest, expiredCertificateValue := newRequest("certificate_expiry", now.Add(40*time.Minute))
	expiredCertificateIssuedAt := now.Add(41 * time.Minute)
	if err := register(expiredCertificateRequest, 3, expiredCertificateIssuedAt, expiredCertificateIssuedAt); err != nil {
		t.Fatalf("register expiring certificate fixture: %v", err)
	}
	expiredCertificateStatus, err := service.EndpointRequest(ctx, userID, expiredCertificateValue.ID, expiredCertificateIssuedAt.Add(time.Hour+time.Second))
	if err != nil || expiredCertificateStatus.State != "revoked" {
		t.Fatalf("expired certificate request status=%+v err=%v", expiredCertificateStatus, err)
	}
}

func TestSQLRepositoryCLIEndpointEnrollmentReplaysOnlyBoundActiveRequests(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run peer identity repository integration tests")
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
	if _, err := service.Register(ctx, RegisterRequest{OperationID: "operation_cli_certificate_" + suffix, UserID: userID, Certificate: raw, Expected: Expected{AccountID: userID, Role: RoleCLI, EndpointID: request.EndpointID, Generation: 1, Serial: 1}, ExpectedRootFingerprint: rootFingerprint, ExpectedCertificateFingerprint: fingerprint, ExpectedIssuedAt: now, ExpectedExpiresAt: now.Add(time.Hour), Now: now}); err != nil {
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
