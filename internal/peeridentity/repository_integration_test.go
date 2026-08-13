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
