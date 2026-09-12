package peeridentity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"os"
	"testing"
	"time"
)

func TestFreshEndpointApprovalUsesServerRegistrationTimeOnPostgres(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
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
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := "peer_time_" + suffix
	endpoint := "machine_time_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status)VALUES($1,$1,$2,'active')`, user, user+"@example.test"); err != nil {
		t.Fatal(err)
	}
	defer store.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, user)
	public, private, _ := ed25519.GenerateKey(nil)
	rootHash := sha256.Sum256(public)
	key := keyIDForFingerprint(rootHash)
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.account_e2ee_roots(user_id,public_key,fingerprint)VALUES($1,$2,$3)`, user, public, rootHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.account_e2ee_keys(key_id,user_id,public_key,fingerprint,generation)VALUES($1,$2,$3,$4,1)`, key, user, public, rootHash[:]); err != nil {
		t.Fatal(err)
	}
	repo, _ := NewSQLRepository(store, audit.NewWriter(store))
	service, _ := NewService(repo)
	noise, quic := []byte(make([]byte, 32)), []byte(make([]byte, 32))
	noise[0] = 1
	quic[0] = 2
	register := func(generation uint64, created, expires, serverNow time.Time) (Certificate, error) {
		t.Helper()
		id := fmt.Sprintf("per_%s_%d", suffix, generation)
		hash := sha256.Sum256([]byte(id))
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.peer_endpoint_enrollment_requests(id,operation_key,request_hash,user_id,endpoint_id,generation,noise_public_key,quic_public_key,created_at,expires_at)VALUES($1,$1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, hash[:], user, endpoint, generation, noise, quic, created, expires); err != nil {
			t.Fatal(err)
		}
		issued := serverNow.Add(-time.Minute).Truncate(time.Second)
		end := issued.Add(time.Hour)
		raw := signedFixture(t, private, user, RoleMachine, endpoint, generation, 1, issued, end)
		return service.Register(ctx, RegisterRequest{OperationID: "operation_" + id, UserID: user, KeyID: key, Certificate: raw, Expected: Expected{AccountID: user, Role: RoleMachine, EndpointID: endpoint, Generation: generation, Serial: 1}, ExpectedRootFingerprint: rootHash, ExpectedCertificateFingerprint: sha256.Sum256(raw), ExpectedIssuedAt: issued, ExpectedExpiresAt: end, Now: serverNow})
	}
	firstNow := time.Now().UTC()
	first, err := register(1, firstNow.Add(-time.Millisecond), firstNow.Add(time.Minute), firstNow)
	if err != nil {
		t.Fatalf("fresh request with backdated certificate: %v", err)
	}
	var fulfilled time.Time
	if err := store.SQL().QueryRowContext(ctx, `SELECT fulfilled_at FROM paperboat.peer_endpoint_enrollment_requests WHERE user_id=$1 AND generation=1`, user).Scan(&fulfilled); err != nil {
		t.Fatal(err)
	}
	if fulfilled.Sub(firstNow) > time.Microsecond || firstNow.Sub(fulfilled) > time.Microsecond {
		t.Fatal("fulfillment did not use server registration time")
	}
	secondNow := time.Now().UTC()
	if _, err := register(2, secondNow.Add(-time.Millisecond), secondNow.Add(time.Minute), secondNow); err != nil {
		t.Fatalf("superseding fresh certificate: %v", err)
	}
	var validRevocation bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT revoked_at>=created_at FROM paperboat.peer_endpoint_certificates WHERE fingerprint=$1`, first.Fingerprint[:]).Scan(&validRevocation); err != nil || !validRevocation {
		t.Fatalf("superseded revocation timestamp invalid: %v", err)
	}
	expiredNow := time.Now().UTC()
	if _, err := register(3, expiredNow.Add(-30*time.Second), expiredNow.Add(-time.Second), expiredNow); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expired request revived by certificate backdating: %v", err)
	}
}
