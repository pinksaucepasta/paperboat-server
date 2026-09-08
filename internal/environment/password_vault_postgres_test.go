package environment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestPostgresPasswordVaultCASAndIdempotentRetry(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run the password vault CAS proof")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(dsn), "_test") {
		t.Fatal("PAPERBOAT_TEST_DATABASE_DSN must name an isolated *_test database")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	migrationCtx, migrationCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer migrationCancel()
	t.Log("applying isolated database migrations")
	if err := db.Migrate(migrationCtx, store); err != nil {
		t.Fatal(err)
	}
	t.Log("migrations applied; checking vault transactions")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	accountID, otherAccountID := "vaultuser_"+suffix, "vaultother_"+suffix
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := store.SQL().ExecContext(cleanupCtx, `DELETE FROM paperboat.users WHERE id IN ($1,$2)`, accountID, otherAccountID); err != nil {
			t.Errorf("clean password vault fixtures: %v", err)
		}
	}()
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$2,$3,'active'),($4,$5,$6,'active')`, accountID, "workos_"+suffix, suffix+"@vault.invalid", otherAccountID, "workos_other_"+suffix, suffix+"@vault-other.invalid"); err != nil {
		t.Fatal(err)
	}
	service := NewService(store, nil, nil, "https://control.example")
	first := passwordVaultFixture(t, "https://control.example", accountID, 1, make([]byte, 32))
	firstHead, err := service.PutPasswordVault(ctx, accountID, first)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("initial vault committed")
	if retry, err := service.PutPasswordVault(ctx, accountID, first); err != nil || retry.DocumentID != firstHead.DocumentID {
		t.Fatalf("exact retry failed or returned a different document: %v", err)
	}
	if _, err := service.GetPasswordVault(ctx, otherAccountID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-account read error=%v", err)
	}
	if _, err := service.PutPasswordVault(ctx, otherAccountID, first); !errors.Is(err, ErrProtocolInvalid) {
		t.Fatalf("cross-account put error=%v", err)
	}
	stale := passwordVaultFixture(t, "https://control.example", accountID, 2, bytes.Repeat([]byte{9}, 32))
	if _, err := service.PutPasswordVault(ctx, accountID, stale); !errors.Is(err, ErrPasswordVaultConflict) {
		t.Fatalf("stale successor error=%v", err)
	}
	previous := sha256.Sum256(first)
	stalePasswordEpoch := passwordVaultFixtureWith(t, "https://control.example", accountID, 2, previous[:], vaultFixtureOptions{passwordSaltByte: 2})
	if _, err := service.PutPasswordVault(ctx, accountID, stalePasswordEpoch); !errors.Is(err, ErrPasswordVaultConflict) {
		t.Fatalf("changed password descriptor at stale epoch error=%v", err)
	}
	second := passwordVaultFixtureWith(t, "https://control.example", accountID, 2, previous[:], vaultFixtureOptions{recovery: true, recoveryEpoch: 2})
	secondHead, err := service.PutPasswordVault(ctx, accountID, second)
	if err != nil {
		t.Fatal(err)
	}
	current, err := service.GetPasswordVault(ctx, accountID)
	if err != nil || current.DocumentID != secondHead.DocumentID || current.Generation != 2 {
		t.Fatalf("current vault is not generation 2 with the committed document: %v", err)
	}
	if _, err := service.PutPasswordVault(ctx, accountID, first); !errors.Is(err, ErrPasswordVaultConflict) {
		t.Fatalf("rollback error=%v", err)
	}

	secondDigest := sha256.Sum256(second)
	thirdA := passwordVaultFixtureWith(t, "https://control.example", accountID, 3, secondDigest[:], vaultFixtureOptions{recovery: true, recoveryEpoch: 2, ciphertextByte: 4})
	thirdB := passwordVaultFixtureWith(t, "https://control.example", accountID, 3, secondDigest[:], vaultFixtureOptions{recovery: true, recoveryEpoch: 2, ciphertextByte: 5})
	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, candidate := range [][]byte{thirdA, thirdB} {
		candidate := candidate
		go func() {
			ready.Done()
			<-start
			_, err := service.PutPasswordVault(ctx, accountID, candidate)
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	var successes, conflicts int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrPasswordVaultConflict):
			conflicts++
		default:
			t.Fatalf("concurrent successor returned unexpected error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent successor results: successes=%d conflicts=%d", successes, conflicts)
	}
	t.Log("concurrent successor CAS verified")
}
