package metering_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
)

func TestStorageAllocationPreventsOverallocation(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres repository integration tests")
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "user_storage_test_" + suffix
	accountID := "storage_account_test_" + suffix
	projectID := "project_storage_test_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1, $2, 'storage-test@example.com', 'active')`, userID, "workos_storage_test_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.storage_accounts (id, user_id, included_gb, purchased_gb, allocated_gb) VALUES ($1, $2, 10, 0, 0)`, accountID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.projects (id, user_id, name, state, idempotency_key) VALUES ($1, $2, 'Storage Test', 'creating', $3)`, projectID, userID, "storage-test-"+suffix); err != nil {
		t.Fatal(err)
	}
	repo := metering.NewStorageRepository(store)
	if err := repo.Allocate(ctx, accountID, projectID, "storage_ledger_test_1_"+suffix, "storage-ledger-test-1-"+suffix, 8); err != nil {
		t.Fatal(err)
	}
	err = repo.Allocate(ctx, accountID, projectID, "storage_ledger_test_2_"+suffix, "storage-ledger-test-2-"+suffix, 3)
	if !errors.Is(err, metering.ErrInsufficientStorage) {
		t.Fatalf("error = %v, want insufficient storage", err)
	}
	if err := repo.Allocate(ctx, accountID, projectID, "storage_ledger_test_1_retry_"+suffix, "storage-ledger-test-1-"+suffix, 8); err != nil {
		t.Fatal(err)
	}
	var allocated int
	if err := store.SQL().QueryRowContext(ctx, `SELECT allocated_gb FROM paperboat.storage_accounts WHERE id = $1`, accountID).Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != 8 {
		t.Fatalf("allocated_gb after idempotent retry = %d, want 8", allocated)
	}
}

func TestConcurrentStorageAllocationCannotOverallocate(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres repository integration tests")
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "user_storage_concurrent_test_" + suffix
	accountID := "storage_account_concurrent_test_" + suffix
	projectA := "project_storage_concurrent_a_" + suffix
	projectB := "project_storage_concurrent_b_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1, $2, 'storage-concurrent-test@example.com', 'active')`, userID, "workos_storage_concurrent_test_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.storage_accounts (id, user_id, included_gb, purchased_gb, allocated_gb) VALUES ($1, $2, 10, 0, 0)`, accountID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.projects (id, user_id, name, state, idempotency_key) VALUES ($1, $2, 'Storage Concurrent A', 'creating', $3)`, projectA, userID, "storage-concurrent-a-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.projects (id, user_id, name, state, idempotency_key) VALUES ($1, $2, 'Storage Concurrent B', 'creating', $3)`, projectB, userID, "storage-concurrent-b-"+suffix); err != nil {
		t.Fatal(err)
	}

	repo := metering.NewStorageRepository(store)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, project := range []string{projectA, projectB} {
		wg.Add(1)
		go func(projectID string) {
			defer wg.Done()
			<-start
			errs <- repo.Allocate(ctx, accountID, projectID, "storage_ledger_"+projectID, "storage-ledger-"+projectID, 7)
		}(project)
	}
	close(start)
	wg.Wait()
	close(errs)

	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes > 1 {
		t.Fatalf("successful allocations = %d, want at most 1", successes)
	}
	var allocated int
	if err := store.SQL().QueryRowContext(ctx, `SELECT allocated_gb FROM paperboat.storage_accounts WHERE id = $1`, accountID).Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated > 10 {
		t.Fatalf("allocated_gb = %d, quota is 10", allocated)
	}
}

func TestConcurrentStorageAllocationWithSameIdempotencyKeySucceeds(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres repository integration tests")
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "user_storage_idempotent_test_" + suffix
	accountID := "storage_account_idempotent_test_" + suffix
	projectID := "project_storage_idempotent_test_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1, $2, 'storage-idempotent-test@example.com', 'active')`, userID, "workos_storage_idempotent_test_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.storage_accounts (id, user_id, included_gb, purchased_gb, allocated_gb) VALUES ($1, $2, 10, 0, 0)`, accountID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.projects (id, user_id, name, state, idempotency_key) VALUES ($1, $2, 'Storage Idempotent', 'creating', $3)`, projectID, userID, "storage-idempotent-"+suffix); err != nil {
		t.Fatal(err)
	}

	repo := metering.NewStorageRepository(store)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			errs <- repo.Allocate(ctx, accountID, projectID, fmt.Sprintf("storage_ledger_idempotent_%s_%d", suffix, index), "storage-ledger-idempotent-"+suffix, 7)
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent idempotent allocation returned error: %v", err)
		}
	}
	var allocated int
	if err := store.SQL().QueryRowContext(ctx, `SELECT allocated_gb FROM paperboat.storage_accounts WHERE id = $1`, accountID).Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != 7 {
		t.Fatalf("allocated_gb = %d, want 7", allocated)
	}
}

func TestStorageAllocationRejectsIdempotencyKeyConflict(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres repository integration tests")
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "user_storage_conflict_test_" + suffix
	accountID := "storage_account_conflict_test_" + suffix
	projectA := "project_storage_conflict_a_" + suffix
	projectB := "project_storage_conflict_b_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1, $2, 'storage-conflict-test@example.com', 'active')`, userID, "workos_storage_conflict_test_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.storage_accounts (id, user_id, included_gb, purchased_gb, allocated_gb) VALUES ($1, $2, 20, 0, 0)`, accountID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.projects (id, user_id, name, state, idempotency_key) VALUES ($1, $2, 'Storage Conflict A', 'creating', $3)`, projectA, userID, "storage-conflict-a-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.projects (id, user_id, name, state, idempotency_key) VALUES ($1, $2, 'Storage Conflict B', 'creating', $3)`, projectB, userID, "storage-conflict-b-"+suffix); err != nil {
		t.Fatal(err)
	}
	repo := metering.NewStorageRepository(store)
	key := "storage-ledger-conflict-" + suffix
	if err := repo.Allocate(ctx, accountID, projectA, "storage_ledger_conflict_a_"+suffix, key, 7); err != nil {
		t.Fatal(err)
	}
	err = repo.Allocate(ctx, accountID, projectB, "storage_ledger_conflict_b_"+suffix, key, 7)
	if !errors.Is(err, metering.ErrIdempotencyConflict) {
		t.Fatalf("error = %v, want idempotency conflict", err)
	}
}
