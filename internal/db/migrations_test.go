package db_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestMigrateRequiresPostgresIntegrationDSN(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres migration integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	var applied bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id = 16 AND is_applied)`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("Goose migration version 16 was not recorded")
	}
	var hasRole bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'paperboat' AND table_name = 'users' AND column_name = 'role'
	)`).Scan(&hasRole); err != nil {
		t.Fatal(err)
	}
	if !hasRole {
		t.Fatal("users.role migration was not applied")
	}
	var hasClientRevocationTrigger bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM pg_trigger
		WHERE tgname = 'trg_users_revoke_client_sessions' AND NOT tgisinternal
	)`).Scan(&hasClientRevocationTrigger); err != nil {
		t.Fatal(err)
	}
	if !hasClientRevocationTrigger {
		t.Fatal("account lifecycle client-revocation trigger was not applied")
	}
	var hasConfigSyncStatus bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT to_regclass('paperboat.config_sync_statuses') IS NOT NULL`).Scan(&hasConfigSyncStatus); err != nil {
		t.Fatal(err)
	}
	if !hasConfigSyncStatus {
		t.Fatal("config_sync_statuses migration was not applied")
	}
	var hasStatusUpdatedAt bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'paperboat' AND table_name = 'config_sync_statuses' AND column_name = 'status_updated_at' AND is_nullable = 'NO'
	)`).Scan(&hasStatusUpdatedAt); err != nil {
		t.Fatal(err)
	}
	if !hasStatusUpdatedAt {
		t.Fatal("config_sync_statuses.status_updated_at migration was not applied")
	}
	var hasReceivedAt bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'paperboat' AND table_name = 'config_sync_statuses' AND column_name = 'received_at' AND is_nullable = 'NO'
	)`).Scan(&hasReceivedAt); err != nil {
		t.Fatal(err)
	}
	if !hasReceivedAt {
		t.Fatal("config_sync_statuses.received_at migration was not applied")
	}
	var hasStatusObservedAt bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'paperboat' AND table_name = 'config_sync_statuses' AND column_name = 'status_observed_at' AND is_nullable = 'NO'
	)`).Scan(&hasStatusObservedAt); err != nil {
		t.Fatal(err)
	}
	if !hasStatusObservedAt {
		t.Fatal("config_sync_statuses.status_observed_at migration was not applied")
	}
}

func TestConcurrentMigrateCallsAreSerialized(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres migration integration tests")
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	start := make(chan struct{})
	errs := make(chan error, 4)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- db.Migrate(ctx, store)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migrate failed: %v", err)
		}
	}
}

func TestTransactionRollsBackOnError(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres transaction integration tests")
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
	sentinel := errors.New("force rollback")
	err = store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Exec(ctx, `
INSERT INTO users (id, workos_subject, primary_email, status)
VALUES ('user_rollback_test', 'workos_rollback_test', 'rollback@example.com', 'active')
ON CONFLICT (id) DO UPDATE SET primary_email = EXCLUDED.primary_email`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want sentinel", err)
	}
	var exists bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM paperboat.users WHERE id = 'user_rollback_test')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("rolled back transaction still inserted user")
	}
}
