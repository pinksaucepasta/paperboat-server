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
	var controlPlaneMigrationApplied bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id = 28 AND is_applied)`).Scan(&controlPlaneMigrationApplied); err != nil {
		t.Fatal(err)
	}
	if !controlPlaneMigrationApplied {
		t.Fatal("Goose control-plane foundation migration was not recorded")
	}
	for _, version := range []int{29, 30, 31, 32} {
		var applied bool
		if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id=$1 AND is_applied)`, version).Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if !applied {
			t.Fatalf("Goose billing operation migration %d was not recorded", version)
		}
	}
	var orchestrationIdempotencyApplied, hasOrchestrationIdempotency bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id=38 AND is_applied)`).Scan(&orchestrationIdempotencyApplied); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT to_regclass('paperboat.orchestration_jobs_idempotency') IS NOT NULL`).Scan(&hasOrchestrationIdempotency); err != nil {
		t.Fatal(err)
	}
	if !orchestrationIdempotencyApplied || !hasOrchestrationIdempotency {
		t.Fatal("orchestration job idempotency migration was not applied")
	}
	for _, index := range []string{"terminal_session_operations_one_pending", "connected_machine_terminal_session_operations_one_pending"} {
		var applied bool
		if err := store.SQL().QueryRowContext(context.Background(), `SELECT to_regclass('paperboat.' || $1) IS NOT NULL`, index).Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if !applied {
			t.Fatalf("terminal operation repair index %s was not applied", index)
		}
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ('usr_migration_revocation_probe', 'workos_migration_revocation_probe', 'migration-revocation@example.test', 'active')
ON CONFLICT (id) DO UPDATE SET status='active';
UPDATE paperboat.users SET status='suspended' WHERE id='usr_migration_revocation_probe';
DELETE FROM paperboat.users WHERE id='usr_migration_revocation_probe'`); err != nil {
		t.Fatalf("account revocation trigger execution failed: %v", err)
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
	for _, table := range []string{"account_config_keys", "config_classification_overrides", "config_classification_cache"} {
		var exists bool
		if err := store.SQL().QueryRowContext(context.Background(), `SELECT to_regclass('paperboat.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("migration did not create %s", table)
		}
	}
	var hasEncryptionVersion bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='paperboat' AND table_name='config_sync_statuses' AND column_name='encryption_key_version')`).Scan(&hasEncryptionVersion); err != nil {
		t.Fatal(err)
	}
	if !hasEncryptionVersion {
		t.Fatal("config sync encryption version column missing")
	}
	for _, table := range []string{
		"control_environments",
		"control_helpers",
		"control_helper_enrollments",
		"control_config_repositories",
		"control_config_assignments",
		"control_operations",
		"control_reconciliation_attempts",
		"control_tunnel_nodes",
		"control_usage_verification_keys",
		"control_connector_generations",
		"control_routes",
		"control_usage_counters",
		"control_usage_receipts",
	} {
		var exists bool
		if err := store.SQL().QueryRowContext(context.Background(), `SELECT to_regclass('paperboat.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatalf("check control-plane table %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("control-plane migration did not create %s", table)
		}
	}
	for _, table := range []string{"billing_portal_operations", "billing_subscription_update_operations", "billing_uncertain_recoveries"} {
		var exists bool
		if err := store.SQL().QueryRowContext(context.Background(), `SELECT to_regclass('paperboat.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatalf("check billing operation table %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("billing operation migration did not create %s", table)
		}
	}
	for _, column := range []string{"last_error", "uncertain_at"} {
		var exists bool
		if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='paperboat' AND table_name='billing_checkout_reservations' AND column_name=$1)`, column).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("billing checkout migration did not create %s", column)
		}
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
