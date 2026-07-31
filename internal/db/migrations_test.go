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
	var controlPlaneMigrationApplied bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id = 28 AND is_applied)`).Scan(&controlPlaneMigrationApplied); err != nil {
		t.Fatal(err)
	}
	if !controlPlaneMigrationApplied {
		t.Fatal("Goose control-plane foundation migration was not recorded")
	}
	var unifiedMachineMigrationApplied bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id = 65 AND is_applied)`).Scan(&unifiedMachineMigrationApplied); err != nil {
		t.Fatal(err)
	}
	if !unifiedMachineMigrationApplied {
		t.Fatal("unified machine identity migration was not recorded")
	}
	for _, column := range []string{"setup_roles", "public_identity_key", "installation_generation"} {
		var exists bool
		if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='paperboat' AND table_name='user_machines' AND column_name=$1
		)`, column).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("unified machine column %s was not created", column)
		}
	}
	var hostedMachineMigrationApplied bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id = 67 AND is_applied)`).Scan(&hostedMachineMigrationApplied); err != nil {
		t.Fatal(err)
	}
	if !hostedMachineMigrationApplied {
		t.Fatal("hosted canonical machine migration was not recorded")
	}
	for table, column := range map[string]string{"user_machines": "machine_kind", "fly_machines": "user_machine_id"} {
		var exists bool
		if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='paperboat' AND table_name=$1 AND column_name=$2
		)`, table, column).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("hosted canonical machine column %s.%s was not created", table, column)
		}
	}
	var machineConfigMigrationApplied bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id = 68 AND is_applied)`).Scan(&machineConfigMigrationApplied); err != nil {
		t.Fatal(err)
	}
	if !machineConfigMigrationApplied {
		t.Fatal("machine-scoped config assignment migration was not recorded")
	}
	var configMachineColumn bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema='paperboat' AND table_name='control_config_assignments' AND column_name='machine_id' AND is_nullable='NO'
	)`).Scan(&configMachineColumn); err != nil {
		t.Fatal(err)
	}
	if !configMachineColumn {
		t.Fatal("machine-scoped config assignment key was not created")
	}
	for _, version := range []int{69, 70, 71, 72, 73, 74} {
		var applied bool
		if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id=$1 AND is_applied)`, version).Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if !applied {
			t.Fatalf("unified runtime migration %d was not recorded", version)
		}
	}
	if _, err := store.SQL().ExecContext(context.Background(), `SELECT paperboat.revoke_config_sync_for_environment('migration_machine_authority_probe')`); err != nil {
		t.Fatalf("machine-authority config revocation function failed: %v", err)
	}
	var configCredentialMachineForeignKey bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conrelid='paperboat.control_config_credentials'::regclass
		  AND confrelid='paperboat.user_machines'::regclass
		  AND conname='control_config_credentials_environment_id_machine_id_fkey'
	)`).Scan(&configCredentialMachineForeignKey); err != nil {
		t.Fatal(err)
	}
	if !configCredentialMachineForeignKey {
		t.Fatal("config credentials are not bound to canonical machines")
	}
	var renewalTable bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT to_regclass('paperboat.machine_control_renewals') IS NOT NULL`).Scan(&renewalTable); err != nil {
		t.Fatal(err)
	}
	if !renewalTable {
		t.Fatal("machine-control renewal table was not created")
	}
	for table, column := range map[string]string{"control_connector_generations": "connector_id", "control_routes": "connector_id"} {
		var exists bool
		if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='paperboat' AND table_name=$1 AND column_name=$2 AND is_nullable='NO'
		)`, table, column).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("connector-instance column %s.%s was not created", table, column)
		}
	}
	var connectorPrimaryKey bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1
		FROM pg_constraint constraint_row
		JOIN pg_class table_row ON table_row.oid = constraint_row.conrelid
		JOIN pg_namespace namespace_row ON namespace_row.oid = table_row.relnamespace
		WHERE namespace_row.nspname='paperboat'
		  AND table_row.relname='control_connector_generations'
		  AND constraint_row.contype='p'
		  AND pg_get_constraintdef(constraint_row.oid) = 'PRIMARY KEY (environment_id, connector_id)'
	)`).Scan(&connectorPrimaryKey); err != nil {
		t.Fatal(err)
	}
	if !connectorPrimaryKey {
		t.Fatal("connector generation primary key is not environment plus connector")
	}
	for _, table := range []string{"project_terminal_sessions", "user_machine_terminal_sessions"} {
		var defaultValue string
		if err := store.SQL().QueryRowContext(context.Background(), `SELECT column_default
			FROM information_schema.columns
			WHERE table_schema='paperboat' AND table_name=$1 AND column_name='thread_id'`, table).Scan(&defaultValue); err != nil {
			t.Fatal(err)
		}
		if defaultValue != "'paperboat'::text" {
			t.Fatalf("%s.thread_id default = %q", table, defaultValue)
		}
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
	for _, index := range []string{"terminal_session_operations_one_pending", "user_machine_terminal_session_operations_one_pending"} {
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
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ('usr_migration_client_revocation_probe', 'workos_migration_client_revocation_probe', 'migration-client-revocation@example.test', 'active')
ON CONFLICT (id) DO UPDATE SET status='active';
INSERT INTO paperboat.cli_client_sessions (id, user_id, client_id, client_label, device_type, os, scopes, state, created_at, approved_at)
VALUES ('cls_migration_revocation_probe', 'usr_migration_client_revocation_probe', 'migration-probe', 'Migration probe', 'cli', 'linux', ARRAY[]::text[], 'active', now(), now())
ON CONFLICT (id) DO UPDATE SET state='active', revoked_at=NULL, revocation_reason=NULL;
UPDATE paperboat.cli_client_sessions
SET state='revoked', revoked_at=now(), revocation_reason='migration_probe'
WHERE id='cls_migration_revocation_probe';
DELETE FROM paperboat.cli_client_sessions WHERE id='cls_migration_revocation_probe';
DELETE FROM paperboat.users WHERE id='usr_migration_client_revocation_probe'`); err != nil {
		t.Fatalf("client revocation trigger execution failed: %v", err)
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
		WHERE tgname = 'trg_users_revoke_cli_client_sessions' AND NOT tgisinternal
	)`).Scan(&hasClientRevocationTrigger); err != nil {
		t.Fatal(err)
	}
	if !hasClientRevocationTrigger {
		t.Fatal("account lifecycle client-revocation trigger was not applied")
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
