package db

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"time"
)

type Migration struct {
	Version int
	Name    string
	SQL     string
}

var Migrations = []Migration{
	{Version: 1, Name: "phase_2_initial_postgres_schema", SQL: phase2SchemaSQL},
	{Version: 2, Name: "phase_3_identity_roles", SQL: phase3IdentityRolesSQL},
	{Version: 3, Name: "phase_5_github_config_repos", SQL: phase5GitHubConfigReposSQL},
	{Version: 4, Name: "phase_6_project_lifecycle", SQL: phase6ProjectLifecycleSQL},
	{Version: 5, Name: "phase_7_fly_orchestration_readiness", SQL: phase7FlyOrchestrationSQL},
	{Version: 6, Name: "phase_8_runtime_metering", SQL: phase8RuntimeMeteringSQL},
	{Version: 7, Name: "phase_9_activity_heartbeat_state", SQL: phase9ActivityHeartbeatSQL},
}

func Migrate(ctx context.Context, d *DB) error {
	if err := d.Ping(ctx); err != nil {
		return err
	}
	if _, err := d.sql.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS paperboat`); err != nil {
		return fmt.Errorf("ensure paperboat schema: %w", err)
	}
	conn, err := d.sql.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open migration connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey()); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockKey())

	if _, err := conn.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS paperboat.schema_migrations (
	version integer PRIMARY KEY,
	name text NOT NULL,
	applied_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}
	for _, migration := range Migrations {
		applied, err := migrationApplied(ctx, conn, migration.Version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		if err := d.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			if _, err := tx.Exec(ctx, migration.SQL); err != nil {
				return fmt.Errorf("apply migration %d %s: %w", migration.Version, migration.Name, err)
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)`, migration.Version, migration.Name, time.Now().UTC())
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

type migrationQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func migrationApplied(ctx context.Context, conn migrationQuerier, version int) (bool, error) {
	var exists bool
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM paperboat.schema_migrations WHERE version = $1)`, version).Scan(&exists); err != nil {
		return false, fmt.Errorf("check migration %d: %w", version, err)
	}
	return exists, nil
}

func migrationLockKey() int64 {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte("paperboat-server:migrations"))
	return int64(hash.Sum64())
}

const phase2SchemaSQL = `
SET LOCAL search_path TO paperboat;

CREATE TABLE IF NOT EXISTS users (
	id text PRIMARY KEY,
	workos_subject text NOT NULL UNIQUE,
	primary_email text NOT NULL,
	display_name text NOT NULL DEFAULT '',
	status text NOT NULL,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES users(id),
	session_hash text NOT NULL UNIQUE,
	csrf_hash text NOT NULL,
	expires_at timestamptz NOT NULL,
	rotated_at timestamptz,
	revoked_at timestamptz,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_identities (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES users(id),
	provider text NOT NULL,
	provider_subject text NOT NULL,
	email text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (provider, provider_subject)
);

CREATE TABLE IF NOT EXISTS github_oauth_tokens (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES users(id),
	token_ciphertext bytea NOT NULL,
	scopes text[] NOT NULL DEFAULT '{}',
	expires_at timestamptz,
	refresh_expires_at timestamptz,
	revoked_at timestamptz,
	last_validated_at timestamptz,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
	id text PRIMARY KEY,
	actor_user_id text REFERENCES users(id),
	actor_type text NOT NULL,
	event_type text NOT NULL,
	resource_type text NOT NULL,
	resource_id text NOT NULL DEFAULT '',
	idempotency_key text,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (idempotency_key)
);

CREATE TABLE IF NOT EXISTS plans (
	id text PRIMARY KEY,
	code text NOT NULL UNIQUE,
	name text NOT NULL,
	active boolean NOT NULL DEFAULT true,
	current_version_id text,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS plan_versions (
	id text PRIMARY KEY,
	plan_id text NOT NULL REFERENCES plans(id),
	version_number integer NOT NULL,
	included_credits numeric(18,6) NOT NULL,
	included_storage_gb integer NOT NULL,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (plan_id, version_number)
);

CREATE TABLE IF NOT EXISTS machine_types (
	id text PRIMARY KEY,
	code text NOT NULL UNIQUE,
	name text NOT NULL,
	vcpu integer NOT NULL,
	memory_mb integer NOT NULL,
	credit_weight numeric(18,6) NOT NULL,
	custom_shape_allowed boolean NOT NULL DEFAULT false,
	active boolean NOT NULL DEFAULT true,
	current_version_id text,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS machine_type_versions (
	id text PRIMARY KEY,
	machine_type_id text NOT NULL REFERENCES machine_types(id),
	version_number integer NOT NULL,
	vcpu integer NOT NULL,
	memory_mb integer NOT NULL,
	credit_weight numeric(18,6) NOT NULL,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (machine_type_id, version_number)
);

CREATE TABLE IF NOT EXISTS vm_presets (
	id text PRIMARY KEY,
	code text NOT NULL UNIQUE,
	name text NOT NULL,
	description text NOT NULL DEFAULT '',
	active boolean NOT NULL DEFAULT true,
	current_version_id text,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vm_preset_versions (
	id text PRIMARY KEY,
	preset_id text NOT NULL REFERENCES vm_presets(id),
	version_number integer NOT NULL,
	manifest jsonb NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (preset_id, version_number)
);

CREATE TABLE IF NOT EXISTS idle_timeout_options (
	id text PRIMARY KEY,
	code text NOT NULL UNIQUE,
	duration_seconds integer NOT NULL,
	active boolean NOT NULL DEFAULT true,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS regions (
	id text PRIMARY KEY,
	code text NOT NULL UNIQUE,
	name text NOT NULL,
	enabled boolean NOT NULL DEFAULT true,
	placement_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS feature_flags (
	id text PRIMARY KEY,
	code text NOT NULL UNIQUE,
	enabled boolean NOT NULL DEFAULT false,
	config jsonb NOT NULL DEFAULT '{}'::jsonb,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS billing_products (
	id text PRIMARY KEY,
	code text NOT NULL UNIQUE,
	provider text NOT NULL,
	provider_product_id text NOT NULL,
	provider_price_id text NOT NULL,
	catalog_type text NOT NULL,
	catalog_ref text NOT NULL,
	active boolean NOT NULL DEFAULT true,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS subscriptions (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES users(id),
	provider text NOT NULL,
	provider_subscription_id text NOT NULL UNIQUE,
	state text NOT NULL,
	active_plan_version_id text REFERENCES plan_versions(id),
	current_period_start timestamptz,
	current_period_end timestamptz,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS credit_accounts (
	id text PRIMARY KEY,
	user_id text NOT NULL UNIQUE REFERENCES users(id),
	balance numeric(18,6) NOT NULL DEFAULT 0,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS credit_ledger_entries (
	id text PRIMARY KEY,
	account_id text NOT NULL REFERENCES credit_accounts(id),
	entry_type text NOT NULL,
	amount numeric(18,6) NOT NULL,
	source_type text NOT NULL,
	source_id text NOT NULL DEFAULT '',
	idempotency_key text NOT NULL UNIQUE,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS storage_accounts (
	id text PRIMARY KEY,
	user_id text NOT NULL UNIQUE REFERENCES users(id),
	included_gb integer NOT NULL DEFAULT 0,
	purchased_gb integer NOT NULL DEFAULT 0,
	allocated_gb integer NOT NULL DEFAULT 0,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT storage_account_nonnegative CHECK (included_gb >= 0 AND purchased_gb >= 0 AND allocated_gb >= 0),
	CONSTRAINT storage_account_not_overallocated CHECK (allocated_gb <= included_gb + purchased_gb)
);

CREATE TABLE IF NOT EXISTS storage_ledger_entries (
	id text PRIMARY KEY,
	account_id text NOT NULL REFERENCES storage_accounts(id),
	entry_type text NOT NULL,
	amount_gb integer NOT NULL,
	source_type text NOT NULL,
	source_id text NOT NULL DEFAULT '',
	idempotency_key text NOT NULL UNIQUE,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS polar_events (
	id text PRIMARY KEY,
	provider_event_id text NOT NULL UNIQUE,
	event_type text NOT NULL,
	processed_state text NOT NULL,
	payload jsonb NOT NULL,
	processed_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES users(id),
	name text NOT NULL,
	state text NOT NULL,
	idempotency_key text NOT NULL,
	create_request_hash text NOT NULL DEFAULT '',
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (user_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS project_repositories (
	project_id text PRIMARY KEY REFERENCES projects(id),
	provider text NOT NULL,
	source_url text NOT NULL,
	default_branch text NOT NULL DEFAULT '',
	clone_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project_storage_allocations (
	project_id text PRIMARY KEY REFERENCES projects(id),
	storage_account_id text NOT NULL REFERENCES storage_accounts(id),
	assigned_gb integer NOT NULL,
	fly_volume_id text,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project_runtime_configs (
	project_id text PRIMARY KEY REFERENCES projects(id),
	machine_type_version_id text REFERENCES machine_type_versions(id),
	preset_version_ids text[] NOT NULL DEFAULT '{}',
	setup_script_ref text NOT NULL DEFAULT '',
	idle_timeout_option_id text REFERENCES idle_timeout_options(id),
	region_id text REFERENCES regions(id),
	pending_restart_apply boolean NOT NULL DEFAULT false,
	desired_config_hash text NOT NULL DEFAULT '',
	applied_storage_gb integer NOT NULL DEFAULT 0,
	applied_machine_type_version_id text REFERENCES machine_type_versions(id),
	applied_preset_version_ids text[] NOT NULL DEFAULT '{}',
	applied_setup_script_ref text NOT NULL DEFAULT '',
	applied_idle_timeout_option_id text REFERENCES idle_timeout_options(id),
	applied_region_id text REFERENCES regions(id),
	applied_config_hash text NOT NULL DEFAULT '',
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project_credentials (
	id text PRIMARY KEY,
	project_id text NOT NULL REFERENCES projects(id),
	credential_type text NOT NULL,
	ciphertext bytea NOT NULL,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (project_id, credential_type)
);

CREATE TABLE IF NOT EXISTS fly_machines (
	id text PRIMARY KEY,
	project_id text NOT NULL UNIQUE REFERENCES projects(id),
	fly_machine_id text NOT NULL UNIQUE,
	state text NOT NULL,
	image_ref text NOT NULL,
	region text NOT NULL,
	observed_config_hash text NOT NULL DEFAULT '',
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fly_volumes (
	id text PRIMARY KEY,
	project_id text NOT NULL UNIQUE REFERENCES projects(id),
	fly_volume_id text NOT NULL UNIQUE,
	size_gb integer NOT NULL,
	region text NOT NULL,
	state text NOT NULL,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS orchestration_jobs (
	id text PRIMARY KEY,
	job_type text NOT NULL,
	aggregate_type text NOT NULL,
	aggregate_id text NOT NULL,
	idempotency_key text NOT NULL UNIQUE,
	state text NOT NULL,
	attempts integer NOT NULL DEFAULT 0,
	next_run_at timestamptz NOT NULL DEFAULT now(),
	payload jsonb NOT NULL DEFAULT '{}'::jsonb,
	last_error text NOT NULL DEFAULT '',
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reconciliation_runs (
	id text PRIMARY KEY,
	scope text NOT NULL,
	state text NOT NULL,
	findings jsonb NOT NULL DEFAULT '[]'::jsonb,
	started_at timestamptz NOT NULL DEFAULT now(),
	finished_at timestamptz
);

CREATE TABLE IF NOT EXISTS access_sessions (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES users(id),
	project_id text NOT NULL REFERENCES projects(id),
	session_type text NOT NULL,
	state text NOT NULL,
	descriptor jsonb NOT NULL DEFAULT '{}'::jsonb,
	expires_at timestamptz NOT NULL,
	revoked_at timestamptz,
	idempotency_key text NOT NULL UNIQUE,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agentunnel_resources (
	id text PRIMARY KEY,
	project_id text NOT NULL UNIQUE REFERENCES projects(id),
	tunnel_id text NOT NULL,
	client_id text NOT NULL DEFAULT '',
	resource_id text NOT NULL DEFAULT '',
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS connection_events (
	id text PRIMARY KEY,
	user_id text REFERENCES users(id),
	project_id text REFERENCES projects(id),
	access_session_id text REFERENCES access_sessions(id),
	result text NOT NULL,
	failure_reason text NOT NULL DEFAULT '',
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS preview_url_records (
	id text PRIMARY KEY,
	project_id text NOT NULL REFERENCES projects(id),
	preview_key text NOT NULL,
	target_url text NOT NULL,
	public_url text NOT NULL,
	state text NOT NULL,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (project_id, preview_key)
);

CREATE TABLE IF NOT EXISTS provider_events (
	id text PRIMARY KEY,
	provider text NOT NULL,
	provider_event_id text NOT NULL,
	event_type text NOT NULL,
	processed_state text NOT NULL,
	payload jsonb NOT NULL,
	processed_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (provider, provider_event_id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_resource ON audit_events(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_projects_user_id ON projects(user_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_jobs_state_next_run ON orchestration_jobs(state, next_run_at);
CREATE INDEX IF NOT EXISTS idx_connection_events_project ON connection_events(project_id, created_at DESC);
`

const phase3IdentityRolesSQL = `
SET LOCAL search_path TO paperboat;

ALTER TABLE users ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'user';

DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conname = 'users_role_valid'
		  AND conrelid = 'paperboat.users'::regclass
	) THEN
		ALTER TABLE users ADD CONSTRAINT users_role_valid CHECK (role IN ('user', 'support', 'admin', 'system_worker'));
	END IF;
END $$;
`

const phase5GitHubConfigReposSQL = `
SET LOCAL search_path TO paperboat;

ALTER TABLE github_oauth_tokens ADD COLUMN IF NOT EXISTS refresh_token_ciphertext bytea;
ALTER TABLE github_oauth_tokens ADD COLUMN IF NOT EXISTS provider_account_login text NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_github_oauth_tokens_user_unique ON github_oauth_tokens(user_id);

CREATE TABLE IF NOT EXISTS github_config_repositories (
	id text PRIMARY KEY,
	user_id text NOT NULL UNIQUE REFERENCES users(id),
	provider_repo_id text NOT NULL DEFAULT '',
	owner text NOT NULL,
	name text NOT NULL,
	default_branch text NOT NULL,
	clone_url text NOT NULL,
	html_url text NOT NULL DEFAULT '',
	private boolean NOT NULL DEFAULT true,
	provisioned_at timestamptz,
	version bigint NOT NULL DEFAULT 1,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (owner, name)
);

CREATE TABLE IF NOT EXISTS github_repo_provisioning_attempts (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES users(id),
	idempotency_key text NOT NULL UNIQUE,
	state text NOT NULL,
	repo_owner text NOT NULL DEFAULT '',
	repo_name text NOT NULL DEFAULT '',
	last_error text NOT NULL DEFAULT '',
	attempts integer NOT NULL DEFAULT 0,
	next_retry_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_github_oauth_tokens_user_id ON github_oauth_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_github_config_repositories_user_id ON github_config_repositories(user_id);
`

const phase6ProjectLifecycleSQL = `
SET LOCAL search_path TO paperboat;

ALTER TABLE projects ADD COLUMN IF NOT EXISTS create_request_hash text NOT NULL DEFAULT '';
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_storage_gb integer NOT NULL DEFAULT 0;
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_machine_type_version_id text REFERENCES machine_type_versions(id);
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_preset_version_ids text[] NOT NULL DEFAULT '{}';
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_setup_script_ref text NOT NULL DEFAULT '';
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_idle_timeout_option_id text REFERENCES idle_timeout_options(id);
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_region_id text REFERENCES regions(id);

CREATE TABLE IF NOT EXISTS project_setup_script_revisions (
	id text PRIMARY KEY,
	project_id text NOT NULL REFERENCES projects(id),
	revision_number integer NOT NULL,
	script_sha256 text NOT NULL,
	script_ciphertext bytea NOT NULL,
	guidance text NOT NULL DEFAULT '',
	created_by_user_id text NOT NULL REFERENCES users(id),
	created_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (project_id, revision_number)
);

CREATE TABLE IF NOT EXISTS project_events (
	id text PRIMARY KEY,
	project_id text NOT NULL REFERENCES projects(id),
	event_type text NOT NULL,
	message text NOT NULL,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_project_events_project_created ON project_events(project_id, created_at DESC);
`

const phase7FlyOrchestrationSQL = `
SET LOCAL search_path TO paperboat;

ALTER TABLE projects ADD COLUMN IF NOT EXISTS create_request_hash text NOT NULL DEFAULT '';
ALTER TABLE project_storage_allocations ADD COLUMN IF NOT EXISTS fly_volume_id text;
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_storage_gb integer NOT NULL DEFAULT 0;
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_machine_type_version_id text REFERENCES machine_type_versions(id);
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_preset_version_ids text[] NOT NULL DEFAULT '{}';
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_setup_script_ref text NOT NULL DEFAULT '';
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_idle_timeout_option_id text REFERENCES idle_timeout_options(id);
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_region_id text REFERENCES regions(id);
ALTER TABLE project_runtime_configs ADD COLUMN IF NOT EXISTS applied_config_hash text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_fly_machines_project_id ON fly_machines(project_id);
CREATE INDEX IF NOT EXISTS idx_fly_volumes_project_id ON fly_volumes(project_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_jobs_aggregate ON orchestration_jobs(aggregate_type, aggregate_id);
CREATE INDEX IF NOT EXISTS idx_reconciliation_runs_scope_started ON reconciliation_runs(scope, started_at DESC);
`

const phase8RuntimeMeteringSQL = `
SET LOCAL search_path TO paperboat;

CREATE TABLE IF NOT EXISTS machine_runtime_intervals (
	id text PRIMARY KEY,
	project_id text NOT NULL REFERENCES projects(id),
	user_id text NOT NULL REFERENCES users(id),
	fly_machine_id text NOT NULL,
	machine_type_version_id text NOT NULL REFERENCES machine_type_versions(id),
	credit_weight numeric(18,6) NOT NULL,
	started_at timestamptz NOT NULL,
	stopped_at timestamptz,
	last_metered_at timestamptz NOT NULL,
	observed_state text NOT NULL,
	observation_source text NOT NULL,
	confidence text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_machine_runtime_intervals_open
ON machine_runtime_intervals(project_id)
WHERE stopped_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_machine_runtime_intervals_project_started
ON machine_runtime_intervals(project_id, started_at DESC);

CREATE TABLE IF NOT EXISTS metering_checkpoints (
	id text PRIMARY KEY,
	runtime_interval_id text NOT NULL REFERENCES machine_runtime_intervals(id),
	project_id text NOT NULL REFERENCES projects(id),
	user_id text NOT NULL REFERENCES users(id),
	period_start timestamptz NOT NULL,
	period_end timestamptz NOT NULL,
	runtime_seconds integer NOT NULL,
	credit_weight numeric(18,6) NOT NULL,
	credits_debited numeric(18,6) NOT NULL,
	idempotency_key text NOT NULL UNIQUE,
	state text NOT NULL,
	last_error text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	processed_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_metering_checkpoints_project_created
ON metering_checkpoints(project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS project_activity_markers (
	project_id text PRIMARY KEY REFERENCES projects(id),
	last_activity_at timestamptz NOT NULL,
	source text NOT NULL,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_project_activity_markers_last_activity
ON project_activity_markers(last_activity_at);
`

const phase9ActivityHeartbeatSQL = `
SET LOCAL search_path TO paperboat;

ALTER TABLE project_activity_markers ADD COLUMN IF NOT EXISTS machine_id text NOT NULL DEFAULT '';
ALTER TABLE project_activity_markers ADD COLUMN IF NOT EXISTS last_heartbeat_at timestamptz;
ALTER TABLE project_activity_markers ADD COLUMN IF NOT EXISTS reporter_version text NOT NULL DEFAULT '';
ALTER TABLE project_activity_markers ADD COLUMN IF NOT EXISTS signals jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE project_activity_markers ADD COLUMN IF NOT EXISTS keep_alive_until timestamptz;
ALTER TABLE project_activity_markers ADD COLUMN IF NOT EXISTS reporter_lost_since timestamptz;
ALTER TABLE project_activity_markers ADD COLUMN IF NOT EXISTS idle_warning_sent_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_project_activity_markers_last_heartbeat
ON project_activity_markers(last_heartbeat_at);
`
