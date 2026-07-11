-- +goose Up

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

-- +goose Down
-- Forward-only migration.
