-- +goose Up

SET LOCAL search_path TO paperboat;

CREATE TABLE IF NOT EXISTS config_sync_statuses (
	project_id text NOT NULL REFERENCES projects(id),
	machine_id text NOT NULL,
	state text NOT NULL,
	last_attempt_at timestamptz,
	last_successful_sync_at timestamptz,
	remote_commit text NOT NULL DEFAULT '',
	pending_path_count integer NOT NULL DEFAULT 0,
	skipped jsonb NOT NULL DEFAULT '[]'::jsonb,
	conflicts jsonb NOT NULL DEFAULT '[]'::jsonb,
	error_code text NOT NULL DEFAULT '',
	error_message text NOT NULL DEFAULT '',
	max_file_bytes bigint NOT NULL,
	max_batch_bytes bigint NOT NULL,
	policy_revision text NOT NULL,
	heartbeat_at timestamptz NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (project_id, machine_id)
);

CREATE INDEX IF NOT EXISTS idx_config_sync_statuses_project_heartbeat
ON config_sync_statuses(project_id, heartbeat_at DESC);

-- +goose Down
-- Forward-only migration.
