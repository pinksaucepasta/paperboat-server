-- +goose Up

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

-- +goose Down
-- Forward-only migration.
