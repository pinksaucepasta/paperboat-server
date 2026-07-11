-- +goose Up

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

-- +goose Down
-- Forward-only migration.
