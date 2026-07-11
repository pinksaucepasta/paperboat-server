-- +goose Up

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

-- +goose Down
-- Forward-only migration.
