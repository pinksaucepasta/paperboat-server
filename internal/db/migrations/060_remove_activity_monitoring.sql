-- +goose Up
SET search_path TO paperboat, public;

ALTER TABLE project_runtime_configs
  DROP COLUMN IF EXISTS idle_timeout_option_id,
  DROP COLUMN IF EXISTS applied_idle_timeout_option_id;

DROP TABLE IF EXISTS project_activity_markers;
DROP TABLE IF EXISTS idle_timeout_options;

-- +goose Down
SELECT 1;
