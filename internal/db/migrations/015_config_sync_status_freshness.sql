-- +goose Up

SET LOCAL search_path TO paperboat;

ALTER TABLE config_sync_statuses
ADD COLUMN IF NOT EXISTS status_updated_at timestamptz;

UPDATE config_sync_statuses
SET status_updated_at = heartbeat_at
WHERE status_updated_at IS NULL;

ALTER TABLE config_sync_statuses
ALTER COLUMN status_updated_at SET NOT NULL;

-- +goose Down
-- Forward-only migration.
