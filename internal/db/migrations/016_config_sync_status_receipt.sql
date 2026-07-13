-- +goose Up

SET LOCAL search_path TO paperboat;

ALTER TABLE config_sync_statuses
ADD COLUMN IF NOT EXISTS received_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE config_sync_statuses
ADD COLUMN IF NOT EXISTS status_observed_at timestamptz;

UPDATE config_sync_statuses
SET status_observed_at = LEAST(status_updated_at, received_at)
WHERE status_observed_at IS NULL;

ALTER TABLE config_sync_statuses
ALTER COLUMN status_observed_at SET NOT NULL;

-- +goose Down
-- Forward-only migration.
