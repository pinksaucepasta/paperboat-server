-- +goose Up
ALTER TABLE control_config_credentials
  RENAME COLUMN helper_id TO machine_id;

ALTER TABLE control_config_repository_lease_authority
  RENAME COLUMN helper_id TO machine_id;
ALTER TABLE control_config_repository_lease_authority
  RENAME COLUMN helper_generation TO installation_generation;

ALTER TABLE control_config_repository_lease_operations
  RENAME COLUMN helper_id TO machine_id;

ALTER TABLE control_config_repository_access_operations
  RENAME COLUMN helper_id TO machine_id;
ALTER TABLE control_config_repository_access_operations
  RENAME COLUMN helper_generation TO installation_generation;

ALTER TABLE control_config_sync_statuses
  RENAME COLUMN helper_id TO machine_id;
ALTER TABLE control_config_sync_statuses
  RENAME COLUMN helper_generation TO installation_generation;
ALTER TABLE control_config_sync_statuses
  RENAME COLUMN helper_updated_at TO machine_updated_at;

ALTER TABLE control_config_sync_status_history
  RENAME COLUMN helper_id TO machine_id;
ALTER TABLE control_config_sync_status_history
  RENAME COLUMN helper_generation TO installation_generation;

DROP INDEX control_config_credentials_active;
CREATE INDEX control_config_credentials_active
  ON control_config_credentials(environment_id, machine_id, expires_at)
  WHERE revoked_at IS NULL;

DROP INDEX control_config_repository_access_active;
CREATE INDEX control_config_repository_access_active
  ON control_config_repository_access_operations(environment_id, machine_id, expires_at)
  WHERE state = 'issued' AND revoked_at IS NULL;

-- +goose Down
SELECT 1;
