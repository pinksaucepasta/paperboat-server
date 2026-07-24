-- +goose Up
ALTER TABLE control_config_repository_lease_operations
  ADD COLUMN assignment_id text,
  ADD COLUMN environment_id text,
  ADD COLUMN helper_id text,
  ADD COLUMN base_remote_revision text;

-- +goose Down
ALTER TABLE control_config_repository_lease_operations
  DROP COLUMN IF EXISTS base_remote_revision,
  DROP COLUMN IF EXISTS helper_id,
  DROP COLUMN IF EXISTS environment_id,
  DROP COLUMN IF EXISTS assignment_id;
