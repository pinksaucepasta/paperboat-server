-- +goose Up
ALTER TABLE control_previews
  DROP CONSTRAINT control_previews_environment_id_logical_name_key;
CREATE UNIQUE INDEX control_previews_active_environment_logical_name
  ON control_previews(environment_id, logical_name)
  WHERE state <> 'removed';

-- +goose Down
DROP INDEX IF EXISTS control_previews_active_environment_logical_name;
ALTER TABLE control_previews
  ADD CONSTRAINT control_previews_environment_id_logical_name_key
  UNIQUE (environment_id, logical_name);
