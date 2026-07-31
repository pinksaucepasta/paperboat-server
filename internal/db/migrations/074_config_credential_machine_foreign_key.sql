-- +goose Up
ALTER TABLE control_config_credentials
  DROP CONSTRAINT control_config_credentials_environment_id_helper_id_fkey;

ALTER TABLE control_config_credentials
  ADD CONSTRAINT control_config_credentials_environment_id_machine_id_fkey
  FOREIGN KEY (machine_id)
  REFERENCES user_machines(id)
  ON DELETE CASCADE;

-- +goose Down
SELECT 1;
