-- +goose Up
ALTER TABLE user_machine_pairings
  ADD COLUMN installation_recovery_operation_key text;

-- +goose Down
ALTER TABLE user_machine_pairings
  DROP COLUMN installation_recovery_operation_key;
