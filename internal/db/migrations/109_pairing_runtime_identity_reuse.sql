-- +goose Up
ALTER TABLE user_machine_pairings
  ADD COLUMN can_reuse_runtime_identity boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE user_machine_pairings DROP COLUMN can_reuse_runtime_identity;
