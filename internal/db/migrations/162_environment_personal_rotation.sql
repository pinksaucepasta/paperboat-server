-- +goose Up
ALTER TABLE environment_vault_personal_epochs ADD COLUMN rotation_required boolean NOT NULL DEFAULT false;
ALTER TABLE environment_vault_teams ADD COLUMN rotation_required boolean NOT NULL DEFAULT false;
-- +goose Down
ALTER TABLE environment_vault_teams DROP COLUMN rotation_required;
ALTER TABLE environment_vault_personal_epochs DROP COLUMN rotation_required;
