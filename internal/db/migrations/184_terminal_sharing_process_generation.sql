-- +goose Up
ALTER TABLE team_resource_bindings ADD COLUMN terminal_process_generation bigint;
ALTER TABLE team_resource_bindings ADD CONSTRAINT team_resource_bindings_terminal_process_generation_check CHECK (
  (resource_kind = 'terminal_session' AND (NOT active OR terminal_process_generation > 0)) OR
  (resource_kind <> 'terminal_session' AND terminal_process_generation IS NULL)
) NOT VALID;

-- +goose Down
ALTER TABLE team_resource_bindings DROP CONSTRAINT IF EXISTS team_resource_bindings_terminal_process_generation_check;
ALTER TABLE team_resource_bindings DROP COLUMN IF EXISTS terminal_process_generation;
