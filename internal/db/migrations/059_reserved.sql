-- +goose Up

ALTER TABLE project_terminal_sessions
  ADD COLUMN terminal_mode text NOT NULL DEFAULT 'shell'
  CHECK (terminal_mode = 'shell');

ALTER TABLE user_machine_terminal_sessions
  ADD COLUMN terminal_mode text NOT NULL DEFAULT 'shell'
  CHECK (terminal_mode = 'shell');

-- +goose Down

ALTER TABLE user_machine_terminal_sessions DROP COLUMN terminal_mode;
ALTER TABLE project_terminal_sessions DROP COLUMN terminal_mode;
