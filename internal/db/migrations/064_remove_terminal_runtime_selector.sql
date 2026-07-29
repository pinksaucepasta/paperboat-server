-- +goose Up

ALTER TABLE project_terminal_sessions DROP COLUMN IF EXISTS terminal_mode;
ALTER TABLE user_machine_terminal_sessions DROP COLUMN IF EXISTS terminal_mode;

-- +goose Down

ALTER TABLE project_terminal_sessions ADD COLUMN terminal_mode text NOT NULL DEFAULT 'shell';
ALTER TABLE user_machine_terminal_sessions ADD COLUMN terminal_mode text NOT NULL DEFAULT 'shell';
