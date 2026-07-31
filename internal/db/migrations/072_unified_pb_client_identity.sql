-- +goose Up
ALTER TABLE project_terminal_sessions
  ALTER COLUMN thread_id SET DEFAULT 'paperboat';

ALTER TABLE user_machine_terminal_sessions
  ALTER COLUMN thread_id SET DEFAULT 'paperboat';

-- +goose Down
SELECT 1;
