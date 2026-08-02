-- +goose Up
ALTER TABLE user_machines
  ALTER COLUMN configured_capabilities SET DEFAULT ARRAY['file_receive','preview_launch','terminal_host','codex_host','session_host','keep_awake']::text[];

-- +goose Down
ALTER TABLE user_machines
  ALTER COLUMN configured_capabilities SET DEFAULT '{}'::text[];
