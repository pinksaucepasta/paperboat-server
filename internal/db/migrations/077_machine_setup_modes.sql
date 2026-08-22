-- +goose Up
ALTER TABLE user_machines
  ADD COLUMN setup_mode text NOT NULL DEFAULT 'host',
  ADD COLUMN configured_capabilities text[] NOT NULL DEFAULT '{}'::text[],
  ADD COLUMN observed_capabilities text[] NOT NULL DEFAULT '{}'::text[];
UPDATE user_machines SET setup_mode = CASE WHEN 'host' = ANY(setup_roles) THEN 'host' ELSE 'session' END;
UPDATE user_machines SET configured_capabilities = CASE setup_mode WHEN 'host' THEN ARRAY['file_receive','preview_launch','terminal_host','codex_host','session_host','keep_awake']::text[] WHEN 'client' THEN ARRAY['file_receive','preview_launch']::text[] ELSE '{}'::text[] END;
ALTER TABLE user_machines
  ADD CONSTRAINT user_machines_setup_mode_check CHECK (setup_mode IN ('client','session','host')),
  ADD CONSTRAINT user_machines_configured_capabilities_check CHECK (configured_capabilities <@ ARRAY['file_receive','preview_launch','terminal_host','codex_host','session_host','keep_awake']::text[]),
  ADD CONSTRAINT user_machines_observed_capabilities_check CHECK (observed_capabilities <@ configured_capabilities);

-- +goose Down
ALTER TABLE user_machines
  DROP CONSTRAINT user_machines_observed_capabilities_check,
  DROP CONSTRAINT user_machines_configured_capabilities_check,
  DROP CONSTRAINT user_machines_setup_mode_check,
  DROP COLUMN observed_capabilities,
  DROP COLUMN configured_capabilities,
  DROP COLUMN setup_mode;
