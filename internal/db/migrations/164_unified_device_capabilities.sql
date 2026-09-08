-- Device capabilities replace permanent client/host product modes. Desired
-- and observed revisions keep UI state distinct from daemon enforcement.
-- +goose Up
ALTER TABLE user_machines
  ADD COLUMN capabilities_desired_version bigint NOT NULL DEFAULT 1 CHECK (capabilities_desired_version > 0),
  ADD COLUMN capabilities_observed_version bigint NOT NULL DEFAULT 0 CHECK (capabilities_observed_version >= 0),
  ADD COLUMN capabilities_status text NOT NULL DEFAULT 'pending'
    CHECK (capabilities_status IN ('pending','applied','offline','error')),
  ADD COLUMN capabilities_error_code text;

ALTER TABLE user_machines
  DROP CONSTRAINT user_machines_observed_capabilities_check,
  DROP CONSTRAINT user_machines_configured_capabilities_check;

UPDATE user_machines
SET configured_capabilities = ARRAY(
      SELECT DISTINCT capability
      FROM unnest(configured_capabilities || ARRAY[
        'file_receive','preview_launch','terminal_host','codex_host','session_host','ssh_host'
      ]::text[]) capability
      ORDER BY capability
    ),
    capabilities_status = CASE WHEN online THEN 'pending' ELSE 'offline' END;

ALTER TABLE user_machines
  ALTER COLUMN configured_capabilities SET DEFAULT ARRAY[
    'file_receive','preview_launch','terminal_host','codex_host','session_host','ssh_host'
  ]::text[],
  ADD CONSTRAINT user_machines_configured_capabilities_check CHECK (
    configured_capabilities <@ ARRAY[
      'file_receive','preview_launch','terminal_host','codex_host','session_host',
      'ssh_host','keep_awake','environment_injection','peer_relay'
    ]::text[]
  ),
  ADD CONSTRAINT user_machines_observed_capabilities_check CHECK (
    observed_capabilities <@ ARRAY[
      'file_receive','preview_launch','terminal_host','codex_host','session_host',
      'ssh_host','keep_awake','environment_injection','peer_relay'
    ]::text[]
  );

CREATE TABLE user_machine_capability_operations (
  id text PRIMARY KEY,
  user_machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  idempotency_key text NOT NULL,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  expected_version bigint NOT NULL CHECK (expected_version > 0),
  resulting_version bigint NOT NULL CHECK (resulting_version = expected_version + 1),
  configured_capabilities text[] NOT NULL,
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, user_machine_id, idempotency_key)
);

-- +goose Down
DROP TABLE IF EXISTS user_machine_capability_operations;
ALTER TABLE user_machines
  DROP CONSTRAINT user_machines_observed_capabilities_check,
  DROP CONSTRAINT user_machines_configured_capabilities_check;
UPDATE user_machines
SET configured_capabilities = array_remove(array_remove(configured_capabilities, 'ssh_host'), 'peer_relay'),
    observed_capabilities = array_remove(array_remove(observed_capabilities, 'ssh_host'), 'peer_relay');
ALTER TABLE user_machines ALTER COLUMN configured_capabilities SET DEFAULT ARRAY['file_receive','preview_launch','terminal_host','codex_host','session_host','keep_awake']::text[];
ALTER TABLE user_machines
  DROP COLUMN IF EXISTS capabilities_error_code,
  DROP COLUMN IF EXISTS capabilities_status,
  DROP COLUMN IF EXISTS capabilities_observed_version,
  DROP COLUMN IF EXISTS capabilities_desired_version,
  ADD CONSTRAINT user_machines_configured_capabilities_check CHECK (
    configured_capabilities <@ ARRAY['file_receive','preview_launch','terminal_host','codex_host','session_host','keep_awake','environment_injection']::text[]
  ),
  ADD CONSTRAINT user_machines_observed_capabilities_check CHECK (observed_capabilities <@ configured_capabilities);
