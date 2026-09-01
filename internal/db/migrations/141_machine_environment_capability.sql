-- +goose Up
-- Environment injection is a host capability. Keep client machines restricted
-- to their existing file and preview capabilities while allowing hosts to
-- advertise and persist the runtime capability during heartbeat reconciliation.
ALTER TABLE user_machines
  DROP CONSTRAINT user_machines_observed_capabilities_check,
  DROP CONSTRAINT user_machines_configured_capabilities_check;

UPDATE user_machines
SET configured_capabilities = ARRAY[
  'file_receive', 'preview_launch', 'terminal_host', 'codex_host',
  'session_host', 'keep_awake', 'environment_injection'
]::text[]
WHERE setup_mode = 'host';

ALTER TABLE user_machines
  ALTER COLUMN configured_capabilities SET DEFAULT ARRAY[
    'file_receive', 'preview_launch', 'terminal_host', 'codex_host',
    'session_host', 'keep_awake', 'environment_injection'
  ]::text[],
  ADD CONSTRAINT user_machines_configured_capabilities_check CHECK (
    configured_capabilities <@ ARRAY[
      'file_receive', 'preview_launch', 'terminal_host', 'codex_host',
      'session_host', 'keep_awake', 'environment_injection'
    ]::text[]
  ),
  ADD CONSTRAINT user_machines_observed_capabilities_check CHECK (
    observed_capabilities <@ configured_capabilities
  );

-- +goose Down
-- This migration is data widening for host capability state. Preserve the
-- client/host rows while removing the new capability before restoring the
-- previous constraint and default.
ALTER TABLE user_machines
  DROP CONSTRAINT user_machines_observed_capabilities_check,
  DROP CONSTRAINT user_machines_configured_capabilities_check;

UPDATE user_machines
SET configured_capabilities = array_remove(configured_capabilities, 'environment_injection'),
    observed_capabilities = array_remove(observed_capabilities, 'environment_injection');

ALTER TABLE user_machines
  ALTER COLUMN configured_capabilities SET DEFAULT ARRAY[
    'file_receive', 'preview_launch', 'terminal_host', 'codex_host',
    'session_host', 'keep_awake'
  ]::text[],
  ADD CONSTRAINT user_machines_configured_capabilities_check CHECK (
    configured_capabilities <@ ARRAY[
      'file_receive', 'preview_launch', 'terminal_host', 'codex_host',
      'session_host', 'keep_awake'
    ]::text[]
  ),
  ADD CONSTRAINT user_machines_observed_capabilities_check CHECK (
    observed_capabilities <@ configured_capabilities
  );
