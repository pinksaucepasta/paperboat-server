-- +goose Up

CREATE TABLE connected_machine_terminal_sessions (
  id text PRIMARY KEY,
  connected_machine_id text NOT NULL REFERENCES connected_machines(id) ON DELETE CASCADE,
  terminal_id text NOT NULL,
  thread_id text NOT NULL DEFAULT 'paperboat-cli',
  name text NOT NULL,
  idempotency_key text,
  is_default boolean NOT NULL DEFAULT false,
  auto_name_ordinal integer,
  launch_cwd text NOT NULL,
  desired_state text NOT NULL DEFAULT 'open',
  runtime_state text NOT NULL DEFAULT 'unknown',
  last_activity_at timestamptz,
  last_runtime_sync_at timestamptz,
  last_runtime_sequence bigint,
  deleted_at timestamptz,
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  CHECK ((is_default AND name = 'default') OR NOT is_default),
  CHECK (desired_state IN ('open', 'closed', 'deleted'))
);

CREATE UNIQUE INDEX connected_machine_terminal_sessions_active_name
  ON connected_machine_terminal_sessions(connected_machine_id, lower(name)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX connected_machine_terminal_sessions_terminal
  ON connected_machine_terminal_sessions(connected_machine_id, terminal_id);
CREATE UNIQUE INDEX connected_machine_terminal_sessions_one_default
  ON connected_machine_terminal_sessions(connected_machine_id) WHERE is_default AND deleted_at IS NULL;
CREATE UNIQUE INDEX connected_machine_terminal_sessions_idempotency
  ON connected_machine_terminal_sessions(connected_machine_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE connected_machine_terminal_session_operations (
  id text PRIMARY KEY,
  connected_machine_id text NOT NULL REFERENCES connected_machines(id) ON DELETE CASCADE,
  terminal_session_id text NOT NULL REFERENCES connected_machine_terminal_sessions(id) ON DELETE CASCADE,
  operation text NOT NULL CHECK (operation IN ('close', 'delete_history')),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'applied', 'failed')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error text,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (terminal_session_id, operation, state)
);

INSERT INTO connected_machine_terminal_sessions (id, connected_machine_id, terminal_id, name, is_default, launch_cwd)
SELECT 'cmts_default_' || id, id, 'term-1', 'default', true, workspace_root
FROM connected_machines
WHERE deleted_at IS NULL
ON CONFLICT DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS connected_machine_terminal_session_operations;
DROP TABLE IF EXISTS connected_machine_terminal_sessions;
