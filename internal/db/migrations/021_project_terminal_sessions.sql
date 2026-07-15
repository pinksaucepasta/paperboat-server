-- +goose Up
CREATE TABLE project_terminal_sessions (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  terminal_id text NOT NULL,
  thread_id text NOT NULL DEFAULT 'paperboat-cli',
  name text NOT NULL,
	  idempotency_key text,
  is_default boolean NOT NULL DEFAULT false,
  auto_name_ordinal integer,
  launch_cwd text NOT NULL DEFAULT '/workspace',
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
  CHECK (desired_state IN ('open','closed','deleted'))
);

CREATE UNIQUE INDEX project_terminal_sessions_active_name
  ON project_terminal_sessions(project_id, lower(name)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX project_terminal_sessions_terminal
  ON project_terminal_sessions(project_id, terminal_id);
CREATE UNIQUE INDEX project_terminal_sessions_one_default
  ON project_terminal_sessions(project_id) WHERE is_default AND deleted_at IS NULL;
CREATE UNIQUE INDEX project_terminal_sessions_idempotency
  ON project_terminal_sessions(project_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE terminal_session_operations (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  terminal_session_id text NOT NULL REFERENCES project_terminal_sessions(id) ON DELETE CASCADE,
  operation text NOT NULL CHECK (operation IN ('close','delete_history')),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','applied','failed')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error text,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (terminal_session_id, operation, state)
);

INSERT INTO project_terminal_sessions (id, project_id, terminal_id, name, is_default, runtime_state)
SELECT 'pts_default_' || p.id, p.id, 'term-1', 'default', true, 'unknown'
FROM projects p
WHERE p.state <> 'deleted'
ON CONFLICT DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS terminal_session_operations;
DROP TABLE IF EXISTS project_terminal_sessions;
