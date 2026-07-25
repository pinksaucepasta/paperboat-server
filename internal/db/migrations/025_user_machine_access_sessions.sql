-- +goose Up

CREATE TABLE user_machine_access_sessions (
  id text PRIMARY KEY,
  user_machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  environment_id text NOT NULL,
  cli_client_session_id text NOT NULL,
  http_base_url text NOT NULL,
  helper_terminal_session_id text,
  helper_file_session_id text,
  state text NOT NULL DEFAULT 'active',
  revocation_reason text,
  revoked_at timestamptz,
  helper_revoked_at timestamptz,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('active', 'revoked')),
  CHECK (helper_terminal_session_id IS NOT NULL OR helper_file_session_id IS NOT NULL)
);

CREATE INDEX user_machine_access_sessions_machine_active
  ON user_machine_access_sessions(user_machine_id, created_at)
  WHERE state = 'active';
CREATE INDEX user_machine_access_sessions_pending_revocation
  ON user_machine_access_sessions(created_at)
  WHERE state = 'revoked' AND helper_revoked_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS user_machine_access_sessions;
