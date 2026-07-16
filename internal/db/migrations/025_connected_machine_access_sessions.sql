-- +goose Up

CREATE TABLE connected_machine_access_sessions (
  id text PRIMARY KEY,
  connected_machine_id text NOT NULL REFERENCES connected_machines(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  environment_id text NOT NULL,
  client_session_id text NOT NULL,
  http_base_url text NOT NULL,
  papercode_terminal_session_id text,
  papercode_file_session_id text,
  state text NOT NULL DEFAULT 'active',
  revocation_reason text,
  revoked_at timestamptz,
  papercode_revoked_at timestamptz,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('active', 'revoked')),
  CHECK (papercode_terminal_session_id IS NOT NULL OR papercode_file_session_id IS NOT NULL)
);

CREATE INDEX connected_machine_access_sessions_machine_active
  ON connected_machine_access_sessions(connected_machine_id, created_at)
  WHERE state = 'active';
CREATE INDEX connected_machine_access_sessions_pending_revocation
  ON connected_machine_access_sessions(created_at)
  WHERE state = 'revoked' AND papercode_revoked_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS connected_machine_access_sessions;
