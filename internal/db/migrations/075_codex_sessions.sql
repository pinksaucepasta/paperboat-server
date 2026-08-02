-- +goose Up
SET LOCAL search_path TO paperboat;

CREATE TABLE codex_sessions (
  id text PRIMARY KEY,
  environment_id text NOT NULL REFERENCES control_environments(id) ON DELETE CASCADE,
  machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cli_client_session_id text NOT NULL REFERENCES cli_client_sessions(id) ON DELETE CASCADE,
  idempotency_key text NOT NULL,
  request_hash bytea NOT NULL,
  state text NOT NULL DEFAULT 'preparing',
  installation_generation bigint NOT NULL CHECK (installation_generation > 0),
  connector_id text NOT NULL DEFAULT 'runtime',
  connector_generation bigint NOT NULL CHECK (connector_generation > 0),
  edge_pool text NOT NULL,
  edge_node_id text NOT NULL,
  edge_assignment_host text NOT NULL,
  remote_codex_version text,
  failure_code text,
  cleanup_status text NOT NULL DEFAULT 'not_requested',
  lease_expires_at timestamptz NOT NULL,
  prepared_at timestamptz,
  reconnecting_at timestamptz,
  stopping_at timestamptz,
  stopped_at timestamptz,
  last_renewed_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('preparing','ready','reconnecting','stopping','stopped','failed')),
  CHECK (cleanup_status IN ('not_requested','pending','complete','uncertain')),
  CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 64),
  UNIQUE (cli_client_session_id, idempotency_key)
);

CREATE INDEX codex_sessions_active_limit ON codex_sessions(user_id, environment_id, created_at)
  WHERE state IN ('preparing','ready','reconnecting');
CREATE INDEX codex_sessions_orphan_cleanup ON codex_sessions(lease_expires_at)
  WHERE state IN ('preparing','ready','reconnecting','stopping');

-- +goose Down
DROP TABLE IF EXISTS paperboat.codex_sessions;
