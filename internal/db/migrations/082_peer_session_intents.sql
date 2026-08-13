-- +goose Up
CREATE TABLE peer_session_intents (
  id text PRIMARY KEY CHECK (id ~ '^psi_[A-Za-z0-9_-]{16,128}$'),
  operation_key text NOT NULL UNIQUE CHECK (length(operation_key) BETWEEN 16 AND 256),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cli_client_session_id text NOT NULL REFERENCES cli_client_sessions(id) ON DELETE CASCADE,
  environment_id text NOT NULL,
  purpose text NOT NULL CHECK (purpose IN ('interactive', 'direct_probe')),
  edge_node_id text NOT NULL REFERENCES control_tunnel_nodes(id) ON DELETE RESTRICT,
  controlling_certificate_fingerprint bytea NOT NULL REFERENCES peer_endpoint_certificates(fingerprint) ON DELETE RESTRICT,
  controlled_certificate_fingerprint bytea NOT NULL REFERENCES peer_endpoint_certificates(fingerprint) ON DELETE RESTRICT,
  attempt_generation bigint NOT NULL CHECK (attempt_generation > 0),
  network_generation bigint NOT NULL CHECK (network_generation > 0),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked', 'expired')),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revocation_reason text CHECK (revocation_reason IS NULL OR revocation_reason IN ('client_revoked', 'endpoint_revoked', 'environment_revoked', 'node_reassigned', 'superseded', 'expired')),
  created_at timestamptz NOT NULL,
  CHECK (controlling_certificate_fingerprint <> controlled_certificate_fingerprint),
  CHECK (expires_at > created_at),
  CHECK ((state = 'active' AND revoked_at IS NULL AND revocation_reason IS NULL) OR
         (state <> 'active' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL))
);

CREATE INDEX peer_session_intents_active_environment_idx
  ON peer_session_intents(environment_id, edge_node_id, expires_at)
  WHERE state = 'active';
CREATE INDEX peer_session_intents_active_client_idx
  ON peer_session_intents(cli_client_session_id, expires_at)
  WHERE state = 'active';

CREATE TABLE peer_signaling_grants (
  intent_id text NOT NULL REFERENCES peer_session_intents(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('controlling', 'controlled')),
  endpoint_id text NOT NULL CHECK (endpoint_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
  peer_endpoint_id text NOT NULL CHECK (peer_endpoint_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
  jti text NOT NULL UNIQUE CHECK (jti ~ '^jti_peer_signal_[A-Za-z0-9_-]{16,128}$'),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  PRIMARY KEY (intent_id, role),
  CHECK (endpoint_id <> peer_endpoint_id),
  CHECK (expires_at > issued_at)
);

CREATE INDEX peer_signaling_grants_active_expiry_idx
  ON peer_signaling_grants(expires_at)
  WHERE revoked_at IS NULL;

CREATE TABLE peer_session_revocation_operations (
  operation_key text PRIMARY KEY CHECK (length(operation_key) BETWEEN 16 AND 256),
  intent_id text NOT NULL REFERENCES peer_session_intents(id) ON DELETE CASCADE,
  actor_user_id text REFERENCES users(id) ON DELETE SET NULL,
  reason text NOT NULL CHECK (reason IN ('client_revoked', 'endpoint_revoked', 'environment_revoked', 'node_reassigned', 'superseded')),
  created_at timestamptz NOT NULL
);

-- +goose Down
SELECT 1;
