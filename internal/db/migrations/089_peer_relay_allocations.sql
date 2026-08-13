-- +goose Up
CREATE TABLE peer_relay_allocations (
  intent_id text PRIMARY KEY REFERENCES peer_session_intents(id) ON DELETE CASCADE,
  route_allocation bytea NOT NULL UNIQUE CHECK (octet_length(route_allocation) = 16),
  jti text NOT NULL UNIQUE CHECK (jti ~ '^jti_peer_relay_[A-Za-z0-9_-]{16,128}$'),
  route_generation bigint NOT NULL CHECK (route_generation > 0),
  byte_limit bigint NOT NULL CHECK (byte_limit > 0 AND byte_limit <= 1099511627776),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at > issued_at)
);

CREATE INDEX peer_relay_allocations_active_expiry_idx
  ON peer_relay_allocations(expires_at)
  WHERE revoked_at IS NULL;

-- +goose Down
SELECT 1;
