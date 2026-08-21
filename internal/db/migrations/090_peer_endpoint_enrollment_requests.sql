-- +goose Up
CREATE TABLE peer_endpoint_enrollment_requests (
  id text PRIMARY KEY CHECK (id ~ '^per_[A-Za-z0-9_-]{16,128}$'),
  operation_key text NOT NULL UNIQUE CHECK (length(operation_key) BETWEEN 8 AND 128),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint_id text NOT NULL,
  generation bigint NOT NULL CHECK (generation > 0),
  role text NOT NULL DEFAULT 'machine' CHECK (role IN ('machine','cli')),
  noise_public_key bytea NOT NULL CHECK (octet_length(noise_public_key) = 32),
  quic_public_key bytea NOT NULL CHECK (octet_length(quic_public_key) = 32),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','fulfilled','expired','revoked')),
  certificate_fingerprint bytea REFERENCES peer_endpoint_certificates(fingerprint) ON DELETE SET NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  fulfilled_at timestamptz,
  CHECK (expires_at > created_at),
  CHECK ((state = 'fulfilled') = (certificate_fingerprint IS NOT NULL AND fulfilled_at IS NOT NULL))
);

CREATE UNIQUE INDEX peer_endpoint_enrollment_requests_pending_identity_idx
  ON peer_endpoint_enrollment_requests(user_id, endpoint_id, generation)
  WHERE state = 'pending';

CREATE INDEX peer_endpoint_enrollment_requests_pending_expiry_idx
  ON peer_endpoint_enrollment_requests(expires_at)
  WHERE state = 'pending';

-- +goose Down
SELECT 1;
