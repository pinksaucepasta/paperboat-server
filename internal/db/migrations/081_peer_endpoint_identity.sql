-- +goose Up
CREATE TABLE account_e2ee_roots (
  user_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  public_key bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
  fingerprint bytea NOT NULL UNIQUE CHECK (octet_length(fingerprint) = 32),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE TABLE peer_endpoint_certificates (
  fingerprint bytea PRIMARY KEY CHECK (octet_length(fingerprint) = 32),
  user_id text NOT NULL REFERENCES account_e2ee_roots(user_id) ON DELETE CASCADE,
  endpoint_id text NOT NULL CHECK (endpoint_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
  role text NOT NULL CHECK (role IN ('cli', 'machine')),
  generation bigint NOT NULL CHECK (generation > 0),
  serial bigint NOT NULL CHECK (serial > 0),
  certificate bytea NOT NULL CHECK (octet_length(certificate) BETWEEN 172 AND 426),
  noise_public_key bytea NOT NULL CHECK (octet_length(noise_public_key) = 32),
  quic_public_key bytea NOT NULL CHECK (octet_length(quic_public_key) = 32),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  revocation_reason text CHECK (revocation_reason IS NULL OR revocation_reason IN ('endpoint_replaced', 'endpoint_removed', 'account_revoked', 'key_compromise', 'certificate_superseded')),
  UNIQUE (user_id, endpoint_id, generation, serial),
  CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE UNIQUE INDEX peer_endpoint_certificates_active_generation_idx
  ON peer_endpoint_certificates (user_id, endpoint_id, generation)
  WHERE revoked_at IS NULL;

CREATE INDEX peer_endpoint_certificates_expiry_idx
  ON peer_endpoint_certificates (expires_at)
  WHERE revoked_at IS NULL;

-- +goose Down
SELECT 1;
