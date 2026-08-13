-- +goose Up
CREATE TABLE peer_endpoint_certificate_operations (
  operation_id text PRIMARY KEY CHECK (operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,255}$'),
  user_id text NOT NULL REFERENCES account_e2ee_roots(user_id) ON DELETE CASCADE,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  certificate_fingerprint bytea NOT NULL REFERENCES peer_endpoint_certificates(fingerprint) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  UNIQUE (user_id, certificate_fingerprint)
);

CREATE TABLE peer_endpoint_certificate_revocations (
  operation_id text PRIMARY KEY CHECK (operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,255}$'),
  user_id text NOT NULL REFERENCES account_e2ee_roots(user_id) ON DELETE CASCADE,
  certificate_fingerprint bytea NOT NULL REFERENCES peer_endpoint_certificates(fingerprint) ON DELETE RESTRICT,
  serial bigint NOT NULL CHECK (serial > 0),
  reason text NOT NULL CHECK (reason IN ('endpoint_removed', 'key_compromise')),
  created_at timestamptz NOT NULL,
  UNIQUE (user_id, certificate_fingerprint)
);

-- +goose Down
SELECT 1;
