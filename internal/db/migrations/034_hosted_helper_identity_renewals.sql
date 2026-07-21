-- +goose Up

CREATE TABLE hosted_helper_identity_renewals (
  operation_key text PRIMARY KEY,
  helper_id text NOT NULL REFERENCES control_helpers(id) ON DELETE CASCADE,
  environment_id text NOT NULL REFERENCES control_environments(id) ON DELETE CASCADE,
  request_hash bytea NOT NULL,
  identity_ciphertext bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (length(operation_key) BETWEEN 8 AND 320),
  UNIQUE (helper_id, operation_key)
);
CREATE INDEX hosted_helper_identity_renewals_expiry ON hosted_helper_identity_renewals(expires_at);

-- +goose Down
DROP TABLE hosted_helper_identity_renewals;
