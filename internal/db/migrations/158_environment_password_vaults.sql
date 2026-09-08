-- +goose Up
CREATE TABLE environment_password_vaults (
  account_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  document_id text NOT NULL CHECK (document_id ~ '^sha256:[0-9a-f]{64}$'),
  envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 264192),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS environment_password_vaults;
