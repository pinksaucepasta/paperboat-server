-- +goose Up

SET LOCAL search_path TO paperboat;

CREATE TABLE billing_portal_operations (
  idempotency_key text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  request_hash bytea NOT NULL,
  state text NOT NULL DEFAULT 'pending',
  result_ciphertext bytea,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('pending','succeeded','failed','uncertain')),
  CHECK (length(trim(idempotency_key)) BETWEEN 1 AND 256),
  CHECK ((state = 'succeeded') = (result_ciphertext IS NOT NULL))
);
CREATE INDEX billing_portal_operations_user_time ON billing_portal_operations(user_id, created_at DESC);

-- +goose Down
-- Forward-only migration.
