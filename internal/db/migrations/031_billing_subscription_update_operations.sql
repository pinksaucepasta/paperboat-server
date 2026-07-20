-- +goose Up

SET LOCAL search_path TO paperboat;

CREATE TABLE billing_subscription_update_operations (
  idempotency_key text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_subscription_id text NOT NULL,
  request_hash bytea NOT NULL,
  state text NOT NULL DEFAULT 'pending',
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('pending','succeeded','failed','uncertain')),
  CHECK (length(trim(idempotency_key)) BETWEEN 1 AND 256)
);
CREATE INDEX billing_subscription_update_operations_user_time ON billing_subscription_update_operations(user_id, created_at DESC);

-- +goose Down
-- Forward-only migration.
