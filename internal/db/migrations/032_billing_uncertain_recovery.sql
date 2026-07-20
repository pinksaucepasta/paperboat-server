-- +goose Up

SET LOCAL search_path TO paperboat;

CREATE TABLE billing_uncertain_recoveries (
  idempotency_key text PRIMARY KEY,
  operation_kind text NOT NULL,
  operation_id text NOT NULL,
  request_hash bytea NOT NULL,
  actor_user_id text REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (operation_kind IN ('checkout','portal','subscription_update','auto_topup')),
  CHECK (length(trim(idempotency_key)) BETWEEN 8 AND 256),
  CHECK (length(trim(operation_id)) BETWEEN 1 AND 256),
  CHECK (octet_length(request_hash) = 32)
);
CREATE INDEX billing_uncertain_recoveries_operation
  ON billing_uncertain_recoveries(operation_kind, operation_id, created_at DESC);

-- +goose Down
-- Forward-only migration.
