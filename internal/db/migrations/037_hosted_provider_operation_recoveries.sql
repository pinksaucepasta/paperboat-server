-- +goose Up

CREATE TABLE hosted_provider_operation_recoveries (
  operation_key text PRIMARY KEY,
  provider_operation_id text NOT NULL REFERENCES hosted_provider_operations(id) ON DELETE CASCADE,
  actor_user_id text REFERENCES users(id),
  action text NOT NULL,
  evidence_reference text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (action IN ('confirm_deleted','retry')),
  CHECK (length(evidence_reference) BETWEEN 1 AND 512)
);

-- +goose Down
DROP TABLE hosted_provider_operation_recoveries;
