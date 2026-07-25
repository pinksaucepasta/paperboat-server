-- +goose Up
CREATE TABLE user_machine_enrollments (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  operation_id text NOT NULL UNIQUE,
  idempotency_key text NOT NULL,
  bootstrap_token_hash bytea NOT NULL UNIQUE,
  bootstrap_token_ciphertext bytea NOT NULL,
  state text NOT NULL DEFAULT 'awaiting_bootstrap',
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  pairing_id text UNIQUE REFERENCES user_machine_pairings(id) ON DELETE SET NULL,
  user_machine_id text REFERENCES user_machines(id) ON DELETE SET NULL,
  requested_display_name text,
  platform text,
  architecture text,
  workspace_root text,
  expires_at timestamptz NOT NULL,
  cancelled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, idempotency_key),
  CHECK (state IN ('awaiting_bootstrap','awaiting_approval','approved','material_issued','installing','connecting','ready','cancelled','expired','denied','failed_retryable','revoked','disconnected','deleted')),
  CHECK (workspace_root IS NULL OR workspace_root ~ '^/')
);
CREATE INDEX user_machine_enrollments_owner_state
  ON user_machine_enrollments(user_id, state, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS user_machine_enrollments;
