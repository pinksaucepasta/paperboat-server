-- +goose Up
CREATE TABLE connected_machine_entitlements (
  id text PRIMARY KEY,
  user_id text NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  provider_subscription_id text NOT NULL UNIQUE,
  product_code text NOT NULL,
  state text NOT NULL,
  seat_quantity integer NOT NULL CHECK (seat_quantity >= 0),
  allowance_bytes bigint NOT NULL CHECK (allowance_bytes >= 0),
  current_period_start timestamptz NOT NULL,
  current_period_end timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('trialing','active','past_due','canceled','revoked')),
  CHECK (current_period_end > current_period_start)
);
CREATE INDEX connected_machine_entitlements_active ON connected_machine_entitlements(user_id, current_period_end)
  WHERE state IN ('trialing','active');

-- +goose Down
DROP TABLE IF EXISTS connected_machine_entitlements;
