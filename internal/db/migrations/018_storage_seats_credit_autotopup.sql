-- +goose Up

SET LOCAL search_path TO paperboat;

ALTER TABLE subscriptions
  ADD COLUMN IF NOT EXISTS storage_units integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS pending_storage_units integer;

CREATE TABLE IF NOT EXISTS credit_auto_topup_policies (
  id text PRIMARY KEY,
  user_id text NOT NULL UNIQUE REFERENCES users(id),
  enabled boolean NOT NULL DEFAULT false,
  threshold numeric(18,6) NOT NULL,
  bundle_credits numeric(18,6) NOT NULL,
  provider_product_id text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT credit_auto_topup_positive CHECK (threshold > 0 AND bundle_credits > 0)
);

CREATE TABLE IF NOT EXISTS credit_auto_topup_attempts (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id),
  idempotency_key text NOT NULL UNIQUE,
  provider_order_id text,
  state text NOT NULL DEFAULT 'reserved',
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
-- Forward-only migration.
