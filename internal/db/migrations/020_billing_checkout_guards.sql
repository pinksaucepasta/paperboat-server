-- +goose Up

SET LOCAL search_path TO paperboat;

ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS pending_plan_version_id text REFERENCES plan_versions(id);

CREATE TABLE IF NOT EXISTS billing_checkout_reservations (
  id text PRIMARY KEY,
  user_id text NOT NULL UNIQUE REFERENCES users(id),
  product_code text NOT NULL,
  idempotency_key text NOT NULL UNIQUE,
  provider_checkout_id text,
  checkout_url text,
  state text NOT NULL DEFAULT 'reserved',
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
-- Forward-only migration.
