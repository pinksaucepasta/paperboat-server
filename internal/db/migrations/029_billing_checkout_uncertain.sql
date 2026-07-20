-- +goose Up

SET LOCAL search_path TO paperboat;

ALTER TABLE billing_checkout_reservations
  ADD COLUMN IF NOT EXISTS last_error text,
  ADD COLUMN IF NOT EXISTS uncertain_at timestamptz;

-- +goose Down
-- Forward-only migration.
