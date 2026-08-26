-- +goose Up

ALTER TABLE cli_client_sessions
  ADD COLUMN IF NOT EXISTS fresh_e2ee_bootstrap boolean NOT NULL DEFAULT false;

-- +goose Down
SELECT 1;
