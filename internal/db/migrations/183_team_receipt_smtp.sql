-- +goose Up
CREATE TABLE team_receipt_smtp (
  team_id text PRIMARY KEY REFERENCES teams(team_id) ON DELETE CASCADE,
  host text NOT NULL,
  port integer NOT NULL CHECK (port IN (465,587)),
  username text NOT NULL,
  password_ciphertext bytea NOT NULL,
  from_address text NOT NULL,
  tls_mode text NOT NULL CHECK (tls_mode IN ('implicit','starttls')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE team_receipt_smtp;
