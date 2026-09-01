-- +goose Up

-- Preview leases are mutable resources. Keep their generation and owner
-- heartbeat on the lease row so every caller observes one authoritative row
-- and SQL can enforce compare-and-swap updates without a sidecar join.
ALTER TABLE preview_leases
  ADD COLUMN generation bigint NOT NULL DEFAULT 1,
  ADD COLUMN owner_last_seen_at timestamptz NOT NULL DEFAULT now();

UPDATE preview_leases
SET owner_last_seen_at = last_renewed_at;

ALTER TABLE preview_leases
  ADD CONSTRAINT preview_leases_generation_positive CHECK (generation > 0);

CREATE INDEX preview_leases_owner_heartbeat
  ON preview_leases(owner_last_seen_at, id)
  WHERE terminal_state = 'active';

-- +goose Down

DROP INDEX IF EXISTS preview_leases_owner_heartbeat;
ALTER TABLE preview_leases
  DROP CONSTRAINT IF EXISTS preview_leases_generation_positive,
  DROP COLUMN IF EXISTS owner_last_seen_at,
  DROP COLUMN IF EXISTS generation;
