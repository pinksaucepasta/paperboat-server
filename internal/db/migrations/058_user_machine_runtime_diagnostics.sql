-- +goose Up
ALTER TABLE user_machines
  ADD COLUMN worker_generation bigint NOT NULL DEFAULT 0 CHECK (worker_generation >= 0),
  ADD COLUMN os_boot_id text,
  ADD COLUMN worker_service_scope text NOT NULL DEFAULT 'unknown'
    CHECK (worker_service_scope IN ('unknown','user','system')),
  ADD COLUMN connector_state text NOT NULL DEFAULT 'unavailable'
    CHECK (connector_state IN ('ready','degraded','unavailable')),
  ADD COLUMN connector_generation bigint NOT NULL DEFAULT 0 CHECK (connector_generation >= 0),
  ADD COLUMN host_update_rollbacks bigint NOT NULL DEFAULT 0 CHECK (host_update_rollbacks >= 0),
  ADD COLUMN runtime_diagnostics_observed_at timestamptz;

-- +goose Down
ALTER TABLE user_machines
  DROP COLUMN IF EXISTS runtime_diagnostics_observed_at,
  DROP COLUMN IF EXISTS connector_generation,
  DROP COLUMN IF EXISTS connector_state,
  DROP COLUMN IF EXISTS host_update_rollbacks,
  DROP COLUMN IF EXISTS os_boot_id,
  DROP COLUMN IF EXISTS worker_service_scope,
  DROP COLUMN IF EXISTS worker_generation;
