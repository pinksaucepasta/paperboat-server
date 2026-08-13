-- +goose Up
ALTER TABLE user_machines
  ADD COLUMN relay_latency_worker_generation bigint NOT NULL DEFAULT 0 CHECK (relay_latency_worker_generation >= 0),
  ADD COLUMN relay_latency_generation bigint NOT NULL DEFAULT 0 CHECK (relay_latency_generation >= 0),
  ADD COLUMN relay_latency_observed_at timestamptz,
  ADD COLUMN relay_latency_vector jsonb;

ALTER TABLE user_machines
  ADD CONSTRAINT user_machines_relay_latency_vector_check CHECK (
    (relay_latency_worker_generation = 0 AND relay_latency_generation = 0 AND relay_latency_observed_at IS NULL AND relay_latency_vector IS NULL) OR
    (relay_latency_worker_generation > 0 AND relay_latency_generation > 0 AND relay_latency_observed_at IS NOT NULL AND jsonb_typeof(relay_latency_vector) = 'array')
  );

-- +goose Down
ALTER TABLE user_machines DROP CONSTRAINT user_machines_relay_latency_vector_check;
ALTER TABLE user_machines
  DROP COLUMN relay_latency_vector,
  DROP COLUMN relay_latency_observed_at,
  DROP COLUMN relay_latency_generation,
  DROP COLUMN relay_latency_worker_generation;
