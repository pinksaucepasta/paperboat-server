-- +goose Up
ALTER TABLE user_machines DROP CONSTRAINT user_machines_relay_latency_vector_check;
ALTER TABLE user_machines
  ADD CONSTRAINT user_machines_relay_latency_vector_check CHECK (
    (relay_latency_worker_generation = 0 AND relay_latency_generation = 0 AND relay_latency_observed_at IS NULL AND relay_latency_vector IS NULL) OR
    (relay_latency_worker_generation > 0 AND relay_latency_generation > 0 AND relay_latency_observed_at IS NOT NULL AND jsonb_typeof(relay_latency_vector) IN ('array', 'object'))
  );

-- +goose Down
ALTER TABLE user_machines DROP CONSTRAINT user_machines_relay_latency_vector_check;
ALTER TABLE user_machines
  ADD CONSTRAINT user_machines_relay_latency_vector_check CHECK (
    (relay_latency_worker_generation = 0 AND relay_latency_generation = 0 AND relay_latency_observed_at IS NULL AND relay_latency_vector IS NULL) OR
    (relay_latency_worker_generation > 0 AND relay_latency_generation > 0 AND relay_latency_observed_at IS NOT NULL AND jsonb_typeof(relay_latency_vector) = 'array')
  );
