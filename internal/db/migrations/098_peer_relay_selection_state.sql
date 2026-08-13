-- +goose Up
CREATE TABLE peer_relay_selection_states (
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
  network_generation bigint NOT NULL CHECK (network_generation > 0),
  host_worker_generation bigint NOT NULL CHECK (host_worker_generation > 0),
  current_region text,
  client_generation bigint NOT NULL DEFAULT 0 CHECK (client_generation >= 0),
  client_observed_at timestamptz,
  candidate_region text,
  candidate_first_observed_at timestamptz,
  candidate_last_observed_at timestamptz,
  candidate_samples integer NOT NULL DEFAULT 0 CHECK (candidate_samples BETWEEN 0 AND 16),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (user_id, machine_id, network_generation, host_worker_generation),
  CHECK ((client_generation = 0 AND client_observed_at IS NULL) OR (client_generation > 0 AND client_observed_at IS NOT NULL)),
  CHECK ((candidate_region IS NULL AND candidate_first_observed_at IS NULL AND candidate_last_observed_at IS NULL AND candidate_samples = 0) OR
         (length(candidate_region) BETWEEN 1 AND 63 AND candidate_first_observed_at IS NOT NULL AND candidate_last_observed_at IS NOT NULL AND candidate_samples BETWEEN 1 AND 16)),
  CHECK (current_region IS NULL OR length(current_region) BETWEEN 1 AND 63)
);
CREATE INDEX peer_relay_selection_states_updated ON peer_relay_selection_states(updated_at);

-- +goose Down
DROP TABLE peer_relay_selection_states;
