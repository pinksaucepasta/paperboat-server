-- +goose Up
ALTER TABLE machine_ssh_host_key_sets
  DROP CONSTRAINT machine_ssh_host_key_sets_user_machine_id_machine_generatio_key,
  DROP CONSTRAINT machine_ssh_host_key_sets_user_machine_id_machine_generati_key1;

CREATE UNIQUE INDEX machine_ssh_host_key_sets_live_observation_idx
  ON machine_ssh_host_key_sets(user_machine_id, machine_generation, observation_generation)
  WHERE state IN ('active', 'pending');

CREATE UNIQUE INDEX machine_ssh_host_key_sets_live_fingerprint_idx
  ON machine_ssh_host_key_sets(user_machine_id, machine_generation, set_fingerprint)
  WHERE state IN ('active', 'pending');

-- +goose Down
DROP INDEX machine_ssh_host_key_sets_live_fingerprint_idx;
DROP INDEX machine_ssh_host_key_sets_live_observation_idx;

ALTER TABLE machine_ssh_host_key_sets
  ADD CONSTRAINT machine_ssh_host_key_sets_user_machine_id_machine_generatio_key
    UNIQUE (user_machine_id, machine_generation, observation_generation),
  ADD CONSTRAINT machine_ssh_host_key_sets_user_machine_id_machine_generati_key1
    UNIQUE (user_machine_id, machine_generation, set_fingerprint);
