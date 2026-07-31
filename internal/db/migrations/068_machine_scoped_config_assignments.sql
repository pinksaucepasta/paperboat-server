-- +goose Up
ALTER TABLE control_config_assignments
  ADD COLUMN machine_id text REFERENCES user_machines(id) ON DELETE CASCADE;

UPDATE control_config_assignments assignment
SET machine_id = machine.id
FROM user_machines machine
WHERE machine.environment_id = assignment.environment_id;

ALTER TABLE control_config_assignments
  ALTER COLUMN machine_id SET NOT NULL,
  DROP CONSTRAINT control_config_assignments_pkey,
  ADD CONSTRAINT control_config_assignments_pkey PRIMARY KEY (machine_id),
  ADD CONSTRAINT control_config_assignments_environment_id_unique UNIQUE (environment_id);

-- +goose Down
ALTER TABLE control_config_assignments
  DROP CONSTRAINT control_config_assignments_environment_id_unique,
  DROP CONSTRAINT control_config_assignments_pkey,
  ADD CONSTRAINT control_config_assignments_pkey PRIMARY KEY (environment_id),
  DROP COLUMN machine_id;
