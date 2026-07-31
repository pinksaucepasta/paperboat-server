-- +goose Up
ALTER TABLE user_machines
  ADD COLUMN machine_kind text NOT NULL DEFAULT 'personal',
  ADD CONSTRAINT user_machines_machine_kind_check
    CHECK (machine_kind IN ('personal', 'hosted'));

INSERT INTO user_machines (
  id, user_id, environment_id, display_name, platform, architecture,
  workspace_root, state, seat_state, runtime_versions, setup_roles, machine_kind
)
SELECT
  'mch_hosted_' || md5(p.id), p.user_id, p.id, p.name, 'linux', 'unknown',
  '/workspace',
  CASE WHEN fm.state IN ('started', 'running') THEN 'online' ELSE 'offline' END,
  'occupied', '{}'::jsonb, ARRAY['host']::text[], 'hosted'
FROM fly_machines fm
JOIN projects p ON p.id = fm.project_id
ON CONFLICT (environment_id) DO NOTHING;

ALTER TABLE fly_machines
  ADD COLUMN user_machine_id text REFERENCES user_machines(id) ON DELETE RESTRICT;

UPDATE fly_machines fm
SET user_machine_id = m.id
FROM user_machines m
WHERE m.environment_id = fm.project_id;

ALTER TABLE fly_machines
  ALTER COLUMN user_machine_id SET NOT NULL,
  ADD CONSTRAINT fly_machines_user_machine_id_unique UNIQUE (user_machine_id);

-- +goose Down
ALTER TABLE fly_machines
  DROP CONSTRAINT fly_machines_user_machine_id_unique,
  DROP COLUMN user_machine_id;

DELETE FROM user_machines WHERE machine_kind = 'hosted';

ALTER TABLE user_machines
  DROP CONSTRAINT user_machines_machine_kind_check,
  DROP COLUMN machine_kind;
