-- +goose Up
ALTER TABLE user_machines DROP CONSTRAINT user_machines_workspace_root_check;
ALTER TABLE user_machines ADD CONSTRAINT user_machines_workspace_root_check
  CHECK (
    workspace_root ~ '^/' OR
    (workspace_root ~ '^[A-Za-z]:' AND substring(workspace_root FROM 3 FOR 1) = chr(92)) OR
    substring(workspace_root FROM 1 FOR 2) = chr(92) || chr(92)
  );

ALTER TABLE user_machine_pairings DROP CONSTRAINT user_machine_pairings_workspace_root_check;
ALTER TABLE user_machine_pairings ADD CONSTRAINT user_machine_pairings_workspace_root_check
  CHECK (
    workspace_root ~ '^/' OR
    (workspace_root ~ '^[A-Za-z]:' AND substring(workspace_root FROM 3 FOR 1) = chr(92)) OR
    substring(workspace_root FROM 1 FOR 2) = chr(92) || chr(92)
  );

ALTER TABLE user_machine_enrollments DROP CONSTRAINT user_machine_enrollments_workspace_root_check;
ALTER TABLE user_machine_enrollments ADD CONSTRAINT user_machine_enrollments_workspace_root_check
  CHECK (
    workspace_root IS NULL OR
    workspace_root ~ '^/' OR
    (workspace_root ~ '^[A-Za-z]:' AND substring(workspace_root FROM 3 FOR 1) = chr(92)) OR
    substring(workspace_root FROM 1 FOR 2) = chr(92) || chr(92)
  );

-- +goose Down
ALTER TABLE user_machine_enrollments DROP CONSTRAINT user_machine_enrollments_workspace_root_check;
ALTER TABLE user_machine_enrollments ADD CONSTRAINT user_machine_enrollments_workspace_root_check
  CHECK (workspace_root IS NULL OR workspace_root ~ '^/');

ALTER TABLE user_machine_pairings DROP CONSTRAINT user_machine_pairings_workspace_root_check;
ALTER TABLE user_machine_pairings ADD CONSTRAINT user_machine_pairings_workspace_root_check
  CHECK (workspace_root ~ '^/');

ALTER TABLE user_machines DROP CONSTRAINT user_machines_workspace_root_check;
ALTER TABLE user_machines ADD CONSTRAINT user_machines_workspace_root_check
  CHECK (workspace_root ~ '^/');
