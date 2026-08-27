-- +goose Up

-- A dashboard-enrolled host/client receives a CLI session as part of its
-- installation material. Keep that session bound to the machine so removing
-- the machine can revoke the complete device identity without guessing from
-- labels or encrypted installation material.
ALTER TABLE cli_client_sessions
  ADD COLUMN user_machine_id text REFERENCES user_machines(id) ON DELETE SET NULL;

CREATE INDEX cli_client_sessions_user_machine
  ON cli_client_sessions(user_machine_id, created_at DESC)
  WHERE user_machine_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS cli_client_sessions_user_machine;
ALTER TABLE cli_client_sessions DROP COLUMN IF EXISTS user_machine_id;
