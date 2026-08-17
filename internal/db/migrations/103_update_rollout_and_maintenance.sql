-- +goose Up
CREATE TABLE user_machine_update_observations (
  user_machine_id text PRIMARY KEY REFERENCES user_machines(id) ON DELETE CASCADE,
  environment_id text NOT NULL,
  schema text NOT NULL,
  current_version text NOT NULL,
  target_version text,
  channel text NOT NULL,
  state text NOT NULL,
  error_code text,
  operation_id text NOT NULL,
  installation_generation bigint NOT NULL CHECK (installation_generation > 0),
  worker_generation bigint NOT NULL CHECK (worker_generation > 0),
  os_boot_id text NOT NULL,
  rollback_count bigint NOT NULL DEFAULT 0 CHECK (rollback_count >= 0),
  observed_at timestamptz NOT NULL,
  payload_hash bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('idle','checking','downloading','staged','activating','deferred','healthy','failed','rolled_back')),
  CHECK (length(trim(schema)) BETWEEN 1 AND 128),
  CHECK (length(trim(current_version)) BETWEEN 1 AND 64),
  CHECK (target_version IS NULL OR length(trim(target_version)) BETWEEN 1 AND 64),
  CHECK (length(trim(channel)) BETWEEN 1 AND 32),
  CHECK (length(trim(operation_id)) BETWEEN 8 AND 128),
  CHECK (length(trim(os_boot_id)) BETWEEN 1 AND 256),
  CHECK ((state IN ('failed','rolled_back') AND error_code IS NOT NULL) OR (state NOT IN ('failed','rolled_back') AND error_code IS NULL))
);
CREATE INDEX user_machine_update_observations_environment
  ON user_machine_update_observations(environment_id, observed_at DESC);

CREATE TABLE user_machine_maintenance_approvals (
  id text PRIMARY KEY,
  user_machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  schema text NOT NULL,
  action text NOT NULL,
  target_version text NOT NULL,
  reason text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'pending',
  idempotency_key text NOT NULL,
  request_hash bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  decided_at timestamptz,
  decided_by_user_id text REFERENCES users(id) ON DELETE SET NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, user_machine_id, idempotency_key),
  CHECK (action IN ('update','restart','migration')),
  CHECK (status IN ('pending','approved','rejected','expired','consumed')),
  CHECK (length(trim(schema)) BETWEEN 1 AND 128),
  CHECK (length(trim(target_version)) BETWEEN 1 AND 64),
  CHECK (length(reason) <= 512),
  CHECK (length(trim(idempotency_key)) BETWEEN 8 AND 128),
  CHECK ((status = 'pending' AND decided_at IS NULL AND decided_by_user_id IS NULL) OR (status <> 'pending'))
);
CREATE INDEX user_machine_maintenance_approvals_machine
  ON user_machine_maintenance_approvals(user_id, user_machine_id, created_at DESC);
CREATE INDEX user_machine_maintenance_approvals_pending
  ON user_machine_maintenance_approvals(expires_at)
  WHERE status = 'pending';

-- +goose Down
DROP TABLE IF EXISTS user_machine_maintenance_approvals;
DROP TABLE IF EXISTS user_machine_update_observations;
