-- +goose Up
ALTER TABLE user_machines
  ADD COLUMN availability_mode text NOT NULL DEFAULT 'keep_awake'
    CHECK (availability_mode IN ('allow_sleep','keep_awake')),
  ADD COLUMN availability_desired_version bigint NOT NULL DEFAULT 0
    CHECK (availability_desired_version >= 0),
  ADD COLUMN availability_observed_mode text
    CHECK (availability_observed_mode IS NULL OR availability_observed_mode IN ('allow_sleep','keep_awake')),
  ADD COLUMN availability_observed_version bigint NOT NULL DEFAULT 0
    CHECK (availability_observed_version >= 0),
  ADD COLUMN availability_observed_at timestamptz,
  ADD COLUMN availability_status text NOT NULL DEFAULT 'pending'
    CHECK (availability_status IN ('applied','pending','unsupported','error')),
  ADD COLUMN availability_error_code text,
  ADD COLUMN host_service_version text,
  ADD COLUMN host_service_scope text
    CHECK (host_service_scope IS NULL OR host_service_scope = 'system');

CREATE TABLE user_machine_availability_operations (
  id text PRIMARY KEY,
  user_machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  idempotency_key text NOT NULL,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  expected_version bigint NOT NULL CHECK (expected_version >= 0),
  resulting_version bigint NOT NULL CHECK (resulting_version > 0),
  mode text NOT NULL CHECK (mode IN ('allow_sleep','keep_awake')),
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, user_machine_id, idempotency_key)
);

-- +goose Down
DROP TABLE IF EXISTS user_machine_availability_operations;
ALTER TABLE user_machines
  DROP COLUMN IF EXISTS host_service_scope,
  DROP COLUMN IF EXISTS host_service_version,
  DROP COLUMN IF EXISTS availability_error_code,
  DROP COLUMN IF EXISTS availability_status,
  DROP COLUMN IF EXISTS availability_observed_at,
  DROP COLUMN IF EXISTS availability_observed_version,
  DROP COLUMN IF EXISTS availability_observed_mode,
  DROP COLUMN IF EXISTS availability_desired_version,
  DROP COLUMN IF EXISTS availability_mode;
