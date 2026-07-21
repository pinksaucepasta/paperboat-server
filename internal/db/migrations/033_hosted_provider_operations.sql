-- +goose Up

-- One durable record per provider mutation step. This is deliberately separate
-- from control_operations: the orchestration worker owns these records and no
-- second worker may lease the same Fly mutation.
CREATE TABLE hosted_provider_operations (
  id text PRIMARY KEY,
  orchestration_job_id text NOT NULL REFERENCES orchestration_jobs(id) ON DELETE CASCADE,
  step text NOT NULL,
  resource_type text NOT NULL,
  request_hash bytea NOT NULL,
  state text NOT NULL DEFAULT 'pending',
  outcome text NOT NULL DEFAULT 'pending',
  provider_request_id text NOT NULL DEFAULT '',
  last_error text NOT NULL DEFAULT '',
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  uncertain_at timestamptz,
  observed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('pending','running','succeeded','failed','uncertain')),
  CHECK (outcome IN ('pending','success','retryable','capacity','not_found','conflict','permanent','uncertain')),
  UNIQUE (orchestration_job_id, step)
);
CREATE INDEX hosted_provider_operations_recovery ON hosted_provider_operations(state, updated_at)
  WHERE state IN ('pending','running','uncertain');

-- +goose Down
DROP TABLE hosted_provider_operations;
