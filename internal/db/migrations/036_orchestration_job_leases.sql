-- +goose Up

ALTER TABLE orchestration_jobs ADD COLUMN lease_token text NOT NULL DEFAULT '';
ALTER TABLE orchestration_jobs ADD COLUMN lease_expires_at timestamptz;
CREATE INDEX orchestration_jobs_reclaim ON orchestration_jobs(state, lease_expires_at)
  WHERE state = 'running';

-- +goose Down
DROP INDEX orchestration_jobs_reclaim;
ALTER TABLE orchestration_jobs DROP COLUMN lease_expires_at;
ALTER TABLE orchestration_jobs DROP COLUMN lease_token;
