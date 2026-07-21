-- +goose Up

CREATE TABLE hosted_readiness_observations (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  orchestration_job_id text REFERENCES orchestration_jobs(id) ON DELETE SET NULL,
  stage text NOT NULL,
  state text NOT NULL,
  reason text NOT NULL DEFAULT '',
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  observed_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (stage IN ('workspace','config_restore','helper_health','connector_admission','runtime_dependencies')),
  CHECK (state IN ('ready','failed','unknown'))
);
CREATE INDEX hosted_readiness_observations_project_time ON hosted_readiness_observations(project_id, observed_at DESC);

-- +goose Down
DROP TABLE hosted_readiness_observations;
