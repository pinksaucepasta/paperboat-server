-- +goose Up
CREATE TABLE control_config_conflict_resolutions (
  id text PRIMARY KEY,
  environment_id text NOT NULL REFERENCES control_environments(id) ON DELETE CASCADE,
  repository_id text NOT NULL REFERENCES control_config_repositories(id) ON DELETE CASCADE,
  assignment_id text NOT NULL,
  conflict_revision text NOT NULL,
  path text NOT NULL,
  action text NOT NULL,
  expected_remote_revision text NOT NULL,
  requested_by_user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  state text NOT NULL DEFAULT 'pending',
  landed_revision text,
  requested_at timestamptz NOT NULL DEFAULT now(),
  applied_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (action IN ('keep_local','keep_remote','externally_resolved')),
  CHECK (state IN ('pending','applied','rejected')),
  CHECK (length(conflict_revision) = 64),
  UNIQUE (environment_id, conflict_revision, path)
);

CREATE INDEX control_config_conflict_resolutions_pending
  ON control_config_conflict_resolutions(environment_id, assignment_id, requested_at)
  WHERE state = 'pending';

-- +goose Down
DROP TABLE IF EXISTS control_config_conflict_resolutions;
