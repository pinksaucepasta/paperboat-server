-- +goose Up
ALTER TABLE control_config_assignments
  ADD COLUMN push_repository_id text REFERENCES control_config_repositories(id) ON DELETE SET NULL,
  ADD COLUMN automatic_updates boolean NOT NULL DEFAULT false,
  ADD COLUMN adopted_team_id text REFERENCES teams(team_id) ON DELETE SET NULL,
  ADD COLUMN adopted_default_version bigint,
  ADD COLUMN approved_pull_revision text,
  ADD COLUMN approved_at timestamptz,
  ADD CONSTRAINT control_config_assignment_adoption_complete CHECK (
    (adopted_team_id IS NULL AND adopted_default_version IS NULL) OR
    (adopted_team_id IS NOT NULL AND adopted_default_version IS NOT NULL AND adopted_default_version > 0)
  );

ALTER TABLE control_config_sync_statuses
  ADD COLUMN review jsonb NOT NULL DEFAULT '[]'::jsonb;

UPDATE control_config_repositories
SET authorization_ref='github-user:' || owner_user_id,
    credential_capability='provider_user_repository',
    version=version+1,
    updated_at=now()
WHERE provider='github' AND state='active';

CREATE INDEX control_config_assignments_push_repository
  ON control_config_assignments(push_repository_id) WHERE push_repository_id IS NOT NULL;

CREATE TABLE team_config_defaults (
  team_id text PRIMARY KEY REFERENCES teams(team_id) ON DELETE CASCADE,
  provider text NOT NULL,
  external_repository_id text NOT NULL,
  display_name text NOT NULL,
  branch text NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  updated_by text NOT NULL REFERENCES users(id),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (length(provider) BETWEEN 1 AND 32),
  CHECK (length(external_repository_id) BETWEEN 1 AND 128),
  CHECK (length(display_name) BETWEEN 1 AND 128),
  CHECK (length(branch) BETWEEN 1 AND 255)
);

CREATE TABLE team_config_default_adoptions (
  team_id text NOT NULL REFERENCES team_config_defaults(team_id) ON DELETE CASCADE,
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  default_version bigint NOT NULL CHECK (default_version > 0),
  repository_id text NOT NULL REFERENCES control_config_repositories(id) ON DELETE CASCADE,
  adopted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id)
);

-- +goose Down
DROP TABLE IF EXISTS team_config_default_adoptions;
DROP TABLE IF EXISTS team_config_defaults;
DROP INDEX IF EXISTS control_config_assignments_push_repository;
ALTER TABLE control_config_sync_statuses DROP COLUMN IF EXISTS review;
ALTER TABLE control_config_assignments
  DROP CONSTRAINT IF EXISTS control_config_assignment_adoption_complete,
  DROP COLUMN IF EXISTS approved_at,
  DROP COLUMN IF EXISTS approved_pull_revision,
  DROP COLUMN IF EXISTS adopted_default_version,
  DROP COLUMN IF EXISTS adopted_team_id,
  DROP COLUMN IF EXISTS automatic_updates,
  DROP COLUMN IF EXISTS push_repository_id;
