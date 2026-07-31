-- +goose Up
-- Preserve historical hosted ownership and assignment intent. Repository
-- connections imported by migration 051 remain quarantined until current
-- GitHub App authorization is established, so these assignments cannot issue
-- credentials or leases during migration.
INSERT INTO control_environments (
  id,
  workspace_id,
  owner_user_id,
  desired_state,
  applied_state,
  created_at,
  updated_at
)
SELECT
  project.id,
  project.id,
  project.user_id,
  CASE WHEN project.state IN ('deleted','deleting') THEN 'revoked' ELSE 'active' END,
  'unknown',
  project.created_at,
  project.updated_at
FROM projects AS project
ON CONFLICT (id) DO NOTHING;

INSERT INTO control_config_assignments (
  id,
  environment_id,
  repository_id,
  consent_state,
  warning_revision,
  version,
  created_at,
  updated_at
)
SELECT
  'legacy_cfgassign_' || project.id,
  project.id,
  repository.id,
  'not_required',
  'hosted',
  1,
  project.created_at,
  project.updated_at
FROM projects AS project
JOIN github_config_repositories AS legacy ON legacy.user_id=project.user_id
JOIN control_config_repositories AS repository
  ON repository.owner_user_id=project.user_id
 AND repository.provider='github'
 AND repository.external_repository_id=nullif(btrim(legacy.provider_repo_id),'')
WHERE project.state NOT IN ('deleted','deleting')
ON CONFLICT (environment_id) DO NOTHING;

CREATE TABLE control_config_sync_migration_reviews (
  source text NOT NULL,
  project_id text NOT NULL,
  machine_id text NOT NULL,
  environment_id text REFERENCES control_environments(id) ON DELETE SET NULL,
  reason text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  reviewed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source, project_id, machine_id),
  CHECK (reason IN (
    'helper_binding_required',
    'baseline_verification_required',
    'repository_reauthorization_required'
  ))
);

-- A review row per historical assignment makes the off-database baseline and
-- journal verification requirement explicit before canonical writes enable.
INSERT INTO control_config_sync_migration_reviews (
  source,
  project_id,
  machine_id,
  environment_id,
  reason,
  details
)
SELECT
  'hosted_config_baseline',
  assignment.environment_id,
  '',
  assignment.environment_id,
  'baseline_verification_required',
  jsonb_build_object(
    'repository_id', assignment.repository_id,
    'assignment_id', assignment.id
  )
FROM control_config_assignments AS assignment
WHERE assignment.id LIKE 'legacy_cfgassign_%'
ON CONFLICT (source, project_id, machine_id) DO NOTHING;

-- +goose Down
-- Forward-only data migration.
