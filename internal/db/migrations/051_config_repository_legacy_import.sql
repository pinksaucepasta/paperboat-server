-- +goose Up
ALTER TABLE control_config_repositories
  DROP CONSTRAINT control_config_repositories_state_check;

ALTER TABLE control_config_repositories
  ADD CONSTRAINT control_config_repositories_state_check
  CHECK (state IN ('active','disconnected','revoked','quarantined'));

CREATE TABLE control_config_repository_migration_reviews (
  source text NOT NULL,
  source_id text NOT NULL,
  repository_id text REFERENCES control_config_repositories(id) ON DELETE SET NULL,
  reason text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  reviewed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source, source_id),
  CHECK (reason IN (
    'missing_external_repository_id',
    'missing_authorization',
    'canonical_identity_already_exists',
    'incomplete_canonical_connection'
  ))
);

-- Historical rows predate GitHub App installation authorization. Import only rows
-- with the immutable provider repository ID, and quarantine them until the owner
-- reconnects the repository through the current authorization flow.
INSERT INTO control_config_repositories (
  id,
  owner_user_id,
  provider,
  external_ref,
  display_name,
  state,
  external_repository_id,
  clone_url,
  publish_url,
  default_branch,
  version,
  created_at,
  updated_at
)
SELECT
  'legacy_github_config_' || legacy.provider_repo_id,
  legacy.user_id,
  'github',
  legacy.provider_repo_id,
  legacy.owner || '/' || legacy.name,
  'quarantined',
  legacy.provider_repo_id,
  legacy.clone_url,
  legacy.clone_url,
  legacy.default_branch,
  legacy.version,
  legacy.created_at,
  legacy.updated_at
FROM github_config_repositories AS legacy
WHERE btrim(legacy.provider_repo_id) <> ''
  AND NOT EXISTS (
    SELECT 1
    FROM control_config_repositories AS current
    WHERE current.owner_user_id = legacy.user_id
      AND current.provider = 'github'
      AND current.external_repository_id = legacy.provider_repo_id
  );

INSERT INTO control_config_repository_migration_reviews (
  source,
  source_id,
  repository_id,
  reason,
  details
)
SELECT
  'github_config_repositories',
  legacy.id,
  current.id,
  CASE
    WHEN btrim(legacy.provider_repo_id) = '' THEN 'missing_external_repository_id'
    WHEN current.id <> 'legacy_github_config_' || legacy.provider_repo_id
      THEN 'canonical_identity_already_exists'
    ELSE 'missing_authorization'
  END,
  jsonb_build_object(
    'provider', 'github',
    'external_repository_id', nullif(btrim(legacy.provider_repo_id), ''),
    'display_name', legacy.owner || '/' || legacy.name
  )
FROM github_config_repositories AS legacy
LEFT JOIN control_config_repositories AS current
  ON current.owner_user_id = legacy.user_id
 AND current.provider = 'github'
 AND current.external_repository_id = nullif(btrim(legacy.provider_repo_id), '');

UPDATE control_config_repositories
SET state = 'quarantined',
    updated_at = now(),
    version = version + 1
WHERE state = 'active'
  AND (
    external_repository_id IS NULL
    OR btrim(external_repository_id) = ''
    OR clone_url IS NULL
    OR btrim(clone_url) = ''
    OR publish_url IS NULL
    OR btrim(publish_url) = ''
    OR default_branch IS NULL
    OR btrim(default_branch) = ''
    OR authorization_ref IS NULL
    OR btrim(authorization_ref) = ''
    OR credential_capability IS NULL
    OR btrim(credential_capability) = ''
  );

INSERT INTO control_config_repository_migration_reviews (
  source,
  source_id,
  repository_id,
  reason,
  details
)
SELECT
  'control_config_repositories',
  repository.id,
  repository.id,
  'incomplete_canonical_connection',
  jsonb_build_object(
    'provider', repository.provider,
    'external_repository_id', repository.external_repository_id,
    'display_name', repository.display_name
  )
FROM control_config_repositories AS repository
WHERE repository.state = 'quarantined'
ON CONFLICT (source, source_id) DO NOTHING;

-- +goose Down
-- Forward-only data migration.
