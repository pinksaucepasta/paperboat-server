-- +goose Up
ALTER TABLE control_config_repositories
  ADD COLUMN provider_account_id text,
  ADD COLUMN external_repository_id text,
  ADD COLUMN clone_url text,
  ADD COLUMN publish_url text,
  ADD COLUMN default_branch text,
  ADD COLUMN authorization_ref text,
  ADD COLUMN credential_capability text,
  ADD COLUMN observed_revision text,
  ADD COLUMN disconnected_at timestamptz,
  ADD COLUMN version bigint NOT NULL DEFAULT 1;

UPDATE control_config_repositories
SET external_repository_id = external_ref
WHERE external_repository_id IS NULL;

CREATE UNIQUE INDEX control_config_repositories_external_identity
  ON control_config_repositories(owner_user_id, provider, external_repository_id)
  WHERE external_repository_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS control_config_repositories_external_identity;
ALTER TABLE control_config_repositories
  DROP COLUMN IF EXISTS version,
  DROP COLUMN IF EXISTS disconnected_at,
  DROP COLUMN IF EXISTS observed_revision,
  DROP COLUMN IF EXISTS credential_capability,
  DROP COLUMN IF EXISTS authorization_ref,
  DROP COLUMN IF EXISTS default_branch,
  DROP COLUMN IF EXISTS publish_url,
  DROP COLUMN IF EXISTS clone_url,
  DROP COLUMN IF EXISTS external_repository_id,
  DROP COLUMN IF EXISTS provider_account_id;
