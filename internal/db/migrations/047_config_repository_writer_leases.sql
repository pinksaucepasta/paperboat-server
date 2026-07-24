-- +goose Up
-- A single row per repository is the database-enforced writer authority. The
-- fencing counter is retained when a lease is released or expires, so a stale
-- holder can never regain authority with an older token.
CREATE TABLE control_config_repository_lease_authority (
  repository_id text PRIMARY KEY REFERENCES control_config_repositories(id) ON DELETE CASCADE,
  last_fencing_token bigint NOT NULL DEFAULT 0 CHECK (last_fencing_token >= 0),
  lease_id text UNIQUE,
  assignment_id text,
  environment_id text,
  helper_id text,
  helper_generation bigint,
  base_remote_revision text,
  operation_id text,
  acquired_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (lease_id IS NULL AND assignment_id IS NULL AND environment_id IS NULL AND helper_id IS NULL
      AND helper_generation IS NULL AND operation_id IS NULL AND acquired_at IS NULL AND expires_at IS NULL)
    OR
    (lease_id IS NOT NULL AND assignment_id IS NOT NULL AND environment_id IS NOT NULL AND helper_id IS NOT NULL
      AND helper_generation > 0 AND operation_id IS NOT NULL AND acquired_at IS NOT NULL AND expires_at > acquired_at)
  )
);
CREATE INDEX control_config_repository_lease_expiry
  ON control_config_repository_lease_authority(expires_at)
  WHERE lease_id IS NOT NULL AND revoked_at IS NULL;

CREATE TABLE control_config_repository_lease_operations (
  operation_id text PRIMARY KEY,
  operation_type text NOT NULL,
  request_hash bytea NOT NULL,
  repository_id text NOT NULL REFERENCES control_config_repositories(id) ON DELETE CASCADE,
  lease_id text,
  fencing_token bigint,
  result_state text NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (operation_type IN ('acquire','renew','release','revoke')),
  CHECK (result_state IN ('acquired','renewed','released','revoked','busy','lost')),
  CHECK (fencing_token IS NULL OR fencing_token > 0)
);
CREATE INDEX control_config_repository_lease_operations_repository
  ON control_config_repository_lease_operations(repository_id, created_at);

-- +goose Down
DROP TABLE IF EXISTS control_config_repository_lease_operations;
DROP TABLE IF EXISTS control_config_repository_lease_authority;
