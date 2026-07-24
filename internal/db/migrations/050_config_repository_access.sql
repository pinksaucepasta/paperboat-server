-- +goose Up
CREATE TABLE control_config_repository_access_operations (
  operation_id text PRIMARY KEY,
  request_hash bytea NOT NULL,
  repository_id text NOT NULL REFERENCES control_config_repositories(id) ON DELETE CASCADE,
  assignment_id text NOT NULL,
  environment_id text NOT NULL,
  helper_id text NOT NULL,
  helper_generation bigint NOT NULL CHECK (helper_generation > 0),
  warning_revision text NOT NULL,
  state text NOT NULL DEFAULT 'pending',
  access_ciphertext bytea,
  expires_at timestamptz,
  revoked_at timestamptz,
  provider_revoked_at timestamptz,
  revoke_attempts integer NOT NULL DEFAULT 0 CHECK (revoke_attempts >= 0),
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('pending','issued','uncertain','revoked')),
  CHECK ((state = 'issued' AND access_ciphertext IS NOT NULL AND expires_at IS NOT NULL) OR state <> 'issued')
);
CREATE INDEX control_config_repository_access_active
  ON control_config_repository_access_operations(environment_id, helper_id, expires_at)
  WHERE state = 'issued' AND revoked_at IS NULL;
CREATE INDEX control_config_repository_access_revoke_pending
  ON control_config_repository_access_operations(revoked_at, expires_at)
  WHERE revoked_at IS NOT NULL AND provider_revoked_at IS NULL AND access_ciphertext IS NOT NULL;

-- +goose Down
DROP TABLE IF EXISTS control_config_repository_access_operations;
