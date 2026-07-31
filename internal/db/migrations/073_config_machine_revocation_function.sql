-- +goose Up
-- PostgreSQL does not rewrite PL/pgSQL function bodies when referenced columns
-- are renamed. Recreate the lifecycle fence after migration 070 moved config
-- authority from helper identity to machine identity.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION revoke_config_sync_for_environment(target_environment text)
RETURNS void
LANGUAGE plpgsql
SET search_path = paperboat, pg_temp
AS $$
DECLARE
  revoked_time timestamptz := now();
BEGIN
  UPDATE control_config_credentials
  SET revoked_at = coalesce(revoked_at, revoked_time)
  WHERE environment_id = target_environment AND revoked_at IS NULL;

  UPDATE control_config_repository_access_operations
  SET state = 'revoked', revoked_at = coalesce(revoked_at, revoked_time), updated_at = revoked_time
  WHERE environment_id = target_environment AND revoked_at IS NULL;

  UPDATE control_config_repository_lease_authority
  SET lease_id = NULL, assignment_id = NULL, environment_id = NULL, machine_id = NULL,
      installation_generation = NULL, base_remote_revision = NULL, operation_id = NULL,
      acquired_at = NULL, expires_at = NULL, revoked_at = revoked_time,
      version = version + 1, updated_at = revoked_time
  WHERE environment_id = target_environment AND lease_id IS NOT NULL;
END;
$$;
-- +goose StatementEnd

-- +goose Down
SELECT 1;
