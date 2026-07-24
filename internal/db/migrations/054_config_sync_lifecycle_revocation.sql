-- +goose Up
-- Lifecycle fencing belongs at the canonical state boundary. This covers
-- orchestrator, account, helper replacement, and operator paths even when they
-- do not call the config-assignment service directly.
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
  SET lease_id = NULL, assignment_id = NULL, environment_id = NULL, helper_id = NULL,
      helper_generation = NULL, base_remote_revision = NULL, operation_id = NULL,
      acquired_at = NULL, expires_at = NULL, revoked_at = revoked_time,
      version = version + 1, updated_at = revoked_time
  WHERE environment_id = target_environment AND lease_id IS NOT NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION control_environment_config_sync_revocation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = paperboat, pg_temp
AS $$
BEGIN
  IF OLD.desired_state = 'active' AND NEW.desired_state <> 'active' THEN
    PERFORM revoke_config_sync_for_environment(NEW.id);
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER control_environment_config_sync_revocation_trigger
AFTER UPDATE OF desired_state ON control_environments
FOR EACH ROW EXECUTE FUNCTION control_environment_config_sync_revocation();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION control_helper_config_sync_revocation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = paperboat, pg_temp
AS $$
BEGIN
  IF OLD.state = 'active' AND NEW.state <> 'active' THEN
    PERFORM revoke_config_sync_for_environment(NEW.environment_id);
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER control_helper_config_sync_revocation_trigger
AFTER UPDATE OF state ON control_helpers
FOR EACH ROW EXECUTE FUNCTION control_helper_config_sync_revocation();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION control_repository_config_sync_revocation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = paperboat, pg_temp
AS $$
DECLARE
  environment record;
BEGIN
  IF OLD.state = 'active' AND NEW.state <> 'active' THEN
    FOR environment IN
      SELECT assignment.environment_id
      FROM control_config_assignments assignment
      WHERE assignment.repository_id = NEW.id
    LOOP
      PERFORM revoke_config_sync_for_environment(environment.environment_id);
    END LOOP;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER control_repository_config_sync_revocation_trigger
AFTER UPDATE OF state ON control_config_repositories
FOR EACH ROW EXECUTE FUNCTION control_repository_config_sync_revocation();

-- +goose Down
DROP TRIGGER IF EXISTS control_repository_config_sync_revocation_trigger ON control_config_repositories;
DROP FUNCTION IF EXISTS control_repository_config_sync_revocation();
DROP TRIGGER IF EXISTS control_helper_config_sync_revocation_trigger ON control_helpers;
DROP FUNCTION IF EXISTS control_helper_config_sync_revocation();
DROP TRIGGER IF EXISTS control_environment_config_sync_revocation_trigger ON control_environments;
DROP FUNCTION IF EXISTS control_environment_config_sync_revocation();
DROP FUNCTION IF EXISTS revoke_config_sync_for_environment(text);
