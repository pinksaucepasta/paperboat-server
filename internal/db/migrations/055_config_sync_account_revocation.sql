-- +goose Up
-- Account authorization loss must synchronously fence every config-sync
-- environment owned by the account. Eligibility queries independently reject
-- inactive accounts, preventing authority from being reacquired afterward.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION control_account_config_sync_revocation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = paperboat, pg_temp
AS $$
DECLARE
  environment record;
BEGIN
  IF OLD.status = 'active' AND NEW.status <> 'active' THEN
    FOR environment IN
      SELECT id
      FROM control_environments
      WHERE owner_user_id = NEW.id
    LOOP
      PERFORM revoke_config_sync_for_environment(environment.id);
    END LOOP;
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER control_account_config_sync_revocation_trigger
AFTER UPDATE OF status ON users
FOR EACH ROW EXECUTE FUNCTION control_account_config_sync_revocation();

-- +goose Down
DROP TRIGGER IF EXISTS control_account_config_sync_revocation_trigger ON users;
DROP FUNCTION IF EXISTS control_account_config_sync_revocation();
