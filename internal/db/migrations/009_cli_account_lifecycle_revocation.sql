-- +goose Up

SET LOCAL search_path TO paperboat;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION revoke_user_client_sessions_on_status_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
	revoked_time timestamptz := now();
	reason text := 'account_' || NEW.status;
BEGIN
	IF OLD.status = 'active' AND NEW.status <> 'active' THEN
		UPDATE client_sessions
		SET state = 'revoked',
			revoked_at = coalesce(revoked_at, revoked_time),
			revocation_reason = coalesce(revocation_reason, reason),
			version = version + 1
		WHERE user_id = NEW.id AND state = 'active';

		UPDATE client_access_tokens
		SET revoked_at = coalesce(revoked_at, revoked_time)
		WHERE client_session_id IN (SELECT id FROM client_sessions WHERE user_id = NEW.id);

		UPDATE client_refresh_tokens
		SET state = 'revoked', revoked_at = coalesce(revoked_at, revoked_time)
		WHERE client_session_id IN (SELECT id FROM client_sessions WHERE user_id = NEW.id)
		  AND state <> 'revoked';
	END IF;
	RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_users_revoke_client_sessions ON users;
CREATE TRIGGER trg_users_revoke_client_sessions
AFTER UPDATE OF status ON users
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION revoke_user_client_sessions_on_status_change();

-- +goose Down
-- Forward-only migration.
