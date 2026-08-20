-- +goose Up

SET LOCAL search_path TO paperboat;

-- Managed SSH keys are materialized on machines as authorized_keys entries.  A
-- revoked CLI session must therefore revoke its corresponding managed key in
-- the same database transaction, rather than relying solely on the next
-- machine reconciliation to notice that the session is no longer active.
--
-- Keep the reason within managed_ssh_client_keys' deliberately small,
-- public-safe vocabulary.  Session revocation reasons are broader and are
-- retained on cli_client_sessions as the detailed audit record.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION revoke_managed_ssh_client_key_on_session_revocation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
	managed_reason text := CASE
		WHEN NEW.revocation_reason LIKE 'account_%' THEN 'account_revoked'
		WHEN NEW.revocation_reason = 'client_logout' THEN 'client_logout'
		ELSE 'client_revoked'
	END;
BEGIN
	UPDATE managed_ssh_client_keys
	SET state = 'revoked',
		revoked_at = coalesce(NEW.revoked_at, now()),
		revocation_reason = managed_reason,
		reconciliation_version = reconciliation_version + 1
	WHERE cli_client_session_id = NEW.id
		AND state = 'active';
	RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_cli_client_sessions_revoke_managed_ssh_client_keys ON cli_client_sessions;
CREATE TRIGGER trg_cli_client_sessions_revoke_managed_ssh_client_keys
AFTER UPDATE OF state ON cli_client_sessions
FOR EACH ROW
WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state = 'revoked')
EXECUTE FUNCTION revoke_managed_ssh_client_key_on_session_revocation();

-- +goose Down
-- Forward-only migration.
