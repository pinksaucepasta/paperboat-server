-- +goose Up

SET LOCAL search_path TO paperboat;

ALTER TABLE access_sessions
ADD COLUMN IF NOT EXISTS client_session_id text REFERENCES client_sessions(id);

CREATE INDEX IF NOT EXISTS idx_access_sessions_client_session
ON access_sessions(client_session_id)
WHERE client_session_id IS NOT NULL;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION revoke_access_sessions_on_client_revocation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	IF OLD.state = 'active' AND NEW.state = 'revoked' THEN
		UPDATE access_sessions
		SET state = 'revoked', revoked_at = coalesce(revoked_at, now()), updated_at = now(),
			version = version + 1,
			descriptor = jsonb_set(descriptor, '{revocation_reason}', to_jsonb(coalesce(NEW.revocation_reason, 'client_revoked')::text), true)
		WHERE client_session_id = NEW.id AND state = 'active' AND revoked_at IS NULL;
	END IF;
	RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_client_sessions_revoke_access ON client_sessions;
CREATE TRIGGER trg_client_sessions_revoke_access
AFTER UPDATE OF state ON client_sessions
FOR EACH ROW
WHEN (OLD.state IS DISTINCT FROM NEW.state)
EXECUTE FUNCTION revoke_access_sessions_on_client_revocation();

-- +goose Down
-- Forward-only migration.
