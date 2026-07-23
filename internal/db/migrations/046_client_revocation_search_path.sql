-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION paperboat.revoke_access_sessions_on_client_revocation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	IF OLD.state = 'active' AND NEW.state = 'revoked' THEN
		UPDATE paperboat.access_sessions
		SET state = 'revoked', revoked_at = coalesce(revoked_at, now()), updated_at = now(),
			version = version + 1,
			descriptor = jsonb_set(descriptor, '{revocation_reason}', to_jsonb(coalesce(NEW.revocation_reason, 'client_revoked')::text), true)
		WHERE client_session_id = NEW.id AND state = 'active' AND revoked_at IS NULL;
	END IF;
	RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- Forward-only trigger repair.
