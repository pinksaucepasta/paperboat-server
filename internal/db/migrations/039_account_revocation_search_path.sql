-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION paperboat.revoke_user_client_sessions_on_status_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  revoked_time timestamptz := now();
  reason text := 'account_' || NEW.status;
BEGIN
  IF OLD.status = 'active' AND NEW.status <> 'active' THEN
    UPDATE paperboat.client_sessions
    SET state = 'revoked',
        revoked_at = coalesce(revoked_at, revoked_time),
        revocation_reason = coalesce(revocation_reason, reason),
        version = version + 1
    WHERE user_id = NEW.id AND state = 'active';

    UPDATE paperboat.client_access_tokens
    SET revoked_at = coalesce(revoked_at, revoked_time)
    WHERE client_session_id IN (SELECT id FROM paperboat.client_sessions WHERE user_id = NEW.id);

    UPDATE paperboat.client_refresh_tokens
    SET state = 'revoked', revoked_at = coalesce(revoked_at, revoked_time)
    WHERE client_session_id IN (SELECT id FROM paperboat.client_sessions WHERE user_id = NEW.id)
      AND state <> 'revoked';
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- Forward-only trigger repair.
