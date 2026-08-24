-- +goose Up
ALTER TABLE peer_endpoint_enrollment_requests
  DROP CONSTRAINT IF EXISTS peer_endpoint_enrollment_requests_state_check;

ALTER TABLE peer_endpoint_enrollment_requests
  ADD CONSTRAINT peer_endpoint_enrollment_requests_state_check
  CHECK (state IN ('pending','fulfilled','expired','denied','revoked')) NOT VALID;

ALTER TABLE peer_endpoint_enrollment_requests
  VALIDATE CONSTRAINT peer_endpoint_enrollment_requests_state_check;

CREATE TABLE peer_endpoint_enrollment_denials (
  operation_id text PRIMARY KEY CHECK (operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,255}$'),
  request_id text NOT NULL UNIQUE REFERENCES peer_endpoint_enrollment_requests(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL
);

ALTER TABLE peer_endpoint_certificates
  DROP CONSTRAINT IF EXISTS peer_endpoint_certificates_revocation_reason_check;

ALTER TABLE peer_endpoint_certificates
  ADD CONSTRAINT peer_endpoint_certificates_revocation_reason_check
  CHECK (revocation_reason IS NULL OR revocation_reason IN
    ('endpoint_replaced','endpoint_removed','account_revoked','key_compromise','certificate_superseded','client_revoked'))
  NOT VALID;

ALTER TABLE peer_endpoint_certificates
  VALIDATE CONSTRAINT peer_endpoint_certificates_revocation_reason_check;

-- Keep endpoint authority coupled to every CLI-session revocation path,
-- including account lifecycle triggers that do not call DeviceService.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION revoke_cli_peer_endpoint_on_session_revocation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  endpoint_reason text := CASE
    WHEN NEW.revocation_reason LIKE 'account_%' THEN 'account_revoked'
    ELSE 'client_revoked'
  END;
BEGIN
  UPDATE peer_endpoint_enrollment_requests
  SET state = 'revoked', certificate_fingerprint = NULL, fulfilled_at = NULL
  WHERE user_id = NEW.user_id AND endpoint_id = NEW.id
    AND role = 'cli' AND state IN ('pending','fulfilled');

  UPDATE peer_endpoint_certificates
  SET revoked_at = coalesce(NEW.revoked_at, now()),
      revocation_reason = endpoint_reason
  WHERE user_id = NEW.user_id AND endpoint_id = NEW.id
    AND role = 'cli' AND revoked_at IS NULL;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_cli_client_sessions_revoke_peer_endpoint ON cli_client_sessions;
CREATE TRIGGER trg_cli_client_sessions_revoke_peer_endpoint
AFTER UPDATE OF state ON cli_client_sessions
FOR EACH ROW
WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state = 'revoked')
EXECUTE FUNCTION revoke_cli_peer_endpoint_on_session_revocation();

-- +goose Down
SELECT 1;
