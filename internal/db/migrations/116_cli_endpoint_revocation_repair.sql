-- +goose Up
-- Migration 115 was published from two histories. Some databases recorded
-- version 115 before the lifecycle DDL below existed, so version 116 must
-- establish the full lifecycle schema instead of assuming 115 did so.
ALTER TABLE peer_endpoint_enrollment_requests
  DROP CONSTRAINT IF EXISTS peer_endpoint_enrollment_requests_state_check;

ALTER TABLE peer_endpoint_enrollment_requests
  ADD CONSTRAINT peer_endpoint_enrollment_requests_state_check
  CHECK (state IN ('pending','fulfilled','expired','denied','revoked')) NOT VALID;

ALTER TABLE peer_endpoint_enrollment_requests
  VALIDATE CONSTRAINT peer_endpoint_enrollment_requests_state_check;

CREATE TABLE IF NOT EXISTS peer_endpoint_enrollment_denials (
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

ALTER TABLE peer_endpoint_certificate_revocations
  DROP CONSTRAINT IF EXISTS peer_endpoint_certificate_revocations_reason_check;

ALTER TABLE peer_endpoint_certificate_revocations
  ADD CONSTRAINT peer_endpoint_certificate_revocations_reason_check
  CHECK (reason IN ('endpoint_removed','key_compromise','client_revoked','account_revoked'))
  NOT VALID;

ALTER TABLE peer_endpoint_certificate_revocations
  VALIDATE CONSTRAINT peer_endpoint_certificate_revocations_reason_check;

-- This function is the single idempotent revocation primitive used by the
-- session trigger and the upgrade backfill. Record the certificate before
-- clearing the enrollment request's certificate link.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION revoke_cli_peer_endpoint_for_session(
  session_id text,
  session_user_id text,
  session_revoked_at timestamptz,
  session_revocation_reason text
)
RETURNS void
LANGUAGE plpgsql
SET search_path = paperboat, pg_temp
AS $$
DECLARE
  endpoint_reason text := CASE
    WHEN coalesce(session_revocation_reason, '') LIKE 'account_%' THEN 'account_revoked'
    ELSE 'client_revoked'
  END;
  effective_revoked_at timestamptz := coalesce(session_revoked_at, now());
BEGIN
  INSERT INTO peer_endpoint_certificate_revocations
    (operation_id, user_id, certificate_fingerprint, serial, reason, created_at)
  SELECT
    'auth.cli_session_revocation:' || encode(certificate.fingerprint, 'hex'),
    certificate.user_id,
    certificate.fingerprint,
    certificate.serial,
    endpoint_reason,
    effective_revoked_at
  FROM peer_endpoint_certificates certificate
  WHERE certificate.user_id = session_user_id
    AND certificate.endpoint_id = session_id
    AND certificate.role = 'cli'
    AND certificate.revoked_at IS NULL
  ON CONFLICT (user_id, certificate_fingerprint) DO NOTHING;

  UPDATE peer_endpoint_enrollment_requests
  SET state = 'revoked', certificate_fingerprint = NULL, fulfilled_at = NULL
  WHERE user_id = session_user_id AND endpoint_id = session_id
    AND role = 'cli' AND state IN ('pending','fulfilled');

  UPDATE peer_endpoint_certificates
  SET revoked_at = effective_revoked_at,
      revocation_reason = endpoint_reason
  WHERE user_id = session_user_id AND endpoint_id = session_id
    AND role = 'cli' AND revoked_at IS NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION revoke_cli_peer_endpoint_on_session_revocation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = paperboat, pg_temp
AS $$
BEGIN
  PERFORM revoke_cli_peer_endpoint_for_session(
    NEW.id,
    NEW.user_id,
    NEW.revoked_at,
    NEW.revocation_reason
  );
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_cli_client_sessions_revoke_peer_endpoint ON cli_client_sessions;
CREATE TRIGGER trg_cli_client_sessions_revoke_peer_endpoint
AFTER UPDATE OF state, revoked_at, revocation_reason ON cli_client_sessions
FOR EACH ROW
WHEN (NEW.state = 'revoked')
EXECUTE FUNCTION revoke_cli_peer_endpoint_on_session_revocation();

-- Repair rows that were revoked while an application image was serving before
-- migration 115 had installed its trigger. The helper is idempotent, so this
-- remains safe if part of the cascade already completed.
SELECT revoke_cli_peer_endpoint_for_session(
  session.id,
  session.user_id,
  session.revoked_at,
  session.revocation_reason
)
FROM cli_client_sessions session
WHERE session.state = 'revoked';

-- +goose Down
SELECT 1;
