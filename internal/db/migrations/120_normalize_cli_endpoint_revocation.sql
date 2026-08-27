-- +goose Up

-- CLI session revocation predates the per-device reason set.  Keep the
-- trigger's mapping inside the v1 certificate contract so removing a machine
-- cannot fail when it encounters a certificate created by an older session
-- lifecycle.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION revoke_cli_peer_endpoint_for_session(
  session_id text,
  session_user_id text,
  session_revoked_at timestamptz,
  session_revocation_reason text
)
RETURNS void
LANGUAGE plpgsql
SET search_path TO 'paperboat', 'pg_temp'
AS $$
DECLARE
  endpoint_reason text := CASE
    WHEN coalesce(session_revocation_reason, '') LIKE 'account_%' THEN 'account_revoked'
    WHEN session_revocation_reason IN ('device_removed', 'key_compromise') THEN session_revocation_reason
    ELSE 'endpoint_removed'
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
  WHERE user_id = session_user_id
    AND endpoint_id = session_id
    AND role = 'cli'
    AND state IN ('pending', 'fulfilled');

  UPDATE peer_endpoint_certificates
  SET revoked_at = effective_revoked_at,
      revocation_reason = endpoint_reason
  WHERE user_id = session_user_id
    AND endpoint_id = session_id
    AND role = 'cli'
    AND revoked_at IS NULL;
END;
$$;
-- +goose StatementEnd

-- Existing development rows may contain the old reason.  Normalize them
-- before any new removal attempts; this is idempotent and remains within the
-- v1 reason contract.
UPDATE peer_endpoint_certificates
SET revocation_reason = 'endpoint_removed'
WHERE revocation_reason = 'client_revoked';

-- +goose Down

