-- name: CreateAccountE2EERoot :one
INSERT INTO account_e2ee_roots (user_id, public_key, fingerprint)
VALUES (sqlc.arg(user_id), sqlc.arg(public_key), sqlc.arg(fingerprint))
ON CONFLICT DO NOTHING
RETURNING *;

-- name: GetAccountE2EERootForUpdate :one
SELECT * FROM account_e2ee_roots
WHERE user_id = sqlc.arg(user_id)
FOR UPDATE;

-- name: GetActiveAccountE2EERoot :one
SELECT * FROM account_e2ee_roots
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL;

-- name: GetFreshEnrollmentClientSession :one
SELECT user_id FROM cli_client_sessions
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
  AND state = 'active' AND fresh_e2ee_bootstrap = true;

-- name: GetFreshEnrollmentMachineID :one
SELECT client_session.user_machine_id
FROM cli_client_sessions client_session
WHERE client_session.id = sqlc.arg(cli_client_session_id)
  AND client_session.user_machine_id IS NOT NULL
UNION ALL
SELECT pairing.user_machine_id
FROM user_machine_pairings pairing
WHERE pairing.authenticated_setup_cli_session_id = sqlc.arg(cli_client_session_id)
  AND pairing.user_machine_id IS NOT NULL
ORDER BY user_machine_id
LIMIT 1;

-- name: CreateAccountE2EEKey :one
INSERT INTO account_e2ee_keys
  (key_id, user_id, public_key, fingerprint, generation, cli_client_session_id,
   user_machine_id, created_at, updated_at)
VALUES
  (sqlc.arg(key_id), sqlc.arg(user_id), sqlc.arg(public_key), sqlc.arg(fingerprint),
   sqlc.arg(generation), sqlc.narg(cli_client_session_id), sqlc.narg(user_machine_id),
   sqlc.arg(created_at), sqlc.arg(updated_at))
ON CONFLICT DO NOTHING
RETURNING *;

-- name: GetAccountE2EEKeyByFingerprintForUpdate :one
SELECT * FROM account_e2ee_keys
WHERE user_id = sqlc.arg(user_id) AND fingerprint = sqlc.arg(fingerprint)
FOR UPDATE;

-- name: GetAccountE2EEKeyByIDForUpdate :one
SELECT * FROM account_e2ee_keys
WHERE user_id = sqlc.arg(user_id) AND key_id = sqlc.arg(key_id)
FOR UPDATE;

-- name: ListActiveAccountE2EEKeys :many
SELECT * FROM account_e2ee_keys
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL
ORDER BY created_at, key_id;

-- name: ListAccountE2EEKeys :many
SELECT * FROM account_e2ee_keys
WHERE user_id = sqlc.arg(user_id)
ORDER BY created_at, key_id;

-- name: RevokeAccountE2EEKey :one
UPDATE account_e2ee_keys
SET revoked_at = coalesce(revoked_at, sqlc.arg(revoked_at)),
    revocation_reason = coalesce(revocation_reason, sqlc.arg(reason)),
    updated_at = sqlc.arg(revoked_at)
WHERE user_id = sqlc.arg(user_id) AND key_id = sqlc.arg(key_id)
RETURNING *;

-- name: ReplaceAccountE2EERoot :one
UPDATE account_e2ee_roots
SET public_key = sqlc.arg(public_key), fingerprint = sqlc.arg(fingerprint),
    generation = 1, updated_at = sqlc.arg(now), revoked_at = NULL
WHERE user_id = sqlc.arg(user_id)
RETURNING *;

-- name: RevokeAllPeerEndpointCertificates :execrows
UPDATE peer_endpoint_certificates
SET revoked_at = sqlc.arg(now), revocation_reason = 'account_revoked'
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL;

-- name: CreatePeerEndpointCertificate :one
INSERT INTO peer_endpoint_certificates
  (fingerprint, user_id, key_id, endpoint_id, role, generation, serial, certificate,
   noise_public_key, quic_public_key, issued_at, expires_at)
VALUES
  (sqlc.arg(fingerprint), sqlc.arg(user_id), sqlc.arg(key_id), sqlc.arg(endpoint_id), sqlc.arg(role),
   sqlc.arg(generation), sqlc.arg(serial), sqlc.arg(certificate),
   sqlc.arg(noise_public_key), sqlc.arg(quic_public_key), sqlc.arg(issued_at), sqlc.arg(expires_at))
ON CONFLICT DO NOTHING
RETURNING *;

-- name: GetPeerEndpointCertificateByFingerprint :one
SELECT * FROM peer_endpoint_certificates
WHERE fingerprint = sqlc.arg(fingerprint);

-- name: GetPeerEndpointCertificateByIdentity :one
SELECT * FROM peer_endpoint_certificates
WHERE user_id = sqlc.arg(user_id) AND endpoint_id = sqlc.arg(endpoint_id)
  AND generation = sqlc.arg(generation);

-- name: GetActivePeerEndpointCertificateForUpdate :one
SELECT certificate.* FROM peer_endpoint_certificates certificate
JOIN account_e2ee_keys trusted_key ON trusted_key.key_id = certificate.key_id
  AND trusted_key.user_id = certificate.user_id AND trusted_key.revoked_at IS NULL
WHERE certificate.user_id = sqlc.arg(user_id)
  AND certificate.endpoint_id = sqlc.arg(endpoint_id)
  AND certificate.generation = sqlc.arg(generation)
  AND certificate.revoked_at IS NULL
  AND certificate.issued_at <= sqlc.arg(now)
  AND certificate.expires_at > sqlc.arg(now)
FOR UPDATE OF certificate, trusted_key;

-- name: RevokePeerEndpointCertificate :one
UPDATE peer_endpoint_certificates
SET revoked_at = sqlc.arg(now), revocation_reason = sqlc.arg(reason)
WHERE fingerprint = sqlc.arg(fingerprint) AND revoked_at IS NULL
RETURNING *;

-- name: RevokeSupersededPeerEndpointCertificates :execrows
UPDATE peer_endpoint_certificates
SET revoked_at = sqlc.arg(now), revocation_reason = 'certificate_superseded'
WHERE user_id = sqlc.arg(user_id) AND endpoint_id = sqlc.arg(endpoint_id)
  AND generation < sqlc.arg(generation) AND revoked_at IS NULL;

-- name: RevokeAccountE2EERoot :one
UPDATE account_e2ee_roots
SET revoked_at = sqlc.arg(now), generation = generation + 1, updated_at = sqlc.arg(now)
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL
RETURNING *;

-- name: GetPeerEndpointCertificateOperationForUpdate :one
SELECT * FROM peer_endpoint_certificate_operations
WHERE operation_id = sqlc.arg(operation_id)
FOR UPDATE;

-- name: CreatePeerEndpointCertificateOperation :one
INSERT INTO peer_endpoint_certificate_operations
  (operation_id, user_id, request_hash, certificate_fingerprint, created_at)
VALUES
  (sqlc.arg(operation_id), sqlc.arg(user_id), sqlc.arg(request_hash),
   sqlc.arg(certificate_fingerprint), sqlc.arg(created_at))
RETURNING *;

-- name: GetPeerEndpointCertificateRevocationForUpdate :one
SELECT * FROM peer_endpoint_certificate_revocations
WHERE operation_id = sqlc.arg(operation_id)
FOR UPDATE;

-- name: CreatePeerEndpointCertificateRevocation :one
INSERT INTO peer_endpoint_certificate_revocations
  (operation_id, user_id, certificate_fingerprint, serial, reason, created_at)
VALUES
  (sqlc.arg(operation_id), sqlc.arg(user_id), sqlc.arg(certificate_fingerprint),
   sqlc.arg(serial), sqlc.arg(reason), sqlc.arg(created_at))
RETURNING *;

-- name: CreatePeerEndpointEnrollmentRequest :one
INSERT INTO peer_endpoint_enrollment_requests
  (id, operation_key, request_hash, user_id, endpoint_id, generation,
   noise_public_key, quic_public_key, role, created_at, expires_at)
SELECT sqlc.arg(id), sqlc.arg(operation_key), sqlc.arg(request_hash), machine.user_id,
       machine.id, sqlc.arg(generation), sqlc.arg(noise_public_key),
       sqlc.arg(quic_public_key), 'machine', sqlc.arg(created_at), sqlc.arg(expires_at)
FROM user_machines machine
WHERE machine.id = sqlc.arg(endpoint_id) AND machine.user_id = sqlc.arg(user_id)
  AND machine.installation_generation = sqlc.arg(generation)
  AND machine.revoked_at IS NULL AND machine.deleted_at IS NULL
ON CONFLICT DO NOTHING
RETURNING *;

-- name: CreateCLIPeerEndpointEnrollmentRequest :one
INSERT INTO peer_endpoint_enrollment_requests
  (id, operation_key, request_hash, user_id, endpoint_id, generation,
   noise_public_key, quic_public_key, role, created_at, expires_at)
VALUES
  (sqlc.arg(id), sqlc.arg(operation_key), sqlc.arg(request_hash), sqlc.arg(user_id),
   sqlc.arg(endpoint_id), sqlc.arg(generation), sqlc.arg(noise_public_key),
   sqlc.arg(quic_public_key), 'cli', sqlc.arg(created_at), sqlc.arg(expires_at))
ON CONFLICT DO NOTHING
RETURNING *;

-- name: GetPeerEndpointEnrollmentRequestByOperation :one
SELECT * FROM peer_endpoint_enrollment_requests
WHERE operation_key = sqlc.arg(operation_key);

-- name: RenewExpiredPeerEndpointEnrollmentRequest :one
UPDATE peer_endpoint_enrollment_requests request
SET state = 'pending', created_at = sqlc.arg(created_at), expires_at = sqlc.arg(expires_at),
    fulfilled_at = NULL, certificate_fingerprint = NULL
WHERE request.operation_key = sqlc.arg(operation_key)
  AND request.request_hash = sqlc.arg(request_hash)
  AND request.user_id = sqlc.arg(user_id)
  AND request.endpoint_id = sqlc.arg(endpoint_id)
  AND request.generation = sqlc.arg(generation)
  AND request.state = 'expired'
  AND EXISTS (
    SELECT 1 FROM user_machines machine
    WHERE machine.id = request.endpoint_id AND machine.user_id = request.user_id
      AND machine.installation_generation = request.generation
      AND machine.revoked_at IS NULL AND machine.deleted_at IS NULL
  )
RETURNING *;

-- name: RenewExpiredCLIPeerEndpointEnrollmentRequest :one
UPDATE peer_endpoint_enrollment_requests request
SET state = 'pending', created_at = sqlc.arg(created_at), expires_at = sqlc.arg(expires_at),
    fulfilled_at = NULL, certificate_fingerprint = NULL
WHERE request.operation_key = sqlc.arg(operation_key)
  AND request.request_hash = sqlc.arg(request_hash)
  AND request.user_id = sqlc.arg(user_id)
  AND request.endpoint_id = sqlc.arg(endpoint_id)
  AND request.generation = sqlc.arg(generation)
  AND request.role = 'cli' AND request.state = 'expired'
  AND NOT EXISTS (
    SELECT 1 FROM peer_endpoint_enrollment_requests pending
    WHERE pending.user_id = request.user_id
      AND pending.endpoint_id = request.endpoint_id
      AND pending.generation = request.generation
      AND pending.state = 'pending'
      AND pending.operation_key <> request.operation_key
  )
RETURNING *;

-- name: ListPendingPeerEndpointEnrollmentRequests :many
SELECT * FROM peer_endpoint_enrollment_requests
WHERE user_id = sqlc.arg(user_id) AND state = 'pending'
  AND expires_at > sqlc.arg(now)
ORDER BY created_at, id
LIMIT sqlc.arg(row_limit);

-- name: GetMatchingPeerEndpointEnrollmentRequestForUpdate :one
SELECT * FROM peer_endpoint_enrollment_requests
WHERE user_id = sqlc.arg(user_id) AND endpoint_id = sqlc.arg(endpoint_id)
  AND generation = sqlc.arg(generation) AND state = 'pending'
  AND expires_at > sqlc.arg(now)
FOR UPDATE;

-- name: FulfillPeerEndpointEnrollmentRequest :one
UPDATE peer_endpoint_enrollment_requests
SET state = 'fulfilled', certificate_fingerprint = sqlc.arg(certificate_fingerprint),
    fulfilled_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'pending'
RETURNING *;

-- name: ExpirePeerEndpointEnrollmentRequests :execrows
UPDATE peer_endpoint_enrollment_requests
SET state = 'expired'
WHERE state = 'pending' AND expires_at <= sqlc.arg(now);
