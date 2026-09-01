-- name: ListDueTunnelDomainsV1 :many
SELECT tunnel_domains.*
FROM tunnel_domains
WHERE deleted_at IS NULL
  AND ownership_state IN ('pending','failed','verified')
  AND dns_next_check_at <= sqlc.arg(now)
ORDER BY dns_next_check_at, id
LIMIT sqlc.arg(row_limit);

-- name: ApplyTunnelDomainDNSObservationV1 :one
UPDATE tunnel_domains
SET observed_records = sqlc.arg(observed_records)::jsonb,
    ownership_state = sqlc.arg(ownership_state),
    conflict_state = sqlc.arg(conflict_state),
    dns_last_checked_at = sqlc.arg(now),
    dns_next_check_at = sqlc.arg(next_check_at),
    dns_ttl_seconds = sqlc.narg(ttl_seconds),
    verification_attempts = CASE WHEN sqlc.arg(observation_verified)::boolean THEN 0 ELSE verification_attempts + 1 END,
    last_verified_at = CASE WHEN sqlc.arg(observation_verified)::boolean THEN sqlc.arg(now) ELSE last_verified_at END,
    certificate_state = CASE
      WHEN sqlc.arg(observation_verified)::boolean AND certificate_state = 'pending' THEN 'issuing'
      ELSE certificate_state
    END,
    generation = generation + 1,
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(domain_id)
  AND generation = sqlc.arg(expected_generation)
  AND deleted_at IS NULL
RETURNING *;

-- name: ApplyTunnelDomainCertificateObservationV1 :one
UPDATE tunnel_domains
SET certificate_state = sqlc.arg(certificate_state),
    certificate_reference = sqlc.narg(certificate_reference),
    certificate_expires_at = sqlc.narg(certificate_expires_at),
    certificate_renewal_attempted_at = sqlc.arg(now),
    certificate_failure_code = sqlc.narg(failure_code),
    caa_state = sqlc.arg(caa_state),
    generation = generation + 1,
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(domain_id)
  AND generation = sqlc.arg(expected_generation)
  AND ownership_state = 'verified'
  AND deleted_at IS NULL
RETURNING *;

-- name: ReleaseExpiredTunnelDomainQuarantinesV1 :execrows
UPDATE tunnel_domains
SET conflict_state = 'clear', quarantine_until = NULL, updated_at = sqlc.arg(now)
WHERE deleted_at IS NOT NULL
  AND conflict_state = 'quarantined'
  AND quarantine_until <= sqlc.arg(now);

-- name: CompleteTunnelDomainVerificationOperationsV1 :execrows
UPDATE operations
SET state = 'succeeded', phase = 'ready', progress = 100,
    outcome = 'changed', completed_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE account_id = sqlc.arg(account_id)
  AND resource_kind = 'domain_binding'
  AND resource_id = sqlc.arg(domain_id)
  AND operation_type = 'domain.verify'
  AND state IN ('pending','running');

-- name: AdvanceTunnelDomainCreateOperationsV1 :execrows
UPDATE operations
SET state = 'running', phase = 'issuing_certificate', progress = GREATEST(progress, 60),
    outcome = 'changed', completed_at = NULL, updated_at = sqlc.arg(now)
WHERE account_id = sqlc.arg(account_id)
  AND resource_kind = 'domain_binding'
  AND resource_id = sqlc.arg(domain_id)
  AND operation_type = 'domain.create'
  AND state IN ('pending','running');
