-- name: AcquireTunnelCertificateIssuanceLockV1 :one
INSERT INTO tunnel_certificate_issuance_locks (domain_id, owner_id, domain_generation, lease_until, updated_at)
VALUES (sqlc.arg(domain_id), sqlc.arg(owner_id), sqlc.arg(domain_generation), sqlc.arg(lease_until), sqlc.arg(now))
ON CONFLICT (domain_id) DO UPDATE
SET owner_id = EXCLUDED.owner_id,
    domain_generation = EXCLUDED.domain_generation,
    lease_until = EXCLUDED.lease_until,
    updated_at = EXCLUDED.updated_at
WHERE (tunnel_certificate_issuance_locks.lease_until <= sqlc.arg(now)
       OR tunnel_certificate_issuance_locks.owner_id = sqlc.arg(owner_id))
  AND tunnel_certificate_issuance_locks.domain_generation <= sqlc.arg(domain_generation)
RETURNING *;

-- name: ReleaseTunnelCertificateIssuanceLockV1 :execrows
DELETE FROM tunnel_certificate_issuance_locks
WHERE domain_id = sqlc.arg(domain_id)
  AND owner_id = sqlc.arg(owner_id);

-- name: ReleaseTunnelCertificateIssuanceLockGenerationV1 :execrows
DELETE FROM tunnel_certificate_issuance_locks
WHERE domain_id = sqlc.arg(domain_id)
  AND owner_id = sqlc.arg(owner_id)
  AND domain_generation = sqlc.arg(domain_generation);

-- name: GetActiveTunnelCertificateV1 :one
SELECT *
FROM tunnel_certificate_records
WHERE domain_id = sqlc.arg(domain_id)
  AND target_kind = 'durable_route'
  AND leaf_hostname IS NULL
  AND state = 'active'
ORDER BY certificate_generation DESC
LIMIT 1;

-- name: GetActiveTunnelCertificateByHostnameV1 :one
SELECT *
FROM tunnel_certificate_records
WHERE domain_id = sqlc.arg(domain_id)
  AND target_kind = 'durable_route'
  AND hostname = sqlc.arg(hostname)
  AND leaf_hostname = sqlc.arg(hostname)
  AND state = 'active'
ORDER BY certificate_generation DESC
LIMIT 1;

-- name: GetTunnelCertificateV1 :one
SELECT *
FROM tunnel_certificate_records
WHERE id = sqlc.arg(id);

-- name: GetTunnelCertificateActivationContextV1 :one
SELECT domain_id, account_id, certificate_generation, hostname, COALESCE(leaf_hostname, ''), target_kind, preview_id, preview_generation
FROM tunnel_certificate_records
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: GetTunnelCertificateRevokeContextV1 :one
SELECT domain_id, account_id, certificate_reference, COALESCE(leaf_hostname, ''), target_kind
FROM tunnel_certificate_records
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: GetDistributionNodeIdentityV1 :one
SELECT process_epoch, state, ready, last_heartbeat_at,
       carrier_server_spki_sha256, carrier_server_certificate_chain_pem
FROM control_tunnel_nodes
WHERE id = sqlc.arg(id);

-- name: ListPendingTunnelCertificateRevocationIDsV1 :many
SELECT id
FROM tunnel_certificate_records
WHERE state = 'revoked' AND failure_code = 'ca_revocation_pending'
ORDER BY updated_at, id
LIMIT sqlc.arg(row_limit);

-- name: ListPendingTunnelCertificateCleanupIDsV1 :many
-- A distribution row is non-terminal until it is retired or revoked. Include
-- failed rows too: a transport can fail after an edge has durably staged a
-- copy, and the cleanup pass must revoke that copy rather than lose it.
SELECT DISTINCT certificate_id
FROM tunnel_certificate_edge_distributions
WHERE state IN ('staged','ready','active','failed')
  AND certificate_id IN (
    SELECT id
    FROM tunnel_certificate_records
    WHERE state IN ('superseded','revoked','failed')
  )
ORDER BY certificate_id
LIMIT sqlc.arg(row_limit);

-- name: MarkTunnelCertificateRevocationResultV1 :execrows
UPDATE tunnel_certificate_records
SET failure_code = sqlc.arg(failure_code), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'revoked';

-- name: ListDueTunnelCertificatesV1 :many
SELECT *
FROM tunnel_certificate_records
WHERE state = 'active'
  AND target_kind = 'durable_route'
  AND leaf_hostname IS NULL
  AND renewal_at <= sqlc.arg(now)
ORDER BY renewal_at, id
LIMIT sqlc.arg(row_limit);

-- name: CreateTunnelCertificateRecordV1 :one
INSERT INTO tunnel_certificate_records (
  id, domain_id, account_id, tunnel_id, target_kind, route_id, preview_id,
  preview_generation, preview_state, preview_expires_at, hostname, leaf_hostname, domain_generation,
  certificate_generation, strategy, state, certificate_reference,
  master_key_reference, certificate_ciphertext, private_key_ciphertext, fingerprint, issuer,
  not_before, expires_at, renewal_at, created_at, updated_at
) SELECT
  sqlc.arg(id), sqlc.arg(domain_id), sqlc.arg(account_id), sqlc.arg(tunnel_id), 'durable_route', sqlc.narg(route_id), NULL,
  NULL, NULL, NULL, sqlc.arg(hostname), sqlc.narg(leaf_hostname), sqlc.arg(domain_generation), sqlc.arg(certificate_generation),
  sqlc.arg(strategy), 'staged', sqlc.arg(certificate_reference), sqlc.arg(master_key_reference),
  sqlc.arg(certificate_ciphertext), sqlc.arg(private_key_ciphertext),
  sqlc.arg(fingerprint), sqlc.arg(issuer), sqlc.arg(not_before),
  sqlc.arg(expires_at), sqlc.arg(renewal_at), sqlc.arg(now), sqlc.arg(now)
WHERE EXISTS (
  SELECT 1
  FROM tunnel_domains AS domain
  WHERE domain.id = sqlc.arg(domain_id)
    AND domain.account_id = sqlc.arg(account_id)
    AND domain.tunnel_id = sqlc.arg(tunnel_id)
    AND domain.generation = sqlc.arg(domain_generation)
    AND domain.ownership_state = 'verified'
    AND domain.conflict_state = 'clear'
    AND domain.deleted_at IS NULL
)
ON CONFLICT (id) DO UPDATE
SET state = 'staged', failure_code = NULL, updated_at = EXCLUDED.updated_at
WHERE tunnel_certificate_records.state IN ('staged','failed')
  AND tunnel_certificate_records.domain_id = EXCLUDED.domain_id
  AND tunnel_certificate_records.account_id = EXCLUDED.account_id
  AND tunnel_certificate_records.tunnel_id = EXCLUDED.tunnel_id
  AND tunnel_certificate_records.target_kind = EXCLUDED.target_kind
  AND COALESCE(tunnel_certificate_records.route_id, '') = COALESCE(EXCLUDED.route_id, '')
  AND tunnel_certificate_records.hostname = EXCLUDED.hostname
  AND COALESCE(tunnel_certificate_records.leaf_hostname, '') = COALESCE(EXCLUDED.leaf_hostname, '')
  AND tunnel_certificate_records.domain_generation = EXCLUDED.domain_generation
  AND tunnel_certificate_records.certificate_generation = EXCLUDED.certificate_generation
  AND tunnel_certificate_records.fingerprint = EXCLUDED.fingerprint
RETURNING *;

-- Preview certificates share the encrypted record/distribution ledger but
-- carry a lease generation and active-lease expiry in their target tuple.
-- The preview-domain and lease predicates are the issuance fence; a terminal
-- lease can never create or activate a new edge certificate.
-- name: CreatePreviewTunnelCertificateRecordV1 :one
INSERT INTO tunnel_certificate_records (
  id, domain_id, account_id, tunnel_id, target_kind, route_id, preview_id,
  preview_generation, preview_state, preview_expires_at, hostname, leaf_hostname, domain_generation,
  certificate_generation, strategy, state, certificate_reference,
  master_key_reference, certificate_ciphertext, private_key_ciphertext, fingerprint, issuer,
  not_before, expires_at, renewal_at, created_at, updated_at
) SELECT
  sqlc.arg(id), sqlc.arg(domain_id), sqlc.arg(account_id), NULL, 'preview_lease', NULL, sqlc.arg(preview_id),
  sqlc.arg(preview_generation), 'active', sqlc.arg(preview_expires_at), sqlc.arg(hostname), sqlc.narg(leaf_hostname), sqlc.arg(domain_generation),
  sqlc.arg(certificate_generation), sqlc.arg(strategy), 'staged', sqlc.arg(certificate_reference),
  sqlc.arg(master_key_reference), sqlc.arg(certificate_ciphertext), sqlc.arg(private_key_ciphertext),
  sqlc.arg(fingerprint), sqlc.arg(issuer), sqlc.arg(not_before), sqlc.arg(expires_at), sqlc.arg(renewal_at), sqlc.arg(now), sqlc.arg(now)
WHERE EXISTS (
  SELECT 1
  FROM preview_domains AS domain
  JOIN preview_leases AS lease
    ON lease.id = domain.preview_id AND lease.account_id = domain.account_id
  WHERE domain.id = sqlc.arg(domain_id)
    AND domain.account_id = sqlc.arg(account_id)
    AND domain.preview_id = sqlc.arg(preview_id)
    AND domain.preview_generation = sqlc.arg(preview_generation)
    AND domain.generation = sqlc.arg(domain_generation)
    AND domain.ownership_state = 'verified'
    AND domain.conflict_state = 'clear'
    AND domain.deleted_at IS NULL
    AND lease.generation = sqlc.arg(preview_generation)
    AND lease.terminal_state = 'active'
    AND lease.lease_deadline > sqlc.arg(now)
    AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now))
)
ON CONFLICT (id) DO UPDATE
SET state = 'staged', failure_code = NULL, updated_at = EXCLUDED.updated_at
WHERE tunnel_certificate_records.state IN ('staged','failed')
  AND tunnel_certificate_records.domain_id = EXCLUDED.domain_id
  AND tunnel_certificate_records.account_id = EXCLUDED.account_id
  AND tunnel_certificate_records.target_kind = EXCLUDED.target_kind
  AND tunnel_certificate_records.preview_id = EXCLUDED.preview_id
  AND tunnel_certificate_records.preview_generation = EXCLUDED.preview_generation
  AND tunnel_certificate_records.hostname = EXCLUDED.hostname
  AND COALESCE(tunnel_certificate_records.leaf_hostname, '') = COALESCE(EXCLUDED.leaf_hostname, '')
  AND tunnel_certificate_records.domain_generation = EXCLUDED.domain_generation
  AND tunnel_certificate_records.certificate_generation = EXCLUDED.certificate_generation
  AND tunnel_certificate_records.fingerprint = EXCLUDED.fingerprint
RETURNING *;

-- name: GetActivePreviewTunnelCertificateV1 :one
SELECT cert.*
FROM tunnel_certificate_records AS cert
JOIN preview_domains AS domain
  ON domain.id = cert.domain_id
 AND domain.account_id = cert.account_id
 AND domain.preview_id = cert.preview_id
JOIN preview_leases AS lease
  ON lease.id = domain.preview_id AND lease.account_id = domain.account_id
WHERE cert.domain_id = sqlc.arg(domain_id)
  AND cert.account_id = sqlc.arg(account_id)
  AND cert.target_kind = 'preview_lease'
  AND cert.preview_id = sqlc.arg(preview_id)
  AND cert.preview_generation = domain.preview_generation
  AND cert.leaf_hostname IS NULL
  AND cert.state = 'active'
  AND domain.deleted_at IS NULL
  AND domain.ownership_state = 'verified'
  AND domain.conflict_state = 'clear'
  AND lease.generation = domain.preview_generation
  AND lease.terminal_state = 'active'
  AND lease.lease_deadline > sqlc.arg(now)
  AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now))
ORDER BY cert.certificate_generation DESC
LIMIT 1;

-- name: GetActivePreviewTunnelCertificateByDomainV1 :one
SELECT cert.*
FROM tunnel_certificate_records AS cert
JOIN preview_domains AS domain
  ON domain.id = cert.domain_id
 AND domain.account_id = cert.account_id
 AND domain.preview_id = cert.preview_id
JOIN preview_leases AS lease
  ON lease.id = domain.preview_id AND lease.account_id = domain.account_id
WHERE cert.domain_id = sqlc.arg(domain_id)
  AND cert.target_kind = 'preview_lease'
  AND cert.preview_generation = domain.preview_generation
  AND cert.leaf_hostname IS NULL
  AND cert.state = 'active'
  AND domain.deleted_at IS NULL
  AND domain.ownership_state = 'verified'
  AND domain.conflict_state = 'clear'
  AND lease.generation = domain.preview_generation
  AND lease.terminal_state = 'active'
  AND lease.lease_deadline > sqlc.arg(now)
  AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now))
ORDER BY cert.certificate_generation DESC
LIMIT 1;

-- Rebind lookup is used in the small gap between a lease renewal and the
-- certificate worker's distribution pass. It finds the newest active
-- certificate for the same preview domain even when its target still carries
-- the previous lease generation. The caller must immediately fence it through
-- RebindPreviewCertificateTargetV1 before publishing an alias.
-- name: GetActivePreviewTunnelCertificateForRebindV1 :one
SELECT cert.*
FROM tunnel_certificate_records AS cert
JOIN preview_domains AS domain
  ON domain.id = cert.domain_id
 AND domain.account_id = cert.account_id
 AND domain.preview_id = cert.preview_id
JOIN preview_leases AS lease
  ON lease.id = domain.preview_id AND lease.account_id = domain.account_id
WHERE cert.domain_id = sqlc.arg(domain_id)
  AND cert.account_id = sqlc.arg(account_id)
  AND cert.target_kind = 'preview_lease'
  AND cert.preview_id = sqlc.arg(preview_id)
  AND cert.leaf_hostname IS NULL
  AND cert.state = 'active'
  AND cert.expires_at > sqlc.arg(now)
  AND domain.deleted_at IS NULL
  AND domain.ownership_state = 'verified'
  AND domain.conflict_state = 'clear'
  AND lease.generation = domain.preview_generation
  AND lease.terminal_state = 'active'
  AND lease.lease_deadline > sqlc.arg(now)
  AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now))
ORDER BY cert.preview_generation DESC, cert.certificate_generation DESC
LIMIT 1;

-- name: GetActivePreviewTunnelCertificateByDomainHostnameV1 :one
SELECT cert.*
FROM tunnel_certificate_records AS cert
JOIN preview_domains AS domain
  ON domain.id = cert.domain_id
 AND domain.account_id = cert.account_id
 AND domain.preview_id = cert.preview_id
JOIN preview_leases AS lease
  ON lease.id = domain.preview_id AND lease.account_id = domain.account_id
WHERE cert.domain_id = sqlc.arg(domain_id)
  AND cert.target_kind = 'preview_lease'
  AND cert.preview_generation = domain.preview_generation
  AND cert.hostname = sqlc.arg(hostname)
  AND cert.leaf_hostname = sqlc.arg(hostname)
  AND cert.state = 'active'
  AND domain.deleted_at IS NULL
  AND domain.ownership_state = 'verified'
  AND domain.conflict_state = 'clear'
  AND lease.generation = domain.preview_generation
  AND lease.terminal_state = 'active'
  AND lease.lease_deadline > sqlc.arg(now)
  AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now))
ORDER BY cert.certificate_generation DESC
LIMIT 1;

-- name: GetActivePreviewTunnelCertificateByDomainHostnameForRebindV1 :one
SELECT cert.*
FROM tunnel_certificate_records AS cert
JOIN preview_domains AS domain
  ON domain.id = cert.domain_id
 AND domain.account_id = cert.account_id
 AND domain.preview_id = cert.preview_id
JOIN preview_leases AS lease
  ON lease.id = domain.preview_id AND lease.account_id = domain.account_id
WHERE cert.domain_id = sqlc.arg(domain_id)
  AND cert.account_id = sqlc.arg(account_id)
  AND cert.target_kind = 'preview_lease'
  AND cert.preview_id = sqlc.arg(preview_id)
  AND cert.hostname = sqlc.arg(hostname)
  AND cert.leaf_hostname = sqlc.arg(hostname)
  AND cert.state = 'active'
  AND cert.expires_at > sqlc.arg(now)
  AND domain.deleted_at IS NULL
  AND domain.ownership_state = 'verified'
  AND domain.conflict_state = 'clear'
  AND lease.generation = domain.preview_generation
  AND lease.terminal_state = 'active'
  AND lease.lease_deadline > sqlc.arg(now)
  AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now))
ORDER BY cert.preview_generation DESC, cert.certificate_generation DESC
LIMIT 1;

-- name: GetActivePreviewTunnelCertificateByHostnameV1 :one
SELECT cert.*
FROM tunnel_certificate_records AS cert
JOIN preview_domains AS domain
  ON domain.id = cert.domain_id
 AND domain.account_id = cert.account_id
 AND domain.preview_id = cert.preview_id
JOIN preview_leases AS lease
  ON lease.id = domain.preview_id AND lease.account_id = domain.account_id
WHERE cert.domain_id = sqlc.arg(domain_id)
  AND cert.account_id = sqlc.arg(account_id)
  AND cert.target_kind = 'preview_lease'
  AND cert.preview_id = sqlc.arg(preview_id)
  AND cert.preview_generation = domain.preview_generation
  AND cert.hostname = sqlc.arg(hostname)
  AND cert.leaf_hostname = sqlc.arg(hostname)
  AND cert.state = 'active'
  AND domain.deleted_at IS NULL
  AND domain.ownership_state = 'verified'
  AND domain.conflict_state = 'clear'
  AND lease.generation = domain.preview_generation
  AND lease.terminal_state = 'active'
  AND lease.lease_deadline > sqlc.arg(now)
  AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now))
ORDER BY cert.certificate_generation DESC
LIMIT 1;

-- name: ActivateTunnelCertificateV1 :one
UPDATE tunnel_certificate_records
SET state = 'active', failure_code = NULL, updated_at = sqlc.arg(now)
WHERE tunnel_certificate_records.id = sqlc.arg(id)
  AND tunnel_certificate_records.domain_generation = sqlc.arg(domain_generation)
  AND tunnel_certificate_records.state = 'staged'
  AND (
    (
      tunnel_certificate_records.target_kind = 'durable_route'
      AND EXISTS (
        SELECT 1
        FROM tunnel_domains AS domain
        WHERE domain.id = tunnel_certificate_records.domain_id
          AND domain.account_id = tunnel_certificate_records.account_id
          AND domain.tunnel_id = tunnel_certificate_records.tunnel_id
          AND domain.generation = sqlc.arg(domain_generation)
          AND domain.deleted_at IS NULL
      )
    ) OR (
      tunnel_certificate_records.target_kind = 'preview_lease'
      AND EXISTS (
      SELECT 1
      FROM preview_domains AS domain
      JOIN preview_leases AS lease
        ON lease.id = domain.preview_id AND lease.account_id = domain.account_id
      WHERE domain.id = tunnel_certificate_records.domain_id
        AND domain.account_id = tunnel_certificate_records.account_id
        AND domain.preview_id = tunnel_certificate_records.preview_id
        AND domain.generation = sqlc.arg(domain_generation)
        AND domain.preview_generation = tunnel_certificate_records.preview_generation
        AND domain.deleted_at IS NULL
        AND domain.ownership_state = 'verified'
        AND domain.conflict_state = 'clear'
        AND lease.generation = domain.preview_generation
        AND lease.terminal_state = 'active'
        AND lease.lease_deadline > sqlc.arg(now)
        AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now))
      )
    )
  )
RETURNING *;

-- name: MarkTunnelCertificateFailedV1 :execrows
UPDATE tunnel_certificate_records
SET state = 'failed', failure_code = sqlc.arg(failure_code), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id)
  AND state = 'staged';

-- name: SupersedeOlderTunnelCertificatesV1 :execrows
UPDATE tunnel_certificate_records
SET state = CASE WHEN state = 'revoked' THEN state ELSE 'superseded' END,
    updated_at = sqlc.arg(now)
WHERE domain_id = sqlc.arg(domain_id)
  AND target_kind = 'durable_route'
  AND leaf_hostname IS NULL
  AND certificate_generation < sqlc.arg(certificate_generation)
  AND state IN ('active','staged');

-- name: RevokeTunnelCertificateV1 :one
UPDATE tunnel_certificate_records
SET state = 'revoked', revoked_at = sqlc.arg(now), updated_at = sqlc.arg(now), failure_code = sqlc.narg(reason)
WHERE id = sqlc.arg(id)
  AND state <> 'revoked'
RETURNING *;

-- Terminal preview leases withdraw every currently live certificate target in
-- the same transaction as the lease/domain transition. This makes the edge
-- cleanup ledger eligible immediately while retaining encrypted material for
-- the documented same-account reuse window.
-- name: RevokePreviewCertificatesForLeaseV1 :execrows
UPDATE tunnel_certificate_records
SET state = 'revoked', revoked_at = sqlc.arg(now),
    updated_at = sqlc.arg(now), failure_code = sqlc.arg(failure_code)
WHERE account_id = sqlc.arg(account_id)
  AND target_kind = 'preview_lease'
  AND preview_id = sqlc.arg(preview_id)
  AND state IN ('staged','active');

-- name: SupersedeOlderTunnelCertificatesByHostnameV1 :execrows
UPDATE tunnel_certificate_records
SET state = CASE WHEN state = 'revoked' THEN state ELSE 'superseded' END,
    updated_at = sqlc.arg(now)
WHERE domain_id = sqlc.arg(domain_id)
  AND hostname = sqlc.arg(hostname)
  AND leaf_hostname = sqlc.arg(hostname)
  AND certificate_generation < sqlc.arg(certificate_generation)
  AND state IN ('active','staged');

-- name: SupersedeOlderPreviewTunnelCertificatesV1 :execrows
UPDATE tunnel_certificate_records
SET state = CASE WHEN state = 'revoked' THEN state ELSE 'superseded' END,
    updated_at = sqlc.arg(now)
WHERE domain_id = sqlc.arg(domain_id)
  AND target_kind = 'preview_lease'
  AND preview_id = sqlc.arg(preview_id)
  AND preview_generation = sqlc.arg(preview_generation)
  AND hostname = sqlc.arg(hostname)
  AND leaf_hostname IS NULL
  AND certificate_generation < sqlc.arg(certificate_generation)
  AND state IN ('active','staged');

-- name: SupersedeOlderPreviewTunnelCertificatesByHostnameV1 :execrows
UPDATE tunnel_certificate_records
SET state = CASE WHEN state = 'revoked' THEN state ELSE 'superseded' END,
    updated_at = sqlc.arg(now)
WHERE domain_id = sqlc.arg(domain_id)
  AND target_kind = 'preview_lease'
  AND preview_id = sqlc.arg(preview_id)
  AND preview_generation = sqlc.arg(preview_generation)
  AND hostname = sqlc.arg(hostname)
  AND leaf_hostname = sqlc.arg(hostname)
  AND certificate_generation < sqlc.arg(certificate_generation)
  AND state IN ('active','staged');

-- Rebinding changes only the lease target fence. Certificate generation,
-- encrypted material, hostname, and domain generation remain unchanged, so a
-- preview lease renewal never causes needless CA issuance or a new cert ID.
-- name: RebindPreviewCertificateTargetV1 :one
UPDATE tunnel_certificate_records AS cert
SET preview_generation = sqlc.arg(preview_generation),
    preview_state = 'active',
    preview_expires_at = sqlc.arg(preview_expires_at),
    updated_at = sqlc.arg(now)
FROM preview_domains AS domain
JOIN preview_leases AS lease
  ON lease.id = domain.preview_id AND lease.account_id = domain.account_id
WHERE cert.id = sqlc.arg(certificate_id)
  AND cert.domain_id = domain.id
  AND cert.account_id = domain.account_id
  AND cert.target_kind = 'preview_lease'
  AND cert.preview_id = domain.preview_id
  AND cert.preview_generation = sqlc.arg(previous_preview_generation)
  AND cert.state IN ('active','staged')
  AND domain.id = sqlc.arg(domain_id)
  AND domain.account_id = sqlc.arg(account_id)
  AND domain.preview_id = sqlc.arg(preview_id)
  AND domain.preview_generation = sqlc.arg(preview_generation)
  AND domain.deleted_at IS NULL
  AND domain.ownership_state = 'verified'
  AND domain.conflict_state = 'clear'
  AND lease.generation = domain.preview_generation
  AND lease.terminal_state = 'active'
  AND lease.lease_deadline > sqlc.arg(now)
  AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now))
RETURNING cert.*;

-- The lease renewal transaction uses this bulk form so every active/staged
-- preview certificate target moves with the lease before the new alias
-- snapshot can be admitted. It does not touch certificate generations.
-- name: RebindPreviewCertificatesForLeaseV1 :execrows
UPDATE tunnel_certificate_records AS cert
SET preview_generation = sqlc.arg(preview_generation),
    preview_state = 'active',
    preview_expires_at = sqlc.arg(preview_expires_at),
    updated_at = sqlc.arg(now)
FROM preview_domains AS domain
JOIN preview_leases AS lease
  ON lease.id = domain.preview_id AND lease.account_id = domain.account_id
WHERE cert.domain_id = domain.id
  AND cert.account_id = domain.account_id
  AND cert.target_kind = 'preview_lease'
  AND cert.preview_id = domain.preview_id
  AND cert.preview_generation = sqlc.arg(previous_preview_generation)
  AND cert.state IN ('active','staged')
  AND domain.account_id = sqlc.arg(account_id)
  AND domain.preview_id = sqlc.arg(preview_id)
  AND domain.preview_generation = sqlc.arg(preview_generation)
  AND domain.deleted_at IS NULL
  AND domain.ownership_state = 'verified'
  AND domain.conflict_state = 'clear'
  AND lease.generation = domain.preview_generation
  AND lease.terminal_state = 'active'
  AND lease.lease_deadline > sqlc.arg(now)
  AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now));

-- name: ClearTunnelDomainCertificateOnRevokeV1 :execrows
UPDATE tunnel_domains
SET certificate_state = 'revoked', certificate_reference = NULL,
    certificate_failure_code = sqlc.arg(failure_code), generation = generation + 1,
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(domain_id)
  AND account_id = sqlc.arg(account_id)
  AND certificate_reference = sqlc.arg(certificate_reference)
  AND sqlc.arg(leaf_hostname) = ''
  AND deleted_at IS NULL;

-- name: StageTunnelCertificateEdgeV1 :one
INSERT INTO tunnel_certificate_edge_distributions (
  certificate_id, edge_node_id, edge_process_epoch, edge_assignment_generation, state,
  observed_certificate_generation, updated_at
) SELECT
  sqlc.arg(certificate_id), sqlc.arg(edge_node_id), sqlc.arg(edge_process_epoch),
  sqlc.arg(edge_assignment_generation), 'staged', sqlc.arg(certificate_generation), sqlc.arg(now)
WHERE NOT EXISTS (
  SELECT 1
  FROM tunnel_certificate_edge_distributions AS prior
  WHERE prior.certificate_id = sqlc.arg(certificate_id)
    AND prior.edge_node_id = sqlc.arg(edge_node_id)
    AND prior.edge_process_epoch <> sqlc.arg(edge_process_epoch)
    AND prior.edge_assignment_generation >= sqlc.arg(edge_assignment_generation)
    AND NOT EXISTS (
      SELECT 1
      FROM tunnel_certificate_records AS platform
      WHERE platform.id = sqlc.arg(certificate_id)
        AND platform.target_kind = 'platform_wildcard'
    )
)
ON CONFLICT (certificate_id, edge_node_id, edge_process_epoch) DO UPDATE
SET edge_assignment_generation = EXCLUDED.edge_assignment_generation,
    state = CASE WHEN tunnel_certificate_edge_distributions.state = 'active' THEN 'active' ELSE 'staged' END,
    observed_certificate_generation = EXCLUDED.observed_certificate_generation,
    failure_code = NULL,
    updated_at = EXCLUDED.updated_at
WHERE tunnel_certificate_edge_distributions.state IN ('staged','ready','active','failed')
  AND tunnel_certificate_edge_distributions.edge_assignment_generation <= EXCLUDED.edge_assignment_generation
RETURNING *;

-- name: MarkTunnelCertificateEdgeStateV1 :one
UPDATE tunnel_certificate_edge_distributions
SET state = CASE
              -- A retry after a successful activation must not regress the
              -- live edge back to ready.  The same rule preserves an active
              -- certificate when a stale transport reports failure.
              WHEN sqlc.arg(state) IN ('ready','failed') AND state = 'active' THEN 'active'
            ELSE sqlc.arg(state)
            END,
    observed_at = sqlc.narg(observed_at), failure_code = sqlc.narg(failure_code), updated_at = sqlc.arg(now)
WHERE certificate_id = sqlc.arg(certificate_id)
  AND edge_node_id = sqlc.arg(edge_node_id)
  AND edge_process_epoch = sqlc.arg(edge_process_epoch)
  AND edge_assignment_generation = sqlc.arg(edge_assignment_generation)
  AND observed_certificate_generation = sqlc.arg(certificate_generation)
  AND (
	    state IN ('staged','ready','active','retired','revoked','failed')
    AND (
      (sqlc.arg(state) = 'ready' AND state IN ('staged','ready','active'))
      OR (sqlc.arg(state) = 'failed' AND state IN ('staged','ready','active'))
      OR (sqlc.arg(state) = 'active' AND state IN ('ready','active'))
      OR (sqlc.arg(state) = 'retired' AND state IN ('staged','ready','active','retired','failed'))
	      OR (sqlc.arg(state) = 'revoked' AND state IN ('staged','ready','active','retired','revoked','failed'))
    )
  )
RETURNING *;

-- name: ListTunnelCertificateEdgesV1 :many
SELECT *
FROM tunnel_certificate_edge_distributions
WHERE certificate_id = sqlc.arg(certificate_id)
ORDER BY edge_node_id, edge_process_epoch;

-- name: CompleteTunnelDomainCreateAfterCertificateV1 :execrows
UPDATE operations AS op
SET state = 'succeeded', phase = 'ready', progress = 100,
    outcome = 'changed', completed_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE op.account_id = sqlc.arg(account_id)
  AND op.resource_kind = 'domain_binding'
  AND op.resource_id = sqlc.arg(domain_id)
  AND op.operation_type = 'domain.create'
  AND op.state IN ('pending','running')
  AND EXISTS (
    SELECT 1 FROM tunnel_certificate_records cert
    WHERE cert.domain_id = sqlc.arg(domain_id)
      AND cert.leaf_hostname IS NULL
      AND cert.state = 'active'
      AND cert.certificate_generation = sqlc.arg(certificate_generation)
  );

-- The coordinator uses these small rows inside its serializable finalization
-- transaction. Keeping the SQL here avoids raw database calls in the
-- certificate lifecycle and makes the generation fence visible to sqlc.
-- name: GetTunnelDomainCertificateCommitContextV1 :one
SELECT account_id, generation, certificate_state, COALESCE(certificate_reference, '')
FROM tunnel_domains
WHERE id = sqlc.arg(domain_id)
  AND deleted_at IS NULL
FOR UPDATE;

-- name: GetTunnelCertificateCommitContextV1 :one
SELECT domain_id, account_id, domain_generation, certificate_generation,
       state, certificate_reference, leaf_hostname
FROM tunnel_certificate_records
WHERE id = sqlc.arg(id)
FOR SHARE;

-- name: MarkTunnelDomainCertificateProjectionReadyV1 :execrows
UPDATE tunnel_domains
SET certificate_state = 'ready',
    certificate_reference = sqlc.arg(certificate_reference),
    certificate_expires_at = sqlc.arg(certificate_expires_at),
    certificate_renewal_attempted_at = sqlc.arg(now),
    certificate_failure_code = NULL,
    caa_state = 'ready',
    generation = generation + 1,
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(domain_id)
  AND account_id = sqlc.arg(account_id)
  AND generation = sqlc.arg(expected_generation)
  AND ownership_state = 'verified'
  AND conflict_state = 'clear'
  AND deleted_at IS NULL;

-- name: CompleteTunnelDomainCreateOperationV1 :execrows
UPDATE operations
SET state = 'succeeded', phase = 'ready', progress = 100,
    outcome = 'changed', completed_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE account_id = sqlc.arg(account_id)
  AND resource_kind = 'domain_binding'
  AND resource_id = sqlc.arg(domain_id)
  AND operation_type = 'domain.create'
  AND state IN ('pending','running');

-- name: HasPendingTunnelDomainCreateOperationV1 :one
SELECT EXISTS (
  SELECT 1
  FROM operations
  WHERE account_id = sqlc.arg(account_id)
    AND resource_kind = 'domain_binding'
    AND resource_id = sqlc.arg(domain_id)
    AND operation_type = 'domain.create'
    AND state IN ('pending','running')
);

-- Platform wildcard targets are server-owned rows, so they intentionally do
-- not use the tunnel_domains/preview_domains existence predicates above. They
-- still use the same encrypted certificate and edge-distribution ledger.
-- name: UpsertTunnelPlatformCertificateTargetV1 :one
INSERT INTO tunnel_platform_certificate_targets (
  id, kind, hostname, account_id, challenge_reference, generation,
  desired_state, certificate_state, created_at, updated_at
) VALUES (
  sqlc.arg(id), sqlc.arg(kind), sqlc.arg(hostname), sqlc.arg(account_id),
  sqlc.arg(challenge_reference), sqlc.arg(generation), 'active', 'pending',
  sqlc.arg(now), sqlc.arg(now)
)
ON CONFLICT (id) DO UPDATE
-- Identity reconciliation is intentionally a lifecycle no-op. Advancing
-- updated_at here while retaining a previously scheduled next_retry_at can
-- violate next_retry_at > updated_at and also makes an immutable seed look
-- like a certificate-state transition.
SET id = tunnel_platform_certificate_targets.id
WHERE tunnel_platform_certificate_targets.kind = EXCLUDED.kind
  AND tunnel_platform_certificate_targets.hostname = EXCLUDED.hostname
  AND tunnel_platform_certificate_targets.account_id = EXCLUDED.account_id
  AND tunnel_platform_certificate_targets.challenge_reference = EXCLUDED.challenge_reference
  AND tunnel_platform_certificate_targets.generation = EXCLUDED.generation
RETURNING *;

-- name: ListTunnelPlatformCertificateTargetsV1 :many
SELECT *
FROM tunnel_platform_certificate_targets
ORDER BY id
LIMIT sqlc.arg(row_limit);

-- name: MarkTunnelPlatformCertificateReadyV1 :execrows
UPDATE tunnel_platform_certificate_targets
SET certificate_state = 'ready', certificate_reference = sqlc.arg(certificate_reference),
    certificate_expires_at = sqlc.arg(certificate_expires_at),
    certificate_renewal_attempted_at = sqlc.arg(now),
    certificate_failure_code = NULL, retry_count = 0, next_retry_at = NULL,
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND desired_state = 'active';

-- name: MarkTunnelPlatformCertificateFailureV1 :execrows
UPDATE tunnel_platform_certificate_targets AS target
SET certificate_state = CASE WHEN EXISTS (
      SELECT 1 FROM tunnel_certificate_records AS cert
      WHERE cert.domain_id = target.id
        AND cert.target_kind = 'platform_wildcard'
        AND cert.leaf_hostname IS NULL
        AND cert.state = 'active'
    ) THEN 'ready' ELSE 'failed' END,
    certificate_failure_code = sqlc.arg(failure_code),
    certificate_renewal_attempted_at = sqlc.arg(now),
    retry_count = LEAST(target.retry_count + 1, 30),
    next_retry_at = sqlc.arg(next_retry_at),
    updated_at = sqlc.arg(now)
WHERE target.id = sqlc.arg(id) AND target.desired_state = 'active';

-- name: MarkTunnelPlatformCertificateTargetRevokedV1 :execrows
UPDATE tunnel_platform_certificate_targets
SET desired_state = 'revoked', certificate_state = 'revoked',
    certificate_failure_code = sqlc.arg(failure_code), next_retry_at = NULL,
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id);

-- name: GetActiveTunnelPlatformCertificateV1 :one
SELECT *
FROM tunnel_certificate_records
WHERE domain_id = sqlc.arg(domain_id)
  AND target_kind = 'platform_wildcard'
  AND leaf_hostname IS NULL
  AND state = 'active'
ORDER BY certificate_generation DESC
LIMIT 1;

-- name: GetTunnelPlatformCertificateForUpdateV1 :one
SELECT *
FROM tunnel_certificate_records
WHERE id = sqlc.arg(id)
  AND target_kind = 'platform_wildcard'
FOR UPDATE;

-- name: NextTunnelPlatformCertificateGenerationV1 :one
SELECT CAST(COALESCE(MAX(certificate_generation), 0::bigint) + 1 AS BIGINT) AS next_generation
FROM tunnel_certificate_records
WHERE domain_id = sqlc.arg(domain_id)
  AND target_kind = 'platform_wildcard'
  AND leaf_hostname IS NULL;

-- name: CreateTunnelPlatformCertificateRecordV1 :one
INSERT INTO tunnel_certificate_records (
  id, domain_id, account_id, tunnel_id, target_kind, route_id, hostname,
  leaf_hostname, domain_generation, certificate_generation, strategy, state,
  certificate_reference, master_key_reference, certificate_ciphertext,
  private_key_ciphertext, fingerprint, issuer, not_before, expires_at,
  renewal_at, created_at, updated_at
) VALUES (
  sqlc.arg(id), sqlc.arg(domain_id), sqlc.arg(account_id), NULL,
  'platform_wildcard', NULL, sqlc.arg(hostname), NULL,
  sqlc.arg(domain_generation), sqlc.arg(certificate_generation),
  sqlc.arg(strategy), 'staged', sqlc.arg(certificate_reference),
  sqlc.arg(master_key_reference), sqlc.arg(certificate_ciphertext),
  sqlc.arg(private_key_ciphertext), sqlc.arg(fingerprint), sqlc.arg(issuer),
  sqlc.arg(not_before), sqlc.arg(expires_at), sqlc.arg(renewal_at),
  sqlc.arg(now), sqlc.arg(now)
)
ON CONFLICT (id) DO UPDATE
SET state = 'staged', failure_code = NULL, updated_at = EXCLUDED.updated_at
WHERE tunnel_certificate_records.state IN ('staged','failed')
  AND tunnel_certificate_records.domain_id = EXCLUDED.domain_id
  AND tunnel_certificate_records.account_id = EXCLUDED.account_id
  AND tunnel_certificate_records.target_kind = EXCLUDED.target_kind
  AND tunnel_certificate_records.hostname = EXCLUDED.hostname
  AND tunnel_certificate_records.domain_generation = EXCLUDED.domain_generation
  AND tunnel_certificate_records.certificate_generation = EXCLUDED.certificate_generation
  AND tunnel_certificate_records.strategy = EXCLUDED.strategy
  AND tunnel_certificate_records.certificate_reference = EXCLUDED.certificate_reference
  AND tunnel_certificate_records.master_key_reference = EXCLUDED.master_key_reference
  AND tunnel_certificate_records.certificate_ciphertext = EXCLUDED.certificate_ciphertext
  AND tunnel_certificate_records.private_key_ciphertext = EXCLUDED.private_key_ciphertext
  AND tunnel_certificate_records.fingerprint = EXCLUDED.fingerprint
  AND tunnel_certificate_records.issuer = EXCLUDED.issuer
  AND tunnel_certificate_records.not_before = EXCLUDED.not_before
  AND tunnel_certificate_records.expires_at = EXCLUDED.expires_at
  AND tunnel_certificate_records.renewal_at = EXCLUDED.renewal_at
RETURNING *;

-- name: SupersedeOlderTunnelPlatformCertificatesV1 :execrows
UPDATE tunnel_certificate_records
SET state = 'superseded', updated_at = sqlc.arg(now)
WHERE domain_id = sqlc.arg(domain_id)
  AND target_kind = 'platform_wildcard'
  AND leaf_hostname IS NULL
  AND certificate_generation < sqlc.arg(certificate_generation)
  AND state IN ('active','staged');

-- name: ActivateTunnelPlatformCertificateV1 :execrows
UPDATE tunnel_certificate_records
SET state = 'active', failure_code = NULL, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id)
  AND target_kind = 'platform_wildcard'
  AND state = 'staged'
  AND domain_generation = sqlc.arg(domain_generation);

-- name: MarkTunnelPlatformCertificateFailedV1 :execrows
UPDATE tunnel_certificate_records
SET state = 'failed', failure_code = sqlc.arg(failure_code), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id)
  AND target_kind = 'platform_wildcard'
  AND state = 'staged';

-- name: RevokeTunnelPlatformCertificateV1 :execrows
UPDATE tunnel_certificate_records
SET state = 'revoked', revoked_at = sqlc.arg(now),
    failure_code = sqlc.arg(failure_code), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND target_kind = 'platform_wildcard' AND state <> 'revoked';

-- name: ListPendingTunnelPlatformCertificateRevocationIDsV1 :many
SELECT id
FROM tunnel_certificate_records
WHERE state = 'revoked'
  AND failure_code = 'ca_revocation_pending'
  AND target_kind = 'platform_wildcard'
ORDER BY updated_at, id
LIMIT sqlc.arg(row_limit);

-- name: MarkTunnelPlatformCertificateRevocationResultV1 :execrows
UPDATE tunnel_certificate_records
SET failure_code = sqlc.arg(failure_code), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id)
  AND target_kind = 'platform_wildcard'
  AND state = 'revoked';

-- name: ListReadyPlatformEdgeTargetsV1 :many
SELECT id, process_epoch
FROM control_tunnel_nodes
WHERE state = 'ready'
  AND ready = true
  AND last_heartbeat_at IS NOT NULL
  AND last_heartbeat_at > sqlc.arg(cutoff)
  AND version > 0
ORDER BY id, process_epoch;

-- name: CommitPreviewDomainCertificateReadyV1 :execrows
UPDATE preview_domains AS d
SET certificate_state = 'ready',
    certificate_reference = sqlc.arg(certificate_reference),
    certificate_expires_at = sqlc.arg(certificate_expires_at),
    certificate_renewal_attempted_at = sqlc.arg(now),
    certificate_failure_code = NULL,
    caa_state = 'ready',
    generation = d.generation + 1,
    updated_at = sqlc.arg(now)
FROM preview_leases AS lease
WHERE d.id = sqlc.arg(domain_id)
  AND d.account_id = sqlc.arg(account_id)
  AND d.preview_id = sqlc.arg(preview_id)
  AND d.preview_generation = sqlc.arg(preview_generation)
  AND d.generation = sqlc.arg(expected_domain_generation)
  AND d.ownership_state = 'verified'
  AND d.conflict_state = 'clear'
  AND d.deleted_at IS NULL
  AND lease.id = d.preview_id
  AND lease.account_id = d.account_id
  AND lease.generation = d.preview_generation
  AND lease.terminal_state = 'active'
  AND lease.lease_deadline > sqlc.arg(now)
  AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now))
  AND EXISTS (
    SELECT 1
    FROM tunnel_certificate_records AS cert
    WHERE cert.id = sqlc.arg(certificate_id)
      AND cert.domain_id = d.id
      AND cert.account_id = d.account_id
      AND cert.target_kind = 'preview_lease'
      AND cert.preview_id = d.preview_id
      AND cert.preview_generation = d.preview_generation
      AND cert.domain_generation = d.generation
      AND cert.certificate_generation = sqlc.arg(certificate_generation)
      AND cert.certificate_reference = sqlc.arg(certificate_reference)
      AND cert.state = 'active'
  );

-- name: GetPreviewCertificateReadinessV1 :one
SELECT EXISTS (
  SELECT 1
  FROM preview_domains AS d
  JOIN preview_leases AS lease
    ON lease.id = d.preview_id AND lease.account_id = d.account_id
  JOIN tunnel_certificate_records AS cert
    ON cert.domain_id = d.id
   AND cert.account_id = d.account_id
   AND cert.target_kind = 'preview_lease'
   AND cert.preview_id = d.preview_id
   AND cert.preview_generation = d.preview_generation
   AND cert.certificate_reference = d.certificate_reference
  WHERE d.id = sqlc.arg(domain_id)
    AND d.account_id = sqlc.arg(account_id)
    AND d.preview_id = sqlc.arg(preview_id)
    AND d.preview_generation = sqlc.arg(preview_generation)
    AND d.generation = sqlc.arg(domain_generation)
    AND d.hostname = sqlc.arg(hostname)
    AND d.ownership_state = 'verified'
    AND d.conflict_state = 'clear'
    AND d.certificate_state = 'ready'
    AND d.certificate_reference IS NOT NULL
    AND lease.generation = d.preview_generation
    AND lease.terminal_state = 'active'
    AND lease.lease_deadline > sqlc.arg(now)
    AND (lease.user_deadline IS NULL OR lease.user_deadline > sqlc.arg(now))
    AND cert.certificate_generation = sqlc.arg(certificate_generation)
    AND cert.state = 'active'
    AND cert.expires_at > sqlc.arg(now)
    AND EXISTS (
      SELECT 1
      FROM tunnel_certificate_edge_distributions AS edge_cert
      WHERE edge_cert.certificate_id = cert.id
        AND edge_cert.edge_node_id = sqlc.arg(edge_node_id)
        AND edge_cert.edge_process_epoch = sqlc.arg(edge_process_epoch)
        AND edge_cert.edge_assignment_generation = sqlc.arg(edge_assignment_generation)
        AND edge_cert.observed_certificate_generation = cert.certificate_generation
        AND edge_cert.state = 'active'
        AND edge_cert.updated_at >= cert.updated_at
    )
);
