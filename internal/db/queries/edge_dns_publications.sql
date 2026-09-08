-- name: GetEdgeDNSPublication :one
SELECT * FROM edge_dns_publications WHERE hostname = sqlc.arg(hostname);

-- name: ListEdgeDNSPublicationHostnamesByOwner :many
SELECT hostname FROM edge_dns_publications WHERE owner_id = sqlc.arg(owner_id) ORDER BY hostname LIMIT 129;

-- name: UpsertEdgeDNSPublicationDesired :one
INSERT INTO edge_dns_publications (
  hostname, owner_id, resource_generation, readiness_version, observed_at, valid_until, publication_generation,
  desired_addresses, provider_records, state, created_at, updated_at
) VALUES (
  sqlc.arg(hostname), sqlc.arg(owner_id), sqlc.arg(resource_generation), sqlc.arg(readiness_version), sqlc.arg(observed_at), sqlc.narg(valid_until), 1,
  sqlc.arg(desired_addresses), '[]'::jsonb, 'desired', sqlc.arg(now), sqlc.arg(now)
)
ON CONFLICT (hostname) DO UPDATE SET
  resource_generation = EXCLUDED.resource_generation,
  readiness_version = EXCLUDED.readiness_version,
  observed_at = EXCLUDED.observed_at,
  valid_until = EXCLUDED.valid_until,
  publication_generation = CASE
    WHEN edge_dns_publications.resource_generation <> EXCLUDED.resource_generation
      OR edge_dns_publications.readiness_version <> EXCLUDED.readiness_version
      OR edge_dns_publications.desired_addresses <> EXCLUDED.desired_addresses
    THEN edge_dns_publications.publication_generation + 1
    ELSE edge_dns_publications.publication_generation
  END,
  desired_addresses = EXCLUDED.desired_addresses,
  state = CASE
    WHEN edge_dns_publications.resource_generation <> EXCLUDED.resource_generation
      OR edge_dns_publications.readiness_version <> EXCLUDED.readiness_version
      OR edge_dns_publications.desired_addresses <> EXCLUDED.desired_addresses
    THEN 'desired'
    ELSE edge_dns_publications.state
  END,
  failure_code = CASE
    WHEN edge_dns_publications.resource_generation <> EXCLUDED.resource_generation
      OR edge_dns_publications.readiness_version <> EXCLUDED.readiness_version
      OR edge_dns_publications.desired_addresses <> EXCLUDED.desired_addresses
    THEN NULL
    ELSE edge_dns_publications.failure_code
  END,
  verified_at = CASE
    WHEN edge_dns_publications.resource_generation <> EXCLUDED.resource_generation
      OR edge_dns_publications.readiness_version <> EXCLUDED.readiness_version
      OR edge_dns_publications.desired_addresses <> EXCLUDED.desired_addresses
    THEN NULL
    ELSE edge_dns_publications.verified_at
  END,
  updated_at = EXCLUDED.updated_at
WHERE edge_dns_publications.owner_id = EXCLUDED.owner_id
  AND (edge_dns_publications.resource_generation < EXCLUDED.resource_generation
    OR (edge_dns_publications.resource_generation = EXCLUDED.resource_generation
      AND edge_dns_publications.observed_at <= EXCLUDED.observed_at))
RETURNING *;

-- name: MarkEdgeDNSPublicationSubmitted :execrows
UPDATE edge_dns_publications
SET provider_records = sqlc.arg(provider_records), state = 'submitted', failure_code = NULL, updated_at = sqlc.arg(now)
WHERE hostname = sqlc.arg(hostname) AND owner_id = sqlc.arg(owner_id)
  AND publication_generation = sqlc.arg(publication_generation);

-- name: MarkEdgeDNSPublicationVerified :execrows
UPDATE edge_dns_publications
SET provider_records = sqlc.arg(provider_records), state = 'verified', failure_code = NULL,
    verified_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE hostname = sqlc.arg(hostname) AND owner_id = sqlc.arg(owner_id)
  AND publication_generation = sqlc.arg(publication_generation);

-- name: MarkEdgeDNSPublicationFailed :execrows
UPDATE edge_dns_publications
SET provider_records = sqlc.arg(provider_records), state = 'failed', failure_code = sqlc.arg(failure_code), updated_at = sqlc.arg(now)
WHERE hostname = sqlc.arg(hostname) AND owner_id = sqlc.arg(owner_id)
  AND publication_generation = sqlc.arg(publication_generation);
