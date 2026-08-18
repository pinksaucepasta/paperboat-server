-- name: GetReleaseAuthorityImportOperation :one
SELECT actor_user_id, idempotency_key, request_hash, bundle_id, created_at
FROM release_authority_import_operations
WHERE actor_user_id = sqlc.arg(actor_user_id) AND idempotency_key = sqlc.arg(idempotency_key);

-- name: GetReleaseAuthorityBundle :one
SELECT id, release_id, version, platform, architecture, action, policy_revision,
       payload, payload_hash, signatures, issued_at, expires_at, authority_request_id, imported_by_user_id, imported_at
FROM release_authority_bundles WHERE id = sqlc.arg(id);

-- name: GetLatestReleaseAuthorityBundleForUpdate :one
SELECT id, release_id, version, platform, architecture, action, policy_revision,
       payload, payload_hash, signatures, issued_at, expires_at, authority_request_id, imported_by_user_id, imported_at
FROM release_authority_bundles
WHERE release_id = sqlc.arg(release_id) AND platform = sqlc.arg(platform) AND architecture = sqlc.arg(architecture)
ORDER BY policy_revision DESC LIMIT 1 FOR UPDATE;

-- name: CreateReleaseAuthorityBundle :one
INSERT INTO release_authority_bundles (
  id, release_id, version, platform, architecture, action, policy_revision, payload,
  payload_hash, signatures, issued_at, expires_at, authority_request_id, imported_by_user_id
) VALUES (
  sqlc.arg(id), sqlc.arg(release_id), sqlc.arg(version), sqlc.arg(platform), sqlc.arg(architecture),
  sqlc.arg(action), sqlc.arg(policy_revision), sqlc.arg(payload), sqlc.arg(payload_hash),
  sqlc.arg(signatures), sqlc.arg(issued_at), sqlc.arg(expires_at), sqlc.arg(authority_request_id), sqlc.arg(imported_by_user_id)
)
RETURNING id, release_id, version, platform, architecture, action, policy_revision,
          payload, payload_hash, signatures, issued_at, expires_at, authority_request_id, imported_by_user_id, imported_at;

-- name: CreateReleaseAuthorityImportOperation :exec
INSERT INTO release_authority_import_operations(actor_user_id, idempotency_key, request_hash, bundle_id)
VALUES (sqlc.arg(actor_user_id), sqlc.arg(idempotency_key), sqlc.arg(request_hash), sqlc.arg(bundle_id));

-- name: ListReleaseAuthorityBundles :many
SELECT id, release_id, version, platform, architecture, action, policy_revision,
       payload, payload_hash, signatures, issued_at, expires_at, authority_request_id, imported_by_user_id, imported_at
FROM release_authority_bundles
ORDER BY imported_at DESC, id DESC LIMIT sqlc.arg(page_limit);

-- name: GetReleaseAuthorityRequestForUpdate :one
SELECT id, action, release_id, version, platform, architecture, policy_revision, rollout_percentage, status, requested_by_user_id, idempotency_key, request_hash, fulfilled_bundle_id, created_at, fulfilled_at
FROM release_authority_requests WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: CreateReleaseAuthorityRequest :one
INSERT INTO release_authority_requests(id, action, release_id, version, platform, architecture, policy_revision, rollout_percentage, requested_by_user_id, idempotency_key, request_hash)
VALUES (sqlc.arg(id), sqlc.arg(action), sqlc.arg(release_id), sqlc.arg(version), sqlc.arg(platform), sqlc.arg(architecture), sqlc.arg(policy_revision), sqlc.arg(rollout_percentage), sqlc.arg(requested_by_user_id), sqlc.arg(idempotency_key), sqlc.arg(request_hash))
RETURNING id, action, release_id, version, platform, architecture, policy_revision, rollout_percentage, status, requested_by_user_id, idempotency_key, request_hash, fulfilled_bundle_id, created_at, fulfilled_at;

-- name: GetReleaseAuthorityRequestForIdempotency :one
SELECT id, action, release_id, version, platform, architecture, policy_revision, rollout_percentage, status, requested_by_user_id, idempotency_key, request_hash, fulfilled_bundle_id, created_at, fulfilled_at
FROM release_authority_requests WHERE requested_by_user_id = sqlc.arg(requested_by_user_id) AND idempotency_key = sqlc.arg(idempotency_key);

-- name: FulfillReleaseAuthorityRequest :one
UPDATE release_authority_requests SET status='fulfilled', fulfilled_bundle_id=sqlc.arg(fulfilled_bundle_id), fulfilled_at=now()
WHERE id=sqlc.arg(id) AND status='pending'
RETURNING id, action, release_id, version, platform, architecture, policy_revision, rollout_percentage, status, requested_by_user_id, idempotency_key, request_hash, fulfilled_bundle_id, created_at, fulfilled_at;

-- name: ListReleaseAuthorityRequests :many
SELECT id, action, release_id, version, platform, architecture, policy_revision, rollout_percentage, status, requested_by_user_id, idempotency_key, request_hash, fulfilled_bundle_id, created_at, fulfilled_at
FROM release_authority_requests ORDER BY created_at DESC, id DESC LIMIT sqlc.arg(page_limit);
