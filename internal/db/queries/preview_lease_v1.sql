-- Preview leases are foreground/session-owned resources. Keep their persistence
-- separate from durable tunnel queries so lease cleanup can be reconciled without
-- changing tunnel identity, routes, or domains.

-- name: VerifyPreviewLeaseOwnerV1 :one
SELECT owned.id
FROM user_machines AS owned
WHERE owned.id = sqlc.arg(owner_device_id)
  AND owned.user_id = sqlc.arg(account_id)
  AND owned.state = 'online'
  AND owned.online
  AND owned.deleted_at IS NULL
  AND owned.revoked_at IS NULL
LIMIT 1;

-- name: GetPreviewLeaseV1 :one
SELECT p.id, p.endpoint_id, p.endpoint, p.account_id, p.actor_id, p.owner_device_id, p.owner_session_id,
       p.target_scheme, p.target_address, p.access_mode, p.lease_deadline, p.user_deadline,
       p.allocation_state, p.edge_state, p.origin_state, p.terminal_state, p.created_at, p.ready_at,
       p.last_renewed_at, p.stopped_at, p.generation, p.owner_last_seen_at
FROM preview_leases AS p
WHERE p.id = sqlc.arg(id) AND p.account_id = sqlc.arg(account_id);

-- name: GetPreviewLeaseForReconciliationV1 :one
SELECT p.id, p.endpoint_id, p.endpoint, p.account_id, p.actor_id, p.owner_device_id, p.owner_session_id,
       p.target_scheme, p.target_address, p.access_mode, p.lease_deadline, p.user_deadline,
       p.allocation_state, p.edge_state, p.origin_state, p.terminal_state, p.created_at, p.ready_at,
       p.last_renewed_at, p.stopped_at, p.generation, p.owner_last_seen_at
FROM preview_leases AS p
WHERE p.id = sqlc.arg(id);

-- name: GetPreviewLeaseCreateOperationV1 :one
SELECT operation.id, operation.account_id, operation.idempotency_key, operation.request_hash, operation.operation_type, operation.resource_kind, operation.resource_id,
       operation.phase, operation.state, operation.progress, operation.retrying, operation.next_retry_at, operation.error_code, operation.outcome, operation.result_reference,
       operation.correlation_id, operation.created_at, operation.updated_at, operation.completed_at
FROM operations AS operation
JOIN preview_lease_create_operations AS create_operation
  ON create_operation.account_id = operation.account_id
 AND create_operation.preview_id = operation.resource_id
 AND create_operation.operation_id = operation.id
WHERE operation.account_id = sqlc.arg(account_id)
  AND operation.resource_kind = 'preview_lease'
  AND operation.resource_id = sqlc.arg(resource_id)
  AND operation.operation_type = 'preview.create';

-- name: CompletePreviewLeaseCreateOperationV1 :one
UPDATE operations
SET phase = 'ready', state = 'succeeded', progress = 100,
    retrying = false, outcome = 'changed', updated_at = sqlc.arg(updated_at),
    completed_at = sqlc.arg(completed_at)
WHERE id = sqlc.arg(id) AND account_id = sqlc.arg(account_id)
  AND state IN ('pending','running')
RETURNING id, account_id, idempotency_key, request_hash, operation_type, resource_kind, resource_id,
          phase, state, progress, retrying, next_retry_at, error_code, outcome, result_reference,
          correlation_id, created_at, updated_at, completed_at;

-- name: FailPreviewLeaseCreateOperationV1 :one
UPDATE operations
SET phase = 'failed', state = 'failed', progress = 100,
    retrying = false, error_code = sqlc.arg(error_code), outcome = 'unchanged',
    updated_at = sqlc.arg(updated_at), completed_at = sqlc.arg(completed_at)
WHERE id = sqlc.arg(id) AND account_id = sqlc.arg(account_id)
  AND state IN ('pending','running')
RETURNING id, account_id, idempotency_key, request_hash, operation_type, resource_kind, resource_id,
          phase, state, progress, retrying, next_retry_at, error_code, outcome, result_reference,
          correlation_id, created_at, updated_at, completed_at;

-- A dispatch timeout or connection loss is not proof that the host did not
-- accept the one-shot request. Keep the lease active and mark only the
-- original create operation uncertain so a later replay can retry the same
-- operation/lease without reporting readiness.
-- name: MarkPreviewLeaseCreateOperationUncertainV1 :one
UPDATE operations AS operation
SET phase = 'dispatch', state = 'uncertain', progress = 60,
    retrying = true, error_code = sqlc.arg(error_code), outcome = 'uncertain',
    updated_at = sqlc.arg(updated_at), completed_at = NULL
WHERE operation.id = (
	SELECT create_operation.operation_id
	FROM preview_lease_create_operations AS create_operation
	JOIN operations AS candidate
	  ON candidate.id = create_operation.operation_id
	 AND candidate.account_id = create_operation.account_id
	WHERE candidate.account_id = sqlc.arg(account_id)
	  AND create_operation.preview_id = sqlc.arg(resource_id)
	  AND candidate.resource_kind = 'preview_lease'
	  AND candidate.resource_id = sqlc.arg(resource_id)
	  AND candidate.operation_type = 'preview.create'
)
AND operation.account_id = sqlc.arg(account_id)
AND operation.state IN ('pending','running','uncertain')
RETURNING id, account_id, idempotency_key, request_hash, operation_type, resource_kind, resource_id,
          phase, state, progress, retrying, next_retry_at, error_code, outcome, result_reference,
          correlation_id, created_at, updated_at, completed_at;

-- name: ListPreviewLeasesV1 :many
SELECT p.id, p.endpoint_id, p.endpoint, p.account_id, p.actor_id, p.owner_device_id, p.owner_session_id,
       p.target_scheme, p.target_address, p.access_mode, p.lease_deadline, p.user_deadline,
       p.allocation_state, p.edge_state, p.origin_state, p.terminal_state, p.created_at, p.ready_at,
       p.last_renewed_at, p.stopped_at, p.generation, p.owner_last_seen_at
FROM preview_leases AS p
WHERE p.account_id = sqlc.arg(account_id)
  AND (
    sqlc.narg(after_created_at)::timestamptz IS NULL
    OR (p.created_at, p.id) < (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::text)
  )
ORDER BY p.created_at DESC, p.id DESC
LIMIT sqlc.arg(row_limit);

-- name: AdvancePreviewLeaseLifecycleV1 :one
UPDATE preview_leases
SET generation = generation + 1,
    owner_last_seen_at = sqlc.arg(owner_last_seen_at)
WHERE id = sqlc.arg(preview_id)
  AND account_id = sqlc.arg(account_id)
  AND owner_device_id = sqlc.arg(owner_device_id)
  AND owner_session_id = sqlc.arg(owner_session_id)
  AND terminal_state = 'active'
  AND generation = sqlc.arg(expected_generation)
RETURNING id AS lifecycle_preview_id,
          generation AS lifecycle_generation,
          owner_last_seen_at AS lifecycle_owner_last_seen_at,
          created_at AS lifecycle_created_at;

-- Readiness observations are authorized by the connector/edge worker rather
-- than by the foreground owner session. They still advance the same strong
-- generation, but deliberately use a separate CAS so a worker cannot borrow
-- owner credentials to mutate a lease.
-- name: AdvancePreviewLeaseReadinessV1 :execrows
UPDATE preview_leases
SET generation = generation + 1
WHERE id = sqlc.arg(preview_id)
  AND account_id = sqlc.arg(account_id)
  AND terminal_state = 'active'
  AND generation = sqlc.arg(expected_generation);

-- name: RenewPreviewLeaseV1 :exec
UPDATE preview_leases
SET lease_deadline = sqlc.arg(lease_deadline),
    last_renewed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id)
  AND account_id = sqlc.arg(account_id)
  AND terminal_state = 'active'
  AND (user_deadline IS NULL OR sqlc.arg(lease_deadline) <= user_deadline);

-- name: StopPreviewLeaseV1 :exec
UPDATE preview_leases
SET allocation_state = 'released',
    edge_state = 'released',
    terminal_state = 'stopped',
    stopped_at = sqlc.arg(now)
WHERE id = sqlc.arg(id)
  AND account_id = sqlc.arg(account_id)
  AND terminal_state = 'active';

-- name: MarkPreviewLeaseReadyV1 :exec
UPDATE preview_leases
SET allocation_state = sqlc.arg(allocation_state),
    edge_state = sqlc.arg(edge_state),
    origin_state = sqlc.arg(origin_state),
    terminal_state = CASE
      WHEN sqlc.arg(allocation_state) = 'failed' THEN 'failed'
      ELSE terminal_state
    END,
    stopped_at = CASE
      WHEN sqlc.arg(allocation_state) = 'failed' THEN COALESCE(stopped_at, sqlc.arg(now))
      ELSE stopped_at
    END,
    ready_at = CASE
      WHEN sqlc.arg(allocation_state) = 'ready'
       AND sqlc.arg(edge_state) = 'ready'
       AND sqlc.arg(origin_state) = 'ready'
      THEN COALESCE(ready_at, sqlc.arg(now))
      ELSE ready_at
    END
WHERE id = sqlc.arg(id)
  AND account_id = sqlc.arg(account_id)
  AND terminal_state = 'active';

-- name: ExpirePreviewLeasesV1 :many
WITH candidates AS (
  SELECT source.id
  FROM preview_leases AS source
  WHERE source.terminal_state = 'active'
    AND LEAST(source.lease_deadline, COALESCE(source.user_deadline, source.lease_deadline)) <= sqlc.arg(now)
  ORDER BY LEAST(source.lease_deadline, COALESCE(source.user_deadline, source.lease_deadline)), source.id
  LIMIT sqlc.arg(row_limit)
)
UPDATE preview_leases AS p
SET allocation_state = 'released',
    edge_state = 'released',
    terminal_state = 'expired',
    generation = generation + 1,
    stopped_at = sqlc.arg(now)
FROM candidates
WHERE p.id = candidates.id
RETURNING p.id;

-- name: MarkLostPreviewLeasesV1 :many
WITH candidates AS (
  SELECT source.id
  FROM preview_leases AS source
  WHERE source.terminal_state = 'active'
    AND source.lease_deadline > sqlc.arg(now)
    AND source.owner_last_seen_at <= sqlc.arg(owner_cutoff)
  ORDER BY source.owner_last_seen_at, source.id
  LIMIT sqlc.arg(row_limit)
)
UPDATE preview_leases AS p
SET allocation_state = 'released',
    edge_state = 'released',
    terminal_state = 'owner_lost',
    generation = generation + 1,
    stopped_at = sqlc.arg(now)
FROM candidates
WHERE p.id = candidates.id
RETURNING p.id;
