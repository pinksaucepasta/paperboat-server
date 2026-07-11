-- name: InsertAuditEvent :exec
INSERT INTO audit_events
	(id, actor_user_id, actor_type, event_type, resource_type, resource_id, idempotency_key, metadata, created_at)
VALUES
	(sqlc.arg(id), nullif(sqlc.arg(actor_user_id), ''), sqlc.arg(actor_type), sqlc.arg(event_type), sqlc.arg(resource_type), sqlc.arg(resource_id), nullif(sqlc.arg(idempotency_key), ''), sqlc.arg(metadata)::jsonb, now())
ON CONFLICT (idempotency_key) DO NOTHING;

-- name: ListAuditEvents :many
SELECT id, coalesce(actor_user_id, '') AS actor_user_id, actor_type, event_type, resource_type, resource_id,
       coalesce(idempotency_key, '') AS idempotency_key, metadata, created_at
FROM audit_events
WHERE (sqlc.arg(resource_type) = '' OR resource_type = sqlc.arg(resource_type))
  AND (sqlc.arg(resource_id) = '' OR resource_id = sqlc.arg(resource_id))
  AND (sqlc.arg(actor_user_id) = '' OR actor_user_id = sqlc.arg(actor_user_id))
ORDER BY created_at DESC
LIMIT sqlc.arg(row_limit);
