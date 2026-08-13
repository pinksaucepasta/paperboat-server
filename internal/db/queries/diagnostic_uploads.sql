-- name: GetDiagnosticUploadIntentByOperationForUpdate :one
SELECT * FROM diagnostic_upload_intents
WHERE user_id = sqlc.arg(user_id) AND operation_key = sqlc.arg(operation_key)
FOR UPDATE;

-- name: CreateDiagnosticUploadIntent :one
INSERT INTO diagnostic_upload_intents
  (id, user_id, cli_client_session_id, operation_key, request_hash, correlation_id,
   object_key, expected_bytes, sha256, categories, expires_at, retain_until, created_at)
SELECT
  sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(cli_client_session_id), sqlc.arg(operation_key),
   sqlc.arg(request_hash), sqlc.arg(correlation_id), sqlc.arg(object_key),
   sqlc.arg(expected_bytes), sqlc.arg(sha256), sqlc.arg(categories), sqlc.arg(expires_at),
   sqlc.arg(retain_until), sqlc.arg(created_at)
FROM cli_client_sessions
WHERE id = sqlc.arg(cli_client_session_id) AND user_id = sqlc.arg(user_id) AND state = 'active'
RETURNING *;

-- name: GetDiagnosticUploadIntentForUserForUpdate :one
SELECT * FROM diagnostic_upload_intents
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
FOR UPDATE;

-- name: CompleteDiagnosticUploadIntent :one
UPDATE diagnostic_upload_intents
SET state = 'uploaded', uploaded_at = sqlc.arg(uploaded_at), object_etag = sqlc.arg(object_etag)
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND state = 'pending'
  AND expires_at > sqlc.arg(uploaded_at)
RETURNING *;

-- name: ExpireDiagnosticUploadIntents :many
UPDATE diagnostic_upload_intents
SET state = 'expired'
WHERE state = 'pending' AND expires_at <= sqlc.arg(now)
RETURNING *;

-- name: ListDiagnosticUploadCleanupCandidates :many
SELECT * FROM diagnostic_upload_intents
WHERE (state = 'pending' AND expires_at <= sqlc.arg(now)) OR retain_until <= sqlc.arg(now)
ORDER BY LEAST(expires_at, retain_until), id
LIMIT sqlc.arg(row_limit);

-- name: MarkDiagnosticUploadIntentExpired :one
UPDATE diagnostic_upload_intents
SET state = 'expired'
WHERE id = sqlc.arg(id) AND state = 'pending' AND expires_at <= sqlc.arg(now)
RETURNING *;

-- name: DeleteRetainedDiagnosticUploadIntent :one
DELETE FROM diagnostic_upload_intents
WHERE id = sqlc.arg(id) AND retain_until <= sqlc.arg(now)
RETURNING object_key;
