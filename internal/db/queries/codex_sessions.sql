-- name: ResolveCodexSessionEnvironment :one
SELECT e.id AS environment_id, e.owner_user_id AS user_id, m.id AS machine_id,
       m.installation_generation, c.generation AS connector_generation,
       c.edge_pool, c.edge_node_id, r.public_host, m.online,
       m.configured_capabilities, m.observed_capabilities
FROM control_environments e
JOIN user_machines m ON m.environment_id=e.id AND m.revoked_at IS NULL AND m.deleted_at IS NULL
JOIN control_connector_generations c ON c.environment_id=e.id AND c.state IN ('pending','admitted') AND c.revoked_at IS NULL
JOIN control_routes r ON r.environment_id=e.id AND r.kind='runtime_https_wss' AND r.desired_state IN ('attached','replacing')
WHERE e.id=sqlc.arg(environment_id) AND e.owner_user_id=sqlc.arg(user_id)
  AND e.desired_state='active' AND e.revoked_at IS NULL;

-- name: GetCodexSessionMachineCapability :one
SELECT m.online, m.configured_capabilities, m.observed_capabilities
FROM user_machines m
WHERE m.id=sqlc.arg(machine_id) AND m.environment_id=sqlc.arg(environment_id)
  AND m.revoked_at IS NULL AND m.deleted_at IS NULL;

-- name: LockCodexSessionLimit :one
SELECT id FROM control_environments WHERE id=sqlc.arg(environment_id) FOR UPDATE;

-- name: CountActiveCodexSessions :one
SELECT count(*) FROM codex_sessions
WHERE user_id=sqlc.arg(user_id) AND environment_id=sqlc.arg(environment_id)
  AND state IN ('preparing','ready','reconnecting') AND lease_expires_at>sqlc.arg(now);

-- name: CreateCodexSession :one
INSERT INTO codex_sessions (id,environment_id,machine_id,user_id,cli_client_session_id,idempotency_key,request_hash,
 installation_generation,connector_generation,edge_pool,edge_node_id,edge_assignment_host,lease_expires_at,last_renewed_at)
VALUES (sqlc.arg(id),sqlc.arg(environment_id),sqlc.arg(machine_id),sqlc.arg(user_id),sqlc.arg(cli_client_session_id),
 sqlc.arg(idempotency_key),sqlc.arg(request_hash),sqlc.arg(installation_generation),sqlc.arg(connector_generation),
 sqlc.arg(edge_pool),sqlc.arg(edge_node_id),sqlc.arg(edge_assignment_host),sqlc.arg(lease_expires_at),sqlc.arg(now))
RETURNING *;

-- name: GetCodexSessionByIdempotency :one
SELECT * FROM codex_sessions WHERE cli_client_session_id=sqlc.arg(cli_client_session_id) AND idempotency_key=sqlc.arg(idempotency_key);

-- name: GetOwnedCodexSession :one
SELECT * FROM codex_sessions WHERE id=sqlc.arg(id) AND user_id=sqlc.arg(user_id) AND cli_client_session_id=sqlc.arg(cli_client_session_id);

-- name: RenewCodexSession :one
UPDATE codex_sessions SET lease_expires_at=sqlc.arg(lease_expires_at),last_renewed_at=sqlc.arg(now),updated_at=sqlc.arg(now)
WHERE id=sqlc.arg(id) AND user_id=sqlc.arg(user_id) AND cli_client_session_id=sqlc.arg(cli_client_session_id)
 AND state IN ('preparing','ready','reconnecting') AND lease_expires_at>sqlc.arg(now)
RETURNING *;

-- name: MarkCodexSessionReady :one
UPDATE codex_sessions SET state='ready',remote_codex_version=sqlc.arg(remote_codex_version),prepared_at=sqlc.arg(now),updated_at=sqlc.arg(now)
WHERE id=sqlc.arg(id) AND state='preparing' RETURNING *;

-- name: StopCodexSession :one
UPDATE codex_sessions SET state='stopping',cleanup_status='pending',stopping_at=sqlc.arg(now),updated_at=sqlc.arg(now)
WHERE id=sqlc.arg(id) AND user_id=sqlc.arg(user_id) AND cli_client_session_id=sqlc.arg(cli_client_session_id)
 AND state NOT IN ('stopped','failed') RETURNING *;

-- name: CompleteCodexSessionStop :exec
UPDATE codex_sessions SET state='stopped',cleanup_status='complete',stopped_at=sqlc.arg(now),updated_at=sqlc.arg(now) WHERE id=sqlc.arg(id);

-- name: StopCodexSessionsForMachine :execrows
UPDATE codex_sessions
SET state='stopping',cleanup_status='pending',stopping_at=sqlc.arg(now),updated_at=sqlc.arg(now)
WHERE machine_id=sqlc.arg(machine_id) AND state IN ('preparing','ready','reconnecting');

-- name: ListExpiredCodexSessions :many
SELECT * FROM codex_sessions WHERE state IN ('preparing','ready','reconnecting','stopping') AND lease_expires_at<=sqlc.arg(now)
ORDER BY lease_expires_at,id LIMIT sqlc.arg(batch_size);

-- name: MarkExpiredCodexSessionStopped :exec
UPDATE codex_sessions SET state='stopped',cleanup_status='uncertain',stopped_at=sqlc.arg(now),updated_at=sqlc.arg(now)
WHERE id=sqlc.arg(id) AND lease_expires_at<=sqlc.arg(now) AND state IN ('preparing','ready','reconnecting','stopping');
