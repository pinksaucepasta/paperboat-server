-- name: CreateDefaultTerminalSession :exec
INSERT INTO project_terminal_sessions (id,project_id,terminal_id,name,is_default)
VALUES (sqlc.arg(id),sqlc.arg(project_id),'term-1','default',true)
ON CONFLICT (project_id) WHERE is_default AND deleted_at IS NULL DO NOTHING;

-- name: GetActiveTerminalSession :one
SELECT project_terminal_sessions.*
FROM project_terminal_sessions WHERE project_id=sqlc.arg(project_id) AND id=sqlc.arg(id) AND deleted_at IS NULL;

-- name: GetDefaultTerminalSession :one
SELECT project_terminal_sessions.*
FROM project_terminal_sessions WHERE project_id=sqlc.arg(project_id) AND is_default AND deleted_at IS NULL;

-- name: GetTerminalSessionProjectOwner :one
SELECT user_id FROM projects WHERE id=sqlc.arg(project_id) AND state<>'deleted';

-- name: LockProjectTerminalSessions :one
SELECT id FROM projects WHERE id=sqlc.arg(project_id) FOR UPDATE;

-- name: CountActiveTerminalSessions :one
SELECT count(*)::integer FROM project_terminal_sessions WHERE project_id=sqlc.arg(project_id) AND deleted_at IS NULL;

-- name: NextTerminalSessionOrdinal :one
SELECT coalesce(max(auto_name_ordinal),1)::integer+1 FROM project_terminal_sessions WHERE project_id=sqlc.arg(project_id);

-- name: CreateTerminalSession :exec
INSERT INTO project_terminal_sessions (id,project_id,terminal_id,name,auto_name_ordinal,idempotency_key)
VALUES (sqlc.arg(id),sqlc.arg(project_id),sqlc.arg(terminal_id),sqlc.arg(name),nullif(sqlc.arg(auto_name_ordinal),0),sqlc.arg(idempotency_key));

-- name: GetTerminalSessionByIdempotencyKey :one
SELECT project_terminal_sessions.*
FROM project_terminal_sessions WHERE project_id=sqlc.arg(project_id) AND idempotency_key=sqlc.arg(idempotency_key);

-- name: ListActiveTerminalSessions :many
SELECT project_terminal_sessions.*
FROM project_terminal_sessions WHERE project_id=sqlc.arg(project_id) AND deleted_at IS NULL
ORDER BY is_default DESC, last_activity_at DESC NULLS LAST, name;

-- name: RenameTerminalSession :execrows
UPDATE project_terminal_sessions SET name=sqlc.arg(name),version=version+1,updated_at=now()
WHERE project_id=sqlc.arg(project_id) AND id=sqlc.arg(id) AND deleted_at IS NULL AND NOT is_default;

-- name: CloseTerminalSession :execrows
UPDATE project_terminal_sessions SET desired_state='closed',runtime_state='closed',version=version+1,updated_at=now()
WHERE project_id=sqlc.arg(project_id) AND id=sqlc.arg(id) AND deleted_at IS NULL AND desired_state<>'closed';

-- name: ReopenTerminalSession :exec
UPDATE project_terminal_sessions SET desired_state='open',version=version+1,updated_at=now()
WHERE project_id=sqlc.arg(project_id) AND id=sqlc.arg(id) AND deleted_at IS NULL AND desired_state='closed';

-- name: DeleteTerminalSession :execrows
UPDATE project_terminal_sessions SET desired_state='deleted',deleted_at=now(),version=version+1,updated_at=now()
WHERE project_id=sqlc.arg(project_id) AND id=sqlc.arg(id) AND deleted_at IS NULL AND NOT is_default;

-- name: TombstoneProjectTerminalSessions :exec
UPDATE project_terminal_sessions
SET desired_state='deleted',deleted_at=now(),version=version+1,updated_at=now()
WHERE project_id=sqlc.arg(project_id) AND deleted_at IS NULL;

-- name: QueueTerminalSessionOperation :exec
INSERT INTO terminal_session_operations (id,project_id,terminal_session_id,operation)
VALUES (sqlc.arg(id),sqlc.arg(project_id),sqlc.arg(terminal_session_id),sqlc.arg(operation))
ON CONFLICT (terminal_session_id,operation,state) DO NOTHING;

-- name: TerminalSessionOperationPending :one
SELECT EXISTS (
  SELECT 1 FROM terminal_session_operations
  WHERE project_id=sqlc.arg(project_id) AND terminal_session_id=sqlc.arg(terminal_session_id) AND state='pending'
);

-- name: ListDueTerminalSessionOperations :many
SELECT o.id,o.project_id,o.terminal_session_id,o.operation,o.attempts,p.user_id,s.thread_id,s.terminal_id
FROM terminal_session_operations o
JOIN projects p ON p.id=o.project_id
JOIN project_terminal_sessions s ON s.id=o.terminal_session_id
WHERE o.state='pending' AND o.next_attempt_at<=now()
ORDER BY o.created_at LIMIT sqlc.arg(batch_size);

-- name: ListPendingTerminalSessionOperationsForProject :many
SELECT o.id,o.project_id,o.terminal_session_id,o.operation,o.attempts,p.user_id,s.thread_id,s.terminal_id
FROM terminal_session_operations o
JOIN projects p ON p.id=o.project_id
JOIN project_terminal_sessions s ON s.id=o.terminal_session_id
WHERE o.project_id=sqlc.arg(project_id) AND o.state='pending'
ORDER BY o.created_at LIMIT sqlc.arg(batch_size);

-- name: MarkTerminalSessionOperationApplied :exec
UPDATE terminal_session_operations SET state='applied',completed_at=now(),updated_at=now(),last_error=NULL
WHERE id=sqlc.arg(id) AND state='pending';

-- name: RetryTerminalSessionOperation :exec
UPDATE terminal_session_operations SET attempts=attempts+1,next_attempt_at=now()+make_interval(secs => sqlc.arg(retry_seconds)),last_error=sqlc.arg(last_error),updated_at=now()
WHERE id=sqlc.arg(id) AND state='pending';

-- name: UpdateTerminalSessionRuntime :exec
UPDATE project_terminal_sessions
SET runtime_state=sqlc.arg(runtime_state),
    launch_cwd=coalesce(nullif(sqlc.arg(launch_cwd)::text,''),launch_cwd),
    last_activity_at=coalesce(sqlc.arg(last_activity_at),last_activity_at),
    last_runtime_sequence=sqlc.arg(last_runtime_sequence),
    last_runtime_sync_at=now(),
    updated_at=now()
WHERE id=sqlc.arg(id);

-- name: MarkTerminalSessionRuntimeClosed :exec
UPDATE project_terminal_sessions
SET runtime_state='closed',last_runtime_sync_at=now(),updated_at=now()
WHERE id=sqlc.arg(id);
