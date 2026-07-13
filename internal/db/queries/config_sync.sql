-- name: UpsertConfigSyncStatus :exec
INSERT INTO config_sync_statuses (
	project_id,machine_id,state,last_attempt_at,last_successful_sync_at,remote_commit,
	pending_path_count,skipped,conflicts,error_code,error_message,max_file_bytes,
	max_batch_bytes,policy_revision,status_updated_at,status_observed_at,heartbeat_at
) VALUES (
	sqlc.arg(project_id),sqlc.arg(machine_id),sqlc.arg(state),sqlc.narg(last_attempt_at),
	sqlc.narg(last_successful_sync_at),sqlc.arg(remote_commit),sqlc.arg(pending_path_count),
	sqlc.arg(skipped)::jsonb,sqlc.arg(conflicts)::jsonb,sqlc.arg(error_code),
	sqlc.arg(error_message),sqlc.arg(max_file_bytes),sqlc.arg(max_batch_bytes),
	sqlc.arg(policy_revision),sqlc.arg(status_updated_at),sqlc.arg(status_observed_at),sqlc.arg(heartbeat_at)
)
ON CONFLICT (project_id,machine_id) DO UPDATE SET
	state=EXCLUDED.state,last_attempt_at=EXCLUDED.last_attempt_at,
	last_successful_sync_at=EXCLUDED.last_successful_sync_at,remote_commit=EXCLUDED.remote_commit,
	pending_path_count=EXCLUDED.pending_path_count,skipped=EXCLUDED.skipped,conflicts=EXCLUDED.conflicts,
	error_code=EXCLUDED.error_code,error_message=EXCLUDED.error_message,
	max_file_bytes=EXCLUDED.max_file_bytes,max_batch_bytes=EXCLUDED.max_batch_bytes,
	policy_revision=EXCLUDED.policy_revision,status_updated_at=EXCLUDED.status_updated_at,
	status_observed_at=EXCLUDED.status_observed_at,
	heartbeat_at=GREATEST(config_sync_statuses.heartbeat_at,EXCLUDED.heartbeat_at),updated_at=now()
WHERE config_sync_statuses.status_updated_at <= EXCLUDED.status_updated_at
   OR config_sync_statuses.status_updated_at > now();

-- name: TouchConfigSyncStatusReceipt :exec
UPDATE config_sync_statuses
SET heartbeat_at=GREATEST(heartbeat_at,sqlc.arg(heartbeat_at)),received_at=now()
WHERE project_id=sqlc.arg(project_id) AND machine_id=sqlc.arg(machine_id);

-- name: ListConfigSyncStatusesByUser :many
SELECT p.id AS project_id,p.name AS project_name,p.state AS project_state,
	fm.fly_machine_id,coalesce(css.machine_id,fm.fly_machine_id,'') AS machine_id,
	coalesce(css.state,''),css.last_attempt_at,css.last_successful_sync_at,coalesce(css.remote_commit,''),
	coalesce(css.pending_path_count,0),coalesce(css.skipped,'[]'::jsonb),coalesce(css.conflicts,'[]'::jsonb),
	coalesce(css.error_code,''),coalesce(css.error_message,''),coalesce(css.max_file_bytes,0),
	coalesce(css.max_batch_bytes,0),coalesce(css.policy_revision,''),
	coalesce(css.status_updated_at,'epoch'::timestamptz),coalesce(css.status_observed_at,'epoch'::timestamptz),
	coalesce(css.heartbeat_at,'epoch'::timestamptz),
	coalesce(css.received_at,'epoch'::timestamptz)
FROM projects p
LEFT JOIN fly_machines fm ON fm.project_id=p.id
LEFT JOIN LATERAL (
	SELECT * FROM config_sync_statuses s
	WHERE s.project_id=p.id AND s.machine_id=fm.fly_machine_id
	LIMIT 1
) css ON true
WHERE p.user_id=sqlc.arg(user_id) AND p.state<>'deleted'
ORDER BY p.created_at DESC;

-- name: GetConfigSyncRepositoryByUser :one
SELECT owner,name,default_branch,html_url
FROM github_config_repositories
WHERE user_id=sqlc.arg(user_id) AND provisioned_at IS NOT NULL;
