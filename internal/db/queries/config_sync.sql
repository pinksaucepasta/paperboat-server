-- name: UpsertConfigSyncStatus :exec
INSERT INTO config_sync_statuses (
	project_id,machine_id,state,last_attempt_at,last_successful_sync_at,remote_commit,
	pending_path_count,skipped,conflicts,classifier_pending,error_code,error_message,max_file_bytes,
	max_batch_bytes,policy_revision,classifier_policy_revision,classifier_model_revision,classifier_health,encryption_key_version,status_updated_at,status_observed_at,heartbeat_at
) VALUES (
	sqlc.arg(project_id),sqlc.arg(machine_id),sqlc.arg(state),sqlc.narg(last_attempt_at),
	sqlc.narg(last_successful_sync_at),sqlc.arg(remote_commit),sqlc.arg(pending_path_count),
	sqlc.arg(skipped)::jsonb,sqlc.arg(conflicts)::jsonb,sqlc.arg(classifier_pending)::jsonb,sqlc.arg(error_code),
	sqlc.arg(error_message),sqlc.arg(max_file_bytes),sqlc.arg(max_batch_bytes),
	sqlc.arg(policy_revision),sqlc.arg(classifier_policy_revision),sqlc.arg(classifier_model_revision),sqlc.arg(classifier_health),sqlc.arg(encryption_key_version),sqlc.arg(status_updated_at),sqlc.arg(status_observed_at),sqlc.arg(heartbeat_at)
)
ON CONFLICT (project_id,machine_id) DO UPDATE SET
	state=EXCLUDED.state,last_attempt_at=EXCLUDED.last_attempt_at,
	last_successful_sync_at=EXCLUDED.last_successful_sync_at,remote_commit=EXCLUDED.remote_commit,
	pending_path_count=EXCLUDED.pending_path_count,skipped=EXCLUDED.skipped,conflicts=EXCLUDED.conflicts,classifier_pending=EXCLUDED.classifier_pending,
	error_code=EXCLUDED.error_code,error_message=EXCLUDED.error_message,
	max_file_bytes=EXCLUDED.max_file_bytes,max_batch_bytes=EXCLUDED.max_batch_bytes,
	policy_revision=EXCLUDED.policy_revision,classifier_policy_revision=EXCLUDED.classifier_policy_revision,classifier_model_revision=EXCLUDED.classifier_model_revision,classifier_health=EXCLUDED.classifier_health,encryption_key_version=EXCLUDED.encryption_key_version,status_updated_at=EXCLUDED.status_updated_at,
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
	coalesce(css.pending_path_count,0),coalesce(css.skipped,'[]'::jsonb),coalesce(css.conflicts,'[]'::jsonb),coalesce(css.classifier_pending,'[]'::jsonb),
	coalesce(css.error_code,''),coalesce(css.error_message,''),coalesce(css.max_file_bytes,0),
	coalesce(css.max_batch_bytes,0),coalesce(css.policy_revision,''),coalesce(css.classifier_policy_revision,''),coalesce(css.classifier_model_revision,''),coalesce(css.classifier_health,''),coalesce(css.encryption_key_version,0),
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

-- name: ListConfigClassificationOverrides :many
SELECT normalized_path,decision,created_at,updated_at FROM config_classification_overrides WHERE user_id=sqlc.arg(user_id) ORDER BY normalized_path;

-- name: UpsertConfigClassificationOverride :exec
INSERT INTO config_classification_overrides (user_id,normalized_path,decision,created_by) VALUES (sqlc.arg(user_id),sqlc.arg(normalized_path),sqlc.arg(decision),sqlc.arg(created_by))
ON CONFLICT (user_id,normalized_path) DO UPDATE SET decision=EXCLUDED.decision,created_by=EXCLUDED.created_by,updated_at=now();

-- name: DeleteConfigClassificationOverride :execrows
DELETE FROM config_classification_overrides WHERE user_id=sqlc.arg(user_id) AND normalized_path=sqlc.arg(normalized_path);

-- name: InsertAccountConfigKey :execrows
INSERT INTO account_config_keys (user_id,key_version,recipient,encrypted_identity)
VALUES (sqlc.arg(user_id),1,sqlc.arg(recipient),sqlc.arg(encrypted_identity))
ON CONFLICT (user_id) DO NOTHING;

-- name: GetAccountConfigKey :one
SELECT user_id,key_version,recipient,encrypted_identity,previous_key_version,previous_recipient,previous_encrypted_identity,created_at,rotated_at
FROM account_config_keys WHERE user_id=sqlc.arg(user_id);

-- name: GetAccountConfigKeyForProject :one
SELECT k.user_id,k.key_version,k.recipient,k.encrypted_identity
FROM account_config_keys k JOIN projects p ON p.user_id=k.user_id
WHERE p.id=sqlc.arg(project_id) AND p.state<>'deleted';

-- name: RotateAccountConfigKey :exec
UPDATE account_config_keys SET
  previous_key_version=key_version,previous_recipient=recipient,previous_encrypted_identity=encrypted_identity,
  key_version=sqlc.arg(key_version),recipient=sqlc.arg(recipient),encrypted_identity=sqlc.arg(encrypted_identity),rotated_at=now()
WHERE user_id=sqlc.arg(user_id);

-- name: RetirePreviousAccountConfigKey :exec
UPDATE account_config_keys SET previous_key_version=NULL,previous_recipient=NULL,previous_encrypted_identity=NULL
WHERE user_id=sqlc.arg(user_id) AND key_version=sqlc.arg(key_version);

-- name: ListCompletedAccountConfigKeyRotations :many
SELECT k.user_id,k.key_version FROM account_config_keys k
WHERE k.previous_key_version IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM projects p
  LEFT JOIN fly_machines fm ON fm.project_id=p.id
  LEFT JOIN config_sync_statuses css ON css.project_id=p.id AND css.machine_id=fm.fly_machine_id
  WHERE p.user_id=k.user_id AND p.state<>'deleted' AND coalesce(css.encryption_key_version,0)<k.key_version
);

-- name: GetConfigClassificationOverride :one
SELECT decision FROM config_classification_overrides WHERE user_id=sqlc.arg(user_id) AND normalized_path=sqlc.arg(normalized_path);

-- name: GetConfigClassificationCache :one
SELECT decision,source,confidence,reason_code,classifier_revision,expires_at FROM config_classification_cache
WHERE user_id=sqlc.arg(user_id) AND normalized_path=sqlc.arg(normalized_path) AND metadata_hash=sqlc.arg(metadata_hash)
  AND policy_revision=sqlc.arg(policy_revision) AND model_revision=sqlc.arg(model_revision) AND classifier_revision=sqlc.arg(classifier_revision)
  AND expires_at>now();

-- name: UpsertConfigClassificationCache :exec
INSERT INTO config_classification_cache (user_id,normalized_path,metadata_hash,decision,source,confidence,reason_code,policy_revision,model_revision,classifier_revision,expires_at)
VALUES (sqlc.arg(user_id),sqlc.arg(normalized_path),sqlc.arg(metadata_hash),sqlc.arg(decision),sqlc.arg(source),sqlc.arg(confidence),sqlc.arg(reason_code),sqlc.arg(policy_revision),sqlc.arg(model_revision),sqlc.arg(classifier_revision),sqlc.arg(expires_at))
ON CONFLICT (user_id,normalized_path,metadata_hash,policy_revision,model_revision,classifier_revision)
DO UPDATE SET decision=EXCLUDED.decision,source=EXCLUDED.source,confidence=EXCLUDED.confidence,reason_code=EXCLUDED.reason_code,expires_at=EXCLUDED.expires_at,created_at=now();

-- name: GetConfigSyncProjectOwner :one
SELECT user_id FROM projects WHERE id=sqlc.arg(project_id) AND state<>'deleted';
