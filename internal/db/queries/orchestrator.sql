-- name: ClaimNextOrchestrationJob :one
SELECT id,job_type,aggregate_id,payload FROM orchestration_jobs
WHERE state='queued' AND next_run_at<=now()
AND NOT EXISTS (SELECT 1 FROM projects WHERE projects.id=orchestration_jobs.aggregate_id AND projects.state IN ('deleted','deleting') AND orchestration_jobs.job_type<>'project.delete')
ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1;

-- name: CompleteOrchestrationJob :exec
UPDATE orchestration_jobs SET state='succeeded',last_error='',version=version+1,updated_at=now() WHERE id=$1;

-- name: RetryOrchestrationJob :exec
UPDATE orchestration_jobs SET state='queued',attempts=attempts+1,next_run_at=now()+interval '30 seconds',last_error=$2,version=version+1,updated_at=now() WHERE id=$1;

-- name: BlockOrchestrationJob :exec
UPDATE orchestration_jobs SET state='blocked',attempts=attempts+1,last_error=$2,version=version+1,updated_at=now() WHERE id=$1;

-- name: RestoreRestartingProjectState :exec
UPDATE projects SET state=$2,version=version+1,updated_at=now() WHERE id=$1 AND state='restarting';

-- name: GetOrchestrationProjectIntent :one
SELECT p.id,p.user_id,pr.source_url,pr.default_branch,psa.assigned_gb,mt.code AS machine_type_code,mtv.vcpu,mtv.memory_mb,rg.code AS region_code,
coalesce(json_agg(vp.code ORDER BY vp.code) FILTER (WHERE vp.code IS NOT NULL),'[]'::json) AS preset_codes,
ito.code AS idle_timeout_code,prc.setup_script_ref,prc.desired_config_hash,prc.pending_restart_apply
FROM projects p JOIN project_repositories pr ON pr.project_id=p.id JOIN project_storage_allocations psa ON psa.project_id=p.id
JOIN project_runtime_configs prc ON prc.project_id=p.id JOIN machine_type_versions mtv ON mtv.id=prc.machine_type_version_id
JOIN machine_types mt ON mt.id=mtv.machine_type_id JOIN regions rg ON rg.id=prc.region_id JOIN idle_timeout_options ito ON ito.id=prc.idle_timeout_option_id
LEFT JOIN vm_preset_versions vpv ON vpv.id=ANY(prc.preset_version_ids) LEFT JOIN vm_presets vp ON vp.id=vpv.preset_id
WHERE p.id=$1 GROUP BY p.id,pr.project_id,psa.project_id,prc.project_id,mt.code,mtv.vcpu,mtv.memory_mb,rg.code,ito.code;

-- name: GetLatestGitHubTokenCiphertext :one
SELECT token_ciphertext FROM github_oauth_tokens WHERE user_id=$1 AND revoked_at IS NULL ORDER BY updated_at DESC LIMIT 1;

-- name: GetGitHubConfigRepository :one
SELECT clone_url,default_branch FROM github_config_repositories WHERE user_id=$1 AND provisioned_at IS NOT NULL LIMIT 1;

-- name: GetProjectSetupScriptCiphertext :one
SELECT script_ciphertext FROM project_setup_script_revisions WHERE project_id=$1 AND id=$2;

-- name: GetOrchestrationAgentunnelResource :one
SELECT tunnel_id,client_id,(metadata->>'machine_token_ciphertext')::text AS machine_token_ciphertext FROM agentunnel_resources WHERE project_id=$1;

-- name: GetProjectMachine :one
SELECT fly_machine_id,state FROM fly_machines WHERE project_id=$1;

-- name: GetProjectVolume :one
SELECT fly_volume_id,size_gb,state FROM fly_volumes WHERE project_id=$1;

-- name: InsertFlyVolumeRecord :exec
INSERT INTO fly_volumes (id,project_id,fly_volume_id,size_gb,region,state) VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (project_id) DO UPDATE SET fly_volume_id=fly_volumes.fly_volume_id;

-- name: SetProjectFlyVolumeID :exec
UPDATE project_storage_allocations SET fly_volume_id=$2,updated_at=now() WHERE project_id=$1;

-- name: UpsertFlyMachineRecord :exec
INSERT INTO fly_machines (id,project_id,fly_machine_id,state,image_ref,region,observed_config_hash)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (project_id) DO UPDATE SET fly_machine_id=EXCLUDED.fly_machine_id,state=EXCLUDED.state,image_ref=EXCLUDED.image_ref,
region=EXCLUDED.region,observed_config_hash=EXCLUDED.observed_config_hash,updated_at=now();

-- name: MarkProvisionedProjectStopped :exec
UPDATE projects SET state='stopped',version=version+1,updated_at=now() WHERE id=$1 AND state<>'deleted';

-- name: ApplyProjectRuntimeConfig :exec
UPDATE project_runtime_configs SET applied_storage_gb=$2,applied_machine_type_version_id=machine_type_version_id,
applied_preset_version_ids=preset_version_ids,applied_setup_script_ref=setup_script_ref,applied_idle_timeout_option_id=idle_timeout_option_id,
applied_region_id=region_id,applied_config_hash=desired_config_hash,pending_restart_apply=false,version=version+1,updated_at=now() WHERE project_id=$1;

-- name: UpdateOrchestratedMachineState :exec
UPDATE fly_machines SET state=$2,version=version+1,updated_at=now() WHERE project_id=$1;

-- name: UpdateOrchestratedProjectState :exec
UPDATE projects SET state=$2,version=version+1,updated_at=now() WHERE id=$1 AND state<>'deleted';

-- name: DeleteProjectMachineRecord :exec
DELETE FROM fly_machines WHERE project_id=$1;

-- name: DeleteProjectVolumeRecord :exec
DELETE FROM fly_volumes WHERE project_id=$1;

-- name: StartReconciliationRun :exec
INSERT INTO reconciliation_runs (id,scope,state) VALUES ($1,$2,$3);

-- name: FinishReconciliationRun :exec
UPDATE reconciliation_runs SET state=$2,findings=$3::jsonb,finished_at=now() WHERE id=$1;

-- name: ListRecordedFlyMachines :many
SELECT project_id,fly_machine_id,state FROM fly_machines;

-- name: UpsertOrphanRemediationJob :exec
INSERT INTO orchestration_jobs (id,job_type,aggregate_type,aggregate_id,idempotency_key,state,payload,last_error)
VALUES (sqlc.arg(id),'fly.orphan.remediate','fly_machine',sqlc.arg(fly_machine_id),sqlc.arg(idempotency_key),'needs_review',sqlc.arg(payload)::jsonb,'Operator approval required before deleting or adopting orphan Fly machine.')
ON CONFLICT (idempotency_key) DO UPDATE SET payload=EXCLUDED.payload,updated_at=now();

-- name: InsertOrchestrationProjectEvent :exec
INSERT INTO project_events (id,project_id,event_type,message,metadata) VALUES (sqlc.arg(id),sqlc.arg(project_id),sqlc.arg(event_type),sqlc.arg(message),sqlc.arg(metadata)::jsonb);
