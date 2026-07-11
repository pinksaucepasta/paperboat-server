-- name: FindProjectByIdempotencyKey :one
SELECT id,create_request_hash FROM projects WHERE user_id=$1 AND idempotency_key=$2;

-- name: GetActiveMachineTypeVersion :one
SELECT current_version_id FROM machine_types WHERE code=$1 AND active AND current_version_id IS NOT NULL;

-- name: GetEnabledRegionID :one
SELECT id FROM regions WHERE code=$1 AND enabled;

-- name: GetActiveIdleTimeoutID :one
SELECT id FROM idle_timeout_options WHERE code=$1 AND active;

-- name: GetActivePresetVersion :one
SELECT current_version_id FROM vm_presets WHERE code=$1 AND active AND current_version_id IS NOT NULL;

-- name: InsertProject :exec
INSERT INTO projects (id,user_id,name,state,idempotency_key,create_request_hash) VALUES ($1,$2,$3,'creating',$4,$5);

-- name: InsertProjectRepository :exec
INSERT INTO project_repositories (project_id,provider,source_url,default_branch) VALUES ($1,'github',$2,$3);

-- name: InsertProjectStorageAllocation :exec
INSERT INTO project_storage_allocations (project_id,storage_account_id,assigned_gb) VALUES ($1,$2,$3);

-- name: InsertProjectRuntimeConfig :exec
INSERT INTO project_runtime_configs (project_id,machine_type_version_id,preset_version_ids,setup_script_ref,idle_timeout_option_id,region_id,pending_restart_apply,desired_config_hash)
VALUES (sqlc.arg(project_id),sqlc.arg(machine_type_version_id),sqlc.arg(preset_version_ids),sqlc.arg(setup_script_ref),sqlc.arg(idle_timeout_option_id),sqlc.arg(region_id),true,sqlc.arg(desired_config_hash));

-- name: InsertProjectSetupScriptRevision :exec
INSERT INTO project_setup_script_revisions (id,project_id,revision_number,script_sha256,script_ciphertext,guidance,created_by_user_id)
VALUES ($1,$2,$3,$4,$5,$6,$7);

-- name: MarkProjectProvisioningStorage :exec
UPDATE projects SET state='provisioning_storage',version=version+1,updated_at=now() WHERE id=$1 AND user_id=$2;

-- name: InsertProjectCreateJob :exec
INSERT INTO orchestration_jobs (id,job_type,aggregate_type,aggregate_id,idempotency_key,state,payload)
VALUES ($1,'project.create','project',$2,$3,'queued',$4::jsonb) ON CONFLICT (idempotency_key) DO NOTHING;

-- name: ListProjectIDs :many
SELECT id FROM projects WHERE user_id=$1 AND state<>'deleted' ORDER BY created_at DESC;

-- name: GetProject :one
SELECT p.id,p.version,p.name,p.state,p.created_at,p.updated_at,
pr.provider,pr.source_url,pr.default_branch,psa.assigned_gb,
mt.code AS machine_type_code,r.code AS region_code,
coalesce(string_agg(DISTINCT vp.code,',' ORDER BY vp.code) FILTER (WHERE vp.code IS NOT NULL),'') AS preset_codes,
ito.code AS idle_timeout_code,prc.setup_script_ref,prc.pending_restart_apply,prc.desired_config_hash,prc.applied_config_hash,
prc.applied_storage_gb,coalesce(amt.code,'') AS applied_machine_type_code,coalesce(ar.code,'') AS applied_region_code,
coalesce(string_agg(DISTINCT avp.code,',' ORDER BY avp.code) FILTER (WHERE avp.code IS NOT NULL),'') AS applied_preset_codes,
coalesce(aito.code,'') AS applied_idle_timeout_code,prc.applied_setup_script_ref,
(SELECT count(*) FROM project_setup_script_revisions psr WHERE psr.project_id=p.id) AS setup_script_revisions
FROM projects p JOIN project_repositories pr ON pr.project_id=p.id JOIN project_storage_allocations psa ON psa.project_id=p.id
JOIN project_runtime_configs prc ON prc.project_id=p.id
LEFT JOIN machine_type_versions mtv ON mtv.id=prc.machine_type_version_id LEFT JOIN machine_types mt ON mt.id=mtv.machine_type_id
LEFT JOIN regions r ON r.id=prc.region_id LEFT JOIN idle_timeout_options ito ON ito.id=prc.idle_timeout_option_id
LEFT JOIN vm_preset_versions vpv ON vpv.id=ANY(prc.preset_version_ids) LEFT JOIN vm_presets vp ON vp.id=vpv.preset_id
LEFT JOIN machine_type_versions amtv ON amtv.id=prc.applied_machine_type_version_id LEFT JOIN machine_types amt ON amt.id=amtv.machine_type_id
LEFT JOIN regions ar ON ar.id=prc.applied_region_id LEFT JOIN idle_timeout_options aito ON aito.id=prc.applied_idle_timeout_option_id
LEFT JOIN vm_preset_versions avpv ON avpv.id=ANY(prc.applied_preset_version_ids) LEFT JOIN vm_presets avp ON avp.id=avpv.preset_id
WHERE p.id=$1 AND p.user_id=$2
GROUP BY p.id,pr.project_id,psa.project_id,prc.project_id,mt.code,r.code,ito.code,amt.code,ar.code,aito.code;

-- name: NextProjectSetupScriptRevision :one
SELECT coalesce(max(revision_number),0)::integer+1 FROM project_setup_script_revisions WHERE project_id=$1;

-- name: SetProjectSetupScriptRef :exec
UPDATE project_runtime_configs SET setup_script_ref=$2 WHERE project_id=$1;

-- name: UpdateProjectDesiredRuntimeConfig :exec
UPDATE project_runtime_configs SET machine_type_version_id=sqlc.arg(machine_type_version_id),preset_version_ids=sqlc.arg(preset_version_ids),
idle_timeout_option_id=sqlc.arg(idle_timeout_option_id),region_id=sqlc.arg(region_id),pending_restart_apply=true,
desired_config_hash=sqlc.arg(desired_config_hash),version=version+1,updated_at=now()
WHERE project_id=sqlc.arg(project_id) AND EXISTS (SELECT 1 FROM projects WHERE id=sqlc.arg(project_id) AND user_id=sqlc.arg(user_id));

-- name: UpdateProjectAssignedStorage :exec
UPDATE project_storage_allocations SET assigned_gb=sqlc.arg(assigned_gb),version=version+1,updated_at=now()
WHERE project_id=sqlc.arg(project_id) AND EXISTS (SELECT 1 FROM projects WHERE id=sqlc.arg(project_id) AND user_id=sqlc.arg(user_id));

-- name: TouchProjectVersion :exec
UPDATE projects SET version=version+1,updated_at=now() WHERE id=$1 AND user_id=$2;

-- name: GetProjectStorageAllocationForUpdate :one
SELECT psa.storage_account_id,psa.assigned_gb,psa.version AS allocation_version,p.version AS project_version,p.state
FROM project_storage_allocations psa JOIN projects p ON p.id=psa.project_id
WHERE p.id=$1 AND p.user_id=$2 FOR UPDATE OF p,psa;

-- name: GetProjectStorageLedgerAmount :one
SELECT amount_gb FROM storage_ledger_entries
WHERE idempotency_key=sqlc.arg(idempotency_key) AND account_id=sqlc.arg(account_id) AND source_type='project' AND source_id=sqlc.arg(project_id) AND entry_type=sqlc.arg(entry_type);

-- name: InsertProjectStorageLedger :exec
INSERT INTO storage_ledger_entries (id,account_id,entry_type,amount_gb,source_type,source_id,idempotency_key)
VALUES (sqlc.arg(id),sqlc.arg(account_id),sqlc.arg(entry_type),sqlc.arg(amount_gb),'project',sqlc.arg(project_id),sqlc.arg(idempotency_key));

-- name: MarkProjectDeleting :execrows
UPDATE projects SET state='deleting',version=version+1,updated_at=now() WHERE id=$1 AND user_id=$2 AND state<>'deleted';

-- name: SupersedeQueuedProjectJobs :exec
UPDATE orchestration_jobs SET state='superseded',updated_at=now()
WHERE aggregate_type='project' AND aggregate_id=$1 AND state='queued' AND job_type<>'project.delete';

-- name: ProjectHasProviderResources :one
SELECT EXISTS (SELECT 1 FROM fly_volumes WHERE project_id=sqlc.arg(project_id)::text) OR EXISTS (SELECT 1 FROM fly_machines WHERE project_id=sqlc.arg(project_id)) OR EXISTS (SELECT 1 FROM agentunnel_resources WHERE project_id=sqlc.arg(project_id));

-- name: InsertProjectDeleteJob :exec
INSERT INTO orchestration_jobs (id,job_type,aggregate_type,aggregate_id,idempotency_key,state,payload)
VALUES ($1,'project.delete','project',$2,$3,'queued','{}'::jsonb) ON CONFLICT (idempotency_key) DO NOTHING;

-- name: GetProjectStorageForDelete :one
SELECT storage_account_id,assigned_gb FROM project_storage_allocations WHERE project_id=$1 FOR UPDATE;

-- name: GetStorageLedgerAmountByKey :one
SELECT amount_gb FROM storage_ledger_entries WHERE idempotency_key=$1;

-- name: MarkProjectDeleted :exec
UPDATE projects SET state='deleted',version=version+1,updated_at=now() WHERE id=$1;

-- name: GetProjectStateForUpdate :one
SELECT state FROM projects WHERE id=$1 AND user_id=$2 FOR UPDATE;

-- name: UpdateProjectLifecycleState :exec
UPDATE projects SET state=$3,version=version+1,updated_at=now() WHERE id=$1 AND user_id=$2;

-- name: UpsertProjectLifecycleJob :exec
INSERT INTO orchestration_jobs (id,job_type,aggregate_type,aggregate_id,idempotency_key,state,payload)
VALUES (sqlc.arg(id),sqlc.arg(job_type),'project',sqlc.arg(project_id),sqlc.arg(idempotency_key),'queued',sqlc.arg(payload)::jsonb)
ON CONFLICT (idempotency_key) DO UPDATE SET state='queued',payload=EXCLUDED.payload,next_run_at=now(),updated_at=now();

-- name: HasProjectStartCredits :one
SELECT coalesce(ca.balance,0)::numeric >= ((((sqlc.arg(window_seconds)::bigint)::numeric/3600.0)*mtv.credit_weight)::numeric(18,6))
FROM projects p JOIN project_runtime_configs prc ON prc.project_id=p.id
JOIN machine_type_versions mtv ON mtv.id=CASE WHEN sqlc.arg(use_desired_config)::boolean THEN prc.machine_type_version_id ELSE prc.applied_machine_type_version_id END
LEFT JOIN credit_accounts ca ON ca.user_id=p.user_id WHERE p.id=sqlc.arg(project_id) AND p.user_id=sqlc.arg(user_id);

-- name: UpsertProjectActivityRecord :exec
INSERT INTO project_activity_markers (project_id,last_activity_at,source,metadata)
VALUES (sqlc.arg(project_id),sqlc.arg(last_activity_at),sqlc.arg(source),sqlc.arg(metadata)::jsonb)
ON CONFLICT (project_id) DO UPDATE SET last_activity_at=greatest(project_activity_markers.last_activity_at,EXCLUDED.last_activity_at),source=EXCLUDED.source,metadata=EXCLUDED.metadata,updated_at=now();

-- name: UpsertProjectKeepAlive :exec
INSERT INTO project_activity_markers (project_id,last_activity_at,source,metadata,keep_alive_until,idle_warning_sent_at)
VALUES (sqlc.arg(project_id),now(),'connect_session','{}'::jsonb,sqlc.narg(keep_alive_until),NULL)
ON CONFLICT (project_id) DO UPDATE SET keep_alive_until=EXCLUDED.keep_alive_until,idle_warning_sent_at=NULL,updated_at=now();

-- name: ListProjectEvents :many
SELECT id,event_type,message,metadata,created_at FROM project_events WHERE project_id=$1 ORDER BY created_at ASC;

-- name: GetFreePlanStorage :one
SELECT pv.id,pv.included_storage_gb FROM plans p JOIN plan_versions pv ON pv.id=p.current_version_id WHERE p.code='free' AND p.active LIMIT 1;

-- name: GetFreePlanStorageLedgerAmount :one
SELECT amount_gb FROM storage_ledger_entries
WHERE idempotency_key=sqlc.arg(idempotency_key) AND account_id=sqlc.arg(account_id) AND source_type='plan' AND source_id=sqlc.arg(plan_version_id) AND entry_type='included_set';

-- name: InsertFreePlanStorageLedger :exec
INSERT INTO storage_ledger_entries (id,account_id,entry_type,amount_gb,source_type,source_id,idempotency_key,metadata)
VALUES (sqlc.arg(id),sqlc.arg(account_id),'included_set',sqlc.arg(amount_gb),'plan',sqlc.arg(plan_version_id),sqlc.arg(idempotency_key),'{"plan_code":"free"}'::jsonb);

-- name: InsertProjectEvent :exec
INSERT INTO project_events (id,project_id,event_type,message,metadata) VALUES (sqlc.arg(id),sqlc.arg(project_id),sqlc.arg(event_type),sqlc.arg(message),sqlc.arg(metadata)::jsonb);
