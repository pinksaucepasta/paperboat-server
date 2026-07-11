-- name: ListMeterableMachines :many
SELECT p.id AS project_id,p.user_id,fm.fly_machine_id,prc.applied_machine_type_version_id,mtv.credit_weight::text AS credit_weight,ito.duration_seconds
FROM projects p JOIN fly_machines fm ON fm.project_id=p.id JOIN project_runtime_configs prc ON prc.project_id=p.id
JOIN machine_type_versions mtv ON mtv.id=prc.applied_machine_type_version_id JOIN idle_timeout_options ito ON ito.id=prc.applied_idle_timeout_option_id
WHERE p.state IN ('ready','running','starting','stopping','restarting','suspended') AND prc.applied_machine_type_version_id IS NOT NULL;

-- name: GetOpenRuntimeInterval :one
SELECT id,project_id,user_id,fly_machine_id,credit_weight::text AS credit_weight,last_metered_at,observed_state,confidence,observation_source
FROM machine_runtime_intervals WHERE project_id=$1 AND stopped_at IS NULL;

-- name: ListPendingMeteringCheckpoints :many
SELECT id,runtime_interval_id,project_id,user_id,period_start,period_end,runtime_seconds,credit_weight::text AS credit_weight,credits_debited::text AS credits_debited,idempotency_key
FROM metering_checkpoints WHERE state IN ('created','failed') ORDER BY period_end ASC,created_at ASC LIMIT 100;

-- name: GetOpenRuntimeIntervalForUpdate :one
SELECT id,project_id,user_id,fly_machine_id,credit_weight::text AS credit_weight,last_metered_at,observed_state,confidence,observation_source
FROM machine_runtime_intervals WHERE project_id=$1 AND stopped_at IS NULL FOR UPDATE;

-- name: MarkRuntimeIntervalRunning :exec
UPDATE machine_runtime_intervals SET observed_state='running',observation_source='fly_poll',confidence='high',updated_at=now() WHERE id=$1;

-- name: InsertRuntimeInterval :exec
INSERT INTO machine_runtime_intervals (id,project_id,user_id,fly_machine_id,machine_type_version_id,credit_weight,started_at,last_metered_at,observed_state,observation_source,confidence)
VALUES (sqlc.arg(id),sqlc.arg(project_id),sqlc.arg(user_id),sqlc.arg(fly_machine_id),sqlc.arg(machine_type_version_id),sqlc.arg(credit_weight)::numeric,sqlc.arg(started_at),sqlc.arg(started_at),'running','fly_poll','high');

-- name: GetRuntimeIntervalForCheckpoint :one
SELECT id,project_id,user_id,fly_machine_id,credit_weight::text AS credit_weight,last_metered_at
FROM machine_runtime_intervals WHERE id=$1 AND stopped_at IS NULL FOR UPDATE;

-- name: GetRuntimeIntervalForFinalCheckpoint :one
SELECT id,project_id,user_id,fly_machine_id,credit_weight::text AS credit_weight,last_metered_at
FROM machine_runtime_intervals WHERE id=$1 FOR UPDATE;

-- name: CalculateRuntimeCredits :one
SELECT ((sqlc.arg(runtime_seconds)::bigint::numeric / 3600.0) * sqlc.arg(credit_weight)::numeric)::numeric(18,6)::text;

-- name: InsertMeteringCheckpoint :exec
INSERT INTO metering_checkpoints (id,runtime_interval_id,project_id,user_id,period_start,period_end,runtime_seconds,credit_weight,credits_debited,idempotency_key,state)
VALUES (sqlc.arg(id),sqlc.arg(runtime_interval_id),sqlc.arg(project_id),sqlc.arg(user_id),sqlc.arg(period_start),sqlc.arg(period_end),sqlc.arg(runtime_seconds),sqlc.arg(credit_weight)::numeric,sqlc.arg(credits_debited)::numeric,sqlc.arg(idempotency_key),'created')
ON CONFLICT (idempotency_key) DO NOTHING;

-- name: GetLatestCheckpointEnd :one
SELECT period_end FROM metering_checkpoints WHERE runtime_interval_id=$1 ORDER BY period_end DESC LIMIT 1;

-- name: GetPendingCheckpointForUpdate :one
SELECT id,runtime_interval_id,project_id,user_id,period_start,period_end,runtime_seconds,credit_weight::text AS credit_weight,credits_debited::text AS credits_debited,idempotency_key
FROM metering_checkpoints WHERE runtime_interval_id=$1 AND state IN ('created','failed') ORDER BY period_end ASC,created_at ASC LIMIT 1 FOR UPDATE;

-- name: MarkMeteringCheckpointProcessed :exec
UPDATE metering_checkpoints SET state='processed',processed_at=now() WHERE id=$1;

-- name: AdvanceRuntimeIntervalMetering :exec
UPDATE machine_runtime_intervals SET last_metered_at=$2,updated_at=now() WHERE id=$1 AND last_metered_at=$3;

-- name: MarkMeteringCheckpointFailed :exec
UPDATE metering_checkpoints SET state='failed',last_error=$2 WHERE id=$1;

-- name: CloseRuntimeInterval :exec
UPDATE machine_runtime_intervals SET stopped_at=$2,observed_state=$3,observation_source=$4,confidence=$5,updated_at=now()
WHERE project_id=$1 AND stopped_at IS NULL;

-- name: UpdateObservedFlyMachineState :exec
UPDATE fly_machines SET state=$2,version=version+1,updated_at=now() WHERE project_id=$1;

-- name: UpdateObservedProjectState :exec
UPDATE projects SET state=$2,version=version+1,updated_at=now()
WHERE id=$1 AND state NOT IN ('deleted','deleting','provisioning_storage','provisioning_machine','stopping','restarting','suspended');

-- name: ListIdleProjectsForUpdate :many
SELECT p.id AS project_id,coalesce(pam.last_activity_at,mri.started_at) AS last_activity_at,ito.duration_seconds,pam.keep_alive_until
FROM projects p JOIN machine_runtime_intervals mri ON mri.project_id=p.id AND mri.stopped_at IS NULL
JOIN project_runtime_configs prc ON prc.project_id=p.id JOIN idle_timeout_options ito ON ito.id=prc.applied_idle_timeout_option_id
LEFT JOIN project_activity_markers pam ON pam.project_id=p.id
WHERE p.state='running' AND (pam.keep_alive_until IS NULL OR pam.keep_alive_until<=sqlc.arg(now)) FOR UPDATE OF p SKIP LOCKED;

-- name: ListEntitlementLostProjectsForUpdate :many
SELECT p.id AS project_id,p.user_id FROM projects p WHERE p.state='running'
AND EXISTS (SELECT 1 FROM machine_runtime_intervals mri WHERE mri.project_id=p.id AND mri.stopped_at IS NULL)
AND NOT EXISTS (SELECT 1 FROM subscriptions s WHERE s.user_id=p.user_id AND s.state IN ('active','trialing') AND (s.current_period_end IS NULL OR s.current_period_end>sqlc.arg(now)))
FOR UPDATE OF p SKIP LOCKED;

-- name: ListReporterLostProjectsForUpdate :many
SELECT p.id AS project_id,pam.last_heartbeat_at,pam.reporter_lost_since FROM projects p
JOIN machine_runtime_intervals mri ON mri.project_id=p.id AND mri.stopped_at IS NULL LEFT JOIN project_activity_markers pam ON pam.project_id=p.id
WHERE p.state='running' AND pam.last_heartbeat_at IS NOT NULL AND pam.last_heartbeat_at<=sqlc.arg(cutoff) FOR UPDATE OF p SKIP LOCKED;

-- name: SetReporterLostSince :exec
UPDATE project_activity_markers SET reporter_lost_since=$2,updated_at=now() WHERE project_id=$1;

-- name: ClearRecoveredReporterLoss :exec
UPDATE project_activity_markers SET reporter_lost_since=NULL,updated_at=now()
WHERE reporter_lost_since IS NOT NULL AND last_heartbeat_at>sqlc.arg(cutoff);

-- name: UpsertMeteringActivity :exec
INSERT INTO project_activity_markers (project_id,last_activity_at,source,metadata)
VALUES (sqlc.arg(project_id),sqlc.arg(last_activity_at),sqlc.arg(source),coalesce(sqlc.arg(metadata)::jsonb,'{}'::jsonb))
ON CONFLICT (project_id) DO UPDATE SET last_activity_at=greatest(project_activity_markers.last_activity_at,EXCLUDED.last_activity_at),source=EXCLUDED.source,metadata=EXCLUDED.metadata,updated_at=now();

-- name: UpsertActivityHeartbeat :exec
INSERT INTO project_activity_markers (project_id,machine_id,last_activity_at,source,metadata,last_heartbeat_at,reporter_version,signals)
VALUES (sqlc.arg(project_id),sqlc.arg(machine_id),sqlc.arg(last_activity_at),'vm_heartbeat','{}'::jsonb,sqlc.arg(last_heartbeat_at),sqlc.arg(reporter_version),sqlc.arg(signals)::jsonb)
ON CONFLICT (project_id) DO UPDATE SET machine_id=EXCLUDED.machine_id,last_activity_at=greatest(project_activity_markers.last_activity_at,EXCLUDED.last_activity_at),
source=EXCLUDED.source,last_heartbeat_at=greatest(coalesce(project_activity_markers.last_heartbeat_at,'-infinity'::timestamptz),EXCLUDED.last_heartbeat_at),
reporter_version=EXCLUDED.reporter_version,signals=EXCLUDED.signals,reporter_lost_since=NULL,
idle_warning_sent_at=CASE WHEN EXCLUDED.last_activity_at>project_activity_markers.last_activity_at THEN NULL ELSE project_activity_markers.idle_warning_sent_at END,updated_at=now();

-- name: GetHeartbeatMachineTokenCiphertext :one
SELECT (ar.metadata->>'machine_token_ciphertext')::text AS machine_token_ciphertext FROM fly_machines fm JOIN agentunnel_resources ar ON ar.project_id=fm.project_id
WHERE fm.project_id=$1 AND fm.fly_machine_id=$2;

-- name: EmitIdleWarning :execrows
INSERT INTO project_activity_markers (project_id,last_activity_at,source,metadata,idle_warning_sent_at)
VALUES ($1,$2,'server','{}'::jsonb,now()) ON CONFLICT (project_id) DO UPDATE SET idle_warning_sent_at=now(),updated_at=now()
WHERE project_activity_markers.idle_warning_sent_at IS NULL;

-- name: MarkProjectStoppingForEnforcement :exec
UPDATE projects SET state='stopping',version=version+1,updated_at=now() WHERE id=$1 AND state NOT IN ('deleted','deleting','stopping','stopped');

-- name: RevokeProjectSessionsForEnforcement :exec
UPDATE access_sessions SET state='revoked',revoked_at=now(),updated_at=now(),version=version+1,
descriptor=jsonb_set(descriptor,'{revocation_reason}',to_jsonb(sqlc.arg(reason)::text),true)
WHERE project_id=sqlc.arg(project_id) AND state='active' AND revoked_at IS NULL;

-- name: InsertEnforcementStopJob :one
INSERT INTO orchestration_jobs (id,job_type,aggregate_type,aggregate_id,idempotency_key,state,payload)
VALUES (sqlc.arg(id),'project.stop','project',sqlc.arg(project_id),sqlc.arg(idempotency_key),'queued',sqlc.arg(payload)::jsonb)
ON CONFLICT (idempotency_key) DO NOTHING RETURNING id;

-- name: RequeueEnforcementStopJob :exec
UPDATE orchestration_jobs SET state='queued',next_run_at=now(),payload=sqlc.arg(payload)::jsonb,updated_at=now() WHERE idempotency_key=sqlc.arg(idempotency_key);

-- name: InsertMeteringProjectEvent :exec
INSERT INTO project_events (id,project_id,event_type,message,metadata) VALUES (sqlc.arg(id),sqlc.arg(project_id),sqlc.arg(event_type),sqlc.arg(message),sqlc.arg(metadata)::jsonb);
