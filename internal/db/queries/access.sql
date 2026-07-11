-- name: HasConnectCredits :one
SELECT coalesce(ca.balance, 0)::numeric >= ((((sqlc.arg(window_seconds)::bigint)::numeric / 3600.0) * mtv.credit_weight)::numeric(18,6))
FROM projects p JOIN project_runtime_configs prc ON prc.project_id = p.id
JOIN machine_type_versions mtv ON mtv.id = prc.applied_machine_type_version_id
LEFT JOIN credit_accounts ca ON ca.user_id = p.user_id
WHERE p.id = sqlc.arg(project_id) AND p.user_id = sqlc.arg(user_id);

-- name: GitHubConfigReady :one
SELECT EXISTS (SELECT 1 FROM github_oauth_tokens t JOIN github_config_repositories cr ON cr.user_id = t.user_id
WHERE t.user_id = $1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > now()) AND cr.provisioned_at IS NOT NULL);

-- name: UpsertAgentunnelResource :exec
INSERT INTO agentunnel_resources (id, project_id, tunnel_id, client_id, resource_id, metadata)
VALUES (sqlc.arg(id), sqlc.arg(project_id), sqlc.arg(tunnel_id), sqlc.arg(client_id), sqlc.arg(resource_id), sqlc.arg(metadata)::jsonb)
ON CONFLICT (project_id) DO UPDATE SET tunnel_id=EXCLUDED.tunnel_id,client_id=EXCLUDED.client_id,resource_id=EXCLUDED.resource_id,
metadata=EXCLUDED.metadata,version=agentunnel_resources.version+1,updated_at=now();

-- name: UpsertPreviewURLRecord :exec
INSERT INTO preview_url_records (id, project_id, preview_key, target_url, public_url, state)
VALUES ($1, $2, 'papercode', $3, $4, 'active')
ON CONFLICT (project_id, preview_key) DO UPDATE SET target_url=EXCLUDED.target_url,public_url=EXCLUDED.public_url,state='active',version=preview_url_records.version+1,updated_at=now();

-- name: GetAgentunnelResource :one
SELECT tunnel_id,client_id,resource_id,metadata FROM agentunnel_resources WHERE project_id=$1;

-- name: GetLatestProjectStopEventType :one
SELECT event_type FROM project_events WHERE project_id=$1 AND event_type LIKE 'project.stop_queued.%' ORDER BY created_at DESC LIMIT 1;

-- name: CreateAccessSession :exec
INSERT INTO access_sessions (id,user_id,project_id,client_session_id,session_type,state,descriptor,expires_at,idempotency_key)
VALUES (sqlc.arg(id),sqlc.arg(user_id),sqlc.arg(project_id),nullif(sqlc.arg(client_session_id),''),sqlc.arg(session_type),'active',sqlc.arg(descriptor)::jsonb,sqlc.arg(expires_at),sqlc.arg(idempotency_key));

-- name: RevokeClientAccessSessions :exec
UPDATE access_sessions SET state='revoked',revoked_at=coalesce(revoked_at,now()),updated_at=now(),version=version+1,
descriptor=jsonb_set(descriptor,'{revocation_reason}',to_jsonb(sqlc.arg(reason)::text),true)
WHERE client_session_id=sqlc.arg(client_session_id) AND state='active' AND revoked_at IS NULL;

-- name: RevokeUserAccessSessions :exec
UPDATE access_sessions SET state='revoked',revoked_at=now(),updated_at=now(),version=version+1,
descriptor=jsonb_set(descriptor,'{revocation_reason}',to_jsonb(sqlc.arg(reason)::text),true)
WHERE state='active' AND revoked_at IS NULL AND user_id=sqlc.arg(user_id);

-- name: RevokeProjectAccessSessions :exec
UPDATE access_sessions SET state='revoked',revoked_at=now(),updated_at=now(),version=version+1,
descriptor=jsonb_set(descriptor,'{revocation_reason}',to_jsonb(sqlc.arg(reason)::text),true)
WHERE state='active' AND revoked_at IS NULL AND project_id=sqlc.arg(project_id);

-- name: RecordConnectionEvent :exec
INSERT INTO connection_events (id,user_id,project_id,access_session_id,result,failure_reason,metadata)
VALUES (sqlc.arg(id),nullif(sqlc.arg(user_id),''),nullif(sqlc.arg(project_id),''),nullif(sqlc.arg(access_session_id),''),sqlc.arg(result),sqlc.arg(failure_reason),sqlc.arg(metadata)::jsonb);

-- name: UpsertProjectActivity :exec
INSERT INTO project_activity_markers (project_id,last_activity_at,source,metadata)
VALUES (sqlc.arg(project_id),now(),sqlc.arg(source),sqlc.arg(metadata)::jsonb)
ON CONFLICT (project_id) DO UPDATE SET last_activity_at=greatest(project_activity_markers.last_activity_at,EXCLUDED.last_activity_at),
source=EXCLUDED.source,metadata=EXCLUDED.metadata,updated_at=now();
