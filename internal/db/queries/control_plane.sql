-- name: CreateControlEnvironment :one
INSERT INTO control_environments (id, workspace_id, owner_user_id, desired_state)
VALUES (sqlc.arg(id), sqlc.arg(workspace_id), sqlc.arg(owner_user_id), sqlc.arg(desired_state))
RETURNING *;

-- name: CreateControlHelper :one
INSERT INTO control_helpers (id, environment_id)
VALUES (sqlc.arg(id), sqlc.arg(environment_id))
RETURNING *;

-- name: CreateControlConfigRepository :one
INSERT INTO control_config_repositories (id, owner_user_id, provider, external_ref, display_name)
VALUES (sqlc.arg(id), sqlc.arg(owner_user_id), sqlc.arg(provider), sqlc.arg(external_ref), sqlc.arg(display_name))
ON CONFLICT (owner_user_id, provider, external_ref) DO UPDATE SET display_name = EXCLUDED.display_name, updated_at = now()
RETURNING *;

-- name: ListControlConfigRepositories :many
SELECT * FROM control_config_repositories
WHERE owner_user_id = sqlc.arg(owner_user_id) AND state = 'active'
ORDER BY display_name, id LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: GetOwnedControlConfigRepository :one
SELECT * FROM control_config_repositories
WHERE id = sqlc.arg(id) AND owner_user_id = sqlc.arg(owner_user_id) AND state = 'active';

-- name: IsControlEnvironmentBYOD :one
SELECT EXISTS (SELECT 1 FROM connected_machines WHERE environment_id = sqlc.arg(environment_id) AND deleted_at IS NULL);

-- name: GetControlConfigAssignment :one
SELECT * FROM control_config_assignments WHERE environment_id = $1;

-- name: SetControlConfigAssignment :one
INSERT INTO control_config_assignments (id, environment_id, repository_id, consent_state, warning_revision)
VALUES (sqlc.arg(assignment_id), sqlc.arg(environment_id), sqlc.arg(repository_id), sqlc.arg(consent_state), sqlc.narg(warning_revision))
ON CONFLICT (environment_id) DO UPDATE
SET id = EXCLUDED.id, repository_id = EXCLUDED.repository_id, consent_state = EXCLUDED.consent_state,
    warning_revision = EXCLUDED.warning_revision, accepted_at = NULL, revoked_at = NULL,
    version = control_config_assignments.version + 1, updated_at = sqlc.arg(now)
WHERE control_config_assignments.version = sqlc.arg(expected_version)
RETURNING *;

-- name: GetEligibleControlConfigAssignment :one
SELECT a.* FROM control_config_assignments a
JOIN control_helpers h ON h.environment_id = a.environment_id
WHERE a.environment_id = sqlc.arg(environment_id) AND h.id = sqlc.arg(helper_id)
  AND h.state = 'active' AND h.revoked_at IS NULL AND a.repository_id IS NOT NULL
  AND a.revoked_at IS NULL AND a.consent_state IN ('not_required','accepted')
FOR UPDATE OF a, h;

-- name: CreateControlConfigCredential :one
INSERT INTO control_config_credentials
  (jti_hash, jti, operation_key, request_hash, environment_id, helper_id, assignment_id,
   warning_revision, credential_ciphertext, expires_at)
VALUES
  (sqlc.arg(jti_hash), sqlc.arg(jti), sqlc.arg(operation_key), sqlc.arg(request_hash), sqlc.arg(environment_id),
   sqlc.arg(helper_id), sqlc.arg(assignment_id), sqlc.narg(warning_revision),
   sqlc.arg(credential_ciphertext), sqlc.arg(expires_at))
ON CONFLICT (operation_key) DO NOTHING
RETURNING *;

-- name: ListRevokedControlCredentialJTIs :many
SELECT jti FROM control_config_credentials
WHERE revoked_at IS NOT NULL AND expires_at > sqlc.arg(now)
ORDER BY revoked_at, jti
LIMIT sqlc.arg(row_limit);

-- name: ListRevokedConnectorGenerations :many
SELECT id AS helper_id, generation FROM control_helpers
WHERE state IN ('revoked','replaced')
ORDER BY updated_at, id
LIMIT sqlc.arg(row_limit);

-- name: ListRevokedControlEnvironments :many
SELECT id FROM control_environments
WHERE desired_state = 'revoked'
ORDER BY updated_at, id
LIMIT sqlc.arg(row_limit);

-- name: RevokeControlSigningKey :one
INSERT INTO control_signing_key_revocations (key_id, reason, revoked_at, actor_user_id)
VALUES (sqlc.arg(key_id), sqlc.arg(reason), sqlc.arg(revoked_at), sqlc.arg(actor_user_id))
ON CONFLICT (key_id) DO UPDATE SET reason = EXCLUDED.reason, revoked_at = least(control_signing_key_revocations.revoked_at, EXCLUDED.revoked_at), actor_user_id = EXCLUDED.actor_user_id
RETURNING *;

-- name: ReserveControlSigningKeyRevocation :one
INSERT INTO control_signing_key_revocation_operations (operation_key, key_id, reason)
VALUES (sqlc.arg(operation_key), sqlc.arg(key_id), sqlc.arg(reason))
ON CONFLICT (operation_key) DO NOTHING
RETURNING *;

-- name: GetControlSigningKeyRevocationOperation :one
SELECT * FROM control_signing_key_revocation_operations WHERE operation_key = $1;

-- name: ListRevokedControlSigningKeyIDs :many
SELECT key_id FROM control_signing_key_revocations
ORDER BY revoked_at, key_id
LIMIT sqlc.arg(row_limit);

-- name: GetControlConfigCredentialByOperation :one
SELECT * FROM control_config_credentials WHERE operation_key = $1;

-- name: RevokeControlConfigCredentialsForEnvironment :execrows
UPDATE control_config_credentials SET revoked_at = coalesce(revoked_at, sqlc.arg(revoked_at))
WHERE environment_id = sqlc.arg(environment_id) AND revoked_at IS NULL;

-- name: AcceptControlConfigConsent :one
UPDATE control_config_assignments
SET consent_state = 'accepted', warning_revision = sqlc.arg(warning_revision), accepted_at = sqlc.arg(now),
    revoked_at = NULL, version = version + 1, updated_at = sqlc.arg(now)
WHERE environment_id = sqlc.arg(environment_id) AND version = sqlc.arg(expected_version)
  AND repository_id IS NOT NULL AND consent_state = 'pending'
  AND warning_revision = sqlc.arg(warning_revision)
RETURNING *;

-- name: ClearControlConfigAssignment :one
UPDATE control_config_assignments
SET repository_id = NULL, consent_state = 'revoked', warning_revision = NULL, accepted_at = NULL,
    revoked_at = sqlc.arg(now), version = version + 1, updated_at = sqlc.arg(now)
WHERE environment_id = sqlc.arg(environment_id) AND version = sqlc.arg(expected_version)
RETURNING *;

-- name: CreateControlHelperEnrollment :one
INSERT INTO control_helper_enrollments (id, environment_id, helper_id, jti_hash, operation_key, request_hash, grant_ciphertext, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(environment_id), sqlc.arg(helper_id), sqlc.arg(jti_hash), sqlc.arg(operation_key), sqlc.arg(request_hash), sqlc.arg(grant_ciphertext), sqlc.arg(expires_at))
ON CONFLICT (operation_key) DO NOTHING
RETURNING *;

-- name: GetControlHelperEnrollmentByOperationKey :one
SELECT * FROM control_helper_enrollments WHERE operation_key = $1;

-- name: GetPendingControlHelperEnrollmentForEnvironment :one
SELECT * FROM control_helper_enrollments
WHERE environment_id = sqlc.arg(environment_id) AND state = 'pending' AND revoked_at IS NULL
ORDER BY created_at DESC LIMIT 1;

-- name: GetActiveControlHelperForEnvironment :one
SELECT * FROM control_helpers
WHERE environment_id = sqlc.arg(environment_id) AND state = 'active' AND revoked_at IS NULL
ORDER BY updated_at DESC LIMIT 1;

-- name: RevokeExpiredControlHelperEnrollments :execrows
UPDATE control_helper_enrollments
SET state='revoked', revoked_at=sqlc.arg(now)
WHERE environment_id=sqlc.arg(environment_id) AND state='pending' AND expires_at<=sqlc.arg(now) AND revoked_at IS NULL;

-- name: ConsumeControlHelperEnrollment :one
UPDATE control_helper_enrollments AS enrollment
SET state = 'consumed', consumed_at = sqlc.arg(now)
WHERE enrollment.id = sqlc.arg(id) AND enrollment.jti_hash = sqlc.arg(jti_hash) AND enrollment.state = 'pending'
  AND enrollment.expires_at > sqlc.arg(now) AND enrollment.revoked_at IS NULL
  AND EXISTS (SELECT 1 FROM control_environments e WHERE e.id = enrollment.environment_id AND e.desired_state = 'active' AND e.revoked_at IS NULL)
RETURNING *;

-- name: ActivateControlHelper :one
UPDATE control_helpers
SET state = 'active', key_thumbprint = sqlc.arg(key_thumbprint), public_key = sqlc.arg(public_key), last_seen_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND environment_id = sqlc.arg(environment_id) AND state = 'pending'
RETURNING *;

-- name: ReplaceControlHelper :one
UPDATE control_helpers
SET state = 'replaced', generation = generation + 1, replacement_operation_key = sqlc.arg(operation_key),
    revoked_at = sqlc.arg(revoked_at), updated_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id) AND environment_id = sqlc.arg(environment_id) AND state = 'active'
RETURNING *;

-- name: GetControlHelperForUpdate :one
SELECT * FROM control_helpers WHERE id = sqlc.arg(id) AND environment_id = sqlc.arg(environment_id) FOR UPDATE;

-- name: GetActiveControlHelper :one
SELECT * FROM control_helpers
WHERE id = sqlc.arg(id) AND environment_id = sqlc.arg(environment_id)
  AND state = 'active' AND revoked_at IS NULL;

-- name: HostedHelperOwnsMachine :one
SELECT EXISTS (
  SELECT 1 FROM control_helpers h
  JOIN fly_machines fm ON fm.project_id=h.environment_id
  WHERE h.id=sqlc.arg(helper_id) AND h.environment_id=sqlc.arg(environment_id)
    AND h.state='active' AND h.revoked_at IS NULL AND fm.fly_machine_id=sqlc.arg(machine_id)
);

-- name: SetControlHelperReplacementGeneration :one
UPDATE control_helpers SET replacement_connector_generation = sqlc.arg(connector_generation), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND replacement_operation_key = sqlc.arg(operation_key)
RETURNING *;

-- name: RevokePendingHelperEnrollments :execrows
UPDATE control_helper_enrollments
SET state = 'revoked', revoked_at = sqlc.arg(revoked_at)
WHERE helper_id = sqlc.arg(helper_id) AND state = 'pending';

-- name: AdvanceControlConnectorGeneration :one
INSERT INTO control_connector_generations (environment_id, helper_id, generation, edge_pool, state)
VALUES (sqlc.arg(environment_id), sqlc.arg(helper_id), 1, sqlc.arg(edge_pool), 'pending')
ON CONFLICT (environment_id) DO UPDATE
SET helper_id = EXCLUDED.helper_id, generation = control_connector_generations.generation + 1,
    edge_pool = EXCLUDED.edge_pool, state = 'pending', edge_node_id = NULL,
    admission_jti_hash = NULL, expires_at = NULL, revoked_at = NULL,
    version = control_connector_generations.version + 1, updated_at = sqlc.arg(updated_at)
RETURNING *;

-- name: BindControlConnectorHelper :one
INSERT INTO control_connector_generations (environment_id, helper_id, generation, edge_pool, state)
VALUES (sqlc.arg(environment_id), sqlc.arg(helper_id), 1, sqlc.arg(edge_pool), 'pending')
ON CONFLICT (environment_id) DO UPDATE
SET helper_id = EXCLUDED.helper_id, state = 'pending', updated_at = sqlc.arg(updated_at)
RETURNING *;

-- name: GetControlEnvironment :one
SELECT * FROM control_environments WHERE id = $1;

-- name: UpdateControlEnvironmentDesiredState :one
UPDATE control_environments
SET desired_state = sqlc.arg(desired_state), desired_version = desired_version + 1,
    revoked_at = CASE WHEN sqlc.arg(desired_state)::text = 'revoked' THEN coalesce(revoked_at, sqlc.arg(now)) ELSE revoked_at END,
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND desired_version = sqlc.arg(expected_version)
RETURNING *;

-- name: ApplyControlEnvironmentState :one
UPDATE control_environments
SET applied_state = sqlc.arg(applied_state), applied_version = sqlc.arg(desired_version), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND desired_version = sqlc.arg(desired_version)
  AND applied_version < sqlc.arg(desired_version)
RETURNING *;

-- name: ReserveHostedProviderOperationRecovery :one
INSERT INTO hosted_provider_operation_recoveries (operation_key, provider_operation_id, actor_user_id, action, evidence_reference)
VALUES (sqlc.arg(operation_key), sqlc.arg(provider_operation_id), sqlc.narg(actor_user_id), sqlc.arg(action), sqlc.arg(evidence_reference))
ON CONFLICT (operation_key) DO NOTHING
RETURNING *;

-- name: GetHostedProviderOperationRecovery :one
SELECT * FROM hosted_provider_operation_recoveries WHERE operation_key=$1;

-- name: RecoverUncertainHostedProviderOperation :execrows
UPDATE hosted_provider_operations
SET state=CASE WHEN sqlc.arg(action)::text='confirm_deleted' THEN 'succeeded' ELSE 'pending' END,
    outcome=CASE WHEN sqlc.arg(action)::text='confirm_deleted' THEN 'success' ELSE 'pending' END,
    last_error='',uncertain_at=NULL,observed_at=now(),updated_at=now()
WHERE id=sqlc.arg(id) AND resource_type='secret' AND state='uncertain';

-- name: SuspendControlEnvironmentForQuota :execrows
UPDATE control_environments
SET desired_state = 'suspended', desired_version = desired_version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND desired_state = 'active';

-- name: ReserveControlOperation :one
INSERT INTO control_operations (id, operation_key, operation_type, request_hash)
VALUES (sqlc.arg(id), sqlc.arg(operation_key), sqlc.arg(operation_type), sqlc.arg(request_hash))
ON CONFLICT (operation_key) DO NOTHING
RETURNING *;

-- name: GetControlOperationByKey :one
SELECT * FROM control_operations WHERE operation_key = $1;

-- name: GetControlPlaneQueueMetrics :one
SELECT
  count(*) FILTER (WHERE state IN ('pending','failed','uncertain') OR (state = 'running' AND lease_expires_at <= now()))::bigint AS operation_depth,
  CAST(coalesce(extract(epoch FROM (now() - min(created_at) FILTER (WHERE state IN ('pending','failed','uncertain') OR (state = 'running' AND lease_expires_at <= now())))), 0) AS bigint) AS operation_oldest_age_seconds,
  count(*) FILTER (WHERE state = 'dead_letter')::bigint AS operation_dead_letter_depth,
  (SELECT count(*) FROM control_reconciliation_attempts WHERE state IN ('started','uncertain'))::bigint AS reconciliation_depth,
  CAST(coalesce((SELECT extract(epoch FROM (now() - min(started_at))) FROM control_reconciliation_attempts WHERE state IN ('started','uncertain')), 0) AS bigint) AS reconciliation_oldest_age_seconds,
  (SELECT count(*) FROM control_tunnel_nodes WHERE state IN ('registered','ready') AND (last_heartbeat_at IS NULL OR last_heartbeat_at <= now() - interval '2 minutes'))::bigint AS stale_node_depth
  ,(SELECT count(*) FROM orchestration_jobs WHERE state IN ('queued','running'))::bigint AS orchestration_queue_depth
  ,(SELECT count(*) FROM orchestration_jobs WHERE state='running' AND lease_expires_at <= now())::bigint AS orchestration_expired_lease_depth
  ,CAST(coalesce((SELECT extract(epoch FROM (now() - min(created_at))) FROM orchestration_jobs WHERE state IN ('queued','running')), 0) AS bigint) AS orchestration_oldest_age_seconds
  ,(SELECT count(*) FROM hosted_provider_operations WHERE state='uncertain')::bigint AS hosted_provider_uncertain_depth
  ,(SELECT count(*) FROM hosted_provider_operations WHERE state='pending' OR (state='running' AND updated_at < now() - interval '2 minutes'))::bigint AS hosted_provider_retryable_depth
  ,CAST(coalesce((SELECT extract(epoch FROM (now() - min(created_at))) FROM hosted_provider_operations WHERE resource_type IN ('machine','volume','secret') AND state IN ('pending','running','uncertain')), 0) AS bigint) AS hosted_provider_oldest_age_seconds
  ,(SELECT count(*) FROM hosted_readiness_observations WHERE state='failed' AND observed_at >= now() - interval '24 hours')::bigint AS hosted_readiness_failure_depth
  ,CAST(coalesce((SELECT extract(epoch FROM (now() - max(observed_at))) FROM hosted_readiness_observations WHERE state='failed' AND observed_at >= now() - interval '24 hours'), 0) AS bigint) AS hosted_readiness_recent_failure_age_seconds
  ,(SELECT count(*) FROM orchestration_jobs WHERE job_type='fly.orphan.remediate' AND state='needs_review')::bigint AS hosted_orphan_review_depth
FROM control_operations;

-- name: LeaseControlOperations :many
UPDATE control_operations
SET state = 'running', attempts = attempts + 1, next_attempt_at = NULL,
    lease_expires_at = sqlc.arg(lease_expires_at), updated_at = sqlc.arg(now)
WHERE id IN (
  SELECT id FROM control_operations
  WHERE (state IN ('pending','failed','uncertain') AND (next_attempt_at IS NULL OR next_attempt_at <= sqlc.arg(now)))
     OR (state = 'running' AND lease_expires_at <= sqlc.arg(now))
  ORDER BY coalesce(next_attempt_at, created_at), created_at
  FOR UPDATE SKIP LOCKED
  LIMIT sqlc.arg(batch_size)
)
RETURNING *;

-- name: CompleteControlOperation :execrows
UPDATE control_operations
SET state = 'succeeded', result = coalesce(sqlc.arg(result)::jsonb, '{}'::jsonb), completed_at = sqlc.arg(now),
    last_error = NULL, lease_expires_at = NULL, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'running' AND lease_expires_at = sqlc.arg(lease_expires_at);

-- name: MarkControlOperationUncertain :execrows
UPDATE control_operations
SET state = 'uncertain', last_error = sqlc.arg(last_error), uncertain_at = coalesce(uncertain_at, sqlc.arg(now)),
    next_attempt_at = sqlc.arg(next_attempt_at), lease_expires_at = NULL, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'running' AND lease_expires_at = sqlc.arg(lease_expires_at);

-- name: MarkControlOperationFailed :execrows
UPDATE control_operations
SET state = CASE WHEN attempts >= sqlc.arg(max_attempts) THEN 'dead_letter' ELSE 'failed' END,
    last_error = sqlc.arg(last_error), next_attempt_at = sqlc.arg(next_attempt_at),
    lease_expires_at = NULL, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'running' AND lease_expires_at = sqlc.arg(lease_expires_at);

-- name: ReserveControlOperationRecovery :one
INSERT INTO control_operation_recoveries (operation_key, operation_id, actor_user_id)
VALUES (sqlc.arg(operation_key), sqlc.arg(operation_id), sqlc.arg(actor_user_id))
ON CONFLICT (operation_key) DO NOTHING
RETURNING *;

-- name: GetControlOperationRecovery :one
SELECT * FROM control_operation_recoveries WHERE operation_key = $1;

-- name: GetHostedHelperIdentityRenewal :one
SELECT * FROM hosted_helper_identity_renewals WHERE operation_key=$1;

-- name: CreateHostedHelperIdentityRenewal :one
INSERT INTO hosted_helper_identity_renewals (operation_key,helper_id,environment_id,request_hash,identity_ciphertext,expires_at)
VALUES (sqlc.arg(operation_key),sqlc.arg(helper_id),sqlc.arg(environment_id),sqlc.arg(request_hash),sqlc.arg(identity_ciphertext),sqlc.arg(expires_at))
ON CONFLICT (operation_key) DO NOTHING
RETURNING *;

-- name: RecoverDeadLetterControlOperation :execrows
UPDATE control_operations
SET state = 'pending', attempts = 0, last_error = NULL, next_attempt_at = NULL,
    lease_expires_at = NULL, uncertain_at = NULL, completed_at = NULL, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'dead_letter';

-- name: RegisterControlTunnelNode :one
INSERT INTO control_tunnel_nodes (id, edge_pool, protocol_version, process_epoch, endpoint_host, endpoint_tcp_port, endpoint_quic_port, state, ready, capacity, last_heartbeat_at)
VALUES (sqlc.arg(id), sqlc.arg(edge_pool), sqlc.arg(protocol_version), sqlc.arg(process_epoch), sqlc.arg(endpoint_host), sqlc.arg(endpoint_tcp_port), sqlc.arg(endpoint_quic_port), 'registered', false,
        coalesce(sqlc.arg(capacity)::jsonb, '{}'::jsonb), sqlc.arg(now))
ON CONFLICT (id) DO UPDATE
SET protocol_version = EXCLUDED.protocol_version, process_epoch = EXCLUDED.process_epoch,
    endpoint_host = EXCLUDED.endpoint_host, endpoint_tcp_port = EXCLUDED.endpoint_tcp_port, endpoint_quic_port = EXCLUDED.endpoint_quic_port,
    state = 'registered', ready = false, capacity = EXCLUDED.capacity,
    observation = '{}'::jsonb, last_heartbeat_at = EXCLUDED.last_heartbeat_at,
    drain_deadline = NULL, version = control_tunnel_nodes.version + 1, updated_at = EXCLUDED.last_heartbeat_at
RETURNING *;

-- name: GetControlConnectorAssignment :one
SELECT c.generation, c.edge_pool, c.edge_node_id, (c.revoked_at IS NOT NULL OR e.desired_state = 'revoked') AS revoked
FROM control_connector_generations c
JOIN control_environments e ON e.id = c.environment_id
JOIN control_helpers h ON h.id = c.helper_id AND h.environment_id = c.environment_id
WHERE c.environment_id = sqlc.arg(environment_id) AND c.helper_id = sqlc.arg(helper_id)
  AND h.state = 'active' AND e.desired_state = 'active';

-- name: GetControlConnectorGenerationForUpdate :one
SELECT * FROM control_connector_generations WHERE environment_id = sqlc.arg(environment_id) FOR UPDATE;

-- name: SelectReadyControlTunnelNodeForUpdate :one
SELECT * FROM control_tunnel_nodes
WHERE edge_pool = sqlc.arg(edge_pool) AND state = 'ready' AND ready = true
  AND last_heartbeat_at > sqlc.arg(stale_after)
ORDER BY last_heartbeat_at DESC, id
FOR UPDATE SKIP LOCKED LIMIT 1;

-- name: SetControlConnectorAdmission :one
UPDATE control_connector_generations
SET edge_node_id = sqlc.arg(edge_node_id), state = 'admitted', admission_jti_hash = sqlc.arg(admission_jti_hash),
    admission_operation_key = sqlc.arg(admission_operation_key), admission_request_hash = sqlc.arg(admission_request_hash),
    admission_credential_ciphertext = sqlc.arg(admission_credential_ciphertext), expires_at = sqlc.arg(expires_at),
    version = version + 1, updated_at = sqlc.arg(updated_at)
WHERE environment_id = sqlc.arg(environment_id) AND generation = sqlc.arg(generation)
RETURNING *;

-- name: ListControlRoutesForNode :many
SELECT r.id AS route_id, r.desired_revision AS route_revision, r.environment_id,
       c.generation AS connector_generation, c.edge_node_id, r.kind, r.public_host,
       r.target_host, r.target_port
FROM control_routes r
JOIN control_connector_generations c ON c.environment_id = r.environment_id
JOIN control_helpers h ON h.id = c.helper_id AND h.environment_id = c.environment_id
WHERE c.edge_node_id = sqlc.arg(edge_node_id)
  AND r.desired_state IN ('attached','replacing')
  AND c.state IN ('pending','admitted') AND h.state = 'active'
ORDER BY r.id;

-- name: ListControlRoutesForEnvironmentAdmission :many
SELECT id AS route_id, desired_revision AS route_revision, kind, public_host, target_host, target_port
FROM control_routes
WHERE environment_id = sqlc.arg(environment_id)
  AND desired_state IN ('attached','replacing')
ORDER BY id
LIMIT 128;

-- name: HeartbeatControlTunnelNode :one
UPDATE control_tunnel_nodes
SET state = CASE WHEN sqlc.arg(draining)::boolean THEN 'draining' WHEN state = 'registered' AND sqlc.arg(ready)::boolean THEN 'ready' ELSE state END,
    ready = CASE WHEN state = 'draining' OR sqlc.arg(draining)::boolean THEN false ELSE sqlc.arg(ready) END,
    observation = coalesce(sqlc.arg(observation)::jsonb, '{}'::jsonb),
    last_heartbeat_at = sqlc.arg(now), version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND process_epoch = sqlc.arg(process_epoch) AND state NOT IN ('offline','retired')
RETURNING *;

-- name: GetActiveControlUsageVerificationKey :one
SELECT public_key FROM control_usage_verification_keys
WHERE key_id = sqlc.arg(key_id) AND edge_node_id = sqlc.arg(edge_node_id)
  AND revoked_at IS NULL AND not_before <= sqlc.arg(now) AND expires_at > sqlc.arg(now);

-- name: CreateControlUsageVerificationKey :one
INSERT INTO control_usage_verification_keys (key_id, edge_node_id, public_key, not_before, expires_at)
VALUES (sqlc.arg(key_id), sqlc.arg(edge_node_id), sqlc.arg(public_key), sqlc.arg(not_before), sqlc.arg(expires_at))
ON CONFLICT (key_id) DO NOTHING
RETURNING *;

-- name: GetControlUsageVerificationKey :one
SELECT * FROM control_usage_verification_keys WHERE key_id = $1;

-- name: RevokeControlUsageVerificationKey :execrows
UPDATE control_usage_verification_keys SET revoked_at = coalesce(revoked_at, sqlc.arg(revoked_at))
WHERE key_id = sqlc.arg(key_id) AND revoked_at IS NULL;

-- name: DrainControlTunnelNode :one
UPDATE control_tunnel_nodes
SET state = 'draining', ready = false, drain_deadline = sqlc.arg(drain_deadline),
    version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND version = sqlc.arg(expected_version) AND state IN ('registered','ready')
RETURNING *;

-- name: ListStaleControlTunnelNodesForUpdate :many
SELECT * FROM control_tunnel_nodes
WHERE state IN ('registered','ready') AND (last_heartbeat_at IS NULL OR last_heartbeat_at <= sqlc.arg(cutoff))
ORDER BY coalesce(last_heartbeat_at, created_at), id
FOR UPDATE SKIP LOCKED LIMIT sqlc.arg(batch_size);

-- name: MarkControlTunnelNodeOffline :execrows
UPDATE control_tunnel_nodes SET state = 'offline', ready = false, version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND version = sqlc.arg(expected_version) AND state IN ('registered','ready');

-- name: FenceControlConnectorsForNode :execrows
UPDATE control_connector_generations
SET edge_node_id = NULL, state = 'pending', generation = generation + 1, admission_jti_hash = NULL,
    admission_operation_key = NULL, admission_request_hash = NULL, admission_credential_ciphertext = NULL,
    expires_at = NULL, version = version + 1, updated_at = sqlc.arg(now)
WHERE edge_node_id = sqlc.arg(edge_node_id) AND state IN ('pending','admitted');

-- name: AdvanceControlRoutesForNodeLoss :execrows
UPDATE control_routes
SET desired_revision = desired_revision + 1, applied_revision = 0, applied_node_id = NULL,
    applied_generation = NULL, version = version + 1, updated_at = sqlc.arg(now)
WHERE applied_node_id = sqlc.arg(edge_node_id) AND desired_state IN ('attached','replacing');

-- name: GetControlRouteForUpdate :one
SELECT * FROM control_routes WHERE id = $1 FOR UPDATE;

-- name: CreateControlRoute :one
INSERT INTO control_routes (id, environment_id, kind, public_host, target_host, target_port)
VALUES (sqlc.arg(id), sqlc.arg(environment_id), sqlc.arg(kind), sqlc.arg(public_host), sqlc.arg(target_host), sqlc.arg(target_port))
RETURNING *;

-- name: ReserveControlRouteOperation :one
INSERT INTO control_route_operations (operation_key, operation_type, request_hash, route_id, result_revision)
VALUES (sqlc.arg(operation_key), sqlc.arg(operation_type), sqlc.arg(request_hash), sqlc.arg(route_id), sqlc.narg(result_revision))
ON CONFLICT (operation_key) DO UPDATE SET operation_key = EXCLUDED.operation_key
RETURNING *;

-- name: GetControlRouteOperation :one
SELECT * FROM control_route_operations WHERE operation_key = $1;

-- name: SetControlRouteOperationResult :execrows
UPDATE control_route_operations SET result_revision = sqlc.arg(result_revision), result = sqlc.arg(result)::jsonb
WHERE operation_key = sqlc.arg(operation_key) AND result_revision IS NULL;

-- name: AdvanceControlRouteRevision :one
UPDATE control_routes
SET desired_revision = desired_revision + 1, desired_state = sqlc.arg(desired_state),
    drain_deadline = sqlc.narg(drain_deadline), version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND desired_revision = sqlc.arg(expected_revision)
RETURNING *;

-- name: ApplyControlRouteObservation :one
UPDATE control_routes
SET applied_revision = sqlc.arg(route_revision), applied_node_id = sqlc.arg(edge_node_id),
    applied_generation = sqlc.arg(connector_generation), version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND desired_revision = sqlc.arg(route_revision)
  AND desired_state IN ('attached','replacing') AND applied_revision <= sqlc.arg(route_revision)
  AND EXISTS (
    SELECT 1 FROM control_connector_generations c
    WHERE c.environment_id = control_routes.environment_id
      AND c.edge_node_id = sqlc.arg(edge_node_id)
      AND c.generation = sqlc.arg(connector_generation)
      AND c.state IN ('pending','admitted')
  )
RETURNING *;

-- name: ListDetachingControlRoutesForNode :many
SELECT id, desired_revision FROM control_routes
WHERE desired_state = 'detaching' AND applied_node_id = sqlc.arg(edge_node_id)
ORDER BY id;

-- name: FinalizeDetachedControlRoute :one
UPDATE control_routes
SET desired_state = 'detached', applied_revision = desired_revision,
    applied_node_id = NULL, applied_generation = NULL,
    version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND desired_state = 'detaching'
  AND desired_revision = sqlc.arg(desired_revision)
  AND applied_node_id = sqlc.arg(edge_node_id)
RETURNING *;

-- name: GetControlUsageCounterForUpdate :one
SELECT * FROM control_usage_counters
WHERE edge_node_id = sqlc.arg(edge_node_id) AND counter_epoch = sqlc.arg(counter_epoch)
  AND environment_id = sqlc.arg(environment_id) AND route_id = sqlc.arg(route_id)
  AND direction = sqlc.arg(direction)
FOR UPDATE;

-- name: UpsertControlUsageCounter :one
INSERT INTO control_usage_counters
  (edge_node_id, counter_epoch, environment_id, route_id, route_revision, direction, bytes, observed_at)
VALUES
  (sqlc.arg(edge_node_id), sqlc.arg(counter_epoch), sqlc.arg(environment_id), sqlc.arg(route_id),
   sqlc.arg(route_revision), sqlc.arg(direction), sqlc.arg(bytes), sqlc.arg(observed_at))
ON CONFLICT (edge_node_id, counter_epoch, environment_id, route_id, direction) DO UPDATE
SET bytes = greatest(control_usage_counters.bytes, EXCLUDED.bytes),
    route_revision = CASE WHEN EXCLUDED.bytes >= control_usage_counters.bytes THEN EXCLUDED.route_revision ELSE control_usage_counters.route_revision END,
    observed_at = greatest(control_usage_counters.observed_at, EXCLUDED.observed_at)
RETURNING *;

-- name: InsertControlUsageReceipt :one
INSERT INTO control_usage_receipts
  (operation_id, edge_node_id, counter_epoch, environment_id, route_id, route_revision, direction,
   observed_bytes, delta_bytes, interval_start, interval_end)
VALUES
  (sqlc.arg(operation_id), sqlc.arg(edge_node_id), sqlc.arg(counter_epoch), sqlc.arg(environment_id), sqlc.arg(route_id),
   sqlc.arg(route_revision), sqlc.arg(direction), sqlc.arg(observed_bytes), sqlc.arg(delta_bytes),
   sqlc.arg(interval_start), sqlc.arg(interval_end))
ON CONFLICT (operation_id) DO NOTHING
RETURNING *;

-- name: GetControlUsageReceipt :one
SELECT * FROM control_usage_receipts WHERE operation_id = $1;

-- name: AcknowledgeControlUsageReceipt :execrows
UPDATE control_usage_receipts SET acknowledged_at = coalesce(acknowledged_at, sqlc.arg(now))
WHERE operation_id = sqlc.arg(operation_id);
