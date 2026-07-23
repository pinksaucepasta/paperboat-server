-- name: CreateConnectedMachinePairing :one
INSERT INTO connected_machine_pairings (
  id, verifier_hash, user_code, requested_display_name, platform, architecture,
  workspace_root, runtime_versions, expires_at
) VALUES (
  sqlc.arg(id), sqlc.arg(verifier_hash), sqlc.arg(user_code), sqlc.arg(requested_display_name),
  sqlc.arg(platform), sqlc.arg(architecture), sqlc.arg(workspace_root), sqlc.arg(runtime_versions),
  sqlc.arg(expires_at)
) RETURNING *;

-- name: CreateConnectedMachineEnrollment :one
INSERT INTO connected_machine_enrollments (
  id, user_id, operation_id, idempotency_key, bootstrap_token_hash, bootstrap_token_ciphertext, expires_at
) VALUES (
  sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(operation_id), sqlc.arg(idempotency_key),
  sqlc.arg(bootstrap_token_hash), sqlc.arg(bootstrap_token_ciphertext), sqlc.arg(expires_at)
)
ON CONFLICT (user_id, idempotency_key) DO UPDATE
SET idempotency_key = excluded.idempotency_key
RETURNING *;

-- name: GetConnectedMachineEnrollmentForUser :one
SELECT * FROM connected_machine_enrollments
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id);

-- name: GetConnectedMachineEnrollmentForTokenUpdate :one
SELECT * FROM connected_machine_enrollments
WHERE bootstrap_token_hash = sqlc.arg(bootstrap_token_hash) FOR UPDATE;

-- name: GetConnectedMachineEnrollmentForPairingUpdate :one
SELECT * FROM connected_machine_enrollments
WHERE pairing_id = sqlc.arg(pairing_id) FOR UPDATE;

-- name: ClaimConnectedMachineEnrollment :execrows
UPDATE connected_machine_enrollments
SET state = 'awaiting_approval', pairing_id = sqlc.arg(pairing_id),
    requested_display_name = sqlc.arg(requested_display_name), platform = sqlc.arg(platform),
    architecture = sqlc.arg(architecture), workspace_root = sqlc.arg(workspace_root), updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'awaiting_bootstrap' AND expires_at > now();

-- name: ApproveConnectedMachineEnrollment :execrows
UPDATE connected_machine_enrollments
SET state = 'approved', connected_machine_id = sqlc.arg(connected_machine_id), updated_at = now()
WHERE pairing_id = sqlc.arg(pairing_id) AND user_id = sqlc.arg(user_id) AND state = 'awaiting_approval';

-- name: DenyConnectedMachineEnrollment :execrows
UPDATE connected_machine_enrollments
SET state = 'denied', updated_at = now()
WHERE pairing_id = sqlc.arg(pairing_id) AND user_id = sqlc.arg(user_id) AND state = 'awaiting_approval';

-- name: MarkConnectedMachineEnrollmentMaterialIssued :execrows
UPDATE connected_machine_enrollments SET state = 'material_issued', updated_at = now()
WHERE pairing_id = sqlc.arg(pairing_id) AND state = 'approved';

-- name: CancelConnectedMachineEnrollment :execrows
UPDATE connected_machine_enrollments
SET state = 'cancelled', cancelled_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
  AND state IN ('awaiting_bootstrap','awaiting_approval','failed_retryable');

-- name: ExpireConnectedMachineEnrollment :execrows
UPDATE connected_machine_enrollments
SET state = 'expired', updated_at = now()
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
  AND state IN ('awaiting_bootstrap','awaiting_approval') AND expires_at <= now();

-- name: RetryConnectedMachineEnrollment :one
UPDATE connected_machine_enrollments
SET state = 'awaiting_bootstrap', generation = generation + 1,
    bootstrap_token_hash = sqlc.arg(bootstrap_token_hash), bootstrap_token_ciphertext = sqlc.arg(bootstrap_token_ciphertext), pairing_id = NULL,
    requested_display_name = NULL, platform = NULL, architecture = NULL, workspace_root = NULL,
    expires_at = sqlc.arg(expires_at), cancelled_at = NULL, updated_at = now()
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
  AND state IN ('cancelled','expired','denied','failed_retryable')
RETURNING *;

-- name: FailConnectedMachineEnrollmentForHelper :execrows
UPDATE connected_machine_enrollments e
SET state = 'failed_retryable', updated_at = now()
FROM connected_machines m, control_helpers h
WHERE e.id = sqlc.arg(id)
  AND e.connected_machine_id = m.id
  AND m.environment_id = sqlc.arg(environment_id)
  AND h.id = sqlc.arg(helper_id)
  AND h.environment_id = m.environment_id
  AND (sqlc.arg(helper_enrollment_id) = '' OR EXISTS (
    SELECT 1 FROM control_helper_enrollments he
    WHERE he.id = sqlc.arg(helper_enrollment_id)
      AND he.helper_id = h.id
      AND he.environment_id = h.environment_id
  ))
  AND h.state IN ('pending','active') AND h.revoked_at IS NULL
  AND e.state IN ('installing','connecting');

-- name: GetConnectedMachineEntitlementForUpdate :one
SELECT * FROM connected_machine_entitlements
WHERE user_id = sqlc.arg(user_id) FOR UPDATE;

-- name: GetConnectedMachineEntitlement :one
SELECT * FROM connected_machine_entitlements
WHERE user_id = sqlc.arg(user_id);

-- name: GetConnectedMachineBandwidthUsage :one
SELECT
  coalesce(sum(p.included_bytes), 0)::bigint AS included_bytes,
  coalesce(sum(p.consumed_included_bytes), 0)::bigint AS consumed_included_bytes,
  coalesce(sum(p.consumed_topup_bytes), 0)::bigint AS consumed_topup_bytes,
  coalesce((SELECT sum(t.remaining_bytes) FROM connected_machine_bandwidth_topups t
    WHERE t.user_id = sqlc.arg(user_id) AND t.state = 'active'
      AND t.remaining_bytes > 0 AND (t.expires_at IS NULL OR t.expires_at > now())), 0)::bigint AS paid_topup_remaining_bytes
FROM connected_machine_bandwidth_periods p
JOIN connected_machines m ON m.id = p.connected_machine_id
JOIN connected_machine_entitlements e ON e.user_id = m.user_id
WHERE m.user_id = sqlc.arg(user_id)
  AND p.period_start = e.current_period_start
  AND p.period_end = e.current_period_end;

-- name: ConnectedMachineEntitlementIsActive :one
SELECT EXISTS (
  SELECT 1 FROM connected_machine_entitlements
  WHERE user_id = sqlc.arg(user_id)
    AND state IN ('active', 'trialing')
    AND current_period_start <= now()
    AND current_period_end > now()
);

-- name: GetActiveConnectedMachineSeatQuantity :one
SELECT seat_quantity FROM connected_machine_entitlements
WHERE user_id = sqlc.arg(user_id)
  AND state IN ('active', 'trialing')
  AND current_period_start <= now()
  AND current_period_end > now();

-- name: UpsertConnectedMachineEntitlement :exec
INSERT INTO connected_machine_entitlements (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end)
VALUES (sqlc.arg(id),sqlc.arg(user_id),sqlc.arg(provider_subscription_id),sqlc.arg(product_code),sqlc.arg(state),sqlc.arg(seat_quantity),sqlc.arg(allowance_bytes),sqlc.arg(current_period_start),sqlc.arg(current_period_end))
ON CONFLICT (user_id) DO UPDATE SET provider_subscription_id=EXCLUDED.provider_subscription_id,product_code=EXCLUDED.product_code,state=EXCLUDED.state,seat_quantity=EXCLUDED.seat_quantity,allowance_bytes=EXCLUDED.allowance_bytes,current_period_start=EXCLUDED.current_period_start,current_period_end=EXCLUDED.current_period_end,updated_at=now();

-- name: UpdateConnectedMachineEntitlementState :execrows
UPDATE connected_machine_entitlements
SET state = sqlc.arg(state), updated_at = now()
WHERE user_id = sqlc.arg(user_id)
  AND provider_subscription_id = sqlc.arg(provider_subscription_id);

-- name: CountOccupiedConnectedMachineSeats :one
SELECT count(*)::integer FROM connected_machines
WHERE user_id = sqlc.arg(user_id) AND seat_state = 'occupied' AND deleted_at IS NULL;

-- name: ListBillableConnectedMachineIDs :many
SELECT id FROM connected_machines
WHERE user_id = sqlc.arg(user_id)
  AND seat_state = 'occupied'
  AND deleted_at IS NULL
  AND state IN ('pending', 'online', 'offline');

-- name: RevokeConnectedMachinesForEntitlement :many
UPDATE connected_machines
SET state = 'revoked', online = false, seat_state = 'released', revoked_at = now(), updated_at = now(), version = version + 1
WHERE user_id = sqlc.arg(user_id)
  AND seat_state = 'occupied'
  AND deleted_at IS NULL
  AND state IN ('pending', 'online', 'offline')
RETURNING id;

-- name: RevokeConnectedMachinesOverSeatLimit :many
WITH excess AS (
  SELECT candidate.id
  FROM connected_machines AS candidate
  WHERE candidate.user_id = sqlc.arg(user_id)
    AND seat_state = 'occupied'
    AND deleted_at IS NULL
    AND state IN ('pending', 'online', 'offline')
  ORDER BY coalesce(enrolled_at, created_at) ASC, created_at ASC, id ASC
  OFFSET sqlc.arg(seat_quantity)
)
UPDATE connected_machines AS machine
SET state = 'revoked', online = false, seat_state = 'released', revoked_at = now(), updated_at = now(), version = version + 1
FROM excess
WHERE machine.id = excess.id
RETURNING machine.id, machine.environment_id;

-- name: ListRevokedConnectedMachineEnvironmentsForUser :many
SELECT id, environment_id FROM connected_machines
WHERE user_id = sqlc.arg(user_id) AND state = 'revoked' AND deleted_at IS NULL
ORDER BY id;

-- name: GetConnectedMachinePairingForVerifier :one
SELECT * FROM connected_machine_pairings
WHERE verifier_hash = sqlc.arg(verifier_hash) FOR UPDATE;

-- name: GetConnectedMachinePairingForCode :one
SELECT * FROM connected_machine_pairings
WHERE user_code = sqlc.arg(user_code) FOR UPDATE;

-- name: GetConnectedMachinePairingByID :one
SELECT * FROM connected_machine_pairings WHERE id = sqlc.arg(id);

-- name: ExpireConnectedMachinePairing :execrows
UPDATE connected_machine_pairings SET state = 'expired', updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'pending' AND expires_at <= now();

-- name: CreateConnectedMachine :one
INSERT INTO connected_machines (
  id, user_id, environment_id, display_name, platform, architecture, workspace_root,
  state, seat_state, runtime_versions, enrolled_at
) VALUES (
  sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(environment_id), sqlc.arg(display_name),
  sqlc.arg(platform), sqlc.arg(architecture), sqlc.arg(workspace_root),
  'offline', 'occupied', sqlc.arg(runtime_versions), now()
) RETURNING *;

-- name: ApproveConnectedMachinePairing :execrows
UPDATE connected_machine_pairings
SET state = 'approved', approved_by_user_id = sqlc.arg(user_id),
    connected_machine_id = sqlc.arg(connected_machine_id), approved_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'pending' AND expires_at > now();

-- name: DenyConnectedMachinePairing :execrows
UPDATE connected_machine_pairings
SET state = 'denied', approved_by_user_id = sqlc.arg(user_id), denied_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'pending' AND expires_at > now();

-- name: ListConnectedMachinesForUser :many
SELECT * FROM connected_machines
WHERE user_id = sqlc.arg(user_id) AND deleted_at IS NULL
ORDER BY lower(display_name), id
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: CountConnectedMachinesForUser :one
SELECT count(*)::integer FROM connected_machines
WHERE user_id = sqlc.arg(user_id) AND deleted_at IS NULL;

-- name: GetConnectedMachineForUser :one
SELECT * FROM connected_machines
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL;

-- name: GetConnectedMachineForUpdate :one
SELECT * FROM connected_machines
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL FOR UPDATE;

-- name: GetConnectedMachineForBandwidthUpdate :one
SELECT * FROM connected_machines
WHERE id = sqlc.arg(id) AND deleted_at IS NULL FOR UPDATE;

-- name: GetConnectedMachineIDForRoute :one
SELECT id FROM connected_machines
WHERE agentunnel_route_id = sqlc.arg(agentunnel_route_id)
  AND deleted_at IS NULL;

-- name: UpdateConnectedMachineStatus :execrows
UPDATE connected_machines
SET state = sqlc.arg(state), online = sqlc.arg(online), last_seen_at = now(),
    runtime_versions = sqlc.arg(runtime_versions), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL
  AND state NOT IN ('revoked','deleted');

-- name: MarkConnectedMachineOnlineFromHelper :execrows
UPDATE connected_machines
SET state = 'online', online = true, last_seen_at = now(), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND environment_id = sqlc.arg(environment_id)
  AND seat_state = 'occupied' AND deleted_at IS NULL AND state IN ('pending','offline','online');

-- name: MarkStaleConnectedMachinesOffline :execrows
UPDATE connected_machines
SET state = 'offline', online = false, updated_at = now(), version = version + 1
WHERE state = 'online' AND online = true AND last_seen_at < sqlc.arg(cutoff);

-- name: MarkConnectedMachineEnrollmentReady :execrows
UPDATE connected_machine_enrollments
SET state = 'ready', updated_at = now()
WHERE connected_machine_id = sqlc.arg(connected_machine_id)
  AND state IN ('approved','material_issued','installing','connecting');

-- name: SetConnectedMachineRoute :execrows
UPDATE connected_machines
SET agentunnel_route_id = sqlc.arg(agentunnel_route_id), agentunnel_client_id = sqlc.arg(agentunnel_client_id),
    agentunnel_http_base_url = sqlc.arg(agentunnel_http_base_url), agentunnel_websocket_base_url = sqlc.arg(agentunnel_websocket_base_url),
    updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL;

-- name: SetConnectedMachineInstallationConfig :execrows
UPDATE connected_machine_pairings
SET installation_config_ciphertext = sqlc.arg(ciphertext), updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'approved' AND installation_config_ciphertext IS NULL;

-- name: ConsumeConnectedMachineInstallationConfig :one
WITH consumed AS (
  UPDATE connected_machine_pairings
  SET state = 'consumed', installation_config_consumed_at = now(), updated_at = now()
  WHERE verifier_hash = sqlc.arg(verifier_hash)
    AND state = 'approved'
    AND installation_config_ciphertext IS NOT NULL
    AND installation_config_consumed_at IS NULL
    AND expires_at > now()
  RETURNING id, installation_config_ciphertext
), advanced AS (
  UPDATE connected_machine_enrollments e SET state = 'installing', updated_at = now()
  FROM consumed WHERE e.pairing_id = consumed.id AND e.state = 'material_issued'
  RETURNING e.id
)
SELECT installation_config_ciphertext FROM consumed;

-- name: RevokeConnectedMachine :execrows
UPDATE connected_machines
SET state = sqlc.arg(state), online = false, seat_state = sqlc.arg(seat_state),
    revoked_at = CASE WHEN sqlc.arg(state) = 'revoked' THEN now() ELSE revoked_at END,
    disconnected_at = CASE WHEN sqlc.arg(state) = 'disconnected' THEN now() ELSE disconnected_at END,
    updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL;

-- name: DeleteConnectedMachine :execrows
UPDATE connected_machines
SET state = 'deleted', online = false, seat_state = 'released', deleted_at = now(),
    updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL;

-- name: UpsertConnectedMachineBandwidthPeriod :one
INSERT INTO connected_machine_bandwidth_periods (
  id, connected_machine_id, period_start, period_end, included_bytes
) VALUES (
  sqlc.arg(id), sqlc.arg(connected_machine_id), sqlc.arg(period_start),
  sqlc.arg(period_end), sqlc.arg(included_bytes)
) ON CONFLICT (connected_machine_id, period_start) DO UPDATE SET updated_at = now()
RETURNING *;

-- name: GetConnectedMachineBandwidthPeriodForUpdate :one
SELECT * FROM connected_machine_bandwidth_periods
WHERE connected_machine_id = sqlc.arg(connected_machine_id)
  AND period_start = sqlc.arg(period_start) FOR UPDATE;

-- name: GetConnectedMachineForEnvironmentBandwidthUpdate :one
SELECT * FROM connected_machines
WHERE environment_id = sqlc.arg(environment_id) AND deleted_at IS NULL
FOR UPDATE;

-- name: ConsumeConnectedMachineIncludedBandwidth :execrows
UPDATE connected_machine_bandwidth_periods
SET consumed_included_bytes = consumed_included_bytes + sqlc.arg(bytes), updated_at = now()
WHERE id = sqlc.arg(id) AND consumed_included_bytes + sqlc.arg(bytes) <= included_bytes;

-- name: ListActiveConnectedMachineTopupsForUpdate :many
SELECT * FROM connected_machine_bandwidth_topups
WHERE user_id = sqlc.arg(user_id) AND state = 'active' AND remaining_bytes > 0
  AND (expires_at IS NULL OR expires_at > now())
ORDER BY created_at, id FOR UPDATE;

-- name: ConsumeConnectedMachineTopup :execrows
UPDATE connected_machine_bandwidth_topups
SET remaining_bytes = remaining_bytes - sqlc.arg(bytes),
    state = CASE WHEN remaining_bytes - sqlc.arg(bytes) = 0 THEN 'exhausted' ELSE 'active' END,
    consumed_at = CASE WHEN remaining_bytes - sqlc.arg(bytes) = 0 THEN now() ELSE consumed_at END,
    updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'active' AND remaining_bytes >= sqlc.arg(bytes);

-- name: RecordConnectedMachineTopupConsumption :execrows
UPDATE connected_machine_bandwidth_periods
SET consumed_topup_bytes = consumed_topup_bytes + sqlc.arg(bytes), updated_at = now()
WHERE id = sqlc.arg(id);

-- name: CreateConnectedMachineBandwidthTopup :execrows
INSERT INTO connected_machine_bandwidth_topups (
  id, user_id, provider_order_id, purchased_bytes, remaining_bytes, expires_at
) VALUES (
  sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(provider_order_id), sqlc.arg(purchased_bytes),
  sqlc.arg(purchased_bytes), sqlc.arg(expires_at)
) ON CONFLICT (provider_order_id) DO NOTHING;

-- name: VoidConnectedMachineBandwidthTopup :execrows
UPDATE connected_machine_bandwidth_topups
SET state = 'void', remaining_bytes = 0, consumed_at = now(), updated_at = now()
WHERE user_id = sqlc.arg(user_id)
  AND provider_order_id = sqlc.arg(provider_order_id)
  AND state = 'active';

-- name: CreateConnectedMachineAccessSession :exec
INSERT INTO connected_machine_access_sessions (
  id, connected_machine_id, user_id, environment_id, client_session_id,
  http_base_url, papercode_terminal_session_id, papercode_file_session_id, expires_at
) VALUES (
  sqlc.arg(id), sqlc.arg(connected_machine_id), sqlc.arg(user_id), sqlc.arg(environment_id), sqlc.arg(client_session_id),
  sqlc.arg(http_base_url), nullif(sqlc.arg(papercode_terminal_session_id), ''), nullif(sqlc.arg(papercode_file_session_id), ''), sqlc.arg(expires_at)
);

-- name: RevokeConnectedMachineAccessSessions :many
UPDATE connected_machine_access_sessions
SET state = 'revoked', revoked_at = now(), revocation_reason = sqlc.arg(reason), updated_at = now()
WHERE connected_machine_id = sqlc.arg(connected_machine_id)
  AND state = 'active'
RETURNING id, user_id, connected_machine_id, environment_id, client_session_id,
  http_base_url, coalesce(papercode_terminal_session_id, '') AS papercode_terminal_session_id,
  coalesce(papercode_file_session_id, '') AS papercode_file_session_id, revocation_reason;

-- name: RevokeConnectedMachineAccessSessionsForUser :many
UPDATE connected_machine_access_sessions
SET state = 'revoked', revoked_at = now(), revocation_reason = sqlc.arg(reason), updated_at = now()
WHERE user_id = sqlc.arg(user_id)
  AND state = 'active'
RETURNING id, user_id, connected_machine_id, environment_id, client_session_id,
  http_base_url, coalesce(papercode_terminal_session_id, '') AS papercode_terminal_session_id,
  coalesce(papercode_file_session_id, '') AS papercode_file_session_id, revocation_reason;

-- name: ListPendingConnectedMachineAccessSessionRevocations :many
SELECT id, user_id, connected_machine_id, environment_id, client_session_id,
  http_base_url, coalesce(papercode_terminal_session_id, '') AS papercode_terminal_session_id,
  coalesce(papercode_file_session_id, '') AS papercode_file_session_id, revocation_reason
FROM connected_machine_access_sessions
WHERE state = 'revoked' AND papercode_revoked_at IS NULL
ORDER BY created_at, id;

-- name: MarkConnectedMachineAccessSessionRevoked :execrows
UPDATE connected_machine_access_sessions
SET papercode_revoked_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'revoked' AND papercode_revoked_at IS NULL;

-- name: CreateDefaultConnectedMachineTerminalSession :exec
INSERT INTO connected_machine_terminal_sessions (id,connected_machine_id,terminal_id,name,is_default,launch_cwd)
VALUES (sqlc.arg(id),sqlc.arg(connected_machine_id),'term-1','default',true,sqlc.arg(launch_cwd))
ON CONFLICT (connected_machine_id) WHERE is_default AND deleted_at IS NULL DO NOTHING;

-- name: GetConnectedMachineTerminalSession :one
SELECT s.* FROM connected_machine_terminal_sessions s
JOIN connected_machines m ON m.id=s.connected_machine_id
WHERE s.id=sqlc.arg(id) AND s.connected_machine_id=sqlc.arg(connected_machine_id)
  AND m.user_id=sqlc.arg(user_id) AND m.deleted_at IS NULL AND s.deleted_at IS NULL;

-- name: GetDefaultConnectedMachineTerminalSession :one
SELECT s.* FROM connected_machine_terminal_sessions s
JOIN connected_machines m ON m.id=s.connected_machine_id
WHERE s.connected_machine_id=sqlc.arg(connected_machine_id) AND m.user_id=sqlc.arg(user_id)
  AND m.deleted_at IS NULL AND s.is_default AND s.deleted_at IS NULL;

-- name: ListConnectedMachineTerminalSessions :many
SELECT s.* FROM connected_machine_terminal_sessions s
JOIN connected_machines m ON m.id=s.connected_machine_id
WHERE s.connected_machine_id=sqlc.arg(connected_machine_id) AND m.user_id=sqlc.arg(user_id)
  AND m.deleted_at IS NULL AND s.deleted_at IS NULL
ORDER BY s.is_default DESC, s.last_activity_at DESC NULLS LAST, s.name;

-- name: GetConnectedMachineTerminalSessionByIdempotencyKey :one
SELECT s.* FROM connected_machine_terminal_sessions s
JOIN connected_machines m ON m.id=s.connected_machine_id
WHERE s.connected_machine_id=sqlc.arg(connected_machine_id) AND m.user_id=sqlc.arg(user_id)
  AND s.idempotency_key=sqlc.arg(idempotency_key) AND s.deleted_at IS NULL;

-- name: LockConnectedMachineTerminalSessions :one
SELECT id FROM connected_machines
WHERE id=sqlc.arg(connected_machine_id) AND user_id=sqlc.arg(user_id) AND deleted_at IS NULL FOR UPDATE;

-- name: CountActiveConnectedMachineTerminalSessions :one
SELECT count(*)::integer FROM connected_machine_terminal_sessions
WHERE connected_machine_id=sqlc.arg(connected_machine_id) AND deleted_at IS NULL;

-- name: NextConnectedMachineTerminalSessionOrdinal :one
SELECT coalesce(max(auto_name_ordinal),1)::integer+1 FROM connected_machine_terminal_sessions
WHERE connected_machine_id=sqlc.arg(connected_machine_id);

-- name: CreateConnectedMachineTerminalSession :exec
INSERT INTO connected_machine_terminal_sessions (id,connected_machine_id,terminal_id,name,auto_name_ordinal,idempotency_key,launch_cwd)
VALUES (sqlc.arg(id),sqlc.arg(connected_machine_id),sqlc.arg(terminal_id),sqlc.arg(name),nullif(sqlc.arg(auto_name_ordinal),0),sqlc.arg(idempotency_key),sqlc.arg(launch_cwd));

-- name: RenameConnectedMachineTerminalSession :execrows
UPDATE connected_machine_terminal_sessions SET name=sqlc.arg(name),version=version+1,updated_at=now()
WHERE connected_machine_id=sqlc.arg(connected_machine_id) AND id=sqlc.arg(id)
  AND deleted_at IS NULL AND NOT is_default;

-- name: CloseConnectedMachineTerminalSession :execrows
UPDATE connected_machine_terminal_sessions SET desired_state='closed',version=version+1,updated_at=now()
WHERE connected_machine_id=sqlc.arg(connected_machine_id) AND id=sqlc.arg(id)
  AND deleted_at IS NULL AND desired_state<>'closed';

-- name: DeleteConnectedMachineTerminalSession :execrows
UPDATE connected_machine_terminal_sessions SET desired_state='deleted',deleted_at=now(),version=version+1,updated_at=now()
WHERE connected_machine_id=sqlc.arg(connected_machine_id) AND id=sqlc.arg(id)
  AND deleted_at IS NULL AND NOT is_default;

-- name: QueueConnectedMachineTerminalSessionOperation :exec
INSERT INTO connected_machine_terminal_session_operations (id,connected_machine_id,terminal_session_id,operation)
VALUES (sqlc.arg(id),sqlc.arg(connected_machine_id),sqlc.arg(terminal_session_id),sqlc.arg(operation))
ON CONFLICT (terminal_session_id,operation) WHERE state='pending' DO NOTHING;

-- name: ConnectedMachineTerminalSessionOperationPending :one
SELECT EXISTS (
  SELECT 1 FROM connected_machine_terminal_session_operations
  WHERE connected_machine_id=sqlc.arg(connected_machine_id)
    AND terminal_session_id=sqlc.arg(terminal_session_id) AND state='pending'
);

-- name: ListDueConnectedMachineTerminalSessionOperations :many
SELECT o.id,o.connected_machine_id,o.terminal_session_id,o.operation,o.attempts,
  m.user_id,m.environment_id,coalesce((SELECT 'https://' || r.public_host
    FROM control_routes r
    JOIN control_environments e ON e.id = r.environment_id
    JOIN control_connector_generations c ON c.environment_id = r.environment_id
    JOIN control_helpers h ON h.id = c.helper_id AND h.environment_id = r.environment_id
    JOIN control_tunnel_nodes n ON n.id = c.edge_node_id AND n.id = r.applied_node_id
    WHERE r.environment_id = m.environment_id AND r.kind = 'helper_https_wss'
      AND r.desired_state IN ('attached','replacing') AND r.applied_revision >= r.desired_revision
      AND r.applied_generation = c.generation AND e.desired_state = 'active'
      AND h.state = 'active' AND c.state = 'admitted' AND n.state = 'ready' AND n.ready = true
    ORDER BY r.id LIMIT 1), '')::text AS agentunnel_http_base_url,s.thread_id,s.terminal_id
FROM connected_machine_terminal_session_operations o
JOIN connected_machines m ON m.id=o.connected_machine_id
JOIN connected_machine_terminal_sessions s ON s.id=o.terminal_session_id
WHERE o.state='pending' AND o.next_attempt_at<=now()
ORDER BY o.created_at LIMIT sqlc.arg(batch_size);

-- name: ListPendingConnectedMachineTerminalSessionOperations :many
SELECT o.id,o.connected_machine_id,o.terminal_session_id,o.operation,o.attempts,
  m.user_id,m.environment_id,coalesce((SELECT 'https://' || r.public_host
    FROM control_routes r
    JOIN control_environments e ON e.id = r.environment_id
    JOIN control_connector_generations c ON c.environment_id = r.environment_id
    JOIN control_helpers h ON h.id = c.helper_id AND h.environment_id = r.environment_id
    JOIN control_tunnel_nodes n ON n.id = c.edge_node_id AND n.id = r.applied_node_id
    WHERE r.environment_id = m.environment_id AND r.kind = 'helper_https_wss'
      AND r.desired_state IN ('attached','replacing') AND r.applied_revision >= r.desired_revision
      AND r.applied_generation = c.generation AND e.desired_state = 'active'
      AND h.state = 'active' AND c.state = 'admitted' AND n.state = 'ready' AND n.ready = true
    ORDER BY r.id LIMIT 1), '')::text AS agentunnel_http_base_url,s.thread_id,s.terminal_id
FROM connected_machine_terminal_session_operations o
JOIN connected_machines m ON m.id=o.connected_machine_id
JOIN connected_machine_terminal_sessions s ON s.id=o.terminal_session_id
WHERE o.connected_machine_id=sqlc.arg(connected_machine_id) AND o.state='pending'
ORDER BY o.created_at LIMIT sqlc.arg(batch_size);

-- name: MarkConnectedMachineTerminalSessionOperationApplied :exec
UPDATE connected_machine_terminal_session_operations
SET state='applied',completed_at=now(),updated_at=now(),last_error=NULL
WHERE id=sqlc.arg(id) AND state='pending';

-- name: MarkConnectedMachineTerminalSessionRuntimeClosed :exec
UPDATE connected_machine_terminal_sessions
SET runtime_state='closed',updated_at=now(),version=version+1
WHERE id=sqlc.arg(id) AND deleted_at IS NULL;

-- name: RetryConnectedMachineTerminalSessionOperation :exec
UPDATE connected_machine_terminal_session_operations
SET attempts=attempts+1,next_attempt_at=now()+make_interval(secs => sqlc.arg(retry_seconds)),last_error=sqlc.arg(last_error),updated_at=now()
WHERE id=sqlc.arg(id) AND state='pending';
