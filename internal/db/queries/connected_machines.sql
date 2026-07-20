-- name: CreateConnectedMachinePairing :one
INSERT INTO connected_machine_pairings (
  id, verifier_hash, user_code, requested_display_name, platform, architecture,
  workspace_root, runtime_versions, expires_at
) VALUES (
  sqlc.arg(id), sqlc.arg(verifier_hash), sqlc.arg(user_code), sqlc.arg(requested_display_name),
  sqlc.arg(platform), sqlc.arg(architecture), sqlc.arg(workspace_root), sqlc.arg(runtime_versions),
  sqlc.arg(expires_at)
) RETURNING *;

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
SET state = 'revoked', online = false, revoked_at = now(), updated_at = now(), version = version + 1
WHERE user_id = sqlc.arg(user_id)
  AND seat_state = 'occupied'
  AND deleted_at IS NULL
  AND state IN ('pending', 'online', 'offline')
RETURNING id;

-- name: GetConnectedMachinePairingForVerifier :one
SELECT * FROM connected_machine_pairings
WHERE verifier_hash = sqlc.arg(verifier_hash) FOR UPDATE;

-- name: GetConnectedMachinePairingForCode :one
SELECT * FROM connected_machine_pairings
WHERE user_code = sqlc.arg(user_code) FOR UPDATE;

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
UPDATE connected_machine_pairings
SET state = 'consumed', installation_config_consumed_at = now(), updated_at = now()
WHERE verifier_hash = sqlc.arg(verifier_hash)
  AND state = 'approved'
  AND installation_config_ciphertext IS NOT NULL
  AND installation_config_consumed_at IS NULL
  AND expires_at > now()
RETURNING installation_config_ciphertext;

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
UPDATE connected_machine_terminal_sessions SET desired_state='closed',runtime_state='closed',version=version+1,updated_at=now()
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
  m.user_id,m.environment_id,m.agentunnel_http_base_url,s.thread_id,s.terminal_id
FROM connected_machine_terminal_session_operations o
JOIN connected_machines m ON m.id=o.connected_machine_id
JOIN connected_machine_terminal_sessions s ON s.id=o.terminal_session_id
WHERE o.state='pending' AND o.next_attempt_at<=now()
ORDER BY o.created_at LIMIT sqlc.arg(batch_size);

-- name: ListPendingConnectedMachineTerminalSessionOperations :many
SELECT o.id,o.connected_machine_id,o.terminal_session_id,o.operation,o.attempts,
  m.user_id,m.environment_id,m.agentunnel_http_base_url,s.thread_id,s.terminal_id
FROM connected_machine_terminal_session_operations o
JOIN connected_machines m ON m.id=o.connected_machine_id
JOIN connected_machine_terminal_sessions s ON s.id=o.terminal_session_id
WHERE o.connected_machine_id=sqlc.arg(connected_machine_id) AND o.state='pending'
ORDER BY o.created_at LIMIT sqlc.arg(batch_size);

-- name: MarkConnectedMachineTerminalSessionOperationApplied :exec
UPDATE connected_machine_terminal_session_operations
SET state='applied',completed_at=now(),updated_at=now(),last_error=NULL
WHERE id=sqlc.arg(id) AND state='pending';

-- name: RetryConnectedMachineTerminalSessionOperation :exec
UPDATE connected_machine_terminal_session_operations
SET attempts=attempts+1,next_attempt_at=now()+make_interval(secs => sqlc.arg(retry_seconds)),last_error=sqlc.arg(last_error),updated_at=now()
WHERE id=sqlc.arg(id) AND state='pending';
