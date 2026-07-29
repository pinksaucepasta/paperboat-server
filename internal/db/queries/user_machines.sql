-- name: CreateUserMachinePairing :one
INSERT INTO user_machine_pairings (
  id, verifier_hash, user_code, requested_display_name, platform, architecture,
  workspace_root, runtime_versions, expires_at
) VALUES (
  sqlc.arg(id), sqlc.arg(verifier_hash), sqlc.arg(user_code), sqlc.arg(requested_display_name),
  sqlc.arg(platform), sqlc.arg(architecture), sqlc.arg(workspace_root), sqlc.arg(runtime_versions),
  sqlc.arg(expires_at)
) RETURNING *;

-- name: CreateUserMachineEnrollment :one
INSERT INTO user_machine_enrollments (
  id, user_id, operation_id, idempotency_key, bootstrap_token_hash, bootstrap_token_ciphertext, expires_at
) VALUES (
  sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(operation_id), sqlc.arg(idempotency_key),
  sqlc.arg(bootstrap_token_hash), sqlc.arg(bootstrap_token_ciphertext), sqlc.arg(expires_at)
)
ON CONFLICT (user_id, idempotency_key) DO UPDATE
SET idempotency_key = excluded.idempotency_key
RETURNING *;

-- name: GetUserMachineEnrollmentForUser :one
SELECT * FROM user_machine_enrollments
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id);

-- name: GetUserMachineEnrollmentForTokenUpdate :one
SELECT * FROM user_machine_enrollments
WHERE bootstrap_token_hash = sqlc.arg(bootstrap_token_hash) FOR UPDATE;

-- name: GetUserMachineEnrollmentForPairingUpdate :one
SELECT * FROM user_machine_enrollments
WHERE pairing_id = sqlc.arg(pairing_id) FOR UPDATE;

-- name: ClaimUserMachineEnrollment :execrows
UPDATE user_machine_enrollments
SET state = 'awaiting_approval', pairing_id = sqlc.arg(pairing_id),
    requested_display_name = sqlc.arg(requested_display_name), platform = sqlc.arg(platform),
    architecture = sqlc.arg(architecture), workspace_root = sqlc.arg(workspace_root), updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'awaiting_bootstrap' AND expires_at > now();

-- name: ApproveUserMachineEnrollment :execrows
UPDATE user_machine_enrollments
SET state = 'approved', user_machine_id = sqlc.arg(user_machine_id), updated_at = now()
WHERE pairing_id = sqlc.arg(pairing_id) AND user_id = sqlc.arg(user_id) AND state = 'awaiting_approval';

-- name: DenyUserMachineEnrollment :execrows
UPDATE user_machine_enrollments
SET state = 'denied', updated_at = now()
WHERE pairing_id = sqlc.arg(pairing_id) AND user_id = sqlc.arg(user_id) AND state = 'awaiting_approval';

-- name: MarkUserMachineEnrollmentMaterialIssued :execrows
UPDATE user_machine_enrollments SET state = 'material_issued', updated_at = now()
WHERE pairing_id = sqlc.arg(pairing_id) AND state = 'approved';

-- name: CancelUserMachineEnrollment :execrows
UPDATE user_machine_enrollments
SET state = 'cancelled', cancelled_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
  AND state IN ('awaiting_bootstrap','awaiting_approval','failed_retryable');

-- name: ExpireUserMachineEnrollment :execrows
UPDATE user_machine_enrollments
SET state = 'expired', updated_at = now()
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
  AND state IN ('awaiting_bootstrap','awaiting_approval') AND expires_at <= now();

-- name: RetryUserMachineEnrollment :one
UPDATE user_machine_enrollments
SET state = 'awaiting_bootstrap', generation = generation + 1,
    bootstrap_token_hash = sqlc.arg(bootstrap_token_hash), bootstrap_token_ciphertext = sqlc.arg(bootstrap_token_ciphertext), pairing_id = NULL,
    requested_display_name = NULL, platform = NULL, architecture = NULL, workspace_root = NULL,
    expires_at = sqlc.arg(expires_at), cancelled_at = NULL, updated_at = now()
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
  AND state IN ('cancelled','expired','denied','failed_retryable')
RETURNING *;

-- name: FailUserMachineEnrollmentForHelper :one
WITH target AS MATERIALIZED (
  SELECT e.id AS enrollment_id, m.id AS machine_id, h.id AS helper_id
  FROM user_machine_enrollments e
  JOIN user_machines m ON m.id = e.user_machine_id
  JOIN control_helpers h ON h.environment_id = m.environment_id
  JOIN control_helper_enrollments he ON he.helper_id = h.id AND he.environment_id = h.environment_id
  WHERE e.id = sqlc.arg(id)
    AND m.environment_id = sqlc.arg(environment_id)
    AND h.id = sqlc.arg(helper_id)
    AND he.id = sqlc.arg(helper_enrollment_id)
    AND he.state IN ('pending','consumed') AND he.revoked_at IS NULL
    AND h.state IN ('pending','active') AND h.revoked_at IS NULL
    AND e.state IN ('installing','connecting')
  FOR UPDATE OF e, m, h, he
), failed AS (
  UPDATE user_machine_enrollments e
  SET state = 'failed_retryable', updated_at = now()
  FROM target t WHERE e.id = t.enrollment_id
  RETURNING e.id
), released AS (
  UPDATE user_machines m
  SET seat_state = 'released', online = false, updated_at = now(), version = version + 1
  FROM target t WHERE m.id = t.machine_id AND m.seat_state = 'occupied'
  RETURNING m.id
), revoked_helper AS (
  UPDATE control_helpers h
  SET state = 'revoked', revoked_at = now(), updated_at = now()
  FROM target t WHERE h.id = t.helper_id
  RETURNING h.id
), revoked_grants AS (
  UPDATE control_helper_enrollments he
  SET state = 'revoked', revoked_at = coalesce(he.revoked_at, now())
  FROM target t
  WHERE he.helper_id = t.helper_id AND he.state IN ('pending','consumed') AND he.revoked_at IS NULL
  RETURNING he.id
)
SELECT (SELECT count(*) FROM failed)::integer AS failed_count,
       (SELECT count(*) FROM released)::integer AS released_count,
       (SELECT count(*) FROM revoked_helper)::integer AS revoked_helper_count,
       (SELECT count(*) FROM revoked_grants)::integer AS revoked_grant_count;

-- name: GetUserMachineEntitlementForUpdate :one
SELECT * FROM user_machine_entitlements
WHERE user_id = sqlc.arg(user_id) FOR UPDATE;

-- name: GetUserMachineEntitlement :one
SELECT * FROM user_machine_entitlements
WHERE user_id = sqlc.arg(user_id);

-- name: GetUserMachineBandwidthUsage :one
SELECT
  coalesce(sum(p.included_bytes), 0)::bigint AS included_bytes,
  coalesce(sum(p.consumed_included_bytes), 0)::bigint AS consumed_included_bytes,
  coalesce(sum(p.consumed_topup_bytes), 0)::bigint AS consumed_topup_bytes,
  coalesce((SELECT sum(t.remaining_bytes) FROM user_machine_bandwidth_topups t
    WHERE t.user_id = sqlc.arg(user_id) AND t.state = 'active'
      AND t.remaining_bytes > 0 AND (t.expires_at IS NULL OR t.expires_at > now())), 0)::bigint AS paid_topup_remaining_bytes
FROM user_machine_bandwidth_periods p
JOIN user_machines m ON m.id = p.user_machine_id
JOIN user_machine_entitlements e ON e.user_id = m.user_id
WHERE m.user_id = sqlc.arg(user_id)
  AND p.period_start = e.current_period_start
  AND p.period_end = e.current_period_end;

-- name: UserMachineEntitlementIsActive :one
SELECT EXISTS (
  SELECT 1 FROM user_machine_entitlements
  WHERE user_id = sqlc.arg(user_id)
    AND state IN ('active', 'trialing')
    AND current_period_start <= now()
    AND current_period_end > now()
);

-- name: GetActiveUserMachineSeatQuantity :one
SELECT seat_quantity FROM user_machine_entitlements
WHERE user_id = sqlc.arg(user_id)
  AND state IN ('active', 'trialing')
  AND current_period_start <= now()
  AND current_period_end > now();

-- name: UpsertUserMachineEntitlement :exec
INSERT INTO user_machine_entitlements (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end)
VALUES (sqlc.arg(id),sqlc.arg(user_id),sqlc.arg(provider_subscription_id),sqlc.arg(product_code),sqlc.arg(state),sqlc.arg(seat_quantity),sqlc.arg(allowance_bytes),sqlc.arg(current_period_start),sqlc.arg(current_period_end))
ON CONFLICT (user_id) DO UPDATE SET provider_subscription_id=EXCLUDED.provider_subscription_id,product_code=EXCLUDED.product_code,state=EXCLUDED.state,seat_quantity=EXCLUDED.seat_quantity,allowance_bytes=EXCLUDED.allowance_bytes,current_period_start=EXCLUDED.current_period_start,current_period_end=EXCLUDED.current_period_end,updated_at=now();

-- name: UpdateUserMachineEntitlementState :execrows
UPDATE user_machine_entitlements
SET state = sqlc.arg(state), updated_at = now()
WHERE user_id = sqlc.arg(user_id)
  AND provider_subscription_id = sqlc.arg(provider_subscription_id);

-- name: CountOccupiedUserMachineSeats :one
SELECT count(*)::integer FROM user_machines
WHERE user_id = sqlc.arg(user_id) AND seat_state = 'occupied' AND deleted_at IS NULL;

-- name: ListBillableUserMachineIDs :many
SELECT id FROM user_machines
WHERE user_id = sqlc.arg(user_id)
  AND seat_state = 'occupied'
  AND deleted_at IS NULL
  AND state IN ('pending', 'online', 'offline');

-- name: RevokeUserMachinesForEntitlement :many
UPDATE user_machines
SET state = 'revoked', online = false, seat_state = 'released', revoked_at = now(), updated_at = now(), version = version + 1
WHERE user_id = sqlc.arg(user_id)
  AND seat_state = 'occupied'
  AND deleted_at IS NULL
  AND state IN ('pending', 'online', 'offline')
RETURNING id;

-- name: RevokeUserMachinesOverSeatLimit :many
WITH excess AS (
  SELECT candidate.id
  FROM user_machines AS candidate
  WHERE candidate.user_id = sqlc.arg(user_id)
    AND seat_state = 'occupied'
    AND deleted_at IS NULL
    AND state IN ('pending', 'online', 'offline')
  ORDER BY coalesce(enrolled_at, created_at) ASC, created_at ASC, id ASC
  OFFSET sqlc.arg(seat_quantity)
)
UPDATE user_machines AS machine
SET state = 'revoked', online = false, seat_state = 'released', revoked_at = now(), updated_at = now(), version = version + 1
FROM excess
WHERE machine.id = excess.id
RETURNING machine.id, machine.environment_id;

-- name: ListRevokedUserMachineEnvironmentsForUser :many
SELECT id, environment_id FROM user_machines
WHERE user_id = sqlc.arg(user_id) AND state = 'revoked' AND deleted_at IS NULL
ORDER BY id;

-- name: GetUserMachinePairingForVerifier :one
SELECT * FROM user_machine_pairings
WHERE verifier_hash = sqlc.arg(verifier_hash) FOR UPDATE;

-- name: GetUserMachinePairingForCode :one
SELECT * FROM user_machine_pairings
WHERE user_code = sqlc.arg(user_code) FOR UPDATE;

-- name: GetUserMachinePairingByID :one
SELECT * FROM user_machine_pairings WHERE id = sqlc.arg(id);

-- name: ExpireUserMachinePairing :execrows
UPDATE user_machine_pairings SET state = 'expired', updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'pending' AND expires_at <= now();

-- name: CreateUserMachine :one
INSERT INTO user_machines (
  id, user_id, environment_id, display_name, platform, architecture, workspace_root,
  state, seat_state, runtime_versions, enrolled_at
) VALUES (
  sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(environment_id), sqlc.arg(display_name),
  sqlc.arg(platform), sqlc.arg(architecture), sqlc.arg(workspace_root),
  'offline', 'occupied', sqlc.arg(runtime_versions), now()
) RETURNING *;

-- name: OccupyUserMachineSeat :execrows
UPDATE user_machines
SET seat_state = 'occupied', updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
  AND seat_state = 'released' AND deleted_at IS NULL
  AND state IN ('pending','offline');

-- name: ApproveUserMachinePairing :execrows
UPDATE user_machine_pairings
SET state = 'approved', approved_by_user_id = sqlc.arg(user_id),
    user_machine_id = sqlc.arg(user_machine_id), approved_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'pending' AND expires_at > now();

-- name: DenyUserMachinePairing :execrows
UPDATE user_machine_pairings
SET state = 'denied', approved_by_user_id = sqlc.arg(user_id), denied_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'pending' AND expires_at > now();

-- name: ListUserMachinesForUser :many
SELECT * FROM user_machines
WHERE user_id = sqlc.arg(user_id) AND deleted_at IS NULL
ORDER BY lower(display_name), id
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: CountUserMachinesForUser :one
SELECT count(*)::integer FROM user_machines
WHERE user_id = sqlc.arg(user_id) AND deleted_at IS NULL;

-- name: GetUserMachineForUser :one
SELECT * FROM user_machines
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL;

-- name: GetUserMachineForUpdate :one
SELECT * FROM user_machines
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL FOR UPDATE;

-- name: GetUserMachineAvailabilityOperation :one
SELECT * FROM user_machine_availability_operations
WHERE user_id = sqlc.arg(user_id) AND user_machine_id = sqlc.arg(user_machine_id)
  AND idempotency_key = sqlc.arg(idempotency_key);

-- name: CreateUserMachineAvailabilityOperation :one
INSERT INTO user_machine_availability_operations (
  id,user_machine_id,user_id,idempotency_key,request_hash,expected_version,resulting_version,mode,result
) VALUES (
  sqlc.arg(id),sqlc.arg(user_machine_id),sqlc.arg(user_id),sqlc.arg(idempotency_key),
  sqlc.arg(request_hash),sqlc.arg(expected_version),sqlc.arg(resulting_version),sqlc.arg(mode),sqlc.arg(result)
) RETURNING *;

-- name: SetUserMachineAvailabilityPolicy :execrows
UPDATE user_machines
SET availability_mode=sqlc.arg(mode),
    availability_desired_version=availability_desired_version+1,
    availability_status='pending', availability_error_code=NULL, updated_at=now()
WHERE id=sqlc.arg(id) AND user_id=sqlc.arg(user_id) AND deleted_at IS NULL
  AND seat_state='occupied' AND state NOT IN ('revoked','disconnected','deleted')
  AND availability_desired_version=sqlc.arg(expected_version);

-- name: GetUserMachineAvailabilityForHelper :one
SELECT m.* FROM user_machines m
JOIN control_helpers h ON h.environment_id=m.environment_id
WHERE h.id=sqlc.arg(helper_id) AND h.environment_id=sqlc.arg(environment_id)
  AND h.state='active' AND h.revoked_at IS NULL
  AND m.deleted_at IS NULL AND m.seat_state='occupied';

-- name: RecordUserMachineAvailabilityObservation :execrows
UPDATE user_machines
SET availability_observed_mode=sqlc.arg(observed_mode),
    availability_observed_version=sqlc.arg(observed_version),
    availability_observed_at=sqlc.arg(observed_at),
    availability_status=sqlc.arg(status),
    availability_error_code=nullif(sqlc.arg(error_code),''),
    host_service_version=nullif(sqlc.arg(host_service_version),''),
    host_service_scope=nullif(sqlc.arg(host_service_scope),''),
    host_update_rollbacks=greatest(host_update_rollbacks, sqlc.arg(update_rollbacks)), updated_at=now()
WHERE id=sqlc.arg(id) AND environment_id=sqlc.arg(environment_id) AND deleted_at IS NULL
  AND sqlc.arg(observed_version) <= availability_desired_version
  AND (availability_observed_at IS NULL OR sqlc.arg(observed_version) > availability_observed_version OR (
    sqlc.arg(observed_version) = availability_observed_version
    AND availability_observed_mode IS NOT DISTINCT FROM sqlc.arg(observed_mode)
    AND availability_status = sqlc.arg(status)
    AND coalesce(availability_error_code,'') = sqlc.arg(error_code)
    AND sqlc.arg(update_rollbacks) >= host_update_rollbacks
  ));

-- name: GetUserMachineForBandwidthUpdate :one
SELECT * FROM user_machines
WHERE id = sqlc.arg(id) AND deleted_at IS NULL FOR UPDATE;

-- name: GetUserMachineIDForRoute :one
SELECT id FROM user_machines
WHERE provider_route_route_id = sqlc.arg(provider_route_route_id)
  AND deleted_at IS NULL;

-- name: UpdateUserMachineStatus :execrows
UPDATE user_machines
SET state = sqlc.arg(state), online = sqlc.arg(online), last_seen_at = now(),
    runtime_versions = sqlc.arg(runtime_versions), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL
  AND state NOT IN ('revoked','deleted');

-- name: MarkUserMachineOnlineFromHelper :execrows
UPDATE user_machines
SET state = 'online', online = true, last_seen_at = now(), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND environment_id = sqlc.arg(environment_id)
  AND seat_state = 'occupied' AND deleted_at IS NULL AND state IN ('pending','offline','online');

-- name: MarkStaleUserMachinesOffline :execrows
UPDATE user_machines
SET state = 'offline', online = false, updated_at = now(), version = version + 1
WHERE state = 'online' AND online = true AND last_seen_at < sqlc.arg(cutoff);

-- name: MarkUserMachineEnrollmentReady :execrows
UPDATE user_machine_enrollments
SET state = 'ready', updated_at = now()
WHERE user_machine_id = sqlc.arg(user_machine_id)
  AND state IN ('approved','material_issued','installing','connecting');

-- name: RecordUserMachineRuntimeDiagnostics :execrows
UPDATE user_machines
SET worker_generation = sqlc.arg(worker_generation),
    os_boot_id = sqlc.arg(os_boot_id),
    worker_service_scope = sqlc.arg(worker_service_scope),
    connector_state = sqlc.arg(connector_state),
    connector_generation = sqlc.arg(connector_generation),
    runtime_diagnostics_observed_at = sqlc.arg(observed_at),
    updated_at = now()
WHERE id = sqlc.arg(id) AND environment_id = sqlc.arg(environment_id)
  AND deleted_at IS NULL
  AND (runtime_diagnostics_observed_at IS NULL OR runtime_diagnostics_observed_at <= sqlc.arg(observed_at));

-- name: GetUserMachineRuntimeMetrics :one
SELECT
  count(*) FILTER (WHERE availability_status IN ('pending','error') OR availability_observed_version < availability_desired_version)::bigint AS availability_drift_depth,
  count(*) FILTER (WHERE availability_status = 'error')::bigint AS privileged_service_error_depth,
  count(*) FILTER (WHERE host_service_scope IS NOT NULL AND host_service_scope <> 'system')::bigint AS unsupported_host_scope_depth,
  coalesce(max(extract(epoch FROM (now() - last_seen_at))) FILTER (WHERE last_seen_at IS NOT NULL), 0)::bigint AS heartbeat_oldest_age_seconds,
  coalesce(sum(host_update_rollbacks), 0)::bigint AS update_rollbacks_total,
  (SELECT count(*)::bigint FROM user_machine_enrollments WHERE state = 'failed_retryable') AS bootstrap_failure_depth
FROM user_machines
WHERE deleted_at IS NULL;

-- name: SetUserMachineRoute :execrows
UPDATE user_machines
SET provider_route_route_id = sqlc.arg(provider_route_route_id), provider_route_client_id = sqlc.arg(provider_route_client_id),
    provider_route_http_base_url = sqlc.arg(provider_route_http_base_url), provider_route_websocket_base_url = sqlc.arg(provider_route_websocket_base_url),
    updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL;

-- name: SetUserMachineInstallationConfig :execrows
UPDATE user_machine_pairings
SET installation_config_ciphertext = sqlc.arg(ciphertext), updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'approved' AND installation_config_ciphertext IS NULL;

-- name: ConsumeUserMachineInstallationConfig :one
WITH consumed AS (
  UPDATE user_machine_pairings
  SET state = 'consumed', installation_config_consumed_at = now(), updated_at = now()
  WHERE verifier_hash = sqlc.arg(verifier_hash)
    AND state = 'approved'
    AND installation_config_ciphertext IS NOT NULL
    AND installation_config_consumed_at IS NULL
    AND expires_at > now()
  RETURNING id, installation_config_ciphertext
), advanced AS (
  UPDATE user_machine_enrollments e SET state = 'installing', updated_at = now()
  FROM consumed WHERE e.pairing_id = consumed.id AND e.state = 'material_issued'
  RETURNING e.id
)
SELECT installation_config_ciphertext FROM consumed;

-- name: RevokeUserMachine :execrows
UPDATE user_machines
SET state = sqlc.arg(state), online = false, seat_state = sqlc.arg(seat_state),
    revoked_at = CASE WHEN sqlc.arg(state) = 'revoked' THEN now() ELSE revoked_at END,
    disconnected_at = CASE WHEN sqlc.arg(state) = 'disconnected' THEN now() ELSE disconnected_at END,
    updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL;

-- name: DeleteUserMachine :execrows
UPDATE user_machines
SET state = 'deleted', online = false, seat_state = 'released', deleted_at = now(),
    updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND deleted_at IS NULL;

-- name: UpsertUserMachineBandwidthPeriod :one
INSERT INTO user_machine_bandwidth_periods (
  id, user_machine_id, period_start, period_end, included_bytes
) VALUES (
  sqlc.arg(id), sqlc.arg(user_machine_id), sqlc.arg(period_start),
  sqlc.arg(period_end), sqlc.arg(included_bytes)
) ON CONFLICT (user_machine_id, period_start) DO UPDATE SET updated_at = now()
RETURNING *;

-- name: GetUserMachineBandwidthPeriodForUpdate :one
SELECT * FROM user_machine_bandwidth_periods
WHERE user_machine_id = sqlc.arg(user_machine_id)
  AND period_start = sqlc.arg(period_start) FOR UPDATE;

-- name: GetUserMachineForEnvironmentBandwidthUpdate :one
SELECT * FROM user_machines
WHERE environment_id = sqlc.arg(environment_id) AND deleted_at IS NULL
FOR UPDATE;

-- name: ConsumeUserMachineIncludedBandwidth :execrows
UPDATE user_machine_bandwidth_periods
SET consumed_included_bytes = consumed_included_bytes + sqlc.arg(bytes), updated_at = now()
WHERE id = sqlc.arg(id) AND consumed_included_bytes + sqlc.arg(bytes) <= included_bytes;

-- name: ListActiveUserMachineTopupsForUpdate :many
SELECT * FROM user_machine_bandwidth_topups
WHERE user_id = sqlc.arg(user_id) AND state = 'active' AND remaining_bytes > 0
  AND (expires_at IS NULL OR expires_at > now())
ORDER BY created_at, id FOR UPDATE;

-- name: ConsumeUserMachineTopup :execrows
UPDATE user_machine_bandwidth_topups
SET remaining_bytes = remaining_bytes - sqlc.arg(bytes),
    state = CASE WHEN remaining_bytes - sqlc.arg(bytes) = 0 THEN 'exhausted' ELSE 'active' END,
    consumed_at = CASE WHEN remaining_bytes - sqlc.arg(bytes) = 0 THEN now() ELSE consumed_at END,
    updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'active' AND remaining_bytes >= sqlc.arg(bytes);

-- name: RecordUserMachineTopupConsumption :execrows
UPDATE user_machine_bandwidth_periods
SET consumed_topup_bytes = consumed_topup_bytes + sqlc.arg(bytes), updated_at = now()
WHERE id = sqlc.arg(id);

-- name: CreateUserMachineBandwidthTopup :execrows
INSERT INTO user_machine_bandwidth_topups (
  id, user_id, provider_order_id, purchased_bytes, remaining_bytes, expires_at
) VALUES (
  sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(provider_order_id), sqlc.arg(purchased_bytes),
  sqlc.arg(purchased_bytes), sqlc.arg(expires_at)
) ON CONFLICT (provider_order_id) DO NOTHING;

-- name: VoidUserMachineBandwidthTopup :execrows
UPDATE user_machine_bandwidth_topups
SET state = 'void', remaining_bytes = 0, consumed_at = now(), updated_at = now()
WHERE user_id = sqlc.arg(user_id)
  AND provider_order_id = sqlc.arg(provider_order_id)
  AND state = 'active';

-- name: CreateUserMachineAccessSession :exec
INSERT INTO user_machine_access_sessions (
  id, user_machine_id, user_id, environment_id, cli_client_session_id,
  http_base_url, helper_terminal_session_id, helper_file_session_id, expires_at
) VALUES (
  sqlc.arg(id), sqlc.arg(user_machine_id), sqlc.arg(user_id), sqlc.arg(environment_id), sqlc.arg(cli_client_session_id),
  sqlc.arg(http_base_url), nullif(sqlc.arg(helper_terminal_session_id), ''), nullif(sqlc.arg(helper_file_session_id), ''), sqlc.arg(expires_at)
);

-- name: RevokeUserMachineAccessSessions :many
UPDATE user_machine_access_sessions
SET state = 'revoked', revoked_at = now(), revocation_reason = sqlc.arg(reason), updated_at = now()
WHERE user_machine_id = sqlc.arg(user_machine_id)
  AND state = 'active'
RETURNING id, user_id, user_machine_id, environment_id, cli_client_session_id,
  http_base_url, coalesce(helper_terminal_session_id, '') AS helper_terminal_session_id,
  coalesce(helper_file_session_id, '') AS helper_file_session_id, revocation_reason;

-- name: RevokeUserMachineAccessSessionsForUser :many
UPDATE user_machine_access_sessions
SET state = 'revoked', revoked_at = now(), revocation_reason = sqlc.arg(reason), updated_at = now()
WHERE user_id = sqlc.arg(user_id)
  AND state = 'active'
RETURNING id, user_id, user_machine_id, environment_id, cli_client_session_id,
  http_base_url, coalesce(helper_terminal_session_id, '') AS helper_terminal_session_id,
  coalesce(helper_file_session_id, '') AS helper_file_session_id, revocation_reason;

-- name: ListPendingUserMachineAccessSessionRevocations :many
SELECT id, user_id, user_machine_id, environment_id, cli_client_session_id,
  http_base_url, coalesce(helper_terminal_session_id, '') AS helper_terminal_session_id,
  coalesce(helper_file_session_id, '') AS helper_file_session_id, revocation_reason
FROM user_machine_access_sessions
WHERE state = 'revoked' AND helper_revoked_at IS NULL
ORDER BY created_at, id;

-- name: MarkUserMachineAccessSessionRevoked :execrows
UPDATE user_machine_access_sessions
SET helper_revoked_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'revoked' AND helper_revoked_at IS NULL;

-- name: CreateDefaultUserMachineTerminalSession :exec
INSERT INTO user_machine_terminal_sessions (id,user_machine_id,terminal_id,name,is_default,launch_cwd)
VALUES (sqlc.arg(id),sqlc.arg(user_machine_id),'term-1','default',true,sqlc.arg(launch_cwd))
ON CONFLICT (user_machine_id) WHERE is_default AND deleted_at IS NULL DO NOTHING;

-- name: GetUserMachineTerminalSession :one
SELECT s.* FROM user_machine_terminal_sessions s
JOIN user_machines m ON m.id=s.user_machine_id
WHERE s.id=sqlc.arg(id) AND s.user_machine_id=sqlc.arg(user_machine_id)
  AND m.user_id=sqlc.arg(user_id) AND m.deleted_at IS NULL AND s.deleted_at IS NULL;

-- name: GetDefaultUserMachineTerminalSession :one
SELECT s.* FROM user_machine_terminal_sessions s
JOIN user_machines m ON m.id=s.user_machine_id
WHERE s.user_machine_id=sqlc.arg(user_machine_id) AND m.user_id=sqlc.arg(user_id)
  AND m.deleted_at IS NULL AND s.is_default AND s.deleted_at IS NULL;

-- name: ListUserMachineTerminalSessions :many
SELECT s.* FROM user_machine_terminal_sessions s
JOIN user_machines m ON m.id=s.user_machine_id
WHERE s.user_machine_id=sqlc.arg(user_machine_id) AND m.user_id=sqlc.arg(user_id)
  AND m.deleted_at IS NULL AND s.deleted_at IS NULL
ORDER BY s.is_default DESC, s.last_activity_at DESC NULLS LAST, s.name;

-- name: GetUserMachineTerminalSessionByIdempotencyKey :one
SELECT s.* FROM user_machine_terminal_sessions s
JOIN user_machines m ON m.id=s.user_machine_id
WHERE s.user_machine_id=sqlc.arg(user_machine_id) AND m.user_id=sqlc.arg(user_id)
  AND s.idempotency_key=sqlc.arg(idempotency_key) AND s.deleted_at IS NULL;

-- name: LockUserMachineTerminalSessions :one
SELECT id FROM user_machines
WHERE id=sqlc.arg(user_machine_id) AND user_id=sqlc.arg(user_id) AND deleted_at IS NULL FOR UPDATE;

-- name: CountActiveUserMachineTerminalSessions :one
SELECT count(*)::integer FROM user_machine_terminal_sessions
WHERE user_machine_id=sqlc.arg(user_machine_id) AND deleted_at IS NULL;

-- name: SelectUserMachineTerminalSessionForEviction :one
SELECT * FROM user_machine_terminal_sessions
WHERE user_machine_id=sqlc.arg(user_machine_id) AND deleted_at IS NULL AND NOT is_default
ORDER BY (desired_state='closed') DESC,
         coalesce(last_activity_at,updated_at,created_at) ASC,
         created_at ASC,
         id ASC
LIMIT 1 FOR UPDATE;

-- name: NextUserMachineTerminalSessionOrdinal :one
SELECT coalesce(max(auto_name_ordinal),1)::integer+1 FROM user_machine_terminal_sessions
WHERE user_machine_id=sqlc.arg(user_machine_id);

-- name: CreateUserMachineTerminalSession :exec
INSERT INTO user_machine_terminal_sessions (id,user_machine_id,terminal_id,name,auto_name_ordinal,idempotency_key,launch_cwd)
VALUES (sqlc.arg(id),sqlc.arg(user_machine_id),sqlc.arg(terminal_id),sqlc.arg(name),nullif(sqlc.arg(auto_name_ordinal),0),sqlc.arg(idempotency_key),sqlc.arg(launch_cwd));

-- name: RenameUserMachineTerminalSession :execrows
UPDATE user_machine_terminal_sessions SET name=sqlc.arg(name),version=version+1,updated_at=now()
WHERE user_machine_id=sqlc.arg(user_machine_id) AND id=sqlc.arg(id)
  AND deleted_at IS NULL AND NOT is_default;

-- name: CloseUserMachineTerminalSession :execrows
UPDATE user_machine_terminal_sessions SET desired_state='closed',version=version+1,updated_at=now()
WHERE user_machine_id=sqlc.arg(user_machine_id) AND id=sqlc.arg(id)
  AND deleted_at IS NULL AND desired_state<>'closed';

-- name: DeleteUserMachineTerminalSession :execrows
UPDATE user_machine_terminal_sessions SET desired_state='deleted',deleted_at=now(),version=version+1,updated_at=now()
WHERE user_machine_id=sqlc.arg(user_machine_id) AND id=sqlc.arg(id)
  AND deleted_at IS NULL AND NOT is_default;

-- name: QueueUserMachineTerminalSessionOperation :exec
INSERT INTO user_machine_terminal_session_operations (id,user_machine_id,terminal_session_id,operation)
VALUES (sqlc.arg(id),sqlc.arg(user_machine_id),sqlc.arg(terminal_session_id),sqlc.arg(operation))
ON CONFLICT (terminal_session_id,operation) WHERE state='pending' DO NOTHING;

-- name: UserMachineTerminalSessionOperationPending :one
SELECT EXISTS (
  SELECT 1 FROM user_machine_terminal_session_operations
  WHERE user_machine_id=sqlc.arg(user_machine_id)
    AND terminal_session_id=sqlc.arg(terminal_session_id) AND state='pending'
);

-- name: ListDueUserMachineTerminalSessionOperations :many
SELECT o.id,o.user_machine_id,o.terminal_session_id,o.operation,o.attempts,
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
    ORDER BY r.id LIMIT 1), '')::text AS provider_route_http_base_url,s.thread_id,s.terminal_id
FROM user_machine_terminal_session_operations o
JOIN user_machines m ON m.id=o.user_machine_id
JOIN user_machine_terminal_sessions s ON s.id=o.terminal_session_id
WHERE o.state='pending' AND o.next_attempt_at<=now()
ORDER BY o.created_at LIMIT sqlc.arg(batch_size);

-- name: ListPendingUserMachineTerminalSessionOperations :many
SELECT o.id,o.user_machine_id,o.terminal_session_id,o.operation,o.attempts,
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
    ORDER BY r.id LIMIT 1), '')::text AS provider_route_http_base_url,s.thread_id,s.terminal_id
FROM user_machine_terminal_session_operations o
JOIN user_machines m ON m.id=o.user_machine_id
JOIN user_machine_terminal_sessions s ON s.id=o.terminal_session_id
WHERE o.user_machine_id=sqlc.arg(user_machine_id) AND o.state='pending'
ORDER BY o.created_at LIMIT sqlc.arg(batch_size);

-- name: MarkUserMachineTerminalSessionOperationApplied :exec
UPDATE user_machine_terminal_session_operations
SET state='applied',completed_at=now(),updated_at=now(),last_error=NULL
WHERE id=sqlc.arg(id) AND state='pending';

-- name: MarkUserMachineTerminalSessionRuntimeClosed :exec
UPDATE user_machine_terminal_sessions
SET runtime_state='closed',updated_at=now(),version=version+1
WHERE id=sqlc.arg(id) AND deleted_at IS NULL;

-- name: RetryUserMachineTerminalSessionOperation :exec
UPDATE user_machine_terminal_session_operations
SET attempts=attempts+1,next_attempt_at=now()+make_interval(secs => sqlc.arg(retry_seconds)),last_error=sqlc.arg(last_error),updated_at=now()
WHERE id=sqlc.arg(id) AND state='pending';
