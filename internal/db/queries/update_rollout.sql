-- name: GetUserMachineUpdateObservation :one
SELECT user_machine_id, environment_id, schema, current_version, target_version,
       channel, state, error_code, operation_id, installation_generation,
       worker_generation, os_boot_id, rollback_count, observed_at, payload_hash,
       created_at, updated_at
FROM user_machine_update_observations
WHERE user_machine_id = sqlc.arg(user_machine_id)
  AND environment_id = sqlc.arg(environment_id);

-- name: CreateUserMachineUpdateObservation :one
INSERT INTO user_machine_update_observations (
  user_machine_id, environment_id, schema, current_version, target_version,
  channel, state, error_code, operation_id, installation_generation,
  worker_generation, os_boot_id, rollback_count, observed_at, payload_hash
) VALUES (
  sqlc.arg(user_machine_id), sqlc.arg(environment_id), sqlc.arg(schema),
  sqlc.arg(current_version), NULLIF(sqlc.arg(target_version), ''), sqlc.arg(channel),
  sqlc.arg(state), NULLIF(sqlc.arg(error_code), ''), sqlc.arg(operation_id),
  sqlc.arg(installation_generation), sqlc.arg(worker_generation), sqlc.arg(os_boot_id),
  sqlc.arg(rollback_count), sqlc.arg(observed_at), sqlc.arg(payload_hash)
)
ON CONFLICT (user_machine_id) DO NOTHING
RETURNING user_machine_id, environment_id, schema, current_version, target_version,
          channel, state, error_code, operation_id, installation_generation,
          worker_generation, os_boot_id, rollback_count, observed_at, payload_hash,
          created_at, updated_at;

-- name: UpdateUserMachineUpdateObservation :one
UPDATE user_machine_update_observations
SET environment_id = sqlc.arg(environment_id), schema = sqlc.arg(schema),
    current_version = sqlc.arg(current_version), target_version = NULLIF(sqlc.arg(target_version), ''),
    channel = sqlc.arg(channel), state = sqlc.arg(state), error_code = NULLIF(sqlc.arg(error_code), ''),
    operation_id = sqlc.arg(operation_id), installation_generation = sqlc.arg(installation_generation),
    worker_generation = sqlc.arg(worker_generation), os_boot_id = sqlc.arg(os_boot_id),
    rollback_count = sqlc.arg(rollback_count), observed_at = sqlc.arg(observed_at),
    payload_hash = sqlc.arg(payload_hash), updated_at = now()
WHERE user_machine_id = sqlc.arg(user_machine_id)
  AND environment_id = sqlc.arg(expected_environment_id)
RETURNING user_machine_id, environment_id, schema, current_version, target_version,
          channel, state, error_code, operation_id, installation_generation,
          worker_generation, os_boot_id, rollback_count, observed_at, payload_hash,
          created_at, updated_at;

-- name: GetUserMachineMaintenanceApprovalForIdempotency :one
SELECT id, user_machine_id, user_id, schema, action, target_version, reason, status,
       idempotency_key, request_hash, expires_at, decided_at, decided_by_user_id,
       version, created_at, updated_at
FROM user_machine_maintenance_approvals
WHERE user_id = sqlc.arg(user_id)
  AND user_machine_id = sqlc.arg(user_machine_id)
  AND idempotency_key = sqlc.arg(idempotency_key);

-- name: CreateUserMachineMaintenanceApproval :one
INSERT INTO user_machine_maintenance_approvals (
  id, user_machine_id, user_id, schema, action, target_version, reason,
  idempotency_key, request_hash, expires_at
) VALUES (
  sqlc.arg(id), sqlc.arg(user_machine_id), sqlc.arg(user_id), sqlc.arg(schema),
  sqlc.arg(action), sqlc.arg(target_version), sqlc.arg(reason), sqlc.arg(idempotency_key),
  sqlc.arg(request_hash), sqlc.arg(expires_at)
)
ON CONFLICT (user_id, user_machine_id, idempotency_key) DO NOTHING
RETURNING id, user_machine_id, user_id, schema, action, target_version, reason, status,
          idempotency_key, request_hash, expires_at, decided_at, decided_by_user_id,
          version, created_at, updated_at;

-- name: ListUserMachineMaintenanceApprovals :many
SELECT id, user_machine_id, user_id, schema, action, target_version, reason, status,
       idempotency_key, request_hash, expires_at, decided_at, decided_by_user_id,
       version, created_at, updated_at
FROM user_machine_maintenance_approvals
WHERE user_id = sqlc.arg(user_id) AND user_machine_id = sqlc.arg(user_machine_id)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ExpireDueUserMachineMaintenanceApprovals :execrows
UPDATE user_machine_maintenance_approvals
SET status = 'expired', version = version + 1, updated_at = now()
WHERE user_id = sqlc.arg(user_id) AND user_machine_id = sqlc.arg(user_machine_id)
  AND status = 'pending' AND expires_at <= now();

-- name: GetUserMachineMaintenanceApprovalForUpdate :one
SELECT id, user_machine_id, user_id, schema, action, target_version, reason, status,
       idempotency_key, request_hash, expires_at, decided_at, decided_by_user_id,
       version, created_at, updated_at
FROM user_machine_maintenance_approvals
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
  AND user_machine_id = sqlc.arg(user_machine_id)
FOR UPDATE;

-- name: ExpireUserMachineMaintenanceApproval :one
UPDATE user_machine_maintenance_approvals
SET status = 'expired', version = version + 1, updated_at = now()
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
  AND user_machine_id = sqlc.arg(user_machine_id) AND status = 'pending'
RETURNING id, user_machine_id, user_id, schema, action, target_version, reason, status,
          idempotency_key, request_hash, expires_at, decided_at, decided_by_user_id,
          version, created_at, updated_at;

-- name: DecideUserMachineMaintenanceApproval :one
UPDATE user_machine_maintenance_approvals
SET status = sqlc.arg(status), decided_at = now(), decided_by_user_id = sqlc.arg(decided_by_user_id),
    version = version + 1, updated_at = now()
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
  AND user_machine_id = sqlc.arg(user_machine_id) AND status = 'pending'
  AND version = sqlc.arg(expected_version) AND expires_at > now()
RETURNING id, user_machine_id, user_id, schema, action, target_version, reason, status,
          idempotency_key, request_hash, expires_at, decided_at, decided_by_user_id,
          version, created_at, updated_at;

-- name: ConsumeUserMachineMaintenanceApproval :one
UPDATE user_machine_maintenance_approvals
SET status = 'consumed', version = version + 1, updated_at = now()
WHERE id = sqlc.arg(id) AND user_machine_id = sqlc.arg(user_machine_id)
  AND status = 'approved' AND expires_at > now()
RETURNING id, user_machine_id, user_id, schema, action, target_version, reason, status,
          idempotency_key, request_hash, expires_at, decided_at, decided_by_user_id,
          version, created_at, updated_at;
