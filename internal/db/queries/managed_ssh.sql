-- name: ResolveManagedSSHClientAuthorityForUpdate :one
SELECT session.id AS cli_client_session_id, session.user_id, session.version
FROM cli_client_sessions session
JOIN users owner ON owner.id = session.user_id
WHERE session.id = sqlc.arg(cli_client_session_id)
  AND session.user_id = sqlc.arg(user_id)
  AND session.state = 'active'
  AND session.revoked_at IS NULL
  AND owner.status = 'active'
FOR UPDATE OF session, owner;

-- name: GetManagedSSHOperationForUpdate :one
SELECT * FROM managed_ssh_operations
WHERE operation_id = sqlc.arg(operation_id)
FOR UPDATE;

-- name: CreateManagedSSHOperation :one
INSERT INTO managed_ssh_operations
  (operation_id, user_id, operation_kind, request_hash, resource_id,
   result_revision, created_at)
VALUES
  (sqlc.arg(operation_id), sqlc.arg(user_id), sqlc.arg(operation_kind),
   sqlc.arg(request_hash), sqlc.arg(resource_id), sqlc.arg(result_revision),
   sqlc.arg(created_at))
RETURNING *;

-- name: GetManagedSSHClientKeyByFingerprint :one
SELECT * FROM managed_ssh_client_keys
WHERE fingerprint = sqlc.arg(fingerprint)
FOR UPDATE;

-- name: GetActiveManagedSSHClientKeyForUpdate :one
SELECT * FROM managed_ssh_client_keys
WHERE cli_client_session_id = sqlc.arg(cli_client_session_id) AND state = 'active'
FOR UPDATE;

-- name: CreateManagedSSHClientKey :one
INSERT INTO managed_ssh_client_keys
  (fingerprint, user_id, cli_client_session_id, algorithm, public_key,
   reconciliation_version, created_at)
VALUES
  (sqlc.arg(fingerprint), sqlc.arg(user_id), sqlc.arg(cli_client_session_id),
   sqlc.arg(algorithm), sqlc.arg(public_key), sqlc.arg(reconciliation_version),
   sqlc.arg(created_at))
RETURNING *;

-- name: RevokeManagedSSHClientKey :one
UPDATE managed_ssh_client_keys
SET state = 'revoked', revoked_at = sqlc.arg(revoked_at),
    revocation_reason = sqlc.arg(revocation_reason),
    reconciliation_version = reconciliation_version + 1
WHERE fingerprint = sqlc.arg(fingerprint) AND state = 'active'
RETURNING *;

-- name: ListActiveManagedSSHClientKeysForUser :many
SELECT k.* FROM managed_ssh_client_keys k
JOIN cli_client_sessions cs ON cs.id = k.cli_client_session_id AND cs.state = 'active'
WHERE k.user_id = sqlc.arg(user_id) AND k.state = 'active'
ORDER BY k.cli_client_session_id;

-- name: ResolveMachineSSHHostKeyAuthorityForUpdate :one
SELECT machine.id AS user_machine_id, machine.user_id, machine.installation_generation
FROM user_machines machine
JOIN users owner ON owner.id = machine.user_id
WHERE machine.id = sqlc.arg(user_machine_id)
  AND machine.user_id = sqlc.arg(user_id)
  AND machine.installation_generation = sqlc.arg(machine_generation)
  AND machine.state NOT IN ('revoked', 'deleted')
  AND machine.deleted_at IS NULL
  AND owner.status = 'active'
FOR UPDATE OF machine, owner;

-- name: GetMachineSSHTargetForUpdate :one
SELECT * FROM machine_ssh_targets
WHERE user_machine_id = sqlc.arg(user_machine_id)
FOR UPDATE;

-- name: CreateMachineSSHTarget :one
INSERT INTO machine_ssh_targets
  (user_machine_id, machine_generation, os_user, target_port,
   reconciliation_version, created_at, updated_at)
VALUES
  (sqlc.arg(user_machine_id), sqlc.arg(machine_generation), sqlc.arg(os_user),
   sqlc.arg(target_port), 1, sqlc.arg(now), sqlc.arg(now))
RETURNING *;

-- name: ReplaceMachineSSHTargetGeneration :one
UPDATE machine_ssh_targets
SET machine_generation = sqlc.arg(machine_generation), os_user = sqlc.arg(os_user),
    target_port = sqlc.arg(target_port),
    reconciliation_version = reconciliation_version + 1, updated_at = sqlc.arg(now)
WHERE user_machine_id = sqlc.arg(user_machine_id)
  AND machine_generation < sqlc.arg(machine_generation)
RETURNING *;

-- name: UpdateMachineSSHTargetPort :one
UPDATE machine_ssh_targets
SET target_port = sqlc.arg(target_port),
    reconciliation_version = reconciliation_version + 1, updated_at = sqlc.arg(now)
WHERE user_machine_id = sqlc.arg(user_machine_id)
  AND machine_generation = sqlc.arg(machine_generation)
  AND reconciliation_version = sqlc.arg(expected_reconciliation_version)
RETURNING *;

-- name: GetMachineSSHHostKeyOwner :one
SELECT * FROM machine_ssh_host_key_owners
WHERE fingerprint = sqlc.arg(fingerprint);

-- name: CreateMachineSSHHostKeyOwner :one
INSERT INTO machine_ssh_host_key_owners
  (fingerprint, user_machine_id, algorithm, public_key, first_observed_at)
VALUES
  (sqlc.arg(fingerprint), sqlc.arg(user_machine_id), sqlc.arg(algorithm),
   sqlc.arg(public_key), sqlc.arg(first_observed_at))
RETURNING *;

-- name: GetMachineSSHHostKeySetByObservation :one
SELECT * FROM machine_ssh_host_key_sets
WHERE user_machine_id = sqlc.arg(user_machine_id)
  AND machine_generation = sqlc.arg(machine_generation)
  AND observation_generation = sqlc.arg(observation_generation)
FOR UPDATE;

-- name: GetMachineSSHHostKeySetByID :one
SELECT * FROM machine_ssh_host_key_sets
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: GetActiveMachineSSHHostKeySetForUpdate :one
SELECT * FROM machine_ssh_host_key_sets
WHERE user_machine_id = sqlc.arg(user_machine_id) AND state = 'active'
FOR UPDATE;

-- name: GetPendingMachineSSHHostKeySetForUpdate :one
SELECT * FROM machine_ssh_host_key_sets
WHERE user_machine_id = sqlc.arg(user_machine_id) AND state = 'pending'
FOR UPDATE;

-- name: CreateMachineSSHHostKeySet :one
INSERT INTO machine_ssh_host_key_sets
  (id, user_machine_id, machine_generation, observation_generation,
   set_fingerprint, state, reconciliation_version, observed_at, promoted_at)
VALUES
  (sqlc.arg(id), sqlc.arg(user_machine_id), sqlc.arg(machine_generation),
   sqlc.arg(observation_generation), sqlc.arg(set_fingerprint), sqlc.arg(state),
   sqlc.arg(reconciliation_version), sqlc.arg(observed_at), sqlc.narg(promoted_at))
RETURNING *;

-- name: AddMachineSSHHostKeyToSet :exec
INSERT INTO machine_ssh_host_keys (set_id, user_machine_id, fingerprint, ordinal)
VALUES (sqlc.arg(set_id), sqlc.arg(user_machine_id), sqlc.arg(fingerprint), sqlc.arg(ordinal));

-- name: ListMachineSSHHostKeysForSet :many
SELECT member.ordinal, owner.fingerprint, owner.algorithm, owner.public_key
FROM machine_ssh_host_keys member
JOIN machine_ssh_host_key_owners owner
  ON owner.fingerprint = member.fingerprint
 AND owner.user_machine_id = member.user_machine_id
WHERE member.set_id = sqlc.arg(set_id)
ORDER BY member.ordinal;

-- name: RejectPendingMachineSSHHostKeySet :one
UPDATE machine_ssh_host_key_sets
SET state = 'rejected', rejected_at = sqlc.arg(rejected_at),
    rejection_reason = sqlc.arg(rejection_reason),
    reconciliation_version = reconciliation_version + 1
WHERE id = sqlc.arg(id) AND state = 'pending'
RETURNING *;

-- name: SupersedeActiveMachineSSHHostKeySet :one
UPDATE machine_ssh_host_key_sets
SET state = 'superseded', reconciliation_version = reconciliation_version + 1
WHERE id = sqlc.arg(id) AND state = 'active'
RETURNING *;

-- name: PromotePendingMachineSSHHostKeySet :one
UPDATE machine_ssh_host_key_sets
SET state = 'active', promoted_at = sqlc.arg(promoted_at),
    reconciliation_version = reconciliation_version + 1
WHERE id = sqlc.arg(id) AND state = 'pending'
RETURNING *;
