-- name: CreateControlEnvironment :one
INSERT INTO control_environments (id, workspace_id, owner_user_id, desired_state)
VALUES (sqlc.arg(id), sqlc.arg(workspace_id), sqlc.arg(owner_user_id), sqlc.arg(desired_state))
RETURNING *;

-- name: CreateControlHelper :one
INSERT INTO control_helpers (id, environment_id)
VALUES (sqlc.arg(id), sqlc.arg(environment_id))
RETURNING *;

-- name: CreateControlConfigRepository :one
INSERT INTO control_config_repositories
  (id, owner_user_id, provider, external_ref, display_name, provider_account_id,
   external_repository_id, clone_url, publish_url, default_branch, authorization_ref,
   credential_capability, observed_revision)
VALUES
  (sqlc.arg(id), sqlc.arg(owner_user_id), sqlc.arg(provider), sqlc.arg(external_ref), sqlc.arg(display_name),
   sqlc.arg(provider_account_id), sqlc.arg(external_repository_id), sqlc.arg(clone_url), sqlc.arg(publish_url),
   sqlc.arg(default_branch), sqlc.arg(authorization_ref), sqlc.arg(credential_capability), sqlc.narg(observed_revision))
ON CONFLICT (owner_user_id, provider, external_ref) DO UPDATE
SET display_name = EXCLUDED.display_name, provider_account_id = EXCLUDED.provider_account_id,
    external_repository_id = EXCLUDED.external_repository_id, clone_url = EXCLUDED.clone_url,
    publish_url = EXCLUDED.publish_url, default_branch = EXCLUDED.default_branch,
    authorization_ref = EXCLUDED.authorization_ref, credential_capability = EXCLUDED.credential_capability,
    observed_revision = EXCLUDED.observed_revision, state = 'active', disconnected_at = NULL,
    version = control_config_repositories.version + 1, updated_at = now()
RETURNING *;

-- name: ListControlConfigRepositories :many
SELECT * FROM control_config_repositories
WHERE owner_user_id = sqlc.arg(owner_user_id) AND state = 'active'
ORDER BY display_name, id LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: GetOwnedControlConfigRepository :one
SELECT * FROM control_config_repositories
WHERE id = sqlc.arg(id) AND owner_user_id = sqlc.arg(owner_user_id) AND state = 'active';

-- name: GetActiveControlConfigRepository :one
SELECT * FROM control_config_repositories
WHERE id = sqlc.arg(id) AND state = 'active';

-- name: DisconnectOwnedControlConfigRepository :one
UPDATE control_config_repositories
SET state = 'disconnected', disconnected_at = sqlc.arg(now), version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND owner_user_id = sqlc.arg(owner_user_id) AND state = 'active'
RETURNING *;

-- name: RevokeControlConfigCredentialsForRepository :execrows
UPDATE control_config_credentials c
SET revoked_at = coalesce(c.revoked_at, sqlc.arg(now))
FROM control_config_assignments a
WHERE a.repository_id = sqlc.arg(repository_id) AND c.assignment_id = a.id AND c.revoked_at IS NULL;

-- name: RevokeControlConfigRepositoryAccessForRepository :execrows
UPDATE control_config_repository_access_operations
SET state = 'revoked', revoked_at = coalesce(revoked_at, sqlc.arg(now)), updated_at = sqlc.arg(now)
WHERE repository_id = sqlc.arg(repository_id) AND revoked_at IS NULL AND state IN ('pending','issued','uncertain');

-- name: DisableControlConfigAssignmentsForRepository :execrows
UPDATE control_config_assignments
SET consent_state = 'revoked', accepted_at = NULL, revoked_at = sqlc.arg(now),
    version = version + 1, updated_at = sqlc.arg(now)
WHERE repository_id = sqlc.arg(repository_id) AND revoked_at IS NULL;

-- name: EnsureControlConfigLeaseAuthority :one
INSERT INTO control_config_repository_lease_authority (repository_id)
VALUES (sqlc.arg(repository_id))
ON CONFLICT (repository_id) DO UPDATE SET repository_id = EXCLUDED.repository_id
RETURNING *;

-- name: GetControlConfigLeaseAuthorityForUpdate :one
SELECT * FROM control_config_repository_lease_authority
WHERE repository_id = sqlc.arg(repository_id)
FOR UPDATE;

-- name: GrantControlConfigRepositoryLease :one
UPDATE control_config_repository_lease_authority
SET last_fencing_token = last_fencing_token + 1,
    lease_id = sqlc.arg(lease_id),
    assignment_id = sqlc.arg(assignment_id),
    environment_id = sqlc.arg(environment_id),
    machine_id = sqlc.arg(machine_id),
    installation_generation = sqlc.arg(installation_generation),
    base_remote_revision = sqlc.narg(base_remote_revision),
    operation_id = sqlc.arg(operation_id),
    acquired_at = sqlc.arg(now),
    expires_at = sqlc.arg(expires_at),
    revoked_at = NULL,
    version = version + 1,
    updated_at = sqlc.arg(now)
WHERE repository_id = sqlc.arg(repository_id)
  AND (lease_id IS NULL OR revoked_at IS NOT NULL OR expires_at <= sqlc.arg(now))
RETURNING *;

-- name: RenewControlConfigRepositoryLease :one
UPDATE control_config_repository_lease_authority
SET expires_at = sqlc.arg(expires_at), version = version + 1, updated_at = sqlc.arg(now)
WHERE repository_id = sqlc.arg(repository_id) AND lease_id = sqlc.arg(lease_id)
  AND last_fencing_token = sqlc.arg(fencing_token) AND revoked_at IS NULL
  AND expires_at > sqlc.arg(now)
RETURNING *;

-- name: ReleaseControlConfigRepositoryLease :one
UPDATE control_config_repository_lease_authority
SET lease_id = NULL, assignment_id = NULL, environment_id = NULL, machine_id = NULL,
    installation_generation = NULL, base_remote_revision = NULL, operation_id = NULL,
    acquired_at = NULL, expires_at = NULL, revoked_at = NULL,
    version = version + 1, updated_at = sqlc.arg(now)
WHERE repository_id = sqlc.arg(repository_id) AND lease_id = sqlc.arg(lease_id)
  AND last_fencing_token = sqlc.arg(fencing_token) AND revoked_at IS NULL
RETURNING *;

-- name: RevokeControlConfigRepositoryLease :one
UPDATE control_config_repository_lease_authority
SET revoked_at = sqlc.arg(now), version = version + 1, updated_at = sqlc.arg(now)
WHERE repository_id = sqlc.arg(repository_id) AND lease_id IS NOT NULL AND revoked_at IS NULL
RETURNING *;

-- name: RevokeControlConfigRepositoryLeasesForEnvironment :execrows
UPDATE control_config_repository_lease_authority
SET revoked_at = sqlc.arg(now), version = version + 1, updated_at = sqlc.arg(now)
WHERE environment_id = sqlc.arg(environment_id) AND lease_id IS NOT NULL AND revoked_at IS NULL;

-- name: CreateControlConfigLeaseOperation :one
INSERT INTO control_config_repository_lease_operations
  (operation_id, operation_type, request_hash, repository_id, assignment_id, environment_id,
   machine_id, base_remote_revision, lease_id, fencing_token, result_state, expires_at)
VALUES
  (sqlc.arg(operation_id), sqlc.arg(operation_type), sqlc.arg(request_hash), sqlc.arg(repository_id),
   sqlc.narg(assignment_id), sqlc.narg(environment_id), sqlc.narg(machine_id), sqlc.narg(base_remote_revision),
   sqlc.narg(lease_id), sqlc.narg(fencing_token), sqlc.arg(result_state), sqlc.narg(expires_at))
ON CONFLICT (operation_id) DO NOTHING
RETURNING *;

-- name: GetControlConfigLeaseOperation :one
SELECT * FROM control_config_repository_lease_operations WHERE operation_id = sqlc.arg(operation_id);

-- name: IsControlEnvironmentBYOD :one
SELECT EXISTS (
  SELECT 1 FROM user_machines
  WHERE environment_id = sqlc.arg(environment_id)
    AND machine_kind <> 'hosted'
    AND deleted_at IS NULL
);

-- name: GetControlConfigAssignment :one
SELECT * FROM control_config_assignments WHERE environment_id = $1;

-- name: SetControlConfigAssignment :one
INSERT INTO control_config_assignments (id, machine_id, environment_id, repository_id, mode, consent_state, warning_revision)
SELECT sqlc.arg(assignment_id), machine.id, sqlc.arg(environment_id), sqlc.arg(repository_id),
       sqlc.arg(mode), sqlc.arg(consent_state), sqlc.narg(warning_revision)
FROM user_machines machine
WHERE machine.environment_id = sqlc.arg(environment_id) AND machine.deleted_at IS NULL
ON CONFLICT (machine_id) DO UPDATE
SET id = EXCLUDED.id, repository_id = EXCLUDED.repository_id, mode = EXCLUDED.mode, consent_state = EXCLUDED.consent_state,
    warning_revision = EXCLUDED.warning_revision, accepted_at = NULL, revoked_at = NULL,
    version = control_config_assignments.version + 1, updated_at = sqlc.arg(now)
WHERE control_config_assignments.version = sqlc.arg(expected_version)
RETURNING *;

-- name: GetEligibleControlConfigAssignment :one
SELECT a.* FROM control_config_assignments a
JOIN user_machines m ON m.id = a.machine_id
JOIN control_environments e ON e.id = a.environment_id
JOIN users u ON u.id = e.owner_user_id
JOIN control_config_repositories r ON r.id = a.repository_id
WHERE a.environment_id = sqlc.arg(environment_id) AND m.id = sqlc.arg(machine_id)
  AND m.revoked_at IS NULL AND m.deleted_at IS NULL AND m.installation_generation = sqlc.arg(installation_generation)
  AND a.repository_id IS NOT NULL
  AND a.revoked_at IS NULL AND a.consent_state IN ('not_required','accepted')
  AND e.desired_state = 'active' AND e.revoked_at IS NULL
  AND u.status = 'active'
  AND r.state = 'active' AND r.disconnected_at IS NULL
FOR UPDATE OF a, m, e, u, r;

-- name: GetEligibleMachineConfigAssignment :one
SELECT a.* FROM control_config_assignments a
JOIN user_machines m ON m.id = a.machine_id
JOIN control_environments e ON e.id = a.environment_id
JOIN users u ON u.id = e.owner_user_id
JOIN control_config_repositories r ON r.id = a.repository_id
WHERE a.machine_id = sqlc.arg(machine_id) AND a.environment_id = sqlc.arg(environment_id)
  AND m.revoked_at IS NULL AND m.deleted_at IS NULL AND m.installation_generation = sqlc.arg(installation_generation)
  AND a.repository_id IS NOT NULL
  AND a.revoked_at IS NULL AND a.consent_state IN ('not_required','accepted')
  AND e.desired_state = 'active' AND e.revoked_at IS NULL
  AND u.status = 'active'
  AND r.state = 'active' AND r.disconnected_at IS NULL
FOR UPDATE OF a, m, e, u, r;

-- name: CreateControlConfigCredential :one
INSERT INTO control_config_credentials
  (jti_hash, jti, operation_key, request_hash, environment_id, machine_id, assignment_id,
   warning_revision, credential_ciphertext, expires_at)
VALUES
  (sqlc.arg(jti_hash), sqlc.arg(jti), sqlc.arg(operation_key), sqlc.arg(request_hash), sqlc.arg(environment_id),
   sqlc.arg(machine_id), sqlc.arg(assignment_id), sqlc.narg(warning_revision),
   sqlc.arg(credential_ciphertext), sqlc.arg(expires_at))
ON CONFLICT (operation_key) DO NOTHING
RETURNING *;

-- name: ListRevokedControlCredentialJTIs :many
SELECT revoked.jti FROM (
  SELECT c.jti, c.revoked_at FROM control_config_credentials c
  WHERE c.revoked_at IS NOT NULL AND c.expires_at > sqlc.arg(now)
  UNION ALL
  SELECT a.helper_terminal_session_id AS jti, a.revoked_at FROM access_sessions a
  WHERE a.revoked_at IS NOT NULL AND a.expires_at > sqlc.arg(now) AND a.helper_terminal_session_id IS NOT NULL
  UNION ALL
  SELECT a.helper_file_session_id AS jti, a.revoked_at FROM access_sessions a
  WHERE a.revoked_at IS NOT NULL AND a.expires_at > sqlc.arg(now) AND a.helper_file_session_id IS NOT NULL
  UNION ALL
  SELECT m.helper_terminal_session_id AS jti, m.revoked_at FROM user_machine_access_sessions m
  WHERE m.revoked_at IS NOT NULL AND m.expires_at > sqlc.arg(now) AND m.helper_terminal_session_id IS NOT NULL
  UNION ALL
  SELECT m.helper_file_session_id AS jti, m.revoked_at FROM user_machine_access_sessions m
  WHERE m.revoked_at IS NOT NULL AND m.expires_at > sqlc.arg(now) AND m.helper_file_session_id IS NOT NULL
  UNION ALL
  SELECT g.jti, coalesce(g.revoked_at, i.revoked_at, client.revoked_at, endpoint.revoked_at, root.revoked_at) AS revoked_at
  FROM peer_signaling_grants g
  JOIN peer_session_intents i ON i.id = g.intent_id
  JOIN cli_client_sessions client ON client.id = i.cli_client_session_id
  JOIN peer_endpoint_certificates endpoint ON endpoint.fingerprint = CASE g.role
    WHEN 'controlling' THEN i.controlling_certificate_fingerprint
    ELSE i.controlled_certificate_fingerprint END
  JOIN account_e2ee_roots root ON root.user_id = i.user_id
  WHERE g.expires_at > sqlc.arg(now) AND
    (g.revoked_at IS NOT NULL OR i.revoked_at IS NOT NULL OR client.state = 'revoked' OR endpoint.revoked_at IS NOT NULL OR root.revoked_at IS NOT NULL)
  UNION ALL
  SELECT relay.jti, coalesce(relay.revoked_at, i.revoked_at, client.revoked_at, controlling.revoked_at, controlled.revoked_at, root.revoked_at) AS revoked_at
  FROM peer_relay_allocations relay
  JOIN peer_session_intents i ON i.id = relay.intent_id
  JOIN cli_client_sessions client ON client.id = i.cli_client_session_id
  JOIN peer_endpoint_certificates controlling ON controlling.fingerprint = i.controlling_certificate_fingerprint
  JOIN peer_endpoint_certificates controlled ON controlled.fingerprint = i.controlled_certificate_fingerprint
  JOIN account_e2ee_roots root ON root.user_id = i.user_id
  WHERE relay.expires_at > sqlc.arg(now) AND
    (relay.revoked_at IS NOT NULL OR i.revoked_at IS NOT NULL OR client.state = 'revoked' OR controlling.revoked_at IS NOT NULL OR controlled.revoked_at IS NOT NULL OR root.revoked_at IS NOT NULL)
) revoked
ORDER BY revoked.revoked_at, revoked.jti
LIMIT sqlc.arg(row_limit);

-- name: ListRevokedConnectorGenerations :many
SELECT machine_id, connector_id, generation FROM control_connector_generations
WHERE state IN ('revoked','replaced')
ORDER BY updated_at, machine_id, connector_id
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

-- name: GetActiveControlConfigCredentialByJTI :one
SELECT * FROM control_config_credentials
WHERE jti = sqlc.arg(jti) AND environment_id = sqlc.arg(environment_id)
  AND machine_id = sqlc.arg(machine_id) AND assignment_id = sqlc.arg(assignment_id)
  AND revoked_at IS NULL AND expires_at > sqlc.arg(now);

-- name: RevokeControlConfigCredentialsForEnvironment :execrows
UPDATE control_config_credentials SET revoked_at = coalesce(revoked_at, sqlc.arg(revoked_at))
WHERE environment_id = sqlc.arg(environment_id) AND revoked_at IS NULL;

-- name: RevokeControlConfigRepositoryAccessForEnvironment :execrows
UPDATE control_config_repository_access_operations
SET state = 'revoked', revoked_at = coalesce(revoked_at, sqlc.arg(now)), updated_at = sqlc.arg(now)
WHERE environment_id = sqlc.arg(environment_id) AND revoked_at IS NULL AND state IN ('pending','issued','uncertain');

-- name: ReserveControlConfigRepositoryAccess :one
INSERT INTO control_config_repository_access_operations
  (operation_id, request_hash, repository_id, assignment_id, environment_id,
   machine_id, installation_generation, warning_revision)
VALUES
  (sqlc.arg(operation_id), sqlc.arg(request_hash), sqlc.arg(repository_id),
   sqlc.arg(assignment_id), sqlc.arg(environment_id), sqlc.arg(machine_id),
   sqlc.arg(installation_generation), sqlc.arg(warning_revision))
ON CONFLICT (operation_id) DO NOTHING
RETURNING *;

-- name: GetControlConfigRepositoryAccessOperation :one
SELECT * FROM control_config_repository_access_operations
WHERE operation_id = sqlc.arg(operation_id);

-- name: CompleteControlConfigRepositoryAccess :one
UPDATE control_config_repository_access_operations
SET state = 'issued', access_ciphertext = sqlc.arg(access_ciphertext),
    expires_at = sqlc.arg(expires_at), updated_at = sqlc.arg(now)
WHERE operation_id = sqlc.arg(operation_id) AND state = 'pending' AND revoked_at IS NULL
RETURNING *;

-- name: MarkControlConfigRepositoryAccessUncertain :execrows
UPDATE control_config_repository_access_operations
SET state = 'uncertain', last_error_code = sqlc.arg(last_error_code), updated_at = sqlc.arg(now)
WHERE operation_id = sqlc.arg(operation_id) AND state = 'pending' AND revoked_at IS NULL;

-- name: ListControlConfigRepositoryAccessPendingProviderRevoke :many
SELECT * FROM control_config_repository_access_operations
WHERE revoked_at IS NOT NULL AND provider_revoked_at IS NULL
  AND access_ciphertext IS NOT NULL AND expires_at > sqlc.arg(now)
ORDER BY revoked_at, operation_id
LIMIT sqlc.arg(row_limit);

-- name: MarkControlConfigRepositoryAccessProviderRevoked :execrows
UPDATE control_config_repository_access_operations
SET provider_revoked_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE operation_id = sqlc.arg(operation_id) AND revoked_at IS NOT NULL AND provider_revoked_at IS NULL;

-- name: RecordControlConfigRepositoryAccessRevokeFailure :execrows
UPDATE control_config_repository_access_operations
SET revoke_attempts = revoke_attempts + 1, last_error_code = sqlc.arg(last_error_code), updated_at = sqlc.arg(now)
WHERE operation_id = sqlc.arg(operation_id) AND revoked_at IS NOT NULL AND provider_revoked_at IS NULL;

-- name: AcceptControlConfigConsent :one
UPDATE control_config_assignments
SET consent_state = 'accepted', warning_revision = sqlc.arg(warning_revision), accepted_at = sqlc.arg(now),
    revoked_at = NULL, version = version + 1, updated_at = sqlc.arg(now)
WHERE environment_id = sqlc.arg(environment_id) AND version = sqlc.arg(expected_version)
  AND repository_id IS NOT NULL AND consent_state = 'pending'
  AND warning_revision = sqlc.arg(warning_revision)
RETURNING *;

-- name: RemoveControlConfigConsent :one
UPDATE control_config_assignments
SET consent_state = 'pending', warning_revision = sqlc.arg(warning_revision), accepted_at = NULL,
    revoked_at = NULL, version = version + 1, updated_at = sqlc.arg(now)
WHERE environment_id = sqlc.arg(environment_id) AND version = sqlc.arg(expected_version)
  AND repository_id IS NOT NULL AND consent_state = 'accepted'
RETURNING *;

-- name: GetControlConfigWarningContext :one
SELECT cm.display_name AS machine_name, cm.workspace_root AS canonical_scope,
	   r.display_name AS repository_name, a.mode
FROM control_config_assignments a
JOIN control_environments e ON e.id = a.environment_id
JOIN user_machines cm ON cm.environment_id = e.id AND cm.deleted_at IS NULL
JOIN control_config_repositories r ON r.id = a.repository_id AND r.state = 'active'
WHERE a.environment_id = sqlc.arg(environment_id) AND e.owner_user_id = sqlc.arg(owner_user_id)
  AND e.desired_state = 'active' AND e.revoked_at IS NULL AND a.revoked_at IS NULL;

-- name: ReconcileStaleControlConfigWarning :many
WITH stale AS (
  SELECT a.environment_id
  FROM control_config_assignments a
  JOIN user_machines cm ON cm.environment_id = a.environment_id AND cm.deleted_at IS NULL
  WHERE a.repository_id IS NOT NULL AND a.revoked_at IS NULL
    AND a.consent_state = 'accepted'
    AND a.warning_revision IS DISTINCT FROM sqlc.arg(warning_revision)
),
updated_assignments AS (
  UPDATE control_config_assignments a
  SET consent_state = 'pending', warning_revision = sqlc.arg(warning_revision), accepted_at = NULL,
      version = version + 1, updated_at = sqlc.arg(now)
  FROM stale
  WHERE a.environment_id = stale.environment_id
  RETURNING a.environment_id
),
revoked_credentials AS (
  UPDATE control_config_credentials c
  SET revoked_at = coalesce(c.revoked_at, sqlc.arg(now))
  FROM updated_assignments u
  WHERE c.environment_id = u.environment_id AND c.revoked_at IS NULL
  RETURNING c.environment_id
),
revoked_access AS (
  UPDATE control_config_repository_access_operations access
  SET state = 'revoked', revoked_at = coalesce(access.revoked_at, sqlc.arg(now)), updated_at = sqlc.arg(now)
  FROM updated_assignments u
  WHERE access.environment_id = u.environment_id AND access.revoked_at IS NULL
    AND access.state IN ('pending','issued','uncertain')
  RETURNING access.environment_id
),
revoked_leases AS (
  UPDATE control_config_repository_lease_authority l
  SET revoked_at = sqlc.arg(now), version = version + 1, updated_at = sqlc.arg(now)
  FROM updated_assignments u
  WHERE l.environment_id = u.environment_id AND l.lease_id IS NOT NULL AND l.revoked_at IS NULL
  RETURNING l.environment_id
)
SELECT environment_id FROM updated_assignments ORDER BY environment_id;

-- name: RecordControlConfigSyncStatus :one
INSERT INTO control_config_sync_statuses
  (environment_id, repository_id, assignment_id, machine_id, installation_generation,
   warning_revision, policy_revision, sync_revision, state, mode,
   remote_revision, manifest_health, manifest_revision, managed_path_count,
   pending_clean_path_count, last_applied_revision, last_published_revision,
   lease_id, fencing_token,
   skipped, conflicts, error_code, recovery_actions, last_attempt_at,
   last_successful_at, machine_updated_at, observed_at)
VALUES
  (sqlc.arg(environment_id), sqlc.arg(repository_id), sqlc.arg(assignment_id), sqlc.arg(machine_id),
   sqlc.arg(installation_generation), sqlc.arg(warning_revision), sqlc.arg(policy_revision),
   sqlc.arg(sync_revision), sqlc.arg(state), sqlc.arg(mode),
   sqlc.narg(remote_revision), sqlc.arg(manifest_health), sqlc.narg(manifest_revision),
   sqlc.arg(managed_path_count), sqlc.arg(pending_clean_path_count),
   sqlc.narg(last_applied_revision), sqlc.narg(last_published_revision),
   sqlc.narg(lease_id), sqlc.narg(fencing_token), sqlc.arg(skipped),
   sqlc.arg(conflicts), sqlc.narg(error_code), sqlc.arg(recovery_actions),
   sqlc.narg(last_attempt_at), sqlc.narg(last_successful_at), sqlc.arg(machine_updated_at), sqlc.arg(observed_at))
ON CONFLICT (environment_id) DO UPDATE
SET repository_id = EXCLUDED.repository_id, assignment_id = EXCLUDED.assignment_id,
    machine_id = EXCLUDED.machine_id, installation_generation = EXCLUDED.installation_generation,
    warning_revision = EXCLUDED.warning_revision, policy_revision = EXCLUDED.policy_revision,
    sync_revision = EXCLUDED.sync_revision,
    state = EXCLUDED.state, mode = EXCLUDED.mode, remote_revision = EXCLUDED.remote_revision,
    manifest_health = EXCLUDED.manifest_health, manifest_revision = EXCLUDED.manifest_revision,
    managed_path_count = EXCLUDED.managed_path_count,
    pending_clean_path_count = EXCLUDED.pending_clean_path_count,
    last_applied_revision = EXCLUDED.last_applied_revision,
    last_published_revision = EXCLUDED.last_published_revision,
    lease_id = EXCLUDED.lease_id, fencing_token = EXCLUDED.fencing_token,
    skipped = EXCLUDED.skipped, conflicts = EXCLUDED.conflicts, error_code = EXCLUDED.error_code,
    recovery_actions = EXCLUDED.recovery_actions, last_attempt_at = EXCLUDED.last_attempt_at,
    last_successful_at = EXCLUDED.last_successful_at, machine_updated_at = EXCLUDED.machine_updated_at,
    observed_at = EXCLUDED.observed_at
WHERE (
    control_config_sync_statuses.sync_revision < EXCLUDED.sync_revision
    OR (
      control_config_sync_statuses.sync_revision = EXCLUDED.sync_revision
      AND control_config_sync_statuses.machine_updated_at < EXCLUDED.machine_updated_at
    )
  )
  AND control_config_sync_statuses.assignment_id = EXCLUDED.assignment_id
  AND control_config_sync_statuses.machine_id = EXCLUDED.machine_id
  AND control_config_sync_statuses.installation_generation = EXCLUDED.installation_generation
RETURNING *;

-- name: GetControlConfigSyncRevision :one
SELECT sync_revision
FROM control_config_sync_statuses
WHERE environment_id = sqlc.arg(environment_id)
  AND assignment_id = sqlc.arg(assignment_id)
  AND machine_id = sqlc.arg(machine_id)
  AND installation_generation = sqlc.arg(installation_generation);

-- name: InsertControlConfigSyncStatusHistory :exec
INSERT INTO control_config_sync_status_history
  (environment_id, sync_revision, repository_id, assignment_id, machine_id,
   installation_generation, state, error_code, remote_revision, observed_at)
VALUES
  (sqlc.arg(environment_id), sqlc.arg(sync_revision), sqlc.arg(repository_id),
   sqlc.arg(assignment_id), sqlc.arg(machine_id), sqlc.arg(installation_generation),
   sqlc.arg(state), sqlc.narg(error_code), sqlc.narg(remote_revision), sqlc.arg(observed_at))
ON CONFLICT (environment_id, sync_revision) DO UPDATE
SET state = EXCLUDED.state, error_code = EXCLUDED.error_code,
    remote_revision = EXCLUDED.remote_revision, observed_at = EXCLUDED.observed_at;

-- name: ListOwnedControlConfigSyncStatus :many
SELECT
  environment.id AS environment_id,
  machine.id AS machine_id,
  environment.workspace_id,
  CASE WHEN machine.machine_kind = 'hosted' THEN 'hosted'::text ELSE 'byod'::text END AS profile,
  COALESCE(machine.display_name, project.name, environment.id)::text AS display_name,
  environment.desired_state AS environment_state,
  assignment.id AS assignment_id,
  assignment.repository_id,
	assignment.mode,
  assignment.consent_state,
  assignment.warning_revision,
  assignment.version AS assignment_version,
  repository.display_name AS repository_name,
  repository.state AS repository_state,
  COALESCE(machine.installation_generation, 0)::bigint AS installation_generation,
  status.state AS sync_state,
  status.assignment_id AS status_assignment_id,
  status.repository_id AS status_repository_id,
  status.machine_id AS status_machine_id,
  status.installation_generation AS status_installation_generation,
  status.policy_revision,
  status.sync_revision,
  status.remote_revision,
  status.manifest_health,
  status.manifest_revision,
  status.managed_path_count,
  status.pending_clean_path_count,
  status.last_applied_revision,
  status.last_published_revision,
  COALESCE(status.skipped, '[]'::jsonb)::jsonb AS skipped,
  COALESCE(status.conflicts, '[]'::jsonb)::jsonb AS conflicts,
  status.error_code,
  COALESCE(status.recovery_actions, '[]'::jsonb)::jsonb AS recovery_actions,
  status.last_attempt_at,
  status.last_successful_at,
  status.machine_updated_at,
  status.observed_at
FROM control_environments environment
LEFT JOIN control_config_assignments assignment
  ON assignment.environment_id = environment.id
LEFT JOIN control_config_repositories repository
  ON repository.id = assignment.repository_id
LEFT JOIN control_config_sync_statuses status
  ON status.environment_id = environment.id
LEFT JOIN user_machines machine
  ON machine.environment_id = environment.id AND machine.deleted_at IS NULL
LEFT JOIN projects project
  ON project.id = environment.workspace_id AND project.user_id = environment.owner_user_id
WHERE environment.owner_user_id = sqlc.arg(owner_user_id)
  AND environment.desired_state <> 'revoked'
ORDER BY lower(COALESCE(machine.display_name, project.name, environment.id)), environment.id;

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

-- name: GetPendingControlHelperForEnvironment :one
SELECT * FROM control_helpers
WHERE environment_id = sqlc.arg(environment_id) AND state = 'pending' AND revoked_at IS NULL
ORDER BY updated_at DESC LIMIT 1;

-- name: GetHostedEnvironmentForMachine :one
SELECT environment.id, environment.owner_user_id
FROM control_environments AS environment
JOIN fly_machines AS machine ON machine.project_id = environment.id
WHERE machine.fly_machine_id = sqlc.arg(machine_id)
  AND environment.desired_state = 'active'
  AND environment.revoked_at IS NULL;

-- name: GetHostedProjectSetupIntent :one
SELECT project.id AS project_id, project.user_id, repository.source_url, runtime.setup_script_ref
FROM control_environments AS environment
JOIN projects AS project
  ON project.id = environment.workspace_id
 AND project.user_id = environment.owner_user_id
JOIN fly_machines AS machine ON machine.project_id = project.id
JOIN project_repositories AS repository ON repository.project_id = project.id
JOIN project_runtime_configs AS runtime ON runtime.project_id = project.id
WHERE environment.id = sqlc.arg(environment_id)
  AND environment.desired_state = 'active'
  AND environment.revoked_at IS NULL
  AND project.state NOT IN ('deleted','failed');

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

-- name: GetHostedMachineIDForEnvironment :one
SELECT id
FROM user_machines
WHERE environment_id = sqlc.arg(environment_id)
  AND machine_kind = 'hosted'
  AND revoked_at IS NULL
  AND deleted_at IS NULL;

-- name: GetMachineIDForActiveHelper :one
SELECT coalesce(
  (SELECT m.id FROM user_machines m
   WHERE m.environment_id = h.environment_id AND m.deleted_at IS NULL
   ORDER BY m.created_at DESC LIMIT 1),
  (SELECT fm.fly_machine_id FROM fly_machines fm
   WHERE fm.project_id = h.environment_id)
)::text AS machine_id
FROM control_helpers h
WHERE h.id = sqlc.arg(helper_id) AND h.environment_id = sqlc.arg(environment_id)
  AND h.state = 'active' AND h.revoked_at IS NULL;

-- name: HostedHelperOwnsMachine :one
SELECT EXISTS (
  SELECT 1 FROM control_helpers h
  JOIN fly_machines fm ON fm.project_id=h.environment_id
  WHERE h.id=sqlc.arg(helper_id) AND h.environment_id=sqlc.arg(environment_id)
    AND h.state='active' AND h.revoked_at IS NULL AND fm.user_machine_id=sqlc.arg(machine_id)
);

-- name: BYODHelperOwnsMachine :one
SELECT EXISTS (
  SELECT 1 FROM control_helpers h
  JOIN user_machines m ON m.environment_id = h.environment_id
  WHERE h.id = sqlc.arg(helper_id) AND h.environment_id = sqlc.arg(environment_id)
    AND h.state = 'active' AND h.revoked_at IS NULL
    AND m.id = sqlc.arg(machine_id) AND m.deleted_at IS NULL
);

-- name: SetControlHelperReplacementGeneration :one
UPDATE control_helpers SET replacement_connector_generation = sqlc.arg(connector_generation), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND replacement_operation_key = sqlc.arg(operation_key)
RETURNING *;

-- name: RevokePendingHelperEnrollments :execrows
UPDATE control_helper_enrollments
SET state = 'revoked', revoked_at = sqlc.arg(revoked_at)
WHERE helper_id = sqlc.arg(helper_id) AND state = 'pending';

-- name: RevokeControlHelpersForEnvironment :execrows
UPDATE control_helpers
SET state = 'revoked', revoked_at = coalesce(revoked_at, sqlc.arg(revoked_at)),
    updated_at = sqlc.arg(revoked_at)
WHERE environment_id = sqlc.arg(environment_id)
  AND state IN ('pending','active') AND revoked_at IS NULL;

-- name: RevokeControlHelperEnrollmentsForEnvironment :execrows
UPDATE control_helper_enrollments
SET state = 'revoked', revoked_at = coalesce(revoked_at, sqlc.arg(revoked_at))
WHERE environment_id = sqlc.arg(environment_id)
  AND state = 'pending' AND revoked_at IS NULL;

-- name: RevokeControlConnectorForEnvironment :execrows
UPDATE control_connector_generations
SET state = 'revoked', revoked_at = coalesce(revoked_at, sqlc.arg(revoked_at)),
    version = version + 1, updated_at = sqlc.arg(revoked_at)
WHERE environment_id = sqlc.arg(environment_id)
  AND state IN ('pending','admitted','draining') AND revoked_at IS NULL;

-- name: AdvanceControlConnectorGeneration :one
INSERT INTO control_connector_generations (environment_id, connector_id, machine_id, generation, edge_pool, state)
VALUES (sqlc.arg(environment_id), sqlc.arg(connector_id), sqlc.arg(machine_id), 1, sqlc.arg(edge_pool), 'pending')
ON CONFLICT (environment_id, connector_id) DO UPDATE
SET machine_id = EXCLUDED.machine_id, generation = control_connector_generations.generation + 1,
    edge_pool = EXCLUDED.edge_pool, state = 'pending', edge_node_id = NULL,
    admission_jti_hash = NULL, expires_at = NULL, revoked_at = NULL,
    version = control_connector_generations.version + 1, updated_at = sqlc.arg(updated_at)
RETURNING *;

-- name: BindControlConnectorMachine :one
INSERT INTO control_connector_generations (environment_id, connector_id, machine_id, generation, edge_pool, state)
VALUES (sqlc.arg(environment_id), sqlc.arg(connector_id), sqlc.arg(machine_id), 1, sqlc.arg(edge_pool), 'pending')
ON CONFLICT (environment_id, connector_id) DO UPDATE
SET machine_id = EXCLUDED.machine_id, state = 'pending', updated_at = sqlc.arg(updated_at)
RETURNING *;

-- name: EnsureControlConnectorMachine :one
INSERT INTO control_connector_generations (environment_id, connector_id, machine_id, generation, edge_pool, state)
VALUES (sqlc.arg(environment_id), sqlc.arg(connector_id), sqlc.arg(machine_id), 1, sqlc.arg(edge_pool), 'pending')
ON CONFLICT (environment_id, connector_id) DO UPDATE
SET environment_id = EXCLUDED.environment_id
RETURNING *;

-- name: GetControlEnvironment :one
SELECT * FROM control_environments WHERE id = $1;

-- name: GetControlPreviewForUpdate :one
SELECT * FROM control_previews
WHERE environment_id = sqlc.arg(environment_id) AND logical_name = sqlc.arg(logical_name)
  AND state <> 'removed'
FOR UPDATE;

-- name: GetControlPreviewByKey :one
SELECT * FROM control_previews WHERE preview_key = sqlc.arg(preview_key);

-- name: CanIssueControlRouteCertificate :one
SELECT EXISTS (
  SELECT 1
  FROM control_routes r
  JOIN control_environments e ON e.id = r.environment_id
  LEFT JOIN control_previews p ON p.route_id = r.id
  WHERE r.public_host = sqlc.arg(public_host)
    AND e.desired_state = 'active'
    AND e.revoked_at IS NULL
    AND r.desired_state = 'attached'
    AND (
      r.kind = 'runtime_https_wss'
      OR (
        r.kind = 'preview_public_https_wss'
        AND p.state <> 'removed'
        AND p.public_acknowledged_at IS NOT NULL
        AND (p.expires_at IS NULL OR p.expires_at > sqlc.arg(now))
      )
    )
);

-- name: ListControlPreviews :many
SELECT * FROM control_previews
WHERE environment_id = sqlc.arg(environment_id) AND state NOT IN ('removed','expired')
  AND (expires_at IS NULL OR expires_at > now())
ORDER BY logical_name, id;

-- name: CountActiveControlPreviews :one
SELECT count(*)::integer FROM control_previews
WHERE environment_id = sqlc.arg(environment_id) AND state NOT IN ('removed','expired')
  AND (expires_at IS NULL OR expires_at > sqlc.arg(now));

-- name: SelectControlPreviewForEviction :one
SELECT * FROM control_previews
WHERE environment_id = sqlc.arg(environment_id) AND state NOT IN ('removed','expired')
  AND (expires_at IS NULL OR expires_at > sqlc.arg(now))
ORDER BY (expires_at IS NULL) ASC, created_at ASC, id ASC
LIMIT 1 FOR UPDATE;

-- name: ListOwnedControlPreviews :many
SELECT p.*, e.owner_user_id, e.workspace_id,
       cm.id AS machine_id,
       COALESCE(cm.display_name, pr.name, e.id) AS environment_name,
       CASE WHEN cm.id IS NULL THEN 'hosted' ELSE 'byod' END AS environment_kind,
       COALESCE(u.primary_email, '') AS owner_email
FROM control_previews p
JOIN control_environments e ON e.id = p.environment_id
LEFT JOIN user_machines cm ON cm.environment_id = e.id AND cm.deleted_at IS NULL
LEFT JOIN projects pr ON pr.id = e.workspace_id
LEFT JOIN users u ON u.id = e.owner_user_id
WHERE e.owner_user_id = sqlc.arg(owner_user_id)
  AND e.desired_state = 'active'
  AND e.revoked_at IS NULL
  AND p.state <> 'removed'
ORDER BY p.updated_at DESC, p.id;

-- name: GetOwnedControlPreview :one
SELECT p.* FROM control_previews p
JOIN control_environments e ON e.id = p.environment_id
WHERE p.id = sqlc.arg(id) AND e.owner_user_id = sqlc.arg(owner_user_id)
FOR UPDATE;

-- name: CreateControlPreview :one
INSERT INTO control_previews
  (id, environment_id, logical_name, preview_key, collision_counter, public_host,
   target_host, target_port, source_kind, owner_mode, public_acknowledged_at, expires_at)
VALUES
  (sqlc.arg(id), sqlc.arg(environment_id), sqlc.arg(logical_name), sqlc.arg(preview_key),
   sqlc.arg(collision_counter), sqlc.arg(public_host), sqlc.arg(target_host), sqlc.arg(target_port),
   sqlc.arg(source_kind), sqlc.arg(owner_mode), sqlc.narg(public_acknowledged_at), sqlc.narg(expires_at))
ON CONFLICT DO NOTHING
RETURNING *;

-- name: UpdateControlPreview :one
UPDATE control_previews
SET target_host = sqlc.arg(target_host), target_port = sqlc.arg(target_port),
    source_kind = sqlc.arg(source_kind), owner_mode = sqlc.arg(owner_mode),
    state = CASE WHEN state = 'removed' THEN state ELSE 'registering' END,
    public_acknowledged_at = coalesce(public_acknowledged_at, sqlc.narg(public_acknowledged_at)),
    expires_at = sqlc.narg(expires_at),
    version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND version = sqlc.arg(expected_version)
RETURNING *;

-- name: SetControlPreviewRoute :one
UPDATE control_previews SET route_id = sqlc.arg(route_id), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND route_id IS NULL
RETURNING *;

-- name: UpdateControlPreviewRouteTarget :one
UPDATE control_routes
SET target_host = sqlc.arg(target_host), target_port = sqlc.arg(target_port),
    desired_state = 'attached', desired_revision = desired_revision + 1,
    version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND environment_id = sqlc.arg(environment_id)
RETURNING *;

-- name: RemoveControlPreview :one
UPDATE control_previews
SET state = 'removed', removed_at = coalesce(removed_at, sqlc.arg(now)),
    retained_until = greatest(coalesce(retained_until, sqlc.arg(now)), sqlc.arg(retained_until)),
    version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND version = sqlc.arg(expected_version)
RETURNING *;

-- name: RemoveControlPreviewRoute :execrows
UPDATE control_routes
SET desired_state = CASE WHEN applied_node_id IS NULL THEN 'detached' ELSE 'detaching' END,
    desired_revision = desired_revision + 1, version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND environment_id = sqlc.arg(environment_id)
  AND desired_state NOT IN ('detaching','detached');

-- name: RevokeControlRoutesForEnvironment :execrows
UPDATE control_routes
SET desired_state = CASE WHEN applied_node_id IS NULL THEN 'detached' ELSE 'detaching' END,
    desired_revision = desired_revision + 1, version = version + 1, updated_at = sqlc.arg(now)
WHERE environment_id = sqlc.arg(environment_id)
  AND desired_state NOT IN ('detaching','detached');

-- name: ApplyControlPreviewHelperObservation :one
UPDATE control_previews
SET helper_ready = sqlc.arg(helper_ready), target_ready = sqlc.arg(target_ready),
    helper_observation_revision = sqlc.arg(observation_revision), helper_observed_at = sqlc.arg(observed_at),
    state = CASE
      WHEN state = 'removed' THEN state
      WHEN expires_at IS NOT NULL AND expires_at <= sqlc.arg(observed_at) THEN 'expired'
      WHEN NOT sqlc.arg(helper_ready) THEN 'offline'
      WHEN sqlc.arg(target_ready) AND edge_ready THEN 'ready'
      ELSE 'degraded'
    END,
    version = version + 1, updated_at = sqlc.arg(observed_at)
WHERE environment_id = sqlc.arg(environment_id) AND preview_key = sqlc.arg(preview_key)
  AND logical_name = sqlc.arg(logical_name) AND target_host = sqlc.arg(target_host)
  AND target_port = sqlc.arg(target_port)
  AND state <> 'removed' AND sqlc.arg(observation_revision) > helper_observation_revision
RETURNING *;

-- name: RefreshControlPreviewEdgeReadiness :exec
UPDATE control_previews p
SET helper_ready = (p.helper_ready AND p.helper_observed_at >= sqlc.arg(now)::timestamptz - interval '1 minute'),
    target_ready = (p.target_ready AND p.helper_observed_at >= sqlc.arg(now)::timestamptz - interval '1 minute'),
    edge_ready = (r.desired_state = 'attached' AND r.applied_revision = r.desired_revision AND r.applied_node_id IS NOT NULL),
    state = CASE
      WHEN p.state IN ('removed','expired') THEN p.state
      WHEN NOT p.helper_ready OR p.helper_observed_at IS NULL OR p.helper_observed_at < sqlc.arg(now)::timestamptz - interval '1 minute' THEN 'offline'
      WHEN p.target_ready AND r.desired_state = 'attached' AND r.applied_revision = r.desired_revision AND r.applied_node_id IS NOT NULL THEN 'ready'
      ELSE 'degraded'
    END,
    version = p.version + 1, updated_at = sqlc.arg(now)
FROM control_routes r
WHERE p.route_id = r.id AND p.state <> 'removed';

-- name: GetControlPreviewOperation :one
SELECT * FROM control_preview_operations WHERE operation_key = $1;

-- name: ReserveControlPreviewOperation :one
INSERT INTO control_preview_operations(operation_key, operation_type, request_hash, preview_id)
VALUES (sqlc.arg(operation_key), sqlc.arg(operation_type), sqlc.arg(request_hash), sqlc.arg(preview_id))
ON CONFLICT (operation_key) DO UPDATE SET operation_key = EXCLUDED.operation_key
RETURNING *;

-- name: SetControlPreviewOperationResult :exec
UPDATE control_preview_operations SET result = sqlc.arg(result), preview_id = sqlc.arg(preview_id)
WHERE operation_key = sqlc.arg(operation_key);

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

-- name: GetConfigSyncMetrics :one
SELECT
  (SELECT count(*)
   FROM control_config_assignments assignment
   JOIN control_environments environment ON environment.id=assignment.environment_id
   JOIN control_config_repositories repository ON repository.id=assignment.repository_id
   WHERE environment.desired_state='active'
     AND repository.state='active'
     AND assignment.consent_state IN ('accepted','not_required'))::bigint AS eligible_environments,
  (SELECT count(*) FROM control_config_sync_statuses WHERE state IN ('restoring','watching','pending','syncing','healthy','warning','conflict','sync_uncertain'))::bigint AS reporting_environments,
  (SELECT count(*) FROM control_config_sync_statuses WHERE state='conflict')::bigint AS conflict_environments,
  (SELECT coalesce(sum(pending_clean_path_count),0) FROM control_config_sync_statuses)::bigint AS pending_paths,
  (SELECT count(*) FROM control_config_sync_statuses WHERE state='sync_uncertain')::bigint AS uncertain_publications,
  (SELECT count(*) FROM control_config_repository_lease_authority
   WHERE lease_id IS NOT NULL AND revoked_at IS NULL AND expires_at>now())::bigint AS active_writer_leases,
  (SELECT count(*) FROM control_config_repository_lease_operations WHERE result_state='busy')::bigint AS lease_contention_total,
  (SELECT count(*) FROM control_config_conflict_resolutions WHERE state='pending')::bigint AS pending_resolutions,
  CAST(coalesce((SELECT extract(epoch FROM (now()-min(requested_at)))
                 FROM control_config_conflict_resolutions WHERE state='pending'),0) AS bigint) AS oldest_pending_resolution_age_seconds,
  (SELECT count(*) FROM control_config_repository_access_operations
   WHERE revoked_at IS NOT NULL AND provider_revoked_at IS NULL)::bigint AS pending_provider_revocations;

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
INSERT INTO control_tunnel_nodes (id, edge_pool, protocol_version, process_epoch, endpoint_host, endpoint_tcp_port, endpoint_quic_port, signaling_host, stun_host, stun_port, state, ready, capacity, last_heartbeat_at)
VALUES (sqlc.arg(id), sqlc.arg(edge_pool), sqlc.arg(protocol_version), sqlc.arg(process_epoch), sqlc.arg(endpoint_host), sqlc.arg(endpoint_tcp_port), sqlc.arg(endpoint_quic_port), sqlc.arg(signaling_host), sqlc.arg(stun_host), sqlc.arg(stun_port), 'registered', false,
        coalesce(sqlc.arg(capacity)::jsonb, '{}'::jsonb), sqlc.arg(now))
ON CONFLICT (id) DO UPDATE
SET protocol_version = EXCLUDED.protocol_version, process_epoch = EXCLUDED.process_epoch,
    endpoint_host = EXCLUDED.endpoint_host, endpoint_tcp_port = EXCLUDED.endpoint_tcp_port, endpoint_quic_port = EXCLUDED.endpoint_quic_port,
    signaling_host = EXCLUDED.signaling_host, stun_host = EXCLUDED.stun_host, stun_port = EXCLUDED.stun_port,
    state = 'registered', ready = false, capacity = EXCLUDED.capacity,
    observation = '{}'::jsonb, last_heartbeat_at = EXCLUDED.last_heartbeat_at,
    drain_deadline = NULL, version = control_tunnel_nodes.version + 1, updated_at = EXCLUDED.last_heartbeat_at
RETURNING *;

-- name: GetControlConnectorAssignment :one
SELECT c.generation, c.edge_pool, c.edge_node_id, (c.revoked_at IS NOT NULL OR e.desired_state = 'revoked') AS revoked
FROM control_connector_generations c
JOIN control_environments e ON e.id = c.environment_id
JOIN user_machines m ON m.id = c.machine_id AND m.environment_id = c.environment_id
WHERE c.environment_id = sqlc.arg(environment_id) AND c.machine_id = sqlc.arg(machine_id)
  AND c.connector_id = sqlc.arg(connector_id)
  AND m.revoked_at IS NULL AND m.deleted_at IS NULL AND e.desired_state = 'active';

-- name: GetControlConnectorGenerationForUpdate :one
SELECT * FROM control_connector_generations
WHERE environment_id = sqlc.arg(environment_id) AND connector_id = sqlc.arg(connector_id)
FOR UPDATE;

-- name: SelectReadyControlTunnelNode :one
SELECT * FROM control_tunnel_nodes
WHERE edge_pool = sqlc.arg(edge_pool) AND state = 'ready' AND ready = true
  AND last_heartbeat_at > sqlc.arg(stale_after)
ORDER BY last_heartbeat_at DESC, id
LIMIT 1;

-- name: ListReadyControlTunnelProbeRegions :many
SELECT DISTINCT ON (edge_pool) edge_pool, signaling_host, stun_host, stun_port
FROM control_tunnel_nodes
WHERE state = 'ready' AND ready = true
  AND last_heartbeat_at > sqlc.arg(stale_after)
  AND signaling_host IS NOT NULL AND trim(signaling_host) <> ''
  AND stun_host IS NOT NULL AND trim(stun_host) <> ''
  AND stun_port BETWEEN 1 AND 65535
ORDER BY edge_pool, last_heartbeat_at DESC, id
LIMIT 32;

-- name: SetControlConnectorAdmission :one
UPDATE control_connector_generations
SET edge_node_id = sqlc.arg(edge_node_id), state = 'admitted', admission_jti_hash = sqlc.arg(admission_jti_hash),
    admission_operation_key = sqlc.arg(admission_operation_key), admission_request_hash = sqlc.arg(admission_request_hash),
    admission_credential_ciphertext = sqlc.arg(admission_credential_ciphertext), expires_at = sqlc.arg(expires_at),
    version = version + 1, updated_at = sqlc.arg(updated_at)
WHERE environment_id = sqlc.arg(environment_id) AND connector_id = sqlc.arg(connector_id)
  AND generation = sqlc.arg(generation)
RETURNING *;

-- name: ListControlRoutesForNode :many
SELECT r.id AS route_id, r.desired_revision AS route_revision, r.environment_id, c.connector_id,
       c.generation AS connector_generation, c.edge_node_id, r.kind, r.public_host,
       r.target_host, r.target_port, COALESCE(p.state, 'ready') AS preview_state,
       CASE WHEN p.state = 'degraded' AND NOT p.target_ready THEN 'target_unhealthy' ELSE '' END AS preview_reason
FROM control_routes r
JOIN control_connector_generations c ON c.environment_id = r.environment_id AND c.connector_id = r.connector_id
JOIN user_machines m ON m.id = c.machine_id AND m.environment_id = c.environment_id
LEFT JOIN control_previews p ON p.route_id = r.id
WHERE c.edge_node_id = sqlc.arg(edge_node_id)
  AND r.desired_state IN ('attached','replacing')
  AND c.state IN ('pending','admitted')
  AND m.revoked_at IS NULL AND m.deleted_at IS NULL
  AND (p.id IS NULL OR (p.state NOT IN ('expired','removed') AND (p.expires_at IS NULL OR p.expires_at > sqlc.arg(now))))
ORDER BY r.id;

-- name: ListControlRoutesForEnvironmentAdmission :many
SELECT r.id AS route_id, r.desired_revision AS route_revision, r.kind, r.public_host, r.target_host, r.target_port
FROM control_routes r
LEFT JOIN control_previews p ON p.route_id = r.id
WHERE r.environment_id = sqlc.arg(environment_id) AND r.connector_id = sqlc.arg(connector_id)
  AND r.desired_state IN ('attached','replacing')
  AND (p.id IS NULL OR (p.state NOT IN ('expired','removed') AND (p.expires_at IS NULL OR p.expires_at > now())))
ORDER BY r.id
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

-- name: GetActiveHelperRouteForEnvironment :one
SELECT r.* FROM control_routes r
JOIN control_environments e ON e.id = r.environment_id
JOIN control_connector_generations c ON c.environment_id = r.environment_id AND c.connector_id = r.connector_id
JOIN user_machines m ON m.id = c.machine_id AND m.environment_id = r.environment_id
JOIN control_tunnel_nodes n ON n.id = c.edge_node_id AND n.id = r.applied_node_id
WHERE r.environment_id = sqlc.arg(environment_id)
  AND r.kind = 'runtime_https_wss'
	AND c.connector_id = 'runtime'
  AND r.desired_state IN ('attached','replacing')
  AND r.applied_revision >= r.desired_revision
  AND r.applied_generation = c.generation
  AND e.desired_state = 'active' AND m.revoked_at IS NULL AND m.deleted_at IS NULL AND c.state = 'admitted'
  AND n.state = 'ready' AND n.ready = true
ORDER BY r.id
LIMIT 1;

-- name: GetHelperRouteForEnvironment :one
SELECT * FROM control_routes
WHERE environment_id = sqlc.arg(environment_id)
  AND kind = 'runtime_https_wss'
  AND desired_state IN ('attached','replacing')
ORDER BY id
LIMIT 1;

-- name: ReactivateHelperRouteForEnvironment :one
UPDATE control_routes
SET desired_state = 'attached', desired_revision = desired_revision + 1,
    version = version + 1, updated_at = sqlc.arg(now)
WHERE id = (
  SELECT existing.id FROM control_routes AS existing
  WHERE existing.environment_id = sqlc.arg(environment_id) AND existing.kind = 'runtime_https_wss'
  ORDER BY existing.created_at DESC LIMIT 1
)
RETURNING *;

-- name: CreateControlRoute :one
INSERT INTO control_routes (id, environment_id, connector_id, kind, public_host, target_host, target_port)
VALUES (sqlc.arg(id), sqlc.arg(environment_id), sqlc.arg(connector_id), sqlc.arg(kind), sqlc.arg(public_host), sqlc.arg(target_host), sqlc.arg(target_port))
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
	  AND c.connector_id = control_routes.connector_id
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

-- name: GetOwnedControlConfigConflictContext :one
SELECT assignment.id AS assignment_id,
       assignment.version AS assignment_version,
       assignment.mode AS assignment_mode,
       assignment.repository_id,
       status.remote_revision,
       status.conflicts
FROM control_environments environment
JOIN control_config_assignments assignment ON assignment.environment_id=environment.id
JOIN control_config_repositories repository ON repository.id=assignment.repository_id
JOIN control_config_sync_statuses status
  ON status.environment_id=environment.id
 AND status.assignment_id=assignment.id
 AND status.repository_id=repository.id
WHERE environment.id=sqlc.arg(environment_id)
  AND environment.owner_user_id=sqlc.arg(owner_user_id)
  AND environment.desired_state='active'
  AND repository.state='active';

-- name: CreateControlConfigConflictResolution :one
INSERT INTO control_config_conflict_resolutions
  (id, environment_id, repository_id, assignment_id, conflict_revision, path, scope,
   action, expected_remote_revision, requested_by_user_id)
VALUES
  (sqlc.arg(id),sqlc.arg(environment_id),sqlc.arg(repository_id),sqlc.arg(assignment_id),
   sqlc.arg(conflict_revision),sqlc.arg(path),sqlc.arg(scope),sqlc.arg(action),
   sqlc.arg(expected_remote_revision),sqlc.arg(requested_by_user_id))
ON CONFLICT (environment_id, conflict_revision, path) DO UPDATE
SET action=EXCLUDED.action,
    expected_remote_revision=EXCLUDED.expected_remote_revision,
    requested_by_user_id=EXCLUDED.requested_by_user_id,
    state='pending',
    landed_revision=NULL,
    applied_at=NULL,
    requested_at=now(),
    updated_at=now()
WHERE control_config_conflict_resolutions.state <> 'applied'
RETURNING *;

-- name: ListPendingControlConfigConflictResolutions :many
SELECT *
FROM control_config_conflict_resolutions
WHERE environment_id=sqlc.arg(environment_id)
  AND repository_id=sqlc.arg(repository_id)
  AND assignment_id=sqlc.arg(assignment_id)
  AND state='pending'
ORDER BY requested_at,id
LIMIT 100;

-- name: ApplyControlConfigConflictResolution :one
UPDATE control_config_conflict_resolutions
SET state='applied', landed_revision=sqlc.arg(landed_revision),
    applied_at=coalesce(applied_at,sqlc.arg(now)), updated_at=sqlc.arg(now)
WHERE id=sqlc.arg(id)
  AND environment_id=sqlc.arg(environment_id)
  AND repository_id=sqlc.arg(repository_id)
  AND assignment_id=sqlc.arg(assignment_id)
  AND (
    state='pending'
    OR (state='applied' AND landed_revision=sqlc.arg(landed_revision))
  )
RETURNING *;
