-- Device removal is a security boundary. Every query in this file is scoped
-- by both user and machine (or by the machine's environment) so removing one
-- device cannot revoke another device belonging to the same account.

-- name: BindCLIClientSessionToUserMachine :execrows
UPDATE cli_client_sessions AS client_session
SET user_machine_id = sqlc.arg(target_machine_id)
WHERE client_session.id = sqlc.arg(target_cli_session_id)
  AND client_session.user_id = sqlc.arg(target_user_id)
  AND client_session.state = 'active'
  AND (client_session.user_machine_id IS NULL OR client_session.user_machine_id = sqlc.arg(target_machine_id))
  AND EXISTS (
    SELECT 1
    FROM user_machines AS machine
    WHERE machine.id = sqlc.arg(target_machine_id)
      AND machine.user_id = sqlc.arg(target_user_id)
      AND machine.deleted_at IS NULL
  );

-- name: RevokeCLIClientSessionsForUserMachine :execrows
UPDATE cli_client_sessions AS client_session
SET state = 'revoked',
    revoked_at = coalesce(client_session.revoked_at, sqlc.arg(revocation_time)),
    revocation_reason = coalesce(client_session.revocation_reason, sqlc.arg(revocation_cause)),
    version = client_session.version + 1
WHERE client_session.user_machine_id = sqlc.arg(target_machine_id)
  AND client_session.user_id = sqlc.arg(target_user_id)
  AND client_session.state = 'active';

-- Keep token revocation explicit even though the session state trigger also
-- revokes them. This remains correct if a session was already revoked or a
-- trigger is disabled during a future migration.
-- name: RevokeCLIClientAccessTokensForUserMachine :execrows
UPDATE cli_access_tokens AS access_token
SET revoked_at = coalesce(access_token.revoked_at, sqlc.arg(revocation_time))
FROM cli_client_sessions AS client_session
WHERE access_token.cli_client_session_id = client_session.id
  AND client_session.user_machine_id = sqlc.arg(target_machine_id)
  AND client_session.user_id = sqlc.arg(target_user_id)
  AND access_token.revoked_at IS NULL;

-- name: RevokeCLIClientRefreshTokensForUserMachine :execrows
UPDATE cli_refresh_tokens AS refresh_token
SET state = 'revoked',
    revoked_at = coalesce(refresh_token.revoked_at, sqlc.arg(revocation_time))
FROM cli_client_sessions AS client_session
WHERE refresh_token.cli_client_session_id = client_session.id
  AND client_session.user_machine_id = sqlc.arg(target_machine_id)
  AND client_session.user_id = sqlc.arg(target_user_id)
  AND refresh_token.state <> 'revoked';

-- A key is the trust root for a device's peer certificates. Revoke it before
-- deleting the machine row; the multi-key migration's trigger then fences all
-- certificates, signaling grants, relays, and intents derived from that key.
-- name: RevokeUserMachineE2EEKeys :execrows
UPDATE account_e2ee_keys AS trusted_key
SET revoked_at = coalesce(trusted_key.revoked_at, sqlc.arg(revocation_time)),
    revocation_reason = coalesce(trusted_key.revocation_reason, 'device_removed'),
    updated_at = sqlc.arg(revocation_time)
WHERE trusted_key.user_id = sqlc.arg(target_user_id)
  AND trusted_key.revoked_at IS NULL
  AND (
    trusted_key.user_machine_id = sqlc.arg(target_machine_id)
    OR trusted_key.cli_client_session_id IN (
      SELECT client_session.id
      FROM cli_client_sessions AS client_session
      WHERE client_session.user_machine_id = sqlc.arg(target_machine_id)
        AND client_session.user_id = sqlc.arg(target_user_id)
    )
  );

-- Revoke all peer authority owned by the machine and its enrollment-created
-- CLI sessions. Endpoint certificate rows remain as revocation tombstones for
-- audit and anti-replay; no active certificate survives this fence.
-- name: RevokeUserMachinePeerAuthority :execrows
WITH target_machine AS (
  SELECT machine.id, machine.user_id, machine.environment_id
  FROM user_machines AS machine
  WHERE machine.id = sqlc.arg(target_machine_id)
    AND machine.user_id = sqlc.arg(target_user_id)
  FOR UPDATE
), machine_cli_sessions AS (
  SELECT client_session.id
  FROM cli_client_sessions AS client_session
  JOIN target_machine ON target_machine.id = client_session.user_machine_id
  WHERE client_session.user_id = target_machine.user_id
), machine_endpoints AS (
  SELECT certificate.fingerprint
  FROM peer_endpoint_certificates AS certificate
  JOIN target_machine ON target_machine.user_id = certificate.user_id
  WHERE certificate.endpoint_id = target_machine.id
     OR certificate.endpoint_id IN (SELECT id FROM machine_cli_sessions)
), revoked_intents AS (
  UPDATE peer_session_intents AS intent
  SET state = 'revoked',
      revoked_at = sqlc.arg(revocation_time),
      revocation_reason = 'endpoint_revoked'
  FROM target_machine
  WHERE intent.user_id = target_machine.user_id
    AND intent.state = 'active'
    AND (
      intent.cli_client_session_id IN (SELECT id FROM machine_cli_sessions)
      OR intent.controlling_certificate_fingerprint IN (SELECT fingerprint FROM machine_endpoints)
      OR intent.controlled_certificate_fingerprint IN (SELECT fingerprint FROM machine_endpoints)
    )
  RETURNING intent.id
), revoked_signaling AS (
  UPDATE peer_signaling_grants AS grant_row
  SET revoked_at = coalesce(grant_row.revoked_at, sqlc.arg(revocation_time))
  WHERE grant_row.intent_id IN (SELECT id FROM revoked_intents)
    AND grant_row.revoked_at IS NULL
  RETURNING 1
), revoked_relays AS (
  UPDATE peer_relay_allocations AS relay
  SET revoked_at = coalesce(relay.revoked_at, sqlc.arg(revocation_time))
  WHERE relay.intent_id IN (SELECT id FROM revoked_intents)
    AND relay.revoked_at IS NULL
  RETURNING 1
), revoked_enrollment_requests AS (
  UPDATE peer_endpoint_enrollment_requests AS enrollment_request
  SET state = 'revoked'
  FROM target_machine
  WHERE enrollment_request.user_id = target_machine.user_id
    AND enrollment_request.state = 'pending'
    AND (
      enrollment_request.endpoint_id = target_machine.id
      OR enrollment_request.endpoint_id IN (SELECT id FROM machine_cli_sessions)
    )
  RETURNING 1
), revoked_certificates AS (
  UPDATE peer_endpoint_certificates AS certificate
  SET revoked_at = coalesce(certificate.revoked_at, sqlc.arg(revocation_time)),
      revocation_reason = CASE
        WHEN certificate.revoked_at IS NULL THEN 'endpoint_removed'
        ELSE certificate.revocation_reason
      END
  FROM target_machine
  WHERE certificate.user_id = target_machine.user_id
    AND certificate.revoked_at IS NULL
    AND (
      certificate.endpoint_id = target_machine.id
      OR certificate.endpoint_id IN (SELECT id FROM machine_cli_sessions)
    )
  RETURNING 1
)
SELECT count(*)::bigint FROM revoked_certificates;

-- These rows are audit/replay records, but an active verifier or pairing must
-- never remain usable after its machine has been removed.
-- name: ExpireUserMachinePairings :execrows
UPDATE user_machine_pairings AS pairing
SET state = 'expired',
    expires_at = least(pairing.expires_at, sqlc.arg(expired_at)),
    installation_config_ciphertext = NULL,
    installation_config_nonce = NULL,
    installation_config_consumed_at = NULL,
    installation_recovery_operation_key = NULL,
    updated_at = sqlc.arg(expired_at)
WHERE pairing.user_machine_id = sqlc.arg(target_machine_id)
  AND pairing.state IN ('pending', 'approved', 'consumed');

-- name: DeleteUserMachineEnrollments :execrows
UPDATE user_machine_enrollments AS enrollment
SET state = 'deleted',
    expires_at = least(enrollment.expires_at, sqlc.arg(expired_at)),
    bootstrap_token_ciphertext = ''::bytea,
    updated_at = sqlc.arg(expired_at)
WHERE enrollment.user_machine_id = sqlc.arg(target_machine_id)
  AND enrollment.state IN ('awaiting_bootstrap', 'awaiting_approval', 'approved', 'material_issued', 'installing', 'connecting', 'ready', 'failed_retryable');

-- Diagnostic archives are user data and are retained according to their
-- retention policy. An upload that has not completed is only made unusable.
-- name: ExpireUserMachineDiagnosticUploadIntents :execrows
UPDATE diagnostic_upload_intents AS upload_intent
SET state = 'expired'
FROM cli_client_sessions AS client_session
WHERE upload_intent.cli_client_session_id = client_session.id
  AND client_session.user_machine_id = sqlc.arg(target_machine_id)
  AND client_session.user_id = sqlc.arg(target_user_id)
  AND upload_intent.state = 'pending';

-- Each of the following statements is intentionally separate. The managed
-- SSH child table has a RESTRICT foreign key to its owner, so sibling data
-- modifying CTEs could fail FK checks depending on PostgreSQL snapshot order.
-- name: DeleteUserMachineControlRenewals :execrows
DELETE FROM machine_control_renewals AS renewal
WHERE renewal.machine_id = sqlc.arg(target_machine_id);

-- name: DeleteUserMachineTransferDestinationDefault :execrows
DELETE FROM user_transfer_destination_defaults AS destination_default
WHERE destination_default.user_id = sqlc.arg(target_user_id)
  AND destination_default.machine_id = sqlc.arg(target_machine_id);

-- name: ClearProjectTerminalTransferDestinationsForMachine :execrows
UPDATE project_terminal_sessions AS terminal_session
SET transfer_destination_machine_id = NULL,
    version = terminal_session.version + 1,
    updated_at = sqlc.arg(expired_at)
WHERE terminal_session.transfer_destination_machine_id = sqlc.arg(target_machine_id);

-- name: ClearUserMachineTerminalTransferDestinationsForMachine :execrows
UPDATE user_machine_terminal_sessions AS terminal_session
SET transfer_destination_machine_id = NULL,
    version = terminal_session.version + 1,
    updated_at = sqlc.arg(expired_at)
WHERE terminal_session.transfer_destination_machine_id = sqlc.arg(target_machine_id);

-- name: DeleteUserMachineTerminalSessions :execrows
UPDATE user_machine_terminal_sessions AS terminal_session
SET desired_state = 'deleted',
    deleted_at = coalesce(terminal_session.deleted_at, sqlc.arg(expired_at)),
    version = terminal_session.version + 1,
    updated_at = sqlc.arg(expired_at)
WHERE terminal_session.user_machine_id = sqlc.arg(target_machine_id)
  AND terminal_session.deleted_at IS NULL;

-- Pending close/history operations must not be retried against a removed
-- machine after its terminal rows have been tombstoned.
-- name: DeleteUserMachineTerminalSessionOperations :execrows
DELETE FROM user_machine_terminal_session_operations AS operation
WHERE operation.user_machine_id = sqlc.arg(target_machine_id);

-- name: DeleteUserMachineAvailabilityOperations :execrows
DELETE FROM user_machine_availability_operations AS availability_operation
WHERE availability_operation.user_machine_id = sqlc.arg(target_machine_id);

-- name: DeleteUserMachineUpdateObservation :execrows
DELETE FROM user_machine_update_observations AS update_observation
WHERE update_observation.user_machine_id = sqlc.arg(target_machine_id);

-- name: ExpireUserMachineMaintenanceApprovals :execrows
UPDATE user_machine_maintenance_approvals AS approval
SET status = 'expired',
    decided_at = coalesce(approval.decided_at, sqlc.arg(expired_at)),
    updated_at = sqlc.arg(expired_at)
WHERE approval.user_machine_id = sqlc.arg(target_machine_id)
  AND approval.status IN ('pending', 'approved');

-- name: DeleteUserMachineRelaySelectionStates :execrows
DELETE FROM peer_relay_selection_states AS selection
WHERE selection.user_id = sqlc.arg(target_user_id)
  AND selection.machine_id = sqlc.arg(target_machine_id);

-- Delete child rows first, then the RESTRICT-referenced owners.
-- name: DeleteUserMachineSSHHostKeys :execrows
DELETE FROM machine_ssh_host_keys AS host_key
WHERE host_key.user_machine_id = sqlc.arg(target_machine_id);

-- name: DeleteUserMachineSSHHostKeySets :execrows
DELETE FROM machine_ssh_host_key_sets AS host_key_set
WHERE host_key_set.user_machine_id = sqlc.arg(target_machine_id);

-- name: DeleteUserMachineSSHHostKeyOwners :execrows
DELETE FROM machine_ssh_host_key_owners AS owner
WHERE owner.user_machine_id = sqlc.arg(target_machine_id);

-- name: DeleteUserMachineSSHTarget :execrows
DELETE FROM machine_ssh_targets AS target
WHERE target.user_machine_id = sqlc.arg(target_machine_id);

-- A removed environment must not continue advertising a preview URL. The
-- row remains until retention cleanup so existing user data and audit history
-- are preserved, but it can no longer be resolved or served.
-- name: RemoveControlPreviewsForEnvironment :execrows
UPDATE control_previews AS preview
SET state = 'removed',
    removed_at = coalesce(preview.removed_at, sqlc.arg(revocation_time)),
    retained_until = greatest(coalesce(preview.retained_until, sqlc.arg(revocation_time)), sqlc.arg(revocation_time)),
    version = preview.version + 1,
    updated_at = sqlc.arg(revocation_time)
WHERE preview.environment_id = sqlc.arg(target_environment_id)
  AND preview.state <> 'removed';
