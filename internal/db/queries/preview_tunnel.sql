-- name: CreatePreviewTunnelOperation :one
INSERT INTO operations
  (id, account_id, idempotency_key, request_hash, operation_type, resource_kind,
   resource_id, phase, state, progress, retrying, outcome, correlation_id)
VALUES
  (sqlc.arg(id), sqlc.arg(account_id), sqlc.arg(idempotency_key), sqlc.arg(request_hash),
   sqlc.arg(operation_type), sqlc.arg(resource_kind), sqlc.narg(resource_id),
   sqlc.arg(phase), sqlc.arg(state), sqlc.arg(progress), false, sqlc.arg(outcome),
   sqlc.arg(correlation_id))
ON CONFLICT (account_id, idempotency_key) DO NOTHING
RETURNING *;

-- name: GetPreviewTunnelOperationByIdempotency :one
SELECT * FROM operations
WHERE account_id = sqlc.arg(account_id) AND idempotency_key = sqlc.arg(idempotency_key);

-- name: GetPreviewTunnelOperation :one
SELECT * FROM operations
WHERE id = sqlc.arg(id) AND account_id = sqlc.arg(account_id);

-- name: CancelPendingPreviewTunnelOperation :one
UPDATE operations
SET state = 'cancelled', retrying = false, next_retry_at = NULL,
    error_code = 'cancelled_by_actor', updated_at = sqlc.arg(now), completed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND account_id = sqlc.arg(account_id) AND state = 'pending'
RETURNING *;

-- name: ListPreviewTunnelEvents :many
SELECT *
FROM audit_events
WHERE account_id = sqlc.arg(account_id)
  AND resource_type = sqlc.arg(resource_type)
  AND resource_id = sqlc.arg(resource_id)
  AND cursor_sequence > sqlc.arg(after_sequence)
ORDER BY cursor_sequence ASC
LIMIT sqlc.arg(row_limit);

-- name: CompletePreviewTunnelOperation :one
UPDATE operations
SET resource_id = sqlc.arg(resource_id), phase = sqlc.arg(phase), state = sqlc.arg(state),
    progress = sqlc.arg(progress), outcome = sqlc.arg(outcome), result_reference = sqlc.narg(result_reference),
    updated_at = sqlc.arg(updated_at), completed_at = sqlc.arg(completed_at)
WHERE id = sqlc.arg(id) AND state IN ('pending','running')
RETURNING *;

-- name: CreatePreviewTunnel :one
INSERT INTO tunnels
  (id, account_id, name, desired_state, access_mode, stable_endpoint_id, stable_endpoint,
   created_by_host_id, created_by_actor_id, expires_at, summary_code, summary_transitioned_at,
   created_at, updated_at)
VALUES
  (sqlc.arg(id), sqlc.arg(account_id), sqlc.arg(name), sqlc.arg(desired_state),
   sqlc.arg(access_mode), sqlc.arg(stable_endpoint_id), sqlc.arg(stable_endpoint),
   sqlc.arg(created_by_host_id), sqlc.arg(created_by_actor_id), sqlc.narg(expires_at),
   sqlc.arg(summary_code), sqlc.arg(now), sqlc.arg(now), sqlc.arg(now))
RETURNING *;

-- name: GetPreviewTunnel :one
SELECT * FROM tunnels WHERE id = sqlc.arg(id) AND account_id = sqlc.arg(account_id);

-- name: UpdatePreviewTunnelDesiredState :one
UPDATE tunnels
SET desired_state = sqlc.arg(desired_state), generation = generation + 1,
    updated_at = sqlc.arg(now)::timestamptz,
    deleted_at = CASE WHEN sqlc.arg(desired_state)::text = 'deleted'
      THEN sqlc.arg(now)::timestamptz ELSE NULL::timestamptz END
WHERE id = sqlc.arg(id) AND account_id = sqlc.arg(account_id)
  AND generation = sqlc.arg(expected_generation) AND desired_state <> 'deleted'
RETURNING *;

-- name: CreatePreviewTunnelRoute :one
INSERT INTO tunnel_routes
  (id, tunnel_id, name, protocol, match_type, match_hostname, wildcard_suffix, path_prefix,
   priority, origin_scheme, origin_address, preserve_host, host_override, tls_verification,
   tls_server_name, ca_reference, mtls_credential_reference, connect_timeout_ms,
   idle_timeout_ms, max_concurrent_streams, desired_state, created_by_actor_id,
   updated_by_actor_id, created_at, updated_at)
VALUES
  (sqlc.arg(id), sqlc.arg(tunnel_id), sqlc.arg(name), sqlc.arg(protocol), sqlc.arg(match_type),
   sqlc.narg(match_hostname), sqlc.narg(wildcard_suffix), sqlc.narg(path_prefix), sqlc.arg(priority),
   sqlc.arg(origin_scheme), sqlc.arg(origin_address), sqlc.arg(preserve_host), sqlc.narg(host_override),
   sqlc.arg(tls_verification), sqlc.narg(tls_server_name), sqlc.narg(ca_reference),
   sqlc.narg(mtls_credential_reference), sqlc.arg(connect_timeout_ms), sqlc.arg(idle_timeout_ms),
   sqlc.arg(max_concurrent_streams), sqlc.arg(desired_state), sqlc.arg(created_by_actor_id),
   sqlc.arg(updated_by_actor_id), sqlc.arg(now), sqlc.arg(now))
RETURNING *;

-- name: CreatePreviewTunnelDomain :one
INSERT INTO tunnel_domains
  (id, account_id, tunnel_id, route_id, hostname, match_type, ownership_challenge_reference,
   ownership_state, dns_target, observed_records, certificate_strategy, certificate_reference,
   certificate_state, caa_state, conflict_state, generation, created_at, updated_at)
VALUES
  (sqlc.arg(id), sqlc.arg(account_id), sqlc.arg(tunnel_id), sqlc.arg(route_id),
   sqlc.arg(hostname), sqlc.arg(match_type), sqlc.arg(ownership_challenge_reference),
   sqlc.arg(ownership_state), sqlc.arg(dns_target), sqlc.arg(observed_records)::jsonb,
   sqlc.arg(certificate_strategy), sqlc.narg(certificate_reference), sqlc.arg(certificate_state),
   sqlc.arg(caa_state), sqlc.arg(conflict_state), 1, sqlc.arg(now), sqlc.arg(now))
RETURNING *;

-- name: CreatePreviewTunnelConnector :one
INSERT INTO tunnel_connectors
  (id, tunnel_id, host_id, credential_reference, credential_thumbprint, rotation_generation,
   desired_state, software_version, protocol_version, operating_system, architecture,
   drain_state, created_at, updated_at)
VALUES
  (sqlc.arg(id), sqlc.arg(tunnel_id), sqlc.arg(host_id), sqlc.arg(credential_reference),
   sqlc.arg(credential_thumbprint), sqlc.arg(rotation_generation), sqlc.arg(desired_state),
   sqlc.narg(software_version), sqlc.arg(protocol_version), sqlc.narg(operating_system),
   sqlc.narg(architecture), sqlc.arg(drain_state), sqlc.arg(now), sqlc.arg(now))
RETURNING *;

-- name: CreatePreviewTunnelConnectorSession :one
INSERT INTO tunnel_connector_sessions
  (id, connector_id, process_generation, protocol_version, capabilities, state,
   lease_deadline, last_heartbeat_at, retained_until, created_at)
VALUES
  (sqlc.arg(id), sqlc.arg(connector_id), sqlc.arg(process_generation), sqlc.arg(protocol_version),
   sqlc.arg(capabilities), sqlc.arg(state), sqlc.arg(lease_deadline), sqlc.arg(now),
   sqlc.arg(retained_until), sqlc.arg(now))
RETURNING *;

-- name: CreatePreviewLease :one
INSERT INTO preview_leases
  (id, endpoint_id, endpoint, account_id, actor_id, owner_device_id, owner_session_id,
   target_scheme, target_address, access_mode, lease_deadline, user_deadline,
   allocation_state, edge_state, origin_state, terminal_state, created_at, last_renewed_at)
VALUES
  (sqlc.arg(id), sqlc.arg(endpoint_id), sqlc.arg(endpoint), sqlc.arg(account_id),
   sqlc.arg(actor_id), sqlc.arg(owner_device_id), sqlc.arg(owner_session_id),
   sqlc.arg(target_scheme), sqlc.arg(target_address), sqlc.arg(access_mode),
   sqlc.arg(lease_deadline), sqlc.narg(user_deadline), sqlc.arg(allocation_state),
   sqlc.arg(edge_state), sqlc.arg(origin_state), 'active', sqlc.arg(now), sqlc.arg(now))
RETURNING *;

-- name: CreatePreviewTunnelConfigGeneration :one
INSERT INTO tunnel_config_generations
  (tunnel_id, generation, previous_generation, content_hash, snapshot, snapshot_reference,
   activation_state, created_by_actor_id, created_at, activated_at, retained_until)
VALUES
  (sqlc.arg(tunnel_id), sqlc.arg(generation), sqlc.narg(previous_generation),
   sqlc.arg(content_hash), sqlc.arg(snapshot), sqlc.narg(snapshot_reference),
   sqlc.arg(activation_state), sqlc.arg(created_by_actor_id), sqlc.arg(now),
   sqlc.narg(activated_at), sqlc.arg(retained_until))
RETURNING *;

-- name: SupersedePreviewTunnelConfigGeneration :execrows
UPDATE tunnel_config_generations
SET activation_state = 'superseded', activated_at = NULL
WHERE tunnel_id = sqlc.arg(tunnel_id) AND activation_state = 'active';

-- name: ActivatePreviewTunnelConfigGeneration :one
UPDATE tunnel_config_generations
SET activation_state = 'active', activated_at = sqlc.arg(activated_at)
WHERE tunnel_id = sqlc.arg(tunnel_id) AND generation = sqlc.arg(generation)
  AND activation_state = 'pending'
RETURNING *;

-- name: InsertPreviewTunnelAuditEvent :one
INSERT INTO audit_events
  (id, account_id, actor_id, actor_user_id, actor_type, event_type, change_type, outcome,
   resource_type, resource_id, idempotency_key, request_id, correlation_id,
   source_device_id, metadata, created_at)
VALUES
  (sqlc.arg(id), sqlc.arg(account_id), sqlc.arg(actor_id), sqlc.narg(actor_user_id),
   sqlc.arg(actor_type), sqlc.arg(event_type), sqlc.arg(change_type), sqlc.arg(outcome),
   sqlc.arg(resource_type), sqlc.arg(resource_id), sqlc.narg(idempotency_key),
   sqlc.narg(request_id), sqlc.arg(correlation_id), sqlc.narg(source_device_id),
   sqlc.arg(metadata)::jsonb, sqlc.arg(created_at))
ON CONFLICT (event_type, resource_type, resource_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL
DO NOTHING
RETURNING *;
