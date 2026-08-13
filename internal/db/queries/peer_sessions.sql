-- name: GetPeerSessionIntentByOperationForUpdate :one
SELECT * FROM peer_session_intents
WHERE operation_key = sqlc.arg(operation_key)
FOR UPDATE;

-- name: EnsurePeerRelaySelectionState :exec
INSERT INTO peer_relay_selection_states
  (user_id, machine_id, network_generation, host_worker_generation, updated_at)
VALUES
  (sqlc.arg(user_id), sqlc.arg(machine_id), sqlc.arg(network_generation),
   sqlc.arg(host_worker_generation), sqlc.arg(updated_at))
ON CONFLICT DO NOTHING;

-- name: PrunePeerRelaySelectionStates :execrows
WITH ranked AS (
  SELECT state.user_id, state.machine_id, state.network_generation, state.host_worker_generation,
         row_number() OVER (ORDER BY updated_at DESC, network_generation DESC, host_worker_generation DESC) AS position
  FROM peer_relay_selection_states state
  WHERE state.user_id = sqlc.arg(user_id) AND state.machine_id = sqlc.arg(machine_id)
), removed AS (
  DELETE FROM peer_relay_selection_states state
  USING ranked
  WHERE state.user_id = ranked.user_id AND state.machine_id = ranked.machine_id
    AND state.network_generation = ranked.network_generation
    AND state.host_worker_generation = ranked.host_worker_generation
    AND (state.updated_at < sqlc.arg(stale_before) OR ranked.position > 64)
  RETURNING 1
)
SELECT count(*) FROM removed;

-- name: GetPeerRelaySelectionStateForUpdate :one
SELECT * FROM peer_relay_selection_states
WHERE user_id = sqlc.arg(user_id) AND machine_id = sqlc.arg(machine_id)
  AND network_generation = sqlc.arg(network_generation)
  AND host_worker_generation = sqlc.arg(host_worker_generation)
FOR UPDATE;

-- name: UpdatePeerRelaySelectionState :execrows
UPDATE peer_relay_selection_states
SET current_region = sqlc.arg(current_region),
    client_generation = sqlc.arg(client_generation),
    client_observed_at = sqlc.arg(client_observed_at),
    candidate_region = sqlc.arg(candidate_region),
    candidate_first_observed_at = sqlc.arg(candidate_first_observed_at),
    candidate_last_observed_at = sqlc.arg(candidate_last_observed_at),
    candidate_samples = sqlc.arg(candidate_samples),
    updated_at = sqlc.arg(updated_at)
WHERE user_id = sqlc.arg(user_id) AND machine_id = sqlc.arg(machine_id)
  AND network_generation = sqlc.arg(network_generation)
  AND host_worker_generation = sqlc.arg(host_worker_generation);

-- name: ResolvePeerSessionAuthorityForUpdate :one
SELECT controlling.endpoint_id AS controlling_endpoint_id,
       controlled.endpoint_id AS controlled_endpoint_id,
       controlling.certificate AS controlling_certificate,
       controlled.certificate AS controlled_certificate,
       node.id AS edge_node_id,
       node.edge_pool,
       node.signaling_host,
       node.stun_host,
       node.stun_port,
       connector.generation AS authorization_generation,
       machine.installation_generation AS host_generation,
       machine.relay_latency_worker_generation,
       machine.relay_latency_generation,
       machine.relay_latency_observed_at,
       machine.relay_latency_vector
FROM cli_client_sessions client
JOIN account_e2ee_roots root ON root.user_id = client.user_id
JOIN peer_endpoint_certificates controlling
  ON controlling.fingerprint = sqlc.arg(controlling_certificate_fingerprint)
  AND controlling.user_id = client.user_id AND controlling.role = 'cli'
  AND controlling.endpoint_id = client.id
JOIN peer_endpoint_certificates controlled
  ON controlled.fingerprint = sqlc.arg(controlled_certificate_fingerprint)
  AND controlled.user_id = client.user_id AND controlled.role = 'machine'
JOIN control_environments environment
  ON environment.id = sqlc.arg(environment_id) AND environment.owner_user_id = client.user_id
JOIN user_machines machine
  ON machine.id = controlled.endpoint_id AND machine.environment_id = environment.id
JOIN control_connector_generations connector
  ON connector.environment_id = environment.id AND connector.machine_id = machine.id
  AND connector.connector_id = 'runtime' AND connector.state = 'admitted' AND connector.revoked_at IS NULL
JOIN control_tunnel_nodes node ON node.id = connector.edge_node_id
WHERE client.id = sqlc.arg(cli_client_session_id)
  AND client.user_id = sqlc.arg(user_id) AND client.state = 'active'
  AND root.revoked_at IS NULL
  AND controlling.revoked_at IS NULL AND controlling.issued_at <= sqlc.arg(now)
  AND controlling.expires_at > sqlc.arg(now)
  AND controlled.revoked_at IS NULL AND controlled.issued_at <= sqlc.arg(now)
  AND controlled.expires_at > sqlc.arg(now)
  AND environment.desired_state = 'active' AND environment.revoked_at IS NULL
  AND machine.revoked_at IS NULL AND machine.deleted_at IS NULL
  AND node.state = 'ready' AND node.ready = true
  AND node.signaling_host IS NOT NULL AND node.stun_host IS NOT NULL AND node.stun_port IS NOT NULL
  AND node.last_heartbeat_at > sqlc.arg(node_stale_after)::timestamptz
FOR UPDATE OF client, root, controlling, controlled, environment, node;

-- name: ListReadyPeerRelayNodes :many
SELECT DISTINCT ON (edge_pool)
  id, edge_pool, signaling_host, stun_host, stun_port
FROM control_tunnel_nodes
WHERE state = 'ready' AND ready = true
  AND last_heartbeat_at > sqlc.arg(node_stale_after)::timestamptz
  AND signaling_host IS NOT NULL AND stun_host IS NOT NULL
  AND stun_port BETWEEN 1 AND 65535
  AND CASE WHEN jsonb_typeof(capacity->'connectors') = 'number'
      THEN (capacity->>'connectors')::bigint ELSE 0 END
    > CASE WHEN jsonb_typeof(observation->'active_streams') = 'number'
      THEN (observation->>'active_streams')::bigint ELSE 0 END
ORDER BY edge_pool, last_heartbeat_at DESC, id
LIMIT 32;

-- name: IsPeerRelayNodeReady :one
SELECT EXISTS (
  SELECT 1 FROM control_tunnel_nodes
  WHERE id = sqlc.arg(id) AND state = 'ready' AND ready = true
    AND last_heartbeat_at > sqlc.arg(node_stale_after)::timestamptz
);

-- name: CreatePeerSessionIntent :one
INSERT INTO peer_session_intents
  (id, operation_key, request_hash, user_id, cli_client_session_id, environment_id, purpose,
   edge_node_id, controlling_certificate_fingerprint, controlled_certificate_fingerprint,
   attempt_generation, network_generation, ice_credentials_ciphertext, edge_pool,
   signaling_host, stun_host, stun_port, expires_at, created_at)
VALUES
  (sqlc.arg(id), sqlc.arg(operation_key), sqlc.arg(request_hash), sqlc.arg(user_id),
   sqlc.arg(cli_client_session_id), sqlc.arg(environment_id), sqlc.arg(purpose), sqlc.arg(edge_node_id),
   sqlc.arg(controlling_certificate_fingerprint), sqlc.arg(controlled_certificate_fingerprint),
   sqlc.arg(attempt_generation), sqlc.arg(network_generation), sqlc.arg(ice_credentials_ciphertext),
   sqlc.arg(edge_pool), sqlc.arg(signaling_host), sqlc.arg(stun_host), sqlc.arg(stun_port),
   sqlc.arg(expires_at), sqlc.arg(created_at))
RETURNING *;

-- name: CreatePeerSignalingGrant :one
INSERT INTO peer_signaling_grants
  (intent_id, role, endpoint_id, peer_endpoint_id, jti, issued_at, expires_at)
VALUES
  (sqlc.arg(intent_id), sqlc.arg(role), sqlc.arg(endpoint_id), sqlc.arg(peer_endpoint_id),
   sqlc.arg(jti), sqlc.arg(issued_at), sqlc.arg(expires_at))
RETURNING *;

-- name: ListPeerSignalingGrantsForIntent :many
SELECT * FROM peer_signaling_grants
WHERE intent_id = sqlc.arg(intent_id)
ORDER BY role;

-- name: CreatePeerRelayAllocation :one
INSERT INTO peer_relay_allocations
  (intent_id, route_allocation, jti, route_generation, byte_limit, issued_at, expires_at)
VALUES
  (sqlc.arg(intent_id), sqlc.arg(route_allocation), sqlc.arg(jti), sqlc.arg(route_generation),
   sqlc.arg(byte_limit), sqlc.arg(issued_at), sqlc.arg(expires_at))
RETURNING *;

-- name: GetPeerRelayAllocationForIntent :one
SELECT * FROM peer_relay_allocations
WHERE intent_id = sqlc.arg(intent_id);

-- name: ResolveControlledPeerSessionForMachine :one
SELECT intent.*,
       controlling.certificate AS controlling_certificate,
       controlled.certificate AS controlled_certificate,
       controlling_grant.endpoint_id AS controlling_endpoint_id,
       controlling_grant.peer_endpoint_id AS controlling_peer_endpoint_id,
       controlling_grant.jti AS controlling_jti,
       controlled_grant.endpoint_id AS controlled_endpoint_id,
       controlled_grant.peer_endpoint_id AS controlled_peer_endpoint_id,
       controlled_grant.jti AS controlled_jti,
       relay.route_allocation, relay.jti AS relay_jti,
       relay.route_generation, relay.byte_limit,
       connector.generation AS authorization_generation,
       machine.installation_generation AS host_generation
FROM peer_session_intents intent
JOIN peer_endpoint_certificates controlling
  ON controlling.fingerprint = intent.controlling_certificate_fingerprint
JOIN peer_endpoint_certificates controlled
  ON controlled.fingerprint = intent.controlled_certificate_fingerprint
JOIN peer_signaling_grants controlling_grant
  ON controlling_grant.intent_id = intent.id AND controlling_grant.role = 'controlling'
JOIN peer_signaling_grants controlled_grant
  ON controlled_grant.intent_id = intent.id AND controlled_grant.role = 'controlled'
JOIN peer_relay_allocations relay ON relay.intent_id = intent.id
JOIN user_machines machine
  ON machine.id = controlled.endpoint_id AND machine.user_id = intent.user_id
JOIN control_connector_generations connector
  ON connector.environment_id = intent.environment_id AND connector.machine_id = machine.id
  AND connector.connector_id = 'runtime'
JOIN control_tunnel_nodes node ON node.id = intent.edge_node_id
JOIN account_e2ee_roots root ON root.user_id = intent.user_id
JOIN cli_client_sessions client ON client.id = intent.cli_client_session_id
WHERE intent.user_id = sqlc.arg(user_id) AND machine.id = sqlc.arg(machine_id)
  AND machine.installation_generation = sqlc.arg(host_generation)
  AND controlled.generation = sqlc.arg(host_generation)
  AND intent.controlled_delivered_at IS NULL
  AND intent.state = 'active' AND intent.expires_at > sqlc.arg(now)
  AND controlling.revoked_at IS NULL AND controlling.expires_at > sqlc.arg(now)
  AND controlled.revoked_at IS NULL AND controlled.expires_at > sqlc.arg(now)
  AND controlling_grant.revoked_at IS NULL AND controlling_grant.expires_at > sqlc.arg(now)
  AND controlled_grant.revoked_at IS NULL AND controlled_grant.expires_at > sqlc.arg(now)
  AND relay.revoked_at IS NULL AND relay.expires_at > sqlc.arg(now)
  AND connector.revoked_at IS NULL AND connector.state = 'admitted'
  AND machine.revoked_at IS NULL AND machine.deleted_at IS NULL
  AND root.revoked_at IS NULL AND client.state = 'active'
  AND node.state = 'ready' AND node.ready = true
  AND node.last_heartbeat_at > sqlc.arg(node_stale_after)::timestamptz
ORDER BY intent.created_at, intent.id
LIMIT 1
FOR UPDATE OF intent SKIP LOCKED;

-- name: MarkControlledPeerSessionDelivered :execrows
UPDATE peer_session_intents
SET controlled_delivered_at = coalesce(controlled_delivered_at, sqlc.arg(delivered_at)::timestamptz)
WHERE id = sqlc.arg(id) AND state = 'active';

-- name: RevokePeerSessionIntent :one
WITH revoked AS (
  UPDATE peer_session_intents
  SET state = CASE WHEN sqlc.arg(reason)::text = 'expired' THEN 'expired' ELSE 'revoked' END,
      revoked_at = sqlc.arg(now)::timestamptz, revocation_reason = sqlc.arg(reason)::text
  WHERE id = sqlc.arg(id) AND state = 'active'
    AND attempt_generation = sqlc.arg(attempt_generation)
    AND (sqlc.arg(actor_user_id)::text = '' OR user_id = sqlc.arg(actor_user_id)::text)
  RETURNING *
), grants AS (
  UPDATE peer_signaling_grants
  SET revoked_at = sqlc.arg(now)::timestamptz
  WHERE intent_id = sqlc.arg(id) AND revoked_at IS NULL
), relay AS (
  UPDATE peer_relay_allocations
  SET revoked_at = sqlc.arg(now)::timestamptz
  WHERE intent_id = sqlc.arg(id) AND revoked_at IS NULL
)
SELECT * FROM revoked;

-- name: ReservePeerSessionRevocation :one
INSERT INTO peer_session_revocation_operations
  (operation_key, intent_id, actor_user_id, reason, created_at)
VALUES
  (sqlc.arg(operation_key), sqlc.arg(intent_id), nullif(sqlc.arg(actor_user_id), ''),
   sqlc.arg(reason), sqlc.arg(created_at))
ON CONFLICT DO NOTHING
RETURNING *;

-- name: GetPeerSessionRevocationOperation :one
SELECT * FROM peer_session_revocation_operations
WHERE operation_key = sqlc.arg(operation_key);

-- name: ExpirePeerSessionIntents :many
WITH expired AS (
  UPDATE peer_session_intents
  SET state = 'expired', revoked_at = sqlc.arg(now)::timestamptz, revocation_reason = 'expired'
  WHERE state = 'active' AND expires_at <= sqlc.arg(now)::timestamptz
  RETURNING *
), grants AS (
  UPDATE peer_signaling_grants g
  SET revoked_at = sqlc.arg(now)::timestamptz
  FROM expired
  WHERE g.intent_id = expired.id AND g.revoked_at IS NULL
), relays AS (
  UPDATE peer_relay_allocations relay
  SET revoked_at = sqlc.arg(now)::timestamptz
  FROM expired
  WHERE relay.intent_id = expired.id AND relay.revoked_at IS NULL
)
SELECT * FROM expired ORDER BY id;

-- name: ListActivePeerSignalingJTIs :many
SELECT g.jti
FROM peer_signaling_grants g
JOIN peer_session_intents intent ON intent.id = g.intent_id
JOIN cli_client_sessions client ON client.id = intent.cli_client_session_id
JOIN peer_endpoint_certificates endpoint ON endpoint.fingerprint = CASE g.role
  WHEN 'controlling' THEN intent.controlling_certificate_fingerprint
  ELSE intent.controlled_certificate_fingerprint END
JOIN account_e2ee_roots root ON root.user_id = intent.user_id
WHERE intent.edge_node_id = sqlc.arg(edge_node_id)
  AND intent.state = 'active' AND intent.expires_at > sqlc.arg(now)
  AND g.revoked_at IS NULL AND g.expires_at > sqlc.arg(now)
  AND client.state = 'active'
  AND endpoint.revoked_at IS NULL AND endpoint.expires_at > sqlc.arg(now)
  AND root.revoked_at IS NULL
ORDER BY g.jti;
