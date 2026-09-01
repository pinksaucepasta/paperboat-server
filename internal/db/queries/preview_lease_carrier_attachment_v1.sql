-- Preview carrier attachment persistence deliberately stores only the
-- operation-bound identity/generation tuple. It has no reusable credential.

-- name: GetPreviewLeaseCarrierAttachmentV1 :one
SELECT a.account_id, a.preview_id, a.operation_id, a.idempotency_key,
       a.request_id, a.correlation_id, a.request_hash, a.owner_device_id, a.owner_session_id, a.host_id,
       a.edge_node_id, a.machine_identity_public_key, a.machine_identity_thumbprint,
       a.carrier_kind, a.lease_generation, a.tunnel_id, a.connector_id,
       a.connector_session_id, a.process_generation, a.config_generation,
       a.config_content_hash, a.route_id, a.route_generation,
       a.edge_endpoints, a.edge_process_epoch, a.attachment_generation, a.state, a.edge_ready,
       a.origin_ready, a.issued_at, a.expires_at, a.ready_at, a.released_at,
       a.created_at, a.updated_at,
       p.endpoint, p.target_scheme, p.target_address, p.access_mode
FROM preview_lease_carrier_attachments AS a
JOIN preview_leases AS p ON p.id = a.preview_id AND p.account_id = a.account_id
WHERE a.account_id = sqlc.arg(account_id)
  AND a.operation_id = sqlc.arg(operation_id);

-- name: GetPreviewLeaseCarrierAttachmentByPreviewV1 :one
SELECT a.account_id, a.preview_id, a.operation_id, a.idempotency_key,
       a.request_id, a.correlation_id, a.request_hash, a.owner_device_id, a.owner_session_id, a.host_id,
       a.edge_node_id, a.machine_identity_public_key, a.machine_identity_thumbprint,
       a.carrier_kind, a.lease_generation, a.tunnel_id, a.connector_id,
       a.connector_session_id, a.process_generation, a.config_generation,
       a.config_content_hash, a.route_id, a.route_generation,
       a.edge_endpoints, a.edge_process_epoch, a.attachment_generation, a.state, a.edge_ready,
       a.origin_ready, a.issued_at, a.expires_at, a.ready_at, a.released_at,
       a.created_at, a.updated_at,
       p.endpoint, p.target_scheme, p.target_address, p.access_mode
FROM preview_lease_carrier_attachments AS a
JOIN preview_leases AS p ON p.id = a.preview_id AND p.account_id = a.account_id
WHERE a.account_id = sqlc.arg(account_id)
  AND a.preview_id = sqlc.arg(preview_id)
  AND a.state NOT IN ('failed','released');

-- name: InsertPreviewLeaseCarrierAttachmentV1 :execrows
INSERT INTO preview_lease_carrier_attachments (
  account_id, preview_id, operation_id, idempotency_key, request_id, correlation_id, request_hash,
  owner_device_id, owner_session_id, host_id, edge_node_id, machine_identity_public_key, machine_identity_thumbprint,
  carrier_kind, lease_generation,
  tunnel_id, connector_id, connector_session_id, process_generation,
  config_generation, config_content_hash, route_id, route_generation,
  edge_endpoints, edge_process_epoch, attachment_generation, state, edge_ready, origin_ready,
  issued_at, expires_at, created_at, updated_at
) VALUES (
  sqlc.arg(account_id), sqlc.arg(preview_id), sqlc.arg(operation_id),
  sqlc.arg(idempotency_key), sqlc.arg(request_id), sqlc.arg(correlation_id), sqlc.arg(request_hash), sqlc.arg(owner_device_id),
  sqlc.arg(owner_session_id), sqlc.arg(host_id), sqlc.arg(edge_node_id), sqlc.arg(machine_identity_public_key), sqlc.arg(machine_identity_thumbprint), 'preview_ephemeral',
  sqlc.arg(lease_generation), sqlc.arg(tunnel_id), sqlc.arg(connector_id),
  sqlc.arg(connector_session_id), sqlc.arg(process_generation),
  sqlc.arg(config_generation), sqlc.arg(config_content_hash), sqlc.arg(route_id),
  sqlc.arg(route_generation), sqlc.arg(edge_endpoints), sqlc.arg(edge_process_epoch), 1, 'pending', false,
  false, sqlc.arg(issued_at), sqlc.arg(expires_at), sqlc.arg(created_at),
  sqlc.arg(updated_at)
)
ON CONFLICT DO NOTHING;

-- name: AdmitPreviewLeaseCarrierAttachmentV1 :execrows
UPDATE preview_lease_carrier_attachments
	SET state = 'admitted',
	    edge_ready = false,
	    attachment_generation = attachment_generation + 1,
	    ready_at = NULL,
    updated_at = sqlc.arg(now)
WHERE account_id = sqlc.arg(account_id)
  AND operation_id = sqlc.arg(operation_id)
  AND state = 'pending'
  AND attachment_generation = sqlc.arg(expected_generation)
  AND preview_id = sqlc.arg(preview_id)
  AND owner_device_id = sqlc.arg(owner_device_id)
  AND owner_session_id = sqlc.arg(owner_session_id)
  AND host_id = sqlc.arg(host_id)
  AND edge_node_id = sqlc.arg(edge_node_id)
  AND machine_identity_public_key = sqlc.arg(machine_identity_public_key)
  AND machine_identity_thumbprint = sqlc.arg(machine_identity_thumbprint)
  AND lease_generation = sqlc.arg(lease_generation)
  AND tunnel_id = sqlc.arg(tunnel_id)
  AND connector_id = sqlc.arg(connector_id)
  AND connector_session_id = sqlc.arg(connector_session_id)
  AND process_generation = sqlc.arg(process_generation)
  AND config_generation = sqlc.arg(config_generation)
  AND route_id = sqlc.arg(route_id)
  AND route_generation = sqlc.arg(route_generation)
  AND edge_process_epoch = sqlc.arg(edge_process_epoch)
  AND expires_at > sqlc.arg(now);

-- name: ObservePreviewLeaseCarrierEdgeV1 :execrows
UPDATE preview_lease_carrier_attachments
SET edge_ready = true,
    origin_ready = false,
    state = 'edge_ready',
    ready_at = NULL,
    attachment_generation = attachment_generation + 1,
    updated_at = sqlc.arg(now)
WHERE account_id = sqlc.arg(account_id)
  AND operation_id = sqlc.arg(operation_id)
  AND state = 'admitted'
  AND attachment_generation = sqlc.arg(expected_generation)
  AND preview_id = sqlc.arg(preview_id)
  AND owner_device_id = sqlc.arg(owner_device_id)
  AND owner_session_id = sqlc.arg(owner_session_id)
  AND host_id = sqlc.arg(host_id)
  AND edge_node_id = sqlc.arg(edge_node_id)
  AND machine_identity_public_key = sqlc.arg(machine_identity_public_key)
  AND machine_identity_thumbprint = sqlc.arg(machine_identity_thumbprint)
  AND lease_generation = sqlc.arg(lease_generation)
  AND tunnel_id = sqlc.arg(tunnel_id)
  AND connector_id = sqlc.arg(connector_id)
  AND connector_session_id = sqlc.arg(connector_session_id)
  AND process_generation = sqlc.arg(process_generation)
  AND config_generation = sqlc.arg(config_generation)
  AND route_id = sqlc.arg(route_id)
  AND route_generation = sqlc.arg(route_generation)
  AND edge_process_epoch = sqlc.arg(edge_process_epoch)
  AND expires_at > sqlc.arg(now);

-- name: ObservePreviewLeaseCarrierOriginV1 :execrows
UPDATE preview_lease_carrier_attachments
SET origin_ready = sqlc.arg(origin_ready),
    state = CASE WHEN sqlc.arg(origin_ready) THEN 'ready' ELSE 'edge_ready' END,
    ready_at = CASE WHEN sqlc.arg(origin_ready) THEN sqlc.arg(now) ELSE NULL END,
    attachment_generation = attachment_generation + 1,
    updated_at = sqlc.arg(now)
WHERE account_id = sqlc.arg(account_id)
  AND operation_id = sqlc.arg(operation_id)
  AND state IN ('edge_ready','ready')
  AND edge_ready
  AND attachment_generation = sqlc.arg(expected_generation)
  AND preview_id = sqlc.arg(preview_id)
  AND owner_device_id = sqlc.arg(owner_device_id)
  AND owner_session_id = sqlc.arg(owner_session_id)
  AND host_id = sqlc.arg(host_id)
  AND edge_node_id = sqlc.arg(edge_node_id)
  AND machine_identity_public_key = sqlc.arg(machine_identity_public_key)
  AND machine_identity_thumbprint = sqlc.arg(machine_identity_thumbprint)
  AND lease_generation = sqlc.arg(lease_generation)
  AND tunnel_id = sqlc.arg(tunnel_id)
  AND connector_id = sqlc.arg(connector_id)
  AND connector_session_id = sqlc.arg(connector_session_id)
  AND process_generation = sqlc.arg(process_generation)
  AND config_generation = sqlc.arg(config_generation)
  AND route_id = sqlc.arg(route_id)
  AND route_generation = sqlc.arg(route_generation)
  AND edge_process_epoch = sqlc.arg(edge_process_epoch)
  AND expires_at > sqlc.arg(now);

-- name: RenewPreviewLeaseCarrierAttachmentV1 :execrows
UPDATE preview_lease_carrier_attachments
SET lease_generation = sqlc.arg(lease_generation),
    connector_session_id = sqlc.arg(connector_session_id),
    process_generation = sqlc.arg(process_generation),
    config_generation = sqlc.arg(config_generation),
    config_content_hash = sqlc.arg(config_content_hash),
    edge_endpoints = sqlc.arg(edge_endpoints),
    edge_node_id = sqlc.arg(edge_node_id),
    edge_process_epoch = sqlc.arg(edge_process_epoch),
    machine_identity_public_key = sqlc.arg(machine_identity_public_key),
    machine_identity_thumbprint = sqlc.arg(machine_identity_thumbprint),
    attachment_generation = attachment_generation + 1,
    edge_ready = CASE WHEN connector_session_id = sqlc.arg(connector_session_id) AND process_generation = sqlc.arg(process_generation) AND config_generation = sqlc.arg(config_generation) AND config_content_hash = sqlc.arg(config_content_hash) AND edge_node_id = sqlc.arg(edge_node_id) AND edge_process_epoch = sqlc.arg(edge_process_epoch) AND machine_identity_public_key = sqlc.arg(machine_identity_public_key) AND machine_identity_thumbprint = sqlc.arg(machine_identity_thumbprint) THEN edge_ready ELSE false END,
    origin_ready = CASE WHEN connector_session_id = sqlc.arg(connector_session_id) AND process_generation = sqlc.arg(process_generation) AND config_generation = sqlc.arg(config_generation) AND config_content_hash = sqlc.arg(config_content_hash) AND edge_node_id = sqlc.arg(edge_node_id) AND edge_process_epoch = sqlc.arg(edge_process_epoch) AND machine_identity_public_key = sqlc.arg(machine_identity_public_key) AND machine_identity_thumbprint = sqlc.arg(machine_identity_thumbprint) THEN origin_ready ELSE false END,
    state = CASE WHEN connector_session_id = sqlc.arg(connector_session_id) AND process_generation = sqlc.arg(process_generation) AND config_generation = sqlc.arg(config_generation) AND config_content_hash = sqlc.arg(config_content_hash) AND edge_node_id = sqlc.arg(edge_node_id) AND edge_process_epoch = sqlc.arg(edge_process_epoch) AND machine_identity_public_key = sqlc.arg(machine_identity_public_key) AND machine_identity_thumbprint = sqlc.arg(machine_identity_thumbprint) THEN state ELSE 'pending' END,
    ready_at = CASE WHEN connector_session_id = sqlc.arg(connector_session_id) AND process_generation = sqlc.arg(process_generation) AND config_generation = sqlc.arg(config_generation) AND config_content_hash = sqlc.arg(config_content_hash) AND edge_node_id = sqlc.arg(edge_node_id) AND edge_process_epoch = sqlc.arg(edge_process_epoch) AND machine_identity_public_key = sqlc.arg(machine_identity_public_key) AND machine_identity_thumbprint = sqlc.arg(machine_identity_thumbprint) THEN ready_at ELSE NULL END,
    expires_at = sqlc.arg(expires_at),
    updated_at = sqlc.arg(now)
WHERE account_id = sqlc.arg(account_id)
  AND operation_id = sqlc.arg(operation_id)
  AND state NOT IN ('failed','released')
  AND attachment_generation = sqlc.arg(expected_generation)
  AND preview_id = sqlc.arg(preview_id)
  AND owner_device_id = sqlc.arg(owner_device_id)
  AND owner_session_id = sqlc.arg(owner_session_id)
  AND host_id = sqlc.arg(host_id)
  AND tunnel_id = sqlc.arg(tunnel_id)
  AND connector_id = sqlc.arg(connector_id)
  AND route_id = sqlc.arg(route_id)
  AND route_generation = sqlc.arg(route_generation)
  AND lease_generation = sqlc.arg(current_lease_generation)
  AND connector_session_id = sqlc.arg(current_connector_session_id)
  AND process_generation = sqlc.arg(current_process_generation)
  AND config_generation = sqlc.arg(current_config_generation)
  AND edge_node_id = sqlc.arg(current_edge_node_id)
  AND edge_process_epoch = sqlc.arg(current_edge_process_epoch)
  AND machine_identity_public_key = sqlc.arg(current_machine_identity_public_key)
  AND machine_identity_thumbprint = sqlc.arg(current_machine_identity_thumbprint)
  AND expires_at > sqlc.arg(now);

-- name: ReleasePreviewLeaseCarrierAttachmentV1 :execrows
UPDATE preview_lease_carrier_attachments
SET state = 'released', edge_ready = false, origin_ready = false,
    ready_at = NULL, released_at = sqlc.arg(now), expires_at = sqlc.arg(now),
    attachment_generation = attachment_generation + 1, updated_at = sqlc.arg(now)
WHERE account_id = sqlc.arg(account_id)
  AND operation_id = sqlc.arg(operation_id)
  AND state NOT IN ('failed','released')
  AND attachment_generation = sqlc.arg(expected_generation)
  AND preview_id = sqlc.arg(preview_id)
  AND owner_device_id = sqlc.arg(owner_device_id)
  AND owner_session_id = sqlc.arg(owner_session_id)
  AND host_id = sqlc.arg(host_id)
  AND edge_node_id = sqlc.arg(edge_node_id)
  AND machine_identity_public_key = sqlc.arg(machine_identity_public_key)
  AND machine_identity_thumbprint = sqlc.arg(machine_identity_thumbprint)
  AND lease_generation = sqlc.arg(lease_generation)
  AND tunnel_id = sqlc.arg(tunnel_id)
  AND connector_id = sqlc.arg(connector_id)
  AND connector_session_id = sqlc.arg(connector_session_id)
  AND process_generation = sqlc.arg(process_generation)
  AND config_generation = sqlc.arg(config_generation)
  AND route_id = sqlc.arg(route_id)
  AND route_generation = sqlc.arg(route_generation)
  AND edge_process_epoch = sqlc.arg(edge_process_epoch);

-- name: ExpirePreviewLeaseCarrierAttachmentsV1 :execrows
UPDATE preview_lease_carrier_attachments
SET state = 'failed', edge_ready = false, origin_ready = false,
    ready_at = NULL, attachment_generation = attachment_generation + 1,
    updated_at = sqlc.arg(now)
WHERE state NOT IN ('failed','released')
  AND expires_at <= sqlc.arg(now);
