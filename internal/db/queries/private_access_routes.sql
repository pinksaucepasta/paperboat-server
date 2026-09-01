-- name: ListPrivateAccessRoutesForMachineV1 :many
WITH private_routes AS (
  SELECT a.account_id,
         'preview'::text AS resource_kind,
         a.preview_id AS resource_id,
         ''::text AS tunnel_name,
         ''::text AS route_name,
         a.operation_id,
         ''::text AS connector_id,
         a.connector_session_id AS carrier_session_id,
         a.route_id,
         a.route_generation,
         a.lease_generation AS session_generation,
         a.process_generation,
         a.config_generation,
         a.lease_generation AS assignment_generation,
         a.edge_node_id,
         a.edge_process_epoch,
         'http'::text AS protocol,
         regexp_replace(p.endpoint, '^https://', '') AS hostname,
         a.edge_endpoints,
         a.expires_at,
         a.tunnel_id,
	         a.connector_id AS carrier_connector_id,
	         a.operation_id AS assignment_id,
	         a.config_content_hash,
	         'exact'::text AS match_type,
	         ''::text AS wildcard_suffix
	         ,a.edge_carrier_server_spki_sha256
	         ,a.edge_carrier_server_certificate_chain_pem
  FROM preview_lease_carrier_attachments AS a
  JOIN preview_leases AS p ON p.id = a.preview_id AND p.account_id = a.account_id
  JOIN control_tunnel_nodes AS n ON n.id = a.edge_node_id AND n.process_epoch = a.edge_process_epoch
  WHERE a.account_id = sqlc.arg(account_id)
    AND p.access_mode = 'private'
    AND p.terminal_state = 'active'
    AND p.lease_deadline > sqlc.arg(now)
    AND a.state = 'ready'
    AND a.expires_at > sqlc.arg(now)
    AND n.state = 'ready' AND n.ready = true
    AND n.last_heartbeat_at > sqlc.arg(now) - interval '2 minutes'
  UNION ALL
  SELECT a.account_id,
         'tunnel'::text AS resource_kind,
         a.tunnel_id AS resource_id,
         t.name AS tunnel_name,
         r.name AS route_name,
         ''::text AS operation_id,
         a.connector_id,
         a.connector_session_id AS carrier_session_id,
         a.route_id,
         a.route_generation,
         a.connector_generation AS session_generation,
         a.connector_process_generation AS process_generation,
         a.config_generation,
         a.assignment_generation,
         a.edge_node_id,
         a.edge_process_epoch,
         r.protocol,
	         CASE WHEN r.protocol = 'http' THEN regexp_replace(COALESCE(r.match_hostname, t.stable_endpoint), '^https://', '') ELSE '' END AS hostname,
         ARRAY[
           'tls://' || n.carrier_endpoint_host || ':' || n.carrier_endpoint_tcp_port::text,
           'quic://' || n.carrier_endpoint_host || ':' || n.carrier_endpoint_quic_port::text
         ]::text[] AS edge_endpoints,
         LEAST(COALESCE(t.expires_at, sqlc.arg(now) + interval '10 minutes'), s.lease_deadline) AS expires_at,
         a.tunnel_id,
	         a.connector_id AS carrier_connector_id,
	         a.assignment_id,
	         'sha256:' || encode(a.config_content_hash, 'hex') AS config_content_hash,
	         r.match_type,
	         CASE WHEN r.match_type = 'one_label_wildcard' THEN regexp_replace(r.match_hostname, '^\\*\\.', '') ELSE '' END AS wildcard_suffix
	         ,n.carrier_server_spki_sha256 AS edge_carrier_server_spki_sha256
	         ,n.carrier_server_certificate_chain_pem AS edge_carrier_server_certificate_chain_pem
  FROM tunnel_edge_route_assignments AS a
  JOIN tunnels AS t ON t.id = a.tunnel_id AND t.account_id = a.account_id
  JOIN tunnel_routes AS r ON r.id = a.route_id AND r.tunnel_id = a.tunnel_id
  JOIN tunnel_connector_sessions AS s ON s.id = a.connector_session_id AND s.connector_id = a.connector_id
  JOIN control_tunnel_nodes AS n ON n.id = a.edge_node_id AND n.process_epoch = a.edge_process_epoch
  WHERE a.account_id = sqlc.arg(account_id)
    AND a.access_mode = 'private'
    AND a.state = 'active' AND a.observed_state = 'ready'
    AND t.desired_state = 'active' AND r.desired_state = 'active'
    AND s.state = 'ready' AND s.lease_deadline > sqlc.arg(now)
    AND n.state = 'ready' AND n.ready = true
    AND n.last_heartbeat_at > sqlc.arg(now) - interval '2 minutes'
    AND n.carrier_endpoint_host IS NOT NULL
    AND n.carrier_endpoint_tcp_port IS NOT NULL
    AND n.carrier_endpoint_quic_port IS NOT NULL
)
SELECT routes.*,
       machine.id AS accessor_device_id,
       machine.installation_generation,
       machine.public_identity_key AS accessor_public_key
FROM private_routes AS routes
JOIN user_machines AS machine
  ON machine.id = sqlc.arg(machine_id)
 AND machine.user_id = routes.account_id
 AND machine.state = 'online' AND machine.online
 AND machine.revoked_at IS NULL AND machine.deleted_at IS NULL
 AND machine.public_identity_key IS NOT NULL
ORDER BY routes.resource_kind, routes.resource_id, routes.route_id
LIMIT sqlc.arg(row_limit);

-- name: ListPrivateAccessCarrierAdmissionsForEdgeV1 :many
WITH private_routes AS (
  SELECT a.account_id, 'preview'::text AS resource_kind, a.preview_id AS resource_id,
         ''::text AS tunnel_name, ''::text AS route_name,
         a.operation_id, ''::text AS connector_id, a.connector_session_id AS carrier_session_id,
         a.route_id, a.route_generation, a.lease_generation AS session_generation,
         a.process_generation, a.config_generation, a.lease_generation AS assignment_generation,
         a.edge_node_id, a.edge_process_epoch, 'http'::text AS protocol, regexp_replace(p.endpoint, '^https://', '') AS hostname,
	         a.edge_endpoints, a.expires_at, a.tunnel_id, a.connector_id AS carrier_connector_id,
	         a.operation_id AS assignment_id, a.config_content_hash,
	         'exact'::text AS match_type, ''::text AS wildcard_suffix
	         ,a.edge_carrier_server_spki_sha256
	         ,a.edge_carrier_server_certificate_chain_pem
  FROM preview_lease_carrier_attachments AS a
  JOIN preview_leases AS p ON p.id = a.preview_id AND p.account_id = a.account_id
  JOIN control_tunnel_nodes AS n ON n.id = a.edge_node_id AND n.process_epoch = a.edge_process_epoch
  WHERE a.edge_node_id = sqlc.arg(edge_node_id) AND a.edge_process_epoch = sqlc.arg(edge_process_epoch)
    AND p.access_mode = 'private' AND p.terminal_state = 'active' AND p.lease_deadline > sqlc.arg(now)
    AND a.state = 'ready' AND a.expires_at > sqlc.arg(now)
    AND n.state = 'ready' AND n.ready = true
    AND n.last_heartbeat_at > sqlc.arg(now) - interval '2 minutes'
  UNION ALL
  SELECT a.account_id, 'tunnel'::text AS resource_kind, a.tunnel_id AS resource_id,
         t.name AS tunnel_name, r.name AS route_name,
         ''::text AS operation_id, a.connector_id, a.connector_session_id AS carrier_session_id,
         a.route_id, a.route_generation, a.connector_generation AS session_generation,
         a.connector_process_generation AS process_generation, a.config_generation, a.assignment_generation,
         a.edge_node_id, a.edge_process_epoch, r.protocol,
	         CASE WHEN r.protocol = 'http' THEN regexp_replace(COALESCE(r.match_hostname, t.stable_endpoint), '^https://', '') ELSE '' END AS hostname,
         ARRAY['tls://' || n.carrier_endpoint_host || ':' || n.carrier_endpoint_tcp_port::text,
               'quic://' || n.carrier_endpoint_host || ':' || n.carrier_endpoint_quic_port::text]::text[] AS edge_endpoints,
         LEAST(COALESCE(t.expires_at, sqlc.arg(now) + interval '10 minutes'), s.lease_deadline) AS expires_at,
	         a.tunnel_id, a.connector_id AS carrier_connector_id,
	         a.assignment_id, 'sha256:' || encode(a.config_content_hash, 'hex') AS config_content_hash,
	         r.match_type,
	         CASE WHEN r.match_type = 'one_label_wildcard' THEN regexp_replace(r.match_hostname, '^\\*\\.', '') ELSE '' END AS wildcard_suffix
	         ,n.carrier_server_spki_sha256 AS edge_carrier_server_spki_sha256
	         ,n.carrier_server_certificate_chain_pem AS edge_carrier_server_certificate_chain_pem
  FROM tunnel_edge_route_assignments AS a
  JOIN tunnels AS t ON t.id = a.tunnel_id AND t.account_id = a.account_id
  JOIN tunnel_routes AS r ON r.id = a.route_id AND r.tunnel_id = a.tunnel_id
  JOIN tunnel_connector_sessions AS s ON s.id = a.connector_session_id AND s.connector_id = a.connector_id
  JOIN control_tunnel_nodes AS n ON n.id = a.edge_node_id AND n.process_epoch = a.edge_process_epoch
  WHERE a.edge_node_id = sqlc.arg(edge_node_id) AND a.edge_process_epoch = sqlc.arg(edge_process_epoch)
    AND a.access_mode = 'private' AND a.state = 'active' AND a.observed_state = 'ready'
    AND t.desired_state = 'active' AND r.desired_state = 'active'
    AND s.state = 'ready' AND s.lease_deadline > sqlc.arg(now)
    AND n.state = 'ready' AND n.ready = true
    AND n.last_heartbeat_at > sqlc.arg(now) - interval '2 minutes'
)
SELECT routes.*,
       machine.id AS accessor_device_id,
       machine.installation_generation,
       machine.public_identity_key AS accessor_public_key
FROM private_routes AS routes
JOIN user_machines AS machine
  ON machine.user_id = routes.account_id
 AND machine.state = 'online' AND machine.online
 AND machine.revoked_at IS NULL AND machine.deleted_at IS NULL
 AND machine.public_identity_key IS NOT NULL
ORDER BY routes.resource_kind, routes.resource_id, routes.route_id, machine.id
LIMIT sqlc.arg(row_limit);
