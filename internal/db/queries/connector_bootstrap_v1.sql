-- name: GetTunnelManagedEndpointForConnectorBootstrapV1 :one
SELECT stable_endpoint_id, stable_endpoint
FROM tunnels
WHERE id = sqlc.arg(tunnel_id)
  AND account_id = sqlc.arg(account_id)
  AND desired_state <> 'deleted';

-- name: ListReadyConnectorCarrierNodesV1 :many
SELECT id AS edge_node_id,
       process_epoch AS edge_process_epoch,
       failure_domain,
       carrier_endpoint_host,
       carrier_endpoint_tcp_port,
       carrier_endpoint_quic_port,
       carrier_server_spki_sha256,
       carrier_server_certificate_chain_pem,
       last_heartbeat_at,
       LEAST(registry_expires_at,last_heartbeat_at+interval '15 seconds')::timestamptz AS valid_until
FROM control_tunnel_nodes
WHERE state = 'ready'
  AND ready = true
  AND last_heartbeat_at > sqlc.arg(now)::timestamptz - interval '15 seconds'
  AND registry_expires_at > sqlc.arg(now)
  AND roles @> ARRAY['edge']::text[]
  AND transports @> ARRAY['http3','http2']::text[]
  AND drain_deadline IS NULL
  AND (allowed_account_ids IS NULL OR sqlc.arg(account_id)::text=ANY(allowed_account_ids))
  AND EXISTS (
    SELECT 1 FROM tunnel_edge_route_assignments a
    WHERE a.edge_node_id=control_tunnel_nodes.id AND a.edge_process_epoch=control_tunnel_nodes.process_epoch
      AND a.account_id=sqlc.arg(account_id) AND a.connector_id=sqlc.arg(connector_id)
      AND a.connector_session_id=sqlc.arg(session_id) AND a.config_generation=sqlc.arg(config_generation)
      AND a.state IN ('staged','active')
  )
  AND carrier_endpoint_host IS NOT NULL
  AND carrier_endpoint_tcp_port IS NOT NULL
  AND carrier_endpoint_quic_port IS NOT NULL
  AND carrier_server_spki_sha256 IS NOT NULL
  AND carrier_server_certificate_chain_pem IS NOT NULL
ORDER BY id, process_epoch
LIMIT sqlc.arg(row_limit);
