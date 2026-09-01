-- name: GetTunnelManagedEndpointForConnectorBootstrapV1 :one
SELECT stable_endpoint_id, stable_endpoint
FROM tunnels
WHERE id = sqlc.arg(tunnel_id)
  AND account_id = sqlc.arg(account_id)
  AND desired_state <> 'deleted';

-- name: ListReadyConnectorCarrierNodesV1 :many
SELECT id AS edge_node_id,
       process_epoch AS edge_process_epoch,
       relay_region AS failure_domain,
       carrier_endpoint_host,
       carrier_endpoint_tcp_port,
       carrier_endpoint_quic_port,
       carrier_server_spki_sha256,
       carrier_server_certificate_chain_pem,
       last_heartbeat_at
FROM control_tunnel_nodes
WHERE state = 'ready'
  AND ready = true
  AND last_heartbeat_at > sqlc.arg(now)::timestamptz - interval '2 minutes'
  AND carrier_endpoint_host IS NOT NULL
  AND carrier_endpoint_tcp_port IS NOT NULL
  AND carrier_endpoint_quic_port IS NOT NULL
  AND carrier_server_spki_sha256 IS NOT NULL
  AND carrier_server_certificate_chain_pem IS NOT NULL
ORDER BY relay_region, id, process_epoch
LIMIT sqlc.arg(row_limit);
