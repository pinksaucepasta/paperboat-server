-- +goose Up
ALTER TABLE control_tunnel_nodes
  DROP CONSTRAINT control_tunnel_nodes_check;
ALTER TABLE control_tunnel_nodes
  ADD CONSTRAINT control_tunnel_nodes_endpoint_check
  CHECK (
    (endpoint_host IS NULL AND endpoint_tcp_port IS NULL AND endpoint_quic_port IS NULL)
    OR (
      length(trim(endpoint_host)) BETWEEN 1 AND 253
      AND endpoint_tcp_port BETWEEN 1 AND 65535
      AND endpoint_quic_port BETWEEN 1 AND 65535
    )
  );

-- +goose Down
ALTER TABLE control_tunnel_nodes
  DROP CONSTRAINT control_tunnel_nodes_endpoint_check;
ALTER TABLE control_tunnel_nodes
  ADD CONSTRAINT control_tunnel_nodes_check
  CHECK (
    (endpoint_host IS NULL AND endpoint_tcp_port IS NULL AND endpoint_quic_port IS NULL)
    OR (
      length(trim(endpoint_host)) BETWEEN 1 AND 253
      AND endpoint_tcp_port BETWEEN 1 AND 65535
      AND endpoint_quic_port BETWEEN 1 AND 65535
      AND endpoint_tcp_port <> endpoint_quic_port
    )
  );
