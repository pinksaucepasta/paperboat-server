-- +goose Up

-- Preview carrier transport endpoints are distinct from the legacy connector
-- endpoint columns.  The latter describe FRP/control connector ports and must
-- never be used to route canonical data-carrier traffic.
ALTER TABLE control_tunnel_nodes
  ADD COLUMN carrier_endpoint_host text,
  ADD COLUMN carrier_endpoint_tcp_port integer,
  ADD COLUMN carrier_endpoint_quic_port integer;

ALTER TABLE control_tunnel_nodes
  ADD CONSTRAINT control_tunnel_nodes_carrier_endpoint_check CHECK (
    (carrier_endpoint_host IS NULL AND carrier_endpoint_tcp_port IS NULL AND carrier_endpoint_quic_port IS NULL)
    OR (
      length(trim(carrier_endpoint_host)) BETWEEN 1 AND 253
      AND carrier_endpoint_tcp_port BETWEEN 1 AND 65535
      AND carrier_endpoint_quic_port BETWEEN 1 AND 65535
      AND carrier_endpoint_tcp_port <> carrier_endpoint_quic_port
    )
  );

-- +goose Down
ALTER TABLE control_tunnel_nodes
  DROP CONSTRAINT IF EXISTS control_tunnel_nodes_carrier_endpoint_check;
ALTER TABLE control_tunnel_nodes
  DROP COLUMN IF EXISTS carrier_endpoint_host,
  DROP COLUMN IF EXISTS carrier_endpoint_tcp_port,
  DROP COLUMN IF EXISTS carrier_endpoint_quic_port;
