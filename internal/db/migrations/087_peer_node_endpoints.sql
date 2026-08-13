-- +goose Up
ALTER TABLE control_tunnel_nodes
  ADD COLUMN signaling_host text,
  ADD COLUMN stun_host text,
  ADD COLUMN stun_port integer;

ALTER TABLE control_tunnel_nodes
  ADD CONSTRAINT control_tunnel_nodes_peer_endpoints_check CHECK (
    (signaling_host IS NULL AND stun_host IS NULL AND stun_port IS NULL) OR
    (length(trim(signaling_host)) BETWEEN 1 AND 253 AND
     length(trim(stun_host)) BETWEEN 1 AND 253 AND
     stun_port BETWEEN 1 AND 65535)
  );

-- +goose Down
ALTER TABLE control_tunnel_nodes DROP CONSTRAINT control_tunnel_nodes_peer_endpoints_check;
ALTER TABLE control_tunnel_nodes
  DROP COLUMN stun_port,
  DROP COLUMN stun_host,
  DROP COLUMN signaling_host;
