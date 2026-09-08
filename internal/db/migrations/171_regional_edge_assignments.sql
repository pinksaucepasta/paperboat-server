-- +goose Up
-- Deployment authority supplies these only after public reachability is proven.
-- Node registration and connector observations cannot authorize public addresses.
ALTER TABLE control_tunnel_nodes
 ADD COLUMN public_ingress_ipv4 inet,
 ADD COLUMN public_ingress_ipv6 inet,
 ADD COLUMN public_ingress_verified_at timestamptz,
 ADD CONSTRAINT control_tunnel_nodes_public_address_family CHECK (
   (public_ingress_ipv4 IS NULL OR family(public_ingress_ipv4)=4) AND
   (public_ingress_ipv6 IS NULL OR family(public_ingress_ipv6)=6));
DROP INDEX tunnel_edge_route_assignments_route_connector_staged;
DROP INDEX tunnel_edge_route_assignments_route_connector_active;
CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_connector_node_staged
  ON tunnel_edge_route_assignments(route_id, connector_id, edge_node_id) WHERE state = 'staged';
CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_connector_node_active
  ON tunnel_edge_route_assignments(route_id, connector_id, edge_node_id) WHERE state = 'active';

-- +goose Down
ALTER TABLE control_tunnel_nodes DROP CONSTRAINT control_tunnel_nodes_public_address_family,
 DROP COLUMN public_ingress_ipv4, DROP COLUMN public_ingress_ipv6, DROP COLUMN public_ingress_verified_at;
-- Refuse downgrade while regional replicas exist rather than discard authority.
CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_connector_staged
  ON tunnel_edge_route_assignments(route_id, connector_id) WHERE state = 'staged';
CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_connector_active
  ON tunnel_edge_route_assignments(route_id, connector_id) WHERE state = 'active';
DROP INDEX tunnel_edge_route_assignments_route_connector_node_staged;
DROP INDEX tunnel_edge_route_assignments_route_connector_node_active;
