-- +goose Up
-- +goose StatementBegin
DROP INDEX tunnel_edge_route_assignments_route_staged;
DROP INDEX tunnel_edge_route_assignments_route_active;
CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_connector_staged
  ON tunnel_edge_route_assignments(route_id, connector_id)
  WHERE state = 'staged';
CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_connector_active
  ON tunnel_edge_route_assignments(route_id, connector_id)
  WHERE state = 'active';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX tunnel_edge_route_assignments_route_connector_staged;
DROP INDEX tunnel_edge_route_assignments_route_connector_active;
CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_staged
  ON tunnel_edge_route_assignments(route_id)
  WHERE state = 'staged';
CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_active
  ON tunnel_edge_route_assignments(route_id)
  WHERE state = 'active';
-- +goose StatementEnd
