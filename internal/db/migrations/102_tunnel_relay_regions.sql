-- +goose Up
ALTER TABLE control_tunnel_nodes
  ADD COLUMN relay_id text,
  ADD COLUMN relay_region text,
  ADD COLUMN relay_name text;

UPDATE control_tunnel_nodes
SET relay_id = id,
    relay_region = edge_pool,
    relay_name = edge_pool;

ALTER TABLE control_tunnel_nodes
  ADD CONSTRAINT control_tunnel_nodes_relay_id_check
    CHECK (relay_id ~ '^[a-z][a-z0-9_-]{0,127}$'),
  ADD CONSTRAINT control_tunnel_nodes_relay_region_check
    CHECK (relay_region ~ '^[a-z][a-z0-9_-]{0,62}$'),
  ADD CONSTRAINT control_tunnel_nodes_relay_name_check
    CHECK (length(trim(relay_name)) BETWEEN 1 AND 80);

CREATE INDEX control_tunnel_nodes_relay_region
  ON control_tunnel_nodes(relay_region, state, ready);

-- +goose Down
DROP INDEX IF EXISTS control_tunnel_nodes_relay_region;
ALTER TABLE control_tunnel_nodes
  DROP CONSTRAINT IF EXISTS control_tunnel_nodes_relay_name_check,
  DROP CONSTRAINT IF EXISTS control_tunnel_nodes_relay_region_check,
  DROP CONSTRAINT IF EXISTS control_tunnel_nodes_relay_id_check,
  DROP COLUMN IF EXISTS relay_name,
  DROP COLUMN IF EXISTS relay_region,
  DROP COLUMN IF EXISTS relay_id;
