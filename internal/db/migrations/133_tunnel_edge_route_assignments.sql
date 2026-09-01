-- +goose Up

-- A canonical route assignment is the durable publication boundary between a
-- ready connector session and an edge process.  It deliberately contains no
-- origin address: origins belong to the connector's authenticated config
-- snapshot and the edge opens an opaque route stream on that connector.
--
-- Assignment history is retained so a replacement can be staged and observed
-- before the old assignment is drained.  The edge receives both records and
-- uses assignment_id/generation as its replacement fence.
ALTER TABLE tunnel_connector_sessions
  ADD CONSTRAINT tunnel_connector_sessions_id_connector_unique UNIQUE (id, connector_id);

CREATE TABLE tunnel_edge_route_assignments (
  assignment_id text PRIMARY KEY,
  route_id text NOT NULL,
  assignment_generation bigint NOT NULL,
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tunnel_id text NOT NULL,
  connector_id text NOT NULL,
  host_id text NOT NULL,
  machine_identity_public_key text NOT NULL,
  machine_identity_thumbprint text NOT NULL,
  connector_generation bigint NOT NULL,
  connector_session_id text NOT NULL,
  connector_process_generation bigint NOT NULL,
  config_generation bigint NOT NULL,
  config_content_hash bytea NOT NULL,
  access_mode text NOT NULL DEFAULT 'public',
  route_generation bigint NOT NULL,
  route_revision bigint NOT NULL,
  edge_node_id text NOT NULL,
  edge_process_epoch text NOT NULL,
  edge_failure_domain text NOT NULL,
  state text NOT NULL DEFAULT 'staged',
  observed_state text NOT NULL DEFAULT 'pending',
  assigned_at timestamptz NOT NULL DEFAULT now(),
  observed_at timestamptz,
  released_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tunnel_id, account_id)
    REFERENCES tunnels(id, account_id) ON DELETE CASCADE,
  FOREIGN KEY (route_id, tunnel_id)
    REFERENCES tunnel_routes(id, tunnel_id) ON DELETE CASCADE,
  FOREIGN KEY (connector_id, tunnel_id)
    REFERENCES tunnel_connectors(id, tunnel_id) ON DELETE CASCADE,
  FOREIGN KEY (connector_id, tunnel_id, host_id)
    REFERENCES tunnel_connectors(id, tunnel_id, host_id) ON DELETE CASCADE,
  FOREIGN KEY (connector_session_id, connector_id)
    REFERENCES tunnel_connector_sessions(id, connector_id) ON DELETE CASCADE,
  FOREIGN KEY (tunnel_id, config_generation)
    REFERENCES tunnel_config_generations(tunnel_id, generation) ON DELETE RESTRICT,
  -- The node row is mutable across process replacement. Keep the stable node
  -- reference here and fence the captured process epoch in every query so a
  -- replacement can coexist with an older draining assignment.
  FOREIGN KEY (edge_node_id)
    REFERENCES control_tunnel_nodes(id) ON DELETE RESTRICT,
  CHECK (length(trim(assignment_id)) BETWEEN 3 AND 128),
  CHECK (assignment_generation > 0),
  CHECK (machine_identity_public_key ~ '^[A-Za-z0-9_-]{43}$'),
  CHECK (machine_identity_thumbprint ~ '^[A-Za-z0-9_-]{43}$'),
  CHECK (connector_generation > 0),
  CHECK (connector_process_generation > 0),
  CHECK (config_generation > 0),
  CHECK (octet_length(config_content_hash) = 32),
  CHECK (access_mode IN ('public','private')),
  CHECK (route_generation > 0 AND route_revision > 0),
  CHECK (route_revision = route_generation),
  CHECK (length(trim(edge_failure_domain)) BETWEEN 1 AND 128),
  CHECK (length(edge_process_epoch) BETWEEN 8 AND 128 AND edge_process_epoch ~ '^[A-Za-z0-9_-]+$'),
  CHECK (state IN ('staged','active','draining','detached')),
  CHECK (observed_state IN ('pending','ready','degraded','draining','detached','failed')),
  CHECK (observed_state <> 'ready' OR state IN ('staged','active')),
  CHECK ((state = 'detached') = (released_at IS NOT NULL))
);

CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_generation
  ON tunnel_edge_route_assignments(route_id, assignment_generation);
CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_staged
  ON tunnel_edge_route_assignments(route_id)
  WHERE state = 'staged';
CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_active
  ON tunnel_edge_route_assignments(route_id)
  WHERE state = 'active';
CREATE INDEX tunnel_edge_route_assignments_node_live
  ON tunnel_edge_route_assignments(edge_node_id, edge_process_epoch, route_id, assignment_generation)
  WHERE state IN ('staged','active','draining');
CREATE INDEX tunnel_edge_route_assignments_connector_live
  ON tunnel_edge_route_assignments(connector_id, connector_session_id, connector_process_generation)
  WHERE state IN ('staged','active','draining');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM tunnel_edge_route_assignments
    WHERE state <> 'detached'
  ) THEN
    RAISE EXCEPTION 'cannot roll back tunnel edge assignments while live assignments exist';
  END IF;
END
$$;
-- +goose StatementEnd

DROP TABLE IF EXISTS tunnel_edge_route_assignments;
ALTER TABLE tunnel_connector_sessions
  DROP CONSTRAINT IF EXISTS tunnel_connector_sessions_id_connector_unique;
