-- +goose Up
-- The connector enrollment exchange reserves the first process generation
-- before the host opens its control stream. Keeping immutable reservations by
-- operation makes retries stable and preserves the fence across reenrollment.
CREATE TABLE tunnel_connector_activations (
  operation_id text PRIMARY KEY,
  account_id text NOT NULL,
  tunnel_id text NOT NULL,
  connector_id text NOT NULL,
  host_id text NOT NULL,
  credential_generation bigint NOT NULL,
  process_generation bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (credential_generation > 0),
  CHECK (process_generation > 0),
  FOREIGN KEY (operation_id, account_id)
    REFERENCES operations(id, account_id) ON DELETE RESTRICT,
  FOREIGN KEY (connector_id, tunnel_id, host_id)
    REFERENCES tunnel_connectors(id, tunnel_id, host_id) ON DELETE CASCADE,
  UNIQUE (connector_id, process_generation)
);

CREATE INDEX tunnel_connector_activations_connector
  ON tunnel_connector_activations(connector_id, process_generation DESC);

-- +goose Down
DROP TABLE IF EXISTS tunnel_connector_activations;
