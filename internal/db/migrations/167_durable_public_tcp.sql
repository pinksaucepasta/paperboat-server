-- +goose Up
-- Task 28 keeps the public TCP listener reservation on the durable route.
-- The port is globally unique because every edge must bind the same port for
-- stable failover; listener_id fences a later reuse of that numeric port.
ALTER TABLE tunnel_routes
  DROP CONSTRAINT IF EXISTS tunnel_routes_protocol_check,
  ADD COLUMN public_tcp_listener_id text,
  ADD COLUMN public_tcp_port integer,
  ADD CONSTRAINT tunnel_routes_protocol_check
    CHECK (protocol IN ('http','tcp','private_tcp')),
  ADD CONSTRAINT tunnel_routes_public_tcp_binding_check CHECK (
    (protocol = 'tcp'
      AND public_tcp_listener_id IS NOT NULL
      AND length(trim(public_tcp_listener_id)) BETWEEN 3 AND 128
      AND public_tcp_port BETWEEN 1024 AND 65535
      AND match_type = 'managed'
      AND origin_scheme = 'tcp'
      AND path_prefix IS NULL)
    OR
    (protocol <> 'tcp'
      AND public_tcp_listener_id IS NULL
      AND public_tcp_port IS NULL)
  );

CREATE UNIQUE INDEX tunnel_routes_public_tcp_listener_id
  ON tunnel_routes(public_tcp_listener_id)
  WHERE public_tcp_listener_id IS NOT NULL;
CREATE UNIQUE INDEX tunnel_routes_public_tcp_port
  ON tunnel_routes(public_tcp_port)
  WHERE public_tcp_port IS NOT NULL AND desired_state <> 'deleted';

-- +goose Down
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM tunnel_routes WHERE protocol = 'tcp') THEN
    RAISE EXCEPTION 'cannot roll back durable public TCP while TCP routes exist';
  END IF;
END
$$;

DROP INDEX IF EXISTS tunnel_routes_public_tcp_port;
DROP INDEX IF EXISTS tunnel_routes_public_tcp_listener_id;
ALTER TABLE tunnel_routes
  DROP CONSTRAINT IF EXISTS tunnel_routes_public_tcp_binding_check,
  DROP CONSTRAINT IF EXISTS tunnel_routes_protocol_check,
  DROP COLUMN IF EXISTS public_tcp_port,
  DROP COLUMN IF EXISTS public_tcp_listener_id,
  ADD CONSTRAINT tunnel_routes_protocol_check
    CHECK (protocol IN ('http','private_tcp'));
