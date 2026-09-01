-- +goose Up
-- TRK-07 widens the durable route model without changing the existing v1
-- tunnel identity. The old constraints were intentionally conservative while
-- TRK-06 established the lifecycle tables.
ALTER TABLE tunnel_routes
  DROP CONSTRAINT IF EXISTS tunnel_routes_origin_scheme_check,
  DROP CONSTRAINT IF EXISTS tunnel_routes_protocol_check;

ALTER TABLE tunnel_routes
  ADD CONSTRAINT tunnel_routes_origin_scheme_check
    CHECK (origin_scheme IN ('http','https','h2c','unix','tcp')),
  ADD CONSTRAINT tunnel_routes_protocol_check
    CHECK (protocol IN ('http','private_tcp'));

ALTER TABLE tunnel_connectors
  DROP CONSTRAINT IF EXISTS tunnel_connectors_drain_state_check;

ALTER TABLE tunnel_connectors
  ADD CONSTRAINT tunnel_connectors_drain_state_check
    CHECK (drain_state IN ('accepting','draining','drained','forced_closed'));

-- The v1 tables originally keyed children by ID only. Keep those IDs opaque,
-- but add scope keys so a duplicated account/tunnel value can never form a
-- valid cross-resource reference.
ALTER TABLE tunnels
  ADD CONSTRAINT tunnels_id_account_unique UNIQUE (id, account_id);
ALTER TABLE tunnel_routes
  ADD CONSTRAINT tunnel_routes_id_tunnel_unique UNIQUE (id, tunnel_id);
ALTER TABLE preview_leases
  ADD CONSTRAINT preview_leases_id_account_unique UNIQUE (id, account_id);
ALTER TABLE tunnel_domains
  ADD CONSTRAINT tunnel_domains_route_tunnel_fk
    FOREIGN KEY (route_id, tunnel_id)
    REFERENCES tunnel_routes(id, tunnel_id) ON DELETE CASCADE,
  ADD CONSTRAINT tunnel_domains_tunnel_account_fk
    FOREIGN KEY (tunnel_id, account_id)
    REFERENCES tunnels(id, account_id) ON DELETE CASCADE;

-- Composite scope keys make every child reference prove that its connector
-- belongs to the tunnel (and, for enrollments, to the host) it claims.
ALTER TABLE tunnel_connectors
  ADD CONSTRAINT tunnel_connectors_id_tunnel_unique UNIQUE (id, tunnel_id),
  ADD CONSTRAINT tunnel_connectors_id_tunnel_host_unique UNIQUE (id, tunnel_id, host_id);

-- A credential generation contains only a write-only reference and a
-- verifier thumbprint. The secret is delivered once by the enrollment flow and
-- is never persisted in Paperboat's database.
CREATE TABLE tunnel_connector_credential_generations (
  id text PRIMARY KEY,
  connector_id text NOT NULL REFERENCES tunnel_connectors(id) ON DELETE CASCADE,
  tunnel_id text NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
  generation bigint NOT NULL,
  credential_reference text NOT NULL,
  credential_thumbprint text NOT NULL,
  verifier_algorithm text NOT NULL DEFAULT 'ed25519',
  verifier_public_key bytea NOT NULL,
  state text NOT NULL DEFAULT 'active',
  valid_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  CHECK (generation > 0),
  CHECK (length(trim(credential_reference)) > 0),
  CHECK (length(trim(credential_thumbprint)) > 0),
  CHECK (verifier_algorithm = 'ed25519'),
  CHECK (octet_length(verifier_public_key) = 32),
  CHECK (state IN ('active','overlap','revoked')),
  CHECK (valid_until > created_at),
  CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
  UNIQUE (connector_id, generation),
  UNIQUE (credential_thumbprint),
  FOREIGN KEY (connector_id, tunnel_id)
    REFERENCES tunnel_connectors(id, tunnel_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX tunnel_connector_credentials_one_active
  ON tunnel_connector_credential_generations(connector_id)
  WHERE state = 'active';
CREATE INDEX tunnel_connector_credentials_validity
  ON tunnel_connector_credential_generations(connector_id, state, valid_until DESC);

-- Enrollment rows are replay-safe without retaining a reusable bearer. A
-- retry of an already delivered enrollment can return the operation reference,
-- but cannot cause a second secret to be issued.
CREATE TABLE tunnel_connector_enrollments (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tunnel_id text NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
  host_id text NOT NULL,
  operation_id text NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
  token_hash bytea NOT NULL,
  capabilities text[] NOT NULL DEFAULT '{}',
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  connector_id text,
  created_by_actor_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (octet_length(token_hash) = 32),
  CHECK (expires_at > created_at),
  CHECK (consumed_at IS NULL OR consumed_at >= created_at),
  UNIQUE (token_hash),
  UNIQUE (operation_id),
  FOREIGN KEY (tunnel_id, account_id)
    REFERENCES tunnels(id, account_id) ON DELETE CASCADE,
  FOREIGN KEY (connector_id, tunnel_id, host_id)
    REFERENCES tunnel_connectors(id, tunnel_id, host_id) ON DELETE RESTRICT
);
CREATE INDEX tunnel_connector_enrollments_scope
  ON tunnel_connector_enrollments(account_id, tunnel_id, host_id, expires_at, id);
CREATE INDEX tunnel_connector_enrollments_replay
  ON tunnel_connector_enrollments(operation_id, consumed_at);

-- Logs are deliberately separate from append-only lifecycle audit events. The
-- row is bounded at construction and contains only safe metadata; payloads,
-- headers, URLs with credentials, and authorization values are not modeled.
CREATE TABLE tunnel_log_entries (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tunnel_id text REFERENCES tunnels(id) ON DELETE CASCADE,
  preview_id text REFERENCES preview_leases(id) ON DELETE CASCADE,
  route_id text,
  connector_id text,
  session_id text,
  level text NOT NULL,
  component text NOT NULL,
  code text NOT NULL,
  message text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  correlation_id text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  cursor_sequence bigint GENERATED BY DEFAULT AS IDENTITY,
  CHECK (level IN ('debug','info','warn','error')),
  CHECK (length(trim(component)) BETWEEN 1 AND 40),
  CHECK (code ~ '^[a-z][a-z0-9_.-]{0,79}$'),
  CHECK (length(trim(message)) BETWEEN 1 AND 1000),
  CHECK (octet_length(metadata::text) <= 32768),
  CHECK (jsonb_typeof(metadata) = 'object'),
  CHECK (length(trim(correlation_id)) BETWEEN 1 AND 256),
  CHECK ((tunnel_id IS NULL) <> (preview_id IS NULL)),
  CHECK (preview_id IS NULL OR (route_id IS NULL AND connector_id IS NULL)),
  FOREIGN KEY (tunnel_id, account_id)
    REFERENCES tunnels(id, account_id) ON DELETE CASCADE,
  FOREIGN KEY (preview_id, account_id)
    REFERENCES preview_leases(id, account_id) ON DELETE CASCADE,
  FOREIGN KEY (route_id, tunnel_id)
    REFERENCES tunnel_routes(id, tunnel_id) ON DELETE CASCADE,
  FOREIGN KEY (connector_id, tunnel_id)
    REFERENCES tunnel_connectors(id, tunnel_id) ON DELETE CASCADE,
  UNIQUE (cursor_sequence)
);
CREATE INDEX tunnel_log_entries_tunnel_cursor
  ON tunnel_log_entries(account_id, tunnel_id, cursor_sequence ASC);
CREATE INDEX tunnel_log_entries_preview_cursor
  ON tunnel_log_entries(account_id, preview_id, cursor_sequence ASC);
CREATE INDEX tunnel_log_entries_retention
  ON tunnel_log_entries(occurred_at, id);

-- +goose Down
-- The widened v1 enum values are intentionally normalized before restoring
-- the legacy constraints. Unix origins cannot be losslessly represented by
-- the legacy schema, so abort before dropping any resource tables rather than
-- partially rolling back and leaving a misleading database state.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM tunnel_routes
    WHERE origin_scheme = 'unix'
  ) THEN
    RAISE EXCEPTION 'cannot roll back tunnel resources: unix origins require a forward migration';
  END IF;
  UPDATE tunnel_routes
  SET origin_scheme = 'http'
  WHERE origin_scheme = 'h2c';
  UPDATE tunnel_connectors
  SET drain_state = 'drained'
  WHERE drain_state = 'forced_closed';
END
$$;

DROP TABLE IF EXISTS tunnel_log_entries;
DROP TABLE IF EXISTS tunnel_connector_enrollments;
DROP TABLE IF EXISTS tunnel_connector_credential_generations;

ALTER TABLE tunnel_connectors
  DROP CONSTRAINT IF EXISTS tunnel_connectors_id_tunnel_host_unique,
  DROP CONSTRAINT IF EXISTS tunnel_connectors_id_tunnel_unique;

ALTER TABLE tunnel_domains
  DROP CONSTRAINT IF EXISTS tunnel_domains_tunnel_account_fk,
  DROP CONSTRAINT IF EXISTS tunnel_domains_route_tunnel_fk;
ALTER TABLE preview_leases
  DROP CONSTRAINT IF EXISTS preview_leases_id_account_unique;
ALTER TABLE tunnel_routes
  DROP CONSTRAINT IF EXISTS tunnel_routes_id_tunnel_unique;
ALTER TABLE tunnels
  DROP CONSTRAINT IF EXISTS tunnels_id_account_unique;

ALTER TABLE tunnel_connectors
  DROP CONSTRAINT IF EXISTS tunnel_connectors_drain_state_check;
ALTER TABLE tunnel_connectors
  ADD CONSTRAINT tunnel_connectors_drain_state_check
    CHECK (drain_state IN ('accepting','draining','drained'));

ALTER TABLE tunnel_routes
  DROP CONSTRAINT IF EXISTS tunnel_routes_origin_scheme_check,
  DROP CONSTRAINT IF EXISTS tunnel_routes_protocol_check;
ALTER TABLE tunnel_routes
  ADD CONSTRAINT tunnel_routes_origin_scheme_check
    CHECK (origin_scheme IN ('http','https','tcp')),
  ADD CONSTRAINT tunnel_routes_protocol_check
    CHECK (protocol IN ('http','private_tcp'));
