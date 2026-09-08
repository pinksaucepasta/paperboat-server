-- +goose Up
ALTER TABLE control_tunnel_nodes
  ADD COLUMN node_generation bigint NOT NULL DEFAULT 1 CHECK (node_generation > 0),
  ADD COLUMN region text,
  ADD COLUMN failure_domain text,
  ADD COLUMN roles text[] NOT NULL DEFAULT ARRAY[]::text[],
  ADD COLUMN transports text[] NOT NULL DEFAULT ARRAY[]::text[],
  ADD COLUMN capacity_limit bigint NOT NULL DEFAULT 0 CHECK (capacity_limit >= 0),
  ADD COLUMN capacity_used bigint NOT NULL DEFAULT 0 CHECK (capacity_used >= 0),
  ADD COLUMN capacity_observed_at timestamptz,
  ADD COLUMN registry_expires_at timestamptz,
  ADD COLUMN allowed_account_ids text[];
ALTER TABLE control_tunnel_nodes ADD CONSTRAINT control_tunnel_nodes_regional_registry_check CHECK (
  (region IS NULL AND failure_domain IS NULL AND cardinality(roles)=0 AND cardinality(transports)=0 AND registry_expires_at IS NULL)
  OR (length(region) BETWEEN 1 AND 63 AND length(failure_domain) BETWEEN 1 AND 128
      AND cardinality(roles) BETWEEN 1 AND 2 AND roles <@ ARRAY['edge','relay']::text[]
      AND cardinality(transports) BETWEEN 1 AND 4 AND transports <@ ARRAY['http3','http2','derp_quic','derp_wss']::text[]
      AND capacity_limit > 0 AND capacity_used <= capacity_limit
      AND capacity_observed_at IS NOT NULL AND registry_expires_at IS NOT NULL));
CREATE INDEX control_tunnel_nodes_regional_candidates ON control_tunnel_nodes(state, ready, region, registry_expires_at);

-- +goose Down
DROP INDEX IF EXISTS control_tunnel_nodes_regional_candidates;
ALTER TABLE control_tunnel_nodes DROP CONSTRAINT IF EXISTS control_tunnel_nodes_regional_registry_check;
ALTER TABLE control_tunnel_nodes DROP COLUMN IF EXISTS allowed_account_ids, DROP COLUMN IF EXISTS registry_expires_at,
  DROP COLUMN IF EXISTS capacity_observed_at, DROP COLUMN IF EXISTS capacity_used, DROP COLUMN IF EXISTS capacity_limit,
  DROP COLUMN IF EXISTS transports, DROP COLUMN IF EXISTS roles, DROP COLUMN IF EXISTS failure_domain,
  DROP COLUMN IF EXISTS region, DROP COLUMN IF EXISTS node_generation;
