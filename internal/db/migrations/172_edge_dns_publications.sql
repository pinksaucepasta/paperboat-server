-- +goose Up
CREATE TABLE edge_dns_publications (
  hostname text PRIMARY KEY,
  owner_id text NOT NULL,
  resource_generation bigint NOT NULL CHECK (resource_generation > 0),
  readiness_version text NOT NULL,
  observed_at timestamptz NOT NULL,
  valid_until timestamptz,
  publication_generation bigint NOT NULL CHECK (publication_generation > 0),
  desired_addresses jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(desired_addresses) = 'array'),
  provider_records jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(provider_records) = 'array'),
  state text NOT NULL CHECK (state IN ('desired','submitted','verified','failed')),
  failure_code text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  verified_at timestamptz
);

CREATE INDEX edge_dns_publications_owner_idx ON edge_dns_publications(owner_id, hostname);

CREATE TABLE edge_dns_provider_budgets (
  zone_id text PRIMARY KEY,
  tokens double precision NOT NULL CHECK (tokens >= 0 AND tokens <= 5),
  refilled_at timestamptz NOT NULL,
  blocked_until timestamptz NOT NULL
);

-- +goose Down
DROP TABLE edge_dns_publications;
DROP TABLE edge_dns_provider_budgets;
