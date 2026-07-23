-- +goose Up
CREATE TABLE control_previews (
  id text PRIMARY KEY,
  environment_id text NOT NULL REFERENCES control_environments(id),
  logical_name text NOT NULL,
  preview_key text NOT NULL UNIQUE,
  collision_counter bigint NOT NULL DEFAULT 0 CHECK (collision_counter >= 0),
  public_host text NOT NULL UNIQUE,
  target_host text NOT NULL CHECK (target_host IN ('127.0.0.1','::1')),
  target_port integer NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
  state text NOT NULL DEFAULT 'registering' CHECK (state IN ('registering','ready','degraded','offline','expired','removed')),
  route_id text REFERENCES control_routes(id) ON DELETE SET NULL,
  helper_ready boolean NOT NULL DEFAULT false,
  edge_ready boolean NOT NULL DEFAULT false,
  target_ready boolean NOT NULL DEFAULT false,
  public_acknowledged_at timestamptz,
  expires_at timestamptz,
  removed_at timestamptz,
  retained_until timestamptz,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (environment_id, logical_name)
);
CREATE INDEX control_previews_environment_state ON control_previews(environment_id, state, logical_name);
CREATE INDEX control_previews_retention ON control_previews(retained_until) WHERE retained_until IS NOT NULL;

CREATE TABLE control_preview_operations (
  operation_key text PRIMARY KEY,
  operation_type text NOT NULL,
  request_hash bytea NOT NULL,
  preview_id text REFERENCES control_previews(id) ON DELETE SET NULL,
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS control_preview_operations;
DROP TABLE IF EXISTS control_previews;
