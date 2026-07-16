-- +goose Up
CREATE TABLE connected_machines (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  environment_id text NOT NULL UNIQUE,
  display_name text NOT NULL,
  platform text NOT NULL,
  architecture text NOT NULL,
  workspace_root text NOT NULL,
  state text NOT NULL DEFAULT 'pending',
  seat_state text NOT NULL DEFAULT 'reserved',
  online boolean NOT NULL DEFAULT false,
  agentunnel_route_id text,
  agentunnel_client_id text,
  agentunnel_http_base_url text,
  agentunnel_websocket_base_url text,
  runtime_versions jsonb NOT NULL DEFAULT '{}'::jsonb,
  enrolled_at timestamptz,
  last_seen_at timestamptz,
  revoked_at timestamptz,
  disconnected_at timestamptz,
  deleted_at timestamptz,
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('pending','online','offline','disconnected','revoked','deleted')),
  CHECK (seat_state IN ('reserved','occupied','released')),
  CHECK (length(trim(display_name)) BETWEEN 1 AND 128),
  CHECK (workspace_root ~ '^/')
);

CREATE UNIQUE INDEX connected_machines_active_name
  ON connected_machines(user_id, lower(display_name))
  WHERE deleted_at IS NULL;
CREATE INDEX connected_machines_owner_state ON connected_machines(user_id, state);
CREATE INDEX connected_machines_agentunnel_client ON connected_machines(agentunnel_client_id)
  WHERE agentunnel_client_id IS NOT NULL;

CREATE TABLE connected_machine_pairings (
  id text PRIMARY KEY,
  verifier_hash bytea NOT NULL UNIQUE,
  user_code text NOT NULL UNIQUE,
  requested_display_name text NOT NULL,
  platform text NOT NULL,
  architecture text NOT NULL,
  workspace_root text NOT NULL,
  runtime_versions jsonb NOT NULL DEFAULT '{}'::jsonb,
  state text NOT NULL DEFAULT 'pending',
  approved_by_user_id text REFERENCES users(id) ON DELETE SET NULL,
  connected_machine_id text REFERENCES connected_machines(id) ON DELETE SET NULL,
  installation_config_ciphertext bytea,
  installation_config_nonce bytea,
  installation_config_consumed_at timestamptz,
  expires_at timestamptz NOT NULL,
  approved_at timestamptz,
  denied_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('pending','approved','denied','expired','consumed')),
  CHECK (length(trim(user_code)) BETWEEN 4 AND 32),
  CHECK (workspace_root ~ '^/')
);
CREATE INDEX connected_machine_pairings_pending_code
  ON connected_machine_pairings(user_code, expires_at) WHERE state = 'pending';

CREATE TABLE connected_machine_bandwidth_periods (
  id text PRIMARY KEY,
  connected_machine_id text NOT NULL REFERENCES connected_machines(id) ON DELETE CASCADE,
  period_start timestamptz NOT NULL,
  period_end timestamptz NOT NULL,
  included_bytes bigint NOT NULL CHECK (included_bytes >= 0),
  consumed_included_bytes bigint NOT NULL DEFAULT 0 CHECK (consumed_included_bytes >= 0),
  consumed_topup_bytes bigint NOT NULL DEFAULT 0 CHECK (consumed_topup_bytes >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (connected_machine_id, period_start),
  CHECK (period_end > period_start)
);

CREATE TABLE connected_machine_bandwidth_topups (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_order_id text UNIQUE,
  purchased_bytes bigint NOT NULL CHECK (purchased_bytes > 0),
  remaining_bytes bigint NOT NULL CHECK (remaining_bytes >= 0 AND remaining_bytes <= purchased_bytes),
  state text NOT NULL DEFAULT 'active',
  expires_at timestamptz,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('active','exhausted','void'))
);
CREATE INDEX connected_machine_bandwidth_topups_active
  ON connected_machine_bandwidth_topups(user_id, created_at)
  WHERE state = 'active' AND remaining_bytes > 0;

-- +goose Down
DROP TABLE IF EXISTS connected_machine_bandwidth_topups;
DROP TABLE IF EXISTS connected_machine_bandwidth_periods;
DROP TABLE IF EXISTS connected_machine_pairings;
DROP TABLE IF EXISTS connected_machines;
