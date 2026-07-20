-- +goose Up
-- Phase 4 control-plane records are additive. Transitional tables remain readable
-- for the Phase 12 rollback window and are not rewritten by this migration.
CREATE TABLE control_environments (
  id text PRIMARY KEY,
  workspace_id text NOT NULL,
  owner_user_id text REFERENCES users(id) ON DELETE SET NULL,
  desired_state text NOT NULL DEFAULT 'active',
  desired_version bigint NOT NULL DEFAULT 1,
  applied_state text NOT NULL DEFAULT 'unknown',
  applied_version bigint NOT NULL DEFAULT 0,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (desired_state IN ('active','suspended','revoked','deleting')),
  CHECK (applied_state IN ('unknown','pending','ready','degraded','suspended','revoked','deleted')),
  CHECK (desired_version > 0 AND applied_version >= 0)
);
CREATE INDEX control_environments_workspace_state ON control_environments(workspace_id, desired_state);
CREATE INDEX control_environments_owner_state ON control_environments(owner_user_id, desired_state);

CREATE TABLE control_helpers (
  id text PRIMARY KEY,
  environment_id text NOT NULL REFERENCES control_environments(id) ON DELETE CASCADE,
  key_thumbprint text,
  public_key bytea,
  state text NOT NULL DEFAULT 'pending',
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  replacement_operation_key text UNIQUE,
  replacement_connector_generation bigint,
  last_seen_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('pending','active','replaced','revoked','deleted')),
  CHECK (public_key IS NULL OR octet_length(public_key) = 32),
  UNIQUE (environment_id, id)
);
CREATE INDEX control_helpers_environment_state ON control_helpers(environment_id, state);

CREATE TABLE control_helper_enrollments (
  id text PRIMARY KEY,
  environment_id text NOT NULL REFERENCES control_environments(id) ON DELETE CASCADE,
  helper_id text NOT NULL REFERENCES control_helpers(id) ON DELETE CASCADE,
  jti_hash bytea NOT NULL UNIQUE,
  operation_key text NOT NULL UNIQUE,
  request_hash bytea NOT NULL,
  grant_ciphertext bytea NOT NULL,
  state text NOT NULL DEFAULT 'pending',
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('pending','consumed','expired','revoked'))
);
CREATE INDEX control_helper_enrollments_active ON control_helper_enrollments(environment_id, helper_id, expires_at)
  WHERE state = 'pending';

CREATE TABLE control_config_repositories (
  id text PRIMARY KEY,
  owner_user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider text NOT NULL,
  external_ref text NOT NULL,
  display_name text NOT NULL,
  state text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('active','disconnected','revoked')),
  UNIQUE (owner_user_id, provider, external_ref)
);

CREATE TABLE control_config_assignments (
  id text NOT NULL UNIQUE,
  environment_id text PRIMARY KEY REFERENCES control_environments(id) ON DELETE CASCADE,
  repository_id text REFERENCES control_config_repositories(id) ON DELETE SET NULL,
  consent_state text NOT NULL DEFAULT 'not_required',
  warning_revision text,
  accepted_at timestamptz,
  revoked_at timestamptz,
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (consent_state IN ('not_required','pending','accepted','revoked')),
  CHECK ((consent_state = 'pending' AND warning_revision IS NOT NULL) OR consent_state <> 'pending'),
  CHECK ((consent_state = 'accepted' AND warning_revision IS NOT NULL AND accepted_at IS NOT NULL) OR consent_state <> 'accepted')
);
CREATE INDEX control_config_assignments_repository ON control_config_assignments(repository_id)
  WHERE repository_id IS NOT NULL;

CREATE TABLE control_config_credentials (
  jti_hash bytea PRIMARY KEY,
  jti text NOT NULL UNIQUE,
  operation_key text NOT NULL UNIQUE,
  request_hash bytea NOT NULL,
  environment_id text NOT NULL,
  helper_id text NOT NULL,
  assignment_id text NOT NULL,
  warning_revision text,
  credential_ciphertext bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (environment_id, helper_id) REFERENCES control_helpers(environment_id, id) ON DELETE CASCADE
);
CREATE INDEX control_config_credentials_active ON control_config_credentials(environment_id, helper_id, expires_at)
  WHERE revoked_at IS NULL;

CREATE TABLE control_signing_key_revocations (
  key_id text PRIMARY KEY,
  reason text NOT NULL,
  revoked_at timestamptz NOT NULL,
  actor_user_id text REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (length(trim(key_id)) BETWEEN 1 AND 128),
  CHECK (length(trim(reason)) BETWEEN 1 AND 512)
);

CREATE TABLE control_signing_key_revocation_operations (
  operation_key text PRIMARY KEY,
  key_id text NOT NULL,
  reason text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (length(trim(operation_key)) BETWEEN 1 AND 256)
);

CREATE TABLE control_operations (
  id text PRIMARY KEY,
  operation_key text NOT NULL UNIQUE,
  operation_type text NOT NULL,
  request_hash bytea NOT NULL,
  state text NOT NULL DEFAULT 'pending',
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_error text,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz,
  lease_expires_at timestamptz,
  uncertain_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('pending','running','succeeded','failed','uncertain','dead_letter'))
);
CREATE INDEX control_operations_retry ON control_operations(next_attempt_at, lease_expires_at, created_at)
  WHERE state IN ('pending','running','failed','uncertain');

CREATE TABLE control_operation_recoveries (
  operation_key text PRIMARY KEY,
  operation_id text NOT NULL REFERENCES control_operations(id) ON DELETE CASCADE,
  actor_user_id text REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (length(trim(operation_key)) BETWEEN 1 AND 256)
);

CREATE TABLE control_reconciliation_attempts (
  id text PRIMARY KEY,
  environment_id text NOT NULL REFERENCES control_environments(id) ON DELETE CASCADE,
  desired_version bigint NOT NULL,
  state text NOT NULL DEFAULT 'started',
  operation_id text REFERENCES control_operations(id) ON DELETE SET NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  last_error text,
  CHECK (state IN ('started','succeeded','failed','cancelled','uncertain'))
);
CREATE INDEX control_reconciliation_pending ON control_reconciliation_attempts(environment_id, desired_version, started_at)
  WHERE state IN ('started','uncertain');

CREATE TABLE control_tunnel_nodes (
  id text PRIMARY KEY,
  edge_pool text NOT NULL,
  protocol_version text NOT NULL,
  process_epoch text NOT NULL,
  endpoint_host text,
  endpoint_tcp_port integer,
  endpoint_quic_port integer,
  state text NOT NULL DEFAULT 'registered',
  ready boolean NOT NULL DEFAULT false,
  capacity jsonb NOT NULL DEFAULT '{}'::jsonb,
  observation jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_heartbeat_at timestamptz,
  drain_deadline timestamptz,
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('registered','ready','draining','offline','retired')),
  CHECK ((endpoint_host IS NULL AND endpoint_tcp_port IS NULL AND endpoint_quic_port IS NULL) OR (length(trim(endpoint_host)) BETWEEN 1 AND 253 AND endpoint_tcp_port BETWEEN 1 AND 65535 AND endpoint_quic_port BETWEEN 1 AND 65535 AND endpoint_tcp_port <> endpoint_quic_port)),
  UNIQUE (id, process_epoch)
);
CREATE INDEX control_tunnel_nodes_assignment ON control_tunnel_nodes(edge_pool, state, ready);

CREATE TABLE control_usage_verification_keys (
  key_id text PRIMARY KEY,
  edge_node_id text NOT NULL REFERENCES control_tunnel_nodes(id) ON DELETE CASCADE,
  public_key bytea NOT NULL,
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (octet_length(public_key) = 32),
  CHECK (expires_at > not_before)
);
CREATE INDEX control_usage_verification_keys_node_active
  ON control_usage_verification_keys(edge_node_id, expires_at)
  WHERE revoked_at IS NULL;

CREATE TABLE control_connector_generations (
  environment_id text PRIMARY KEY REFERENCES control_environments(id) ON DELETE CASCADE,
  helper_id text NOT NULL,
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  edge_pool text NOT NULL,
  edge_node_id text REFERENCES control_tunnel_nodes(id) ON DELETE SET NULL,
  state text NOT NULL DEFAULT 'pending',
  admission_jti_hash bytea,
  admission_operation_key text,
  admission_request_hash bytea,
  admission_credential_ciphertext bytea,
  expires_at timestamptz,
  revoked_at timestamptz,
  version bigint NOT NULL DEFAULT 1,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('pending','admitted','draining','revoked','replaced'))
);
CREATE UNIQUE INDEX control_connector_admission_jti ON control_connector_generations(admission_jti_hash)
  WHERE admission_jti_hash IS NOT NULL;

CREATE TABLE control_routes (
  id text PRIMARY KEY,
  environment_id text NOT NULL REFERENCES control_environments(id) ON DELETE CASCADE,
  kind text NOT NULL,
  public_host text NOT NULL UNIQUE,
  target_host text NOT NULL,
  target_port integer NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
  desired_revision bigint NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
  desired_state text NOT NULL DEFAULT 'attached',
  applied_revision bigint NOT NULL DEFAULT 0,
  applied_node_id text REFERENCES control_tunnel_nodes(id) ON DELETE SET NULL,
  applied_generation bigint,
  drain_deadline timestamptz,
  version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (kind IN ('helper_https_wss','preview_public_https_wss')),
  CHECK (target_host IN ('127.0.0.1','::1')),
  CHECK (desired_state IN ('attached','detaching','detached','replacing'))
);
CREATE INDEX control_routes_environment ON control_routes(environment_id, desired_state);

CREATE TABLE control_route_operations (
  operation_key text PRIMARY KEY,
  operation_type text NOT NULL,
  request_hash bytea NOT NULL,
  route_id text NOT NULL,
  result_revision bigint,
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (operation_type IN ('create','transition')),
  CHECK (length(trim(operation_key)) BETWEEN 1 AND 256)
);

CREATE TABLE control_usage_counters (
  edge_node_id text NOT NULL REFERENCES control_tunnel_nodes(id) ON DELETE CASCADE,
  counter_epoch text NOT NULL,
  environment_id text NOT NULL REFERENCES control_environments(id) ON DELETE CASCADE,
  route_id text NOT NULL REFERENCES control_routes(id) ON DELETE CASCADE,
  route_revision bigint NOT NULL,
  direction text NOT NULL,
  bytes bigint NOT NULL DEFAULT 0 CHECK (bytes >= 0),
  observed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (edge_node_id, counter_epoch, environment_id, route_id, direction),
  CHECK (direction IN ('ingress','egress'))
);

CREATE TABLE control_usage_receipts (
  operation_id text PRIMARY KEY,
  edge_node_id text NOT NULL,
  counter_epoch text NOT NULL,
  environment_id text NOT NULL,
  route_id text NOT NULL,
  route_revision bigint NOT NULL,
  direction text NOT NULL,
  observed_bytes bigint NOT NULL CHECK (observed_bytes >= 0),
  delta_bytes bigint NOT NULL CHECK (delta_bytes >= 0),
  interval_start timestamptz NOT NULL,
  interval_end timestamptz NOT NULL,
  acknowledged_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (direction IN ('ingress','egress')),
  CHECK (interval_end >= interval_start)
);
CREATE INDEX control_usage_receipts_route_time ON control_usage_receipts(route_id, created_at);

-- +goose Down
DROP TABLE IF EXISTS control_usage_receipts;
DROP TABLE IF EXISTS control_usage_counters;
DROP TABLE IF EXISTS control_routes;
DROP TABLE IF EXISTS control_route_operations;
DROP TABLE IF EXISTS control_connector_generations;
DROP TABLE IF EXISTS control_usage_verification_keys;
DROP TABLE IF EXISTS control_tunnel_nodes;
DROP TABLE IF EXISTS control_reconciliation_attempts;
DROP TABLE IF EXISTS control_operation_recoveries;
DROP TABLE IF EXISTS control_helper_enrollments;
DROP TABLE IF EXISTS control_config_credentials;
DROP TABLE IF EXISTS control_signing_key_revocations;
DROP TABLE IF EXISTS control_signing_key_revocation_operations;
DROP TABLE IF EXISTS control_helpers;
DROP TABLE IF EXISTS control_config_assignments;
DROP TABLE IF EXISTS control_config_repositories;
DROP TABLE IF EXISTS control_operations;
DROP TABLE IF EXISTS control_environments;
