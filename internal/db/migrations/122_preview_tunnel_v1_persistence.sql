-- +goose Up
-- Preview/tunnel v1 is additive until TRK-29 removes the unreleased control_*
-- persistence path. A server rollback can therefore keep using the prior schema
-- without interpreting partially migrated v1 rows.

CREATE TABLE tunnels (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  desired_state text NOT NULL DEFAULT 'active',
  access_mode text NOT NULL DEFAULT 'public',
  generation bigint NOT NULL DEFAULT 1,
  stable_endpoint_id text NOT NULL UNIQUE,
  stable_endpoint text NOT NULL UNIQUE,
  created_by_host_id text NOT NULL,
  created_by_actor_id text NOT NULL,
  expires_at timestamptz,
  summary_code text NOT NULL DEFAULT 'pending',
  summary_transitioned_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK (length(trim(name)) BETWEEN 1 AND 80),
  CHECK (desired_state IN ('active','paused','deleted')),
  CHECK (access_mode IN ('public','private')),
  CHECK (generation > 0),
  CHECK (stable_endpoint_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  CHECK (stable_endpoint ~ ('^https://' || stable_endpoint_id || '[.][a-z0-9.-]+$')),
  CHECK ((desired_state = 'deleted') = (deleted_at IS NOT NULL)),
  CHECK (expires_at IS NULL OR expires_at > created_at),
  UNIQUE (account_id, name)
);
CREATE INDEX tunnels_account_state_updated
  ON tunnels(account_id, desired_state, updated_at DESC, id);
CREATE INDEX tunnels_expiry
  ON tunnels(expires_at, id)
  WHERE expires_at IS NOT NULL AND desired_state <> 'deleted';
CREATE INDEX tunnels_summary
  ON tunnels(account_id, summary_code, summary_transitioned_at DESC, id);

CREATE TABLE tunnel_routes (
  id text PRIMARY KEY,
  tunnel_id text NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
  name text NOT NULL,
  protocol text NOT NULL DEFAULT 'http',
  match_type text NOT NULL,
  match_hostname text,
  wildcard_suffix text,
  path_prefix text,
  priority integer NOT NULL DEFAULT 100,
  origin_scheme text NOT NULL,
  origin_address text NOT NULL,
  preserve_host boolean NOT NULL DEFAULT true,
  host_override text,
  tls_verification text NOT NULL DEFAULT 'not_applicable',
  tls_server_name text,
  ca_reference text,
  mtls_credential_reference text,
  connect_timeout_ms integer NOT NULL DEFAULT 10000,
  idle_timeout_ms integer NOT NULL DEFAULT 90000,
  max_concurrent_streams integer NOT NULL DEFAULT 128,
  desired_state text NOT NULL DEFAULT 'active',
  generation bigint NOT NULL DEFAULT 1,
  created_by_actor_id text NOT NULL,
  updated_by_actor_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK (length(trim(name)) BETWEEN 1 AND 80),
  CHECK (protocol IN ('http','private_tcp')),
  CHECK (match_type IN ('managed','exact','one_label_wildcard','catch_all')),
  CHECK (
    (match_type IN ('managed','exact') AND match_hostname IS NOT NULL AND wildcard_suffix IS NULL)
    OR (match_type = 'one_label_wildcard' AND match_hostname IS NULL AND wildcard_suffix IS NOT NULL)
    OR (match_type = 'catch_all' AND match_hostname IS NULL AND wildcard_suffix IS NULL)
  ),
  CHECK (match_hostname IS NULL OR (match_hostname = lower(match_hostname) AND match_hostname !~ '[.]$' AND match_hostname !~ '[*]')),
  CHECK (wildcard_suffix IS NULL OR (wildcard_suffix = lower(wildcard_suffix) AND wildcard_suffix !~ '[.]$' AND wildcard_suffix !~ '[*]')),
  CHECK (path_prefix IS NULL OR path_prefix LIKE '/%'),
  CHECK (origin_scheme IN ('http','https','tcp')),
  CHECK (length(trim(origin_address)) BETWEEN 1 AND 512),
  CHECK (tls_verification IN ('not_applicable','system','custom_ca','mutual_tls','insecure_development')),
  CHECK ((origin_scheme = 'https') OR tls_verification = 'not_applicable'),
  CHECK (connect_timeout_ms BETWEEN 100 AND 120000),
  CHECK (idle_timeout_ms BETWEEN 1000 AND 3600000),
  CHECK (max_concurrent_streams BETWEEN 1 AND 100000),
  CHECK (desired_state IN ('active','disabled','deleted')),
  CHECK (generation > 0),
  CHECK ((desired_state = 'deleted') = (deleted_at IS NOT NULL)),
  UNIQUE (tunnel_id, name)
);
CREATE INDEX tunnel_routes_match
  ON tunnel_routes(match_type, match_hostname, wildcard_suffix, path_prefix, priority, id)
  WHERE desired_state = 'active';
CREATE INDEX tunnel_routes_tunnel_state
  ON tunnel_routes(tunnel_id, desired_state, priority, name, id);

CREATE TABLE tunnel_domains (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tunnel_id text NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
  route_id text NOT NULL REFERENCES tunnel_routes(id) ON DELETE CASCADE,
  hostname text NOT NULL,
  match_type text NOT NULL,
  ownership_challenge_reference text NOT NULL,
  ownership_state text NOT NULL DEFAULT 'pending',
  dns_target text NOT NULL,
  observed_records jsonb NOT NULL DEFAULT '[]'::jsonb,
  certificate_strategy text NOT NULL DEFAULT 'managed',
  certificate_reference text,
  certificate_state text NOT NULL DEFAULT 'pending',
  certificate_expires_at timestamptz,
  certificate_renewal_attempted_at timestamptz,
  certificate_failure_code text,
  caa_state text NOT NULL DEFAULT 'unknown',
  conflict_state text NOT NULL DEFAULT 'clear',
  last_verified_at timestamptz,
  generation bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK (hostname = lower(hostname) AND hostname !~ '[.]$'),
  CHECK (
    (match_type = 'exact' AND hostname !~ '^[*][.]')
    OR (match_type = 'one_label_wildcard' AND hostname ~ '^[*][.][a-z0-9]')
  ),
  CHECK (ownership_state IN ('pending','verified','failed','expired','revoked')),
  CHECK (jsonb_typeof(observed_records) = 'array'),
  CHECK (certificate_strategy IN ('managed','provided_reference','none')),
  CHECK (certificate_state IN ('pending','ready','renewing','failed','expired','revoked','not_applicable')),
  CHECK ((certificate_strategy = 'none') = (certificate_state = 'not_applicable')),
  CHECK (caa_state IN ('unknown','ready','blocked','not_applicable')),
  CHECK (conflict_state IN ('clear','conflicted','quarantined')),
  CHECK (generation > 0),
  UNIQUE (hostname)
);
CREATE INDEX tunnel_domains_tunnel_state
  ON tunnel_domains(tunnel_id, ownership_state, certificate_state, hostname, id);
CREATE INDEX tunnel_domains_verification
  ON tunnel_domains(ownership_state, last_verified_at, id)
  WHERE deleted_at IS NULL AND ownership_state IN ('pending','failed');
CREATE INDEX tunnel_domains_renewal
  ON tunnel_domains(certificate_expires_at, id)
  WHERE deleted_at IS NULL AND certificate_state IN ('ready','renewing','failed');

CREATE TABLE tunnel_connectors (
  id text PRIMARY KEY,
  tunnel_id text NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
  host_id text NOT NULL,
  credential_reference text NOT NULL,
  credential_thumbprint text NOT NULL,
  rotation_generation bigint NOT NULL DEFAULT 1,
  desired_state text NOT NULL DEFAULT 'active',
  software_version text,
  protocol_version text NOT NULL,
  operating_system text,
  architecture text,
  last_session_id text,
  last_heartbeat_at timestamptz,
  ready_at timestamptz,
  disconnect_reason_code text,
  last_applied_config_generation bigint NOT NULL DEFAULT 0,
  drain_state text NOT NULL DEFAULT 'accepting',
  generation bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  CHECK (length(trim(credential_reference)) > 0),
  CHECK (length(trim(credential_thumbprint)) > 0),
  CHECK (rotation_generation > 0),
  CHECK (desired_state IN ('active','draining','revoked')),
  CHECK (last_applied_config_generation >= 0),
  CHECK (drain_state IN ('accepting','draining','drained')),
  CHECK (generation > 0),
  CHECK ((desired_state = 'revoked') = (revoked_at IS NOT NULL)),
  UNIQUE (tunnel_id, host_id)
);
CREATE UNIQUE INDEX tunnel_connectors_credential_thumbprint
  ON tunnel_connectors(credential_thumbprint);
CREATE INDEX tunnel_connectors_tunnel_readiness
  ON tunnel_connectors(tunnel_id, desired_state, drain_state, last_heartbeat_at DESC, id);

CREATE TABLE tunnel_connector_sessions (
  id text PRIMARY KEY,
  connector_id text NOT NULL REFERENCES tunnel_connectors(id) ON DELETE CASCADE,
  process_generation bigint NOT NULL,
  protocol_version text NOT NULL,
  capabilities text[] NOT NULL DEFAULT '{}',
  state text NOT NULL DEFAULT 'authenticating',
  lease_deadline timestamptz NOT NULL,
  last_heartbeat_at timestamptz NOT NULL DEFAULT now(),
  ready_at timestamptz,
  disconnected_at timestamptz,
  disconnect_reason_code text,
  applied_config_generation bigint NOT NULL DEFAULT 0,
  retained_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (process_generation > 0),
  CHECK (state IN ('authenticating','ready','draining','disconnected','expired')),
  CHECK (applied_config_generation >= 0),
  CHECK (lease_deadline > created_at),
  CHECK (retained_until >= lease_deadline),
  CHECK ((state IN ('disconnected','expired')) = (disconnected_at IS NOT NULL)),
  UNIQUE (connector_id, process_generation)
);
CREATE INDEX tunnel_connector_sessions_live
  ON tunnel_connector_sessions(connector_id, lease_deadline, process_generation DESC)
  WHERE state IN ('authenticating','ready','draining');
CREATE INDEX tunnel_connector_sessions_retention
  ON tunnel_connector_sessions(retained_until, id)
  WHERE state IN ('disconnected','expired');

CREATE TABLE preview_leases (
  id text PRIMARY KEY,
  endpoint_id text NOT NULL UNIQUE,
  endpoint text NOT NULL UNIQUE,
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_id text NOT NULL,
  owner_device_id text NOT NULL,
  owner_session_id text NOT NULL,
  target_scheme text NOT NULL,
  target_address text NOT NULL,
  access_mode text NOT NULL DEFAULT 'public',
  lease_deadline timestamptz NOT NULL,
  user_deadline timestamptz,
  allocation_state text NOT NULL DEFAULT 'pending',
  edge_state text NOT NULL DEFAULT 'pending',
  origin_state text NOT NULL DEFAULT 'unknown',
  terminal_state text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  ready_at timestamptz,
  last_renewed_at timestamptz NOT NULL DEFAULT now(),
  stopped_at timestamptz,
  CHECK (endpoint ~ '^https://[a-z0-9.-]+$'),
  CHECK (target_scheme IN ('http','https')),
  CHECK (length(trim(target_address)) BETWEEN 1 AND 512),
  CHECK (access_mode IN ('public','private')),
  CHECK (lease_deadline > created_at),
  CHECK (user_deadline IS NULL OR user_deadline >= created_at),
  CHECK (allocation_state IN ('pending','ready','failed','released')),
  CHECK (edge_state IN ('pending','ready','degraded','down','released')),
  CHECK (origin_state IN ('unknown','ready','degraded','down')),
  CHECK (terminal_state IN ('active','stopped','expired','owner_lost','failed')),
  CHECK ((terminal_state = 'active') = (stopped_at IS NULL))
);
CREATE INDEX preview_leases_account_state
  ON preview_leases(account_id, terminal_state, created_at DESC, id);
CREATE INDEX preview_leases_owner
  ON preview_leases(owner_device_id, owner_session_id, terminal_state, lease_deadline, id);
CREATE INDEX preview_leases_expiry
  ON preview_leases(least(lease_deadline, coalesce(user_deadline, lease_deadline)), id)
  WHERE terminal_state = 'active';

CREATE TABLE tunnel_config_generations (
  tunnel_id text NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
  generation bigint NOT NULL,
  previous_generation bigint,
  content_hash bytea NOT NULL,
  snapshot jsonb NOT NULL,
  snapshot_reference text,
  activation_state text NOT NULL DEFAULT 'pending',
  created_by_actor_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  retained_until timestamptz NOT NULL,
  PRIMARY KEY (tunnel_id, generation),
  FOREIGN KEY (tunnel_id, previous_generation)
    REFERENCES tunnel_config_generations(tunnel_id, generation) ON DELETE RESTRICT,
  CHECK (generation > 0),
  CHECK ((generation = 1 AND previous_generation IS NULL) OR (generation > 1 AND previous_generation = generation - 1)),
  CHECK (octet_length(content_hash) = 32),
  CHECK (jsonb_typeof(snapshot) = 'object'),
  CHECK (activation_state IN ('pending','active','superseded','rejected')),
  CHECK ((activation_state = 'active') = (activated_at IS NOT NULL)),
  CHECK (retained_until > created_at)
);
CREATE UNIQUE INDEX tunnel_config_generations_content
  ON tunnel_config_generations(tunnel_id, content_hash);
CREATE UNIQUE INDEX tunnel_config_generations_one_active
  ON tunnel_config_generations(tunnel_id)
  WHERE activation_state = 'active';
CREATE INDEX tunnel_config_generations_retention
  ON tunnel_config_generations(retained_until, tunnel_id, generation)
  WHERE activation_state IN ('superseded','rejected');

-- +goose StatementBegin
CREATE FUNCTION reject_tunnel_config_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.tunnel_id IS DISTINCT FROM OLD.tunnel_id
     OR NEW.generation IS DISTINCT FROM OLD.generation
     OR NEW.previous_generation IS DISTINCT FROM OLD.previous_generation
     OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
     OR NEW.snapshot IS DISTINCT FROM OLD.snapshot
     OR NEW.snapshot_reference IS DISTINCT FROM OLD.snapshot_reference
     OR NEW.created_by_actor_id IS DISTINCT FROM OLD.created_by_actor_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'immutable tunnel configuration generation fields cannot change'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tunnel_config_generations_immutable
  BEFORE UPDATE ON tunnel_config_generations
  FOR EACH ROW EXECUTE FUNCTION reject_tunnel_config_identity_mutation();

CREATE TABLE operations (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  idempotency_key text NOT NULL,
  request_hash bytea NOT NULL,
  operation_type text NOT NULL,
  resource_kind text NOT NULL,
  resource_id text,
  phase text NOT NULL DEFAULT 'validating',
  state text NOT NULL DEFAULT 'pending',
  progress smallint NOT NULL DEFAULT 0,
  retrying boolean NOT NULL DEFAULT false,
  next_retry_at timestamptz,
  error_code text,
  outcome text NOT NULL DEFAULT 'unchanged',
  result_reference text,
  correlation_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  CHECK (length(trim(idempotency_key)) BETWEEN 1 AND 256),
  CHECK (octet_length(request_hash) = 32),
  CHECK (length(trim(operation_type)) BETWEEN 1 AND 80),
  CHECK (resource_kind IN ('preview_lease','tunnel','route','domain_binding','connector')),
  CHECK (phase IN ('validating','persisting','waiting_for_dns','issuing_certificate','installing_service','connecting','checking_origin','draining','rolling_back','ready','failed')),
  CHECK (state IN ('pending','running','succeeded','failed','cancelled','uncertain')),
  CHECK (progress BETWEEN 0 AND 100),
  CHECK (outcome IN ('unchanged','changed','uncertain')),
  CHECK ((state IN ('succeeded','failed','cancelled')) = (completed_at IS NOT NULL)),
  UNIQUE (account_id, idempotency_key)
);
CREATE INDEX operations_resource
  ON operations(resource_kind, resource_id, created_at DESC, id);
CREATE INDEX operations_pending
  ON operations(state, next_retry_at, updated_at, id)
  WHERE state IN ('pending','running','uncertain');

ALTER TABLE audit_events
  ADD COLUMN account_id text,
  ADD COLUMN actor_id text,
  ADD COLUMN change_type text NOT NULL DEFAULT 'legacy',
  ADD COLUMN outcome text NOT NULL DEFAULT 'changed',
  ADD COLUMN request_id text,
  ADD COLUMN correlation_id text,
  ADD COLUMN source_device_id text,
  ADD COLUMN cursor_sequence bigint GENERATED BY DEFAULT AS IDENTITY,
  ADD CONSTRAINT audit_events_outcome_check CHECK (outcome IN ('unchanged','changed','uncertain'));

ALTER TABLE audit_events
  DROP CONSTRAINT IF EXISTS audit_events_idempotency_key_key;
CREATE UNIQUE INDEX audit_events_idempotency_scope
  ON audit_events(event_type, resource_type, resource_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX audit_events_cursor_sequence
  ON audit_events(cursor_sequence);
CREATE INDEX audit_events_account_cursor
  ON audit_events(account_id, cursor_sequence DESC);
CREATE INDEX audit_events_correlation
  ON audit_events(correlation_id, cursor_sequence)
  WHERE correlation_id IS NOT NULL;

-- +goose StatementBegin
CREATE FUNCTION reject_audit_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = '55000';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER audit_events_append_only
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();

-- +goose Down
-- Non-destructive on purpose. The migration is additive and a binary rollback
-- must preserve accepted v1 desired state rather than silently discard it.
SELECT 1;
