-- +goose Up

-- Development databases may contain rows from an earlier, rejected
-- server-decryptable ENV design. Delete those unreleased tables without
-- reading or migrating them. Keep these drops unconditional: the old schema
-- is not allowed to survive merely because its value column had a different
-- name or one of its companion tables was created first.
DROP TABLE IF EXISTS environment_variable_observations;
DROP TABLE IF EXISTS environment_variables;
DROP TABLE IF EXISTS environment_variable_scopes;

CREATE TABLE IF NOT EXISTS environment_authority_heads (
  account_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  authority_id text NOT NULL CHECK (authority_id ~ '^sha256:[0-9a-f]{64}$'), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS environment_authorities (
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  authority_id text NOT NULL CHECK (authority_id ~ '^sha256:[0-9a-f]{64}$'), previous_authority_id text CHECK (previous_authority_id IS NULL OR previous_authority_id ~ '^sha256:[0-9a-f]{64}$'),
  operation_id text NOT NULL CHECK (operation_id ~ '^envop_[0-9a-f]{32}$'), envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 2097152), created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(account_id,generation), UNIQUE(account_id,authority_id), UNIQUE(account_id,operation_id));
CREATE TABLE IF NOT EXISTS environment_authority_roots (
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, key_id text NOT NULL CHECK (key_id ~ '^aek_[0-9a-f]{64}$'), public_key bytea NOT NULL CHECK (octet_length(public_key)=32), PRIMARY KEY(account_id,key_id));
CREATE TABLE IF NOT EXISTS environment_key_bindings (
  binding_id text PRIMARY KEY CHECK (binding_id ~ '^sha256:[0-9a-f]{64}$'), account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject_kind text NOT NULL CHECK (subject_kind IN ('manager_cli','manager_browser','host','recovery')), subject_id text NOT NULL,
  subject_generation bigint NOT NULL CHECK (subject_generation BETWEEN 1 AND 9007199254740991), key_generation bigint NOT NULL CHECK (key_generation BETWEEN 1 AND 9007199254740991),
  signing_key_id text CHECK (signing_key_id IS NULL OR signing_key_id ~ '^sigk_[A-Za-z0-9_-]{43}$'), signing_public_key bytea CHECK (signing_public_key IS NULL OR octet_length(signing_public_key)=32),
  recipient_key_id text NOT NULL CHECK (recipient_key_id ~ '^envk_[A-Za-z0-9_-]{43}$'), recipient_public_key bytea NOT NULL CHECK (octet_length(recipient_public_key)=32),
  envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 2048), created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(account_id,subject_kind,subject_id,key_generation), UNIQUE(account_id,signing_key_id), UNIQUE(account_id,recipient_key_id));
CREATE TABLE IF NOT EXISTS environment_key_enrollment_requests (
  id text PRIMARY KEY, account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, requester_kind text NOT NULL CHECK (requester_kind IN ('human_session','cli_session','machine')), requester_id text NOT NULL,
  subject_kind text NOT NULL CHECK (subject_kind IN ('manager_cli','manager_browser','host')), subject_id text NOT NULL, subject_generation bigint NOT NULL CHECK (subject_generation BETWEEN 1 AND 9007199254740991), key_generation bigint NOT NULL CHECK (key_generation BETWEEN 1 AND 9007199254740991),
  operation_id text NOT NULL CHECK (operation_id ~ '^envop_[0-9a-f]{32}$'), request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32), canonical_request bytea NOT NULL CHECK (octet_length(canonical_request) BETWEEN 1 AND 8192),
  signing_proof bytea CHECK (signing_proof IS NULL OR octet_length(signing_proof)=64), recipient_key_id text NOT NULL CHECK (recipient_key_id ~ '^envk_[A-Za-z0-9_-]{43}$'), recipient_public_key bytea NOT NULL CHECK (octet_length(recipient_public_key)=32),
  safety_code text NOT NULL CHECK (safety_code ~ '^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$'), challenge_envelope bytea NOT NULL CHECK (octet_length(challenge_envelope) BETWEEN 49 AND 256), expected_proof bytea NOT NULL CHECK (octet_length(expected_proof)=32),
  state text NOT NULL CHECK (state IN ('challenge','pending','approved','expired')), transition_id text, expires_at timestamptz NOT NULL, proved_at timestamptz, approved_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(account_id,operation_id));
CREATE INDEX IF NOT EXISTS environment_key_enrollment_pending_idx ON environment_key_enrollment_requests(account_id,expires_at,created_at) WHERE state='pending';
CREATE TABLE IF NOT EXISTS environment_authority_transitions (
  transition_id text PRIMARY KEY CHECK (transition_id ~ '^sha256:[0-9a-f]{64}$'), account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, operation_id text NOT NULL CHECK (operation_id ~ '^envop_[0-9a-f]{32}$'), base_authority_id text,
  proposed_generation bigint NOT NULL CHECK (proposed_generation BETWEEN 1 AND 9007199254740991), proposed_authority_id text NOT NULL CHECK (proposed_authority_id ~ '^sha256:[0-9a-f]{64}$'), proposed_authority bytea NOT NULL CHECK (octet_length(proposed_authority) BETWEEN 1 AND 2097152),
  state text NOT NULL CHECK (state IN ('staged','ready','active','aborted')), required_scopes text[] NOT NULL, abort_operation_id text CHECK (abort_operation_id IS NULL OR abort_operation_id ~ '^envop_[0-9a-f]{32}$'), abort_authorization bytea,
  created_at timestamptz NOT NULL DEFAULT now(), activated_at timestamptz, aborted_at timestamptz, UNIQUE(account_id,operation_id));
ALTER TABLE environment_key_enrollment_requests ADD COLUMN IF NOT EXISTS transition_id text;
CREATE UNIQUE INDEX IF NOT EXISTS environment_authority_transition_pending_unique ON environment_authority_transitions(account_id) WHERE state IN ('staged','ready');
CREATE TABLE IF NOT EXISTS environment_scopes (
  id text PRIMARY KEY, account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, scope text NOT NULL CHECK (scope IN ('global','machine')), machine_id text, scope_state text NOT NULL CHECK (scope_state IN ('active','retired')),
  version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991), key_epoch bigint NOT NULL CHECK (key_epoch BETWEEN 1 AND 9007199254740991), authority_generation bigint NOT NULL CHECK (authority_generation BETWEEN 1 AND 9007199254740991),
  authority_id text NOT NULL CHECK (authority_id ~ '^sha256:[0-9a-f]{64}$'), manifest_id text NOT NULL CHECK (manifest_id ~ '^sha256:[0-9a-f]{64}$'), updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((scope='global' AND machine_id IS NULL AND scope_state='active') OR (scope='machine' AND machine_id IS NOT NULL)), FOREIGN KEY(machine_id,account_id) REFERENCES user_machines(id,user_id) ON DELETE CASCADE);
CREATE UNIQUE INDEX IF NOT EXISTS environment_scopes_global_unique ON environment_scopes(account_id) WHERE scope='global';
CREATE UNIQUE INDEX IF NOT EXISTS environment_scopes_machine_unique ON environment_scopes(account_id,machine_id) WHERE scope='machine';
CREATE TABLE IF NOT EXISTS environment_scope_manifests (
  scope_id text NOT NULL REFERENCES environment_scopes(id) ON DELETE CASCADE, version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991), key_epoch bigint NOT NULL CHECK (key_epoch BETWEEN 1 AND 9007199254740991), authority_generation bigint NOT NULL CHECK (authority_generation BETWEEN 1 AND 9007199254740991),
  authority_id text NOT NULL CHECK (authority_id ~ '^sha256:[0-9a-f]{64}$'), operation_id text NOT NULL CHECK (operation_id ~ '^envop_[0-9a-f]{32}$'), manifest_id text NOT NULL CHECK (manifest_id ~ '^sha256:[0-9a-f]{64}$'), envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 1048576), created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(scope_id,version), UNIQUE(scope_id,manifest_id), UNIQUE(scope_id,operation_id));
CREATE TABLE IF NOT EXISTS environment_scope_names (scope_id text NOT NULL REFERENCES environment_scopes(id) ON DELETE CASCADE, name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128), updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(scope_id,name));
CREATE TABLE IF NOT EXISTS environment_host_bootstraps (
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, machine_id text NOT NULL, subject_generation bigint NOT NULL CHECK (subject_generation BETWEEN 1 AND 9007199254740991), key_generation bigint NOT NULL CHECK (key_generation BETWEEN 1 AND 9007199254740991), recipient_key_id text NOT NULL CHECK (recipient_key_id ~ '^envk_[A-Za-z0-9_-]{43}$'),
  authority_generation bigint NOT NULL CHECK (authority_generation BETWEEN 1 AND 9007199254740991), authority_id text NOT NULL CHECK (authority_id ~ '^sha256:[0-9a-f]{64}$'),
  global_version bigint NOT NULL, global_key_epoch bigint NOT NULL, global_manifest_id text NOT NULL, global_envelope bytea NOT NULL CHECK (octet_length(global_envelope) BETWEEN 1 AND 1048576), machine_version bigint NOT NULL, machine_key_epoch bigint NOT NULL, machine_manifest_id text NOT NULL, machine_envelope bytea NOT NULL CHECK (octet_length(machine_envelope) BETWEEN 1 AND 1048576), created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(account_id,machine_id,recipient_key_id), FOREIGN KEY(machine_id,account_id) REFERENCES user_machines(id,user_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS environment_transition_manifests (
  transition_id text NOT NULL REFERENCES environment_authority_transitions(transition_id) ON DELETE CASCADE, scope_ref text NOT NULL, expected_version bigint NOT NULL CHECK (expected_version BETWEEN 0 AND 9007199254740990), version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
  key_epoch bigint NOT NULL CHECK (key_epoch BETWEEN 1 AND 9007199254740991), operation_id text NOT NULL CHECK (operation_id ~ '^envop_[0-9a-f]{32}$'), manifest_id text NOT NULL CHECK (manifest_id ~ '^sha256:[0-9a-f]{64}$'), envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 1048576), names text[] NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(transition_id,scope_ref), UNIQUE(transition_id,operation_id));
CREATE TABLE IF NOT EXISTS environment_observations (
  machine_id text PRIMARY KEY REFERENCES user_machines(id) ON DELETE CASCADE, account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, host_recipient_key_id text NOT NULL CHECK (host_recipient_key_id ~ '^envk_[A-Za-z0-9_-]{43}$'), observation_seq bigint NOT NULL CHECK (observation_seq>0),
  authority_generation bigint, authority_id text, global_version bigint, global_key_epoch bigint, global_manifest_id text, machine_version bigint, machine_key_epoch bigint, machine_manifest_id text,
  state text NOT NULL CHECK (state IN ('pending','applied','failed')), error_code text CHECK (error_code IS NULL OR error_code ~ '^[a-z0-9_]{1,64}$'), observed_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(machine_id,account_id) REFERENCES user_machines(id,user_id) ON DELETE CASCADE,
  CHECK ((state='failed' AND error_code IS NOT NULL) OR (state<>'failed' AND error_code IS NULL)), CHECK ((authority_generation IS NULL)=(authority_id IS NULL)),
  CHECK ((global_version IS NULL)=(global_key_epoch IS NULL) AND (global_version IS NULL)=(global_manifest_id IS NULL)), CHECK ((machine_version IS NULL)=(machine_key_epoch IS NULL) AND (machine_version IS NULL)=(machine_manifest_id IS NULL)));
CREATE INDEX IF NOT EXISTS environment_observations_account_idx ON environment_observations(account_id,received_at DESC);

-- +goose Down
-- Irreversible without a full pre-cutover development database restore.
