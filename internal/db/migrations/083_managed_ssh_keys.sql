-- +goose Up
CREATE TABLE managed_ssh_client_keys (
  fingerprint bytea PRIMARY KEY CHECK (octet_length(fingerprint) = 32),
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cli_client_session_id text NOT NULL REFERENCES cli_client_sessions(id) ON DELETE CASCADE,
  algorithm text NOT NULL CHECK (algorithm = 'ssh-ed25519'),
  public_key text NOT NULL CHECK (octet_length(public_key) BETWEEN 80 AND 256),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
  reconciliation_version bigint NOT NULL DEFAULT 1 CHECK (reconciliation_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  revocation_reason text CHECK (revocation_reason IS NULL OR revocation_reason IN
    ('client_revoked', 'client_logout', 'account_revoked', 'key_rotated', 'key_compromise')),
  UNIQUE (public_key),
  CHECK ((state = 'active') = (revoked_at IS NULL)),
  CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE UNIQUE INDEX managed_ssh_client_keys_active_session_idx
  ON managed_ssh_client_keys(cli_client_session_id)
  WHERE state = 'active';
CREATE INDEX managed_ssh_client_keys_active_user_idx
  ON managed_ssh_client_keys(user_id, reconciliation_version)
  WHERE state = 'active';

CREATE TABLE machine_ssh_host_key_owners (
  fingerprint bytea PRIMARY KEY CHECK (octet_length(fingerprint) = 32),
  user_machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
  algorithm text NOT NULL CHECK (algorithm IN
    ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa')),
  public_key text NOT NULL CHECK (octet_length(public_key) BETWEEN 80 AND 8192),
  first_observed_at timestamptz NOT NULL,
  UNIQUE (public_key),
  UNIQUE (fingerprint, user_machine_id)
);

CREATE TABLE machine_ssh_host_key_sets (
  id text PRIMARY KEY CHECK (id ~ '^sshks_[A-Za-z0-9_-]{16,128}$'),
  user_machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
  machine_generation bigint NOT NULL CHECK (machine_generation > 0),
  observation_generation bigint NOT NULL CHECK (observation_generation > 0),
  set_fingerprint bytea NOT NULL CHECK (octet_length(set_fingerprint) = 32),
  state text NOT NULL CHECK (state IN ('pending', 'active', 'superseded', 'rejected')),
  reconciliation_version bigint NOT NULL CHECK (reconciliation_version > 0),
  observed_at timestamptz NOT NULL,
  promoted_at timestamptz,
  rejected_at timestamptz,
  rejection_reason text CHECK (rejection_reason IS NULL OR rejection_reason IN
    ('operator_rejected', 'machine_reenrolled', 'account_revoked', 'key_conflict')),
  UNIQUE (id, user_machine_id),
  UNIQUE (user_machine_id, machine_generation, observation_generation),
  UNIQUE (user_machine_id, machine_generation, set_fingerprint),
  CHECK ((state IN ('active', 'superseded')) = (promoted_at IS NOT NULL)),
  CHECK ((state = 'rejected') = (rejected_at IS NOT NULL)),
  CHECK ((rejected_at IS NULL) = (rejection_reason IS NULL)),
  CHECK (promoted_at IS NULL OR promoted_at >= observed_at),
  CHECK (rejected_at IS NULL OR rejected_at >= observed_at)
);

CREATE UNIQUE INDEX machine_ssh_host_key_sets_active_idx
  ON machine_ssh_host_key_sets(user_machine_id)
  WHERE state = 'active';
CREATE UNIQUE INDEX machine_ssh_host_key_sets_pending_idx
  ON machine_ssh_host_key_sets(user_machine_id)
  WHERE state = 'pending';

CREATE TABLE machine_ssh_host_keys (
  set_id text NOT NULL,
  user_machine_id text NOT NULL,
  fingerprint bytea NOT NULL,
  ordinal smallint NOT NULL CHECK (ordinal >= 0 AND ordinal < 16),
  PRIMARY KEY (set_id, fingerprint),
  UNIQUE (set_id, ordinal),
  FOREIGN KEY (set_id, user_machine_id)
    REFERENCES machine_ssh_host_key_sets(id, user_machine_id) ON DELETE CASCADE,
  FOREIGN KEY (fingerprint, user_machine_id)
    REFERENCES machine_ssh_host_key_owners(fingerprint, user_machine_id) ON DELETE RESTRICT
);

-- +goose Down
SELECT 1;
