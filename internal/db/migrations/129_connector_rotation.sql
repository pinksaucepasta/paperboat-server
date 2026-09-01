-- +goose Up
-- Connector credential rotation is an aggregate operation.  The target rows
-- below are the durable state machine: the target set and its hash are
-- immutable, while challenge/proof/install/readiness/revoke state advances by
-- exact operation, account, tunnel, connector, and generation predicates.
-- Private keys, bearer credentials, and secret payloads are never stored.

-- Rotation proof transcripts use the same bounded dedicated replay ledger as
-- authentication and renewal. Widen the proof-kind constraint in this
-- migration so migration 127 remains independently reversible while every
-- accepted rotation nonce is durable before the staged key is committed.
ALTER TABLE connector_proof_replays
  DROP CONSTRAINT IF EXISTS connector_proof_replays_proof_kind_check,
  ADD CONSTRAINT connector_proof_replays_proof_kind_check
    CHECK (proof_kind IN ('auth', 'renew', 'rotation'));

ALTER TABLE tunnel_connector_sessions
  ADD COLUMN credential_generation bigint NOT NULL DEFAULT 1,
  ADD COLUMN last_heartbeat_sent_at timestamptz,
  ADD CONSTRAINT tunnel_connector_sessions_credential_generation_check
    CHECK (credential_generation > 0);

ALTER TABLE tunnel_connector_credential_generations
  ADD COLUMN source_operation_id text REFERENCES operations(id) ON DELETE SET NULL;

CREATE INDEX tunnel_connector_sessions_credential_generation
  ON tunnel_connector_sessions(connector_id, credential_generation, process_generation DESC);
CREATE INDEX tunnel_connector_credentials_source_operation
  ON tunnel_connector_credential_generations(source_operation_id, connector_id, generation)
  WHERE source_operation_id IS NOT NULL;

CREATE TABLE tunnel_connector_rotation_targets (
  operation_id text NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tunnel_id text NOT NULL,
  connector_id text NOT NULL,
  host_id text NOT NULL,
  target_set_hash text NOT NULL,
  old_credential_generation bigint NOT NULL,
  new_credential_generation bigint NOT NULL,
  state text NOT NULL DEFAULT 'pending',
  old_identity_key_id text,
  old_identity_key_thumbprint text,
  challenge_nonce text,
  challenge_issued_at timestamptz,
  challenge_expires_at timestamptz,
  overlap_until timestamptz,
  new_credential_valid_until timestamptz,
  proof_session_id text,
  proof_process_generation bigint,
  new_identity_key_id text,
  new_identity_key_thumbprint text,
  new_public_key bytea,
  new_credential_reference text,
  replacement_session_id text,
  replacement_process_generation bigint,
  config_generation bigint,
  config_content_hash bytea,
  edge_ready boolean,
  route_ready boolean,
  origin_ready boolean,
  ready_at timestamptz,
  revoke_nonce text,
  revoke_session_id text,
  revoke_process_generation bigint,
  revoke_issued_at timestamptz,
  revoke_deadline timestamptz,
  revoked_at timestamptz,
  failure_code text,
  failure_message text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (operation_id, connector_id),
  FOREIGN KEY (tunnel_id, account_id)
    REFERENCES tunnels(id, account_id) ON DELETE CASCADE,
  FOREIGN KEY (connector_id, tunnel_id, host_id)
    REFERENCES tunnel_connectors(id, tunnel_id, host_id) ON DELETE CASCADE,
  CHECK (target_set_hash ~ '^sha256:[0-9a-f]{64}$'),
  CHECK (old_credential_generation > 0),
  CHECK (new_credential_generation = old_credential_generation + 1),
  CHECK (state IN ('pending','challenged','installed','ready','revoking','revoked','failed')),
  CHECK (challenge_nonce IS NULL OR length(trim(challenge_nonce)) BETWEEN 16 AND 128),
  CHECK (challenge_nonce IS NULL OR challenge_nonce !~ '[\r\n]'),
  CHECK (new_public_key IS NULL OR octet_length(new_public_key) = 32),
  CHECK (config_content_hash IS NULL OR octet_length(config_content_hash) = 32),
  CHECK (proof_process_generation IS NULL OR proof_process_generation > 0),
  CHECK (replacement_process_generation IS NULL OR replacement_process_generation > 0),
  CHECK (revoke_process_generation IS NULL OR revoke_process_generation > 0),
  CHECK (config_generation IS NULL OR config_generation > 0),
  CHECK (state NOT IN ('installed','ready','revoking','revoked') OR (new_public_key IS NOT NULL AND new_credential_reference IS NOT NULL AND new_credential_valid_until IS NOT NULL)),
  CHECK (state NOT IN ('ready','revoking','revoked') OR (replacement_session_id IS NOT NULL AND replacement_process_generation IS NOT NULL AND config_generation IS NOT NULL AND config_content_hash IS NOT NULL AND edge_ready IS TRUE AND route_ready IS TRUE AND origin_ready IS TRUE AND ready_at IS NOT NULL)),
  CHECK (state NOT IN ('revoking','revoked') OR (revoke_nonce IS NOT NULL AND revoke_session_id IS NOT NULL AND revoke_process_generation IS NOT NULL AND revoke_deadline IS NOT NULL)),
  CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
  CHECK ((state = 'failed') = (failure_code IS NOT NULL)),
  CHECK (new_credential_valid_until IS NULL OR overlap_until IS NULL OR new_credential_valid_until > overlap_until)
);

CREATE INDEX tunnel_connector_rotation_targets_state
  ON tunnel_connector_rotation_targets(account_id, tunnel_id, state, updated_at, connector_id);
CREATE INDEX tunnel_connector_rotation_targets_expiry
  ON tunnel_connector_rotation_targets(overlap_until, state, operation_id, connector_id)
  WHERE state IN ('installed','ready','revoking');

-- The operation itself must be the tunnel-level credential rotation created by
-- TRK-07.  This also prevents a caller from using a valid operation ID from a
-- different resource as an authorization boundary.
-- +goose StatementBegin
CREATE FUNCTION validate_connector_rotation_target_scope() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  operation_account text;
  operation_resource text;
  operation_kind text;
BEGIN
  SELECT account_id, resource_id, resource_kind
    INTO operation_account, operation_resource, operation_kind
  FROM operations
  WHERE id = NEW.operation_id;
  IF operation_account IS NULL
     OR operation_account <> NEW.account_id
     OR operation_resource <> NEW.tunnel_id
     OR operation_kind <> 'tunnel' THEN
    RAISE EXCEPTION 'connector rotation target operation scope mismatch' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM operations
    WHERE id = NEW.operation_id
      AND operation_type <> 'connector.credentials.rotate'
  ) THEN
    RAISE EXCEPTION 'connector rotation target operation type mismatch' USING ERRCODE = '22023';
  END IF;
  IF TG_OP = 'UPDATE' AND (
    NEW.operation_id IS DISTINCT FROM OLD.operation_id
    OR NEW.account_id IS DISTINCT FROM OLD.account_id
    OR NEW.tunnel_id IS DISTINCT FROM OLD.tunnel_id
    OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
    OR NEW.host_id IS DISTINCT FROM OLD.host_id
    OR NEW.target_set_hash IS DISTINCT FROM OLD.target_set_hash
    OR NEW.old_credential_generation IS DISTINCT FROM OLD.old_credential_generation
    OR NEW.new_credential_generation IS DISTINCT FROM OLD.new_credential_generation
    OR (OLD.overlap_until IS NOT NULL AND NEW.overlap_until IS DISTINCT FROM OLD.overlap_until)
    OR (OLD.new_credential_valid_until IS NOT NULL AND NEW.new_credential_valid_until IS DISTINCT FROM OLD.new_credential_valid_until)
  ) THEN
    RAISE EXCEPTION 'connector rotation target identity and policy are immutable' USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM tunnel_connector_rotation_targets
    WHERE operation_id = NEW.operation_id
      AND target_set_hash <> NEW.target_set_hash
  ) THEN
    RAISE EXCEPTION 'connector rotation target set hash is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tunnel_connector_rotation_target_scope
  BEFORE INSERT OR UPDATE ON tunnel_connector_rotation_targets
  FOR EACH ROW EXECUTE FUNCTION validate_connector_rotation_target_scope();

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM tunnel_connector_rotation_targets) THEN
    RAISE EXCEPTION 'cannot roll back connector rotation state with retained targets';
  END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE connector_proof_replays
  DROP CONSTRAINT IF EXISTS connector_proof_replays_proof_kind_check,
  ADD CONSTRAINT connector_proof_replays_proof_kind_check
    CHECK (proof_kind IN ('auth', 'renew'));

DROP INDEX tunnel_connector_rotation_targets_expiry;
DROP INDEX tunnel_connector_rotation_targets_state;
DROP TRIGGER tunnel_connector_rotation_target_scope ON tunnel_connector_rotation_targets;
DROP FUNCTION validate_connector_rotation_target_scope();
DROP TABLE tunnel_connector_rotation_targets;
DROP INDEX tunnel_connector_credentials_source_operation;
DROP INDEX tunnel_connector_sessions_credential_generation;
ALTER TABLE tunnel_connector_credential_generations
  DROP COLUMN source_operation_id;
ALTER TABLE tunnel_connector_sessions
  DROP CONSTRAINT tunnel_connector_sessions_credential_generation_check,
  DROP COLUMN credential_generation,
  DROP COLUMN last_heartbeat_sent_at;
