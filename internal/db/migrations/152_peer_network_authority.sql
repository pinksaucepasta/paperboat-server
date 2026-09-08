-- +goose Up
CREATE SEQUENCE peer_network_virtual_address_seq MINVALUE 1 MAXVALUE 9007199254740991;

CREATE TABLE peer_network_identities (
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint_id text NOT NULL,
  role text NOT NULL CHECK (role IN ('cli', 'machine')),
  machine_id text REFERENCES user_machines(id) ON DELETE CASCADE,
  endpoint_generation bigint NOT NULL CHECK (endpoint_generation > 0),
  machine_generation bigint NOT NULL CHECK (machine_generation >= 0),
  key_generation bigint NOT NULL CHECK (key_generation > 0),
  wireguard_public_key bytea NOT NULL CHECK (octet_length(wireguard_public_key) = 32),
  quic_certificate_fingerprint bytea NOT NULL REFERENCES peer_endpoint_certificates(fingerprint) ON DELETE RESTRICT,
  virtual_address inet NOT NULL UNIQUE,
  config_generation bigint NOT NULL DEFAULT 0 CHECK (config_generation >= 0),
  revoked_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (user_id, endpoint_id),
  UNIQUE (wireguard_public_key),
  CHECK ((role = 'cli' AND machine_id IS NULL AND machine_generation = 0) OR
         (role = 'machine' AND machine_id = endpoint_id AND machine_generation > 0))
);

CREATE TABLE peer_network_registration_operations (
  operation_id text PRIMARY KEY CHECK (length(operation_id) BETWEEN 8 AND 128),
  user_id text NOT NULL,
  endpoint_id text NOT NULL,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  key_generation bigint NOT NULL CHECK (key_generation > 0),
  created_at timestamptz NOT NULL,
  FOREIGN KEY (user_id, endpoint_id) REFERENCES peer_network_identities(user_id, endpoint_id) ON DELETE CASCADE
);

CREATE INDEX peer_network_identity_active_endpoint_idx
  ON peer_network_identities(endpoint_id) WHERE revoked_at IS NULL;
CREATE INDEX user_machine_access_sessions_network_authority_idx
  ON user_machine_access_sessions(user_id, cli_client_session_id, user_machine_id, expires_at)
  WHERE state = 'active' AND revoked_at IS NULL;

-- +goose StatementBegin
CREATE FUNCTION advance_peer_network_for_access_session() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities
  SET config_generation = config_generation + 1, updated_at = now()
  WHERE user_id = NEW.user_id
    AND endpoint_id IN (NEW.cli_client_session_id, NEW.user_machine_id);
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER user_machine_access_peer_network_generation
AFTER INSERT OR UPDATE OF state, revoked_at, expires_at ON user_machine_access_sessions
FOR EACH ROW EXECUTE FUNCTION advance_peer_network_for_access_session();

-- +goose StatementBegin
CREATE FUNCTION advance_peer_network_for_identity() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.user_id AND n.endpoint_id <> NEW.endpoint_id AND EXISTS (
    SELECT 1 FROM user_machine_access_sessions a
    WHERE a.user_id = NEW.user_id AND
      ((a.cli_client_session_id = NEW.endpoint_id AND a.user_machine_id = n.endpoint_id) OR
       (a.user_machine_id = NEW.endpoint_id AND a.cli_client_session_id = n.endpoint_id)));
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER identity_peer_network_generation
AFTER UPDATE OF wireguard_public_key, key_generation, quic_certificate_fingerprint, revoked_at
ON peer_network_identities FOR EACH ROW
EXECUTE FUNCTION advance_peer_network_for_identity();

-- +goose StatementBegin
CREATE FUNCTION advance_peer_network_for_cli_session() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.user_id AND (n.endpoint_id = NEW.id OR EXISTS (
    SELECT 1 FROM user_machine_access_sessions a
    WHERE a.user_id = NEW.user_id AND a.cli_client_session_id = NEW.id
      AND a.user_machine_id = n.endpoint_id));
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER cli_session_peer_network_generation
AFTER UPDATE OF state, revoked_at ON cli_client_sessions
FOR EACH ROW
EXECUTE FUNCTION advance_peer_network_for_cli_session();

-- +goose StatementBegin
CREATE FUNCTION advance_peer_network_for_machine() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.user_id AND (n.endpoint_id = NEW.id OR EXISTS (
    SELECT 1 FROM user_machine_access_sessions a
    WHERE a.user_id = NEW.user_id AND a.user_machine_id = NEW.id
      AND a.cli_client_session_id = n.endpoint_id));
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER machine_peer_network_generation
AFTER UPDATE OF state, seat_state, revoked_at, deleted_at, installation_generation ON user_machines
FOR EACH ROW EXECUTE FUNCTION advance_peer_network_for_machine();

-- +goose StatementBegin
CREATE FUNCTION advance_peer_network_for_environment() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.owner_user_id AND EXISTS (
    SELECT 1 FROM user_machine_access_sessions a
    WHERE a.user_id = NEW.owner_user_id AND a.environment_id = NEW.id
      AND (a.cli_client_session_id = n.endpoint_id OR a.user_machine_id = n.endpoint_id));
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER environment_peer_network_generation
AFTER UPDATE OF desired_state, revoked_at ON control_environments
FOR EACH ROW EXECUTE FUNCTION advance_peer_network_for_environment();

-- +goose StatementBegin
CREATE FUNCTION advance_peer_network_for_certificate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.user_id AND (n.endpoint_id = NEW.endpoint_id OR EXISTS (
    SELECT 1 FROM user_machine_access_sessions a
    WHERE a.user_id = NEW.user_id AND
      ((a.cli_client_session_id = NEW.endpoint_id AND a.user_machine_id = n.endpoint_id) OR
       (a.user_machine_id = NEW.endpoint_id AND a.cli_client_session_id = n.endpoint_id))));
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER certificate_peer_network_generation
AFTER UPDATE OF revoked_at, expires_at ON peer_endpoint_certificates
FOR EACH ROW EXECUTE FUNCTION advance_peer_network_for_certificate();

-- +goose StatementBegin
CREATE FUNCTION advance_peer_network_for_account_key() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.user_id;
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER account_key_peer_network_generation
AFTER UPDATE OF revoked_at ON account_e2ee_keys
FOR EACH ROW WHEN (OLD.revoked_at IS DISTINCT FROM NEW.revoked_at)
EXECUTE FUNCTION advance_peer_network_for_account_key();

-- +goose StatementBegin
CREATE FUNCTION advance_peer_network_for_account_root() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities
  SET config_generation = config_generation + 1, updated_at = now()
  WHERE user_id = NEW.user_id;
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER account_root_peer_network_generation
AFTER UPDATE OF revoked_at, generation ON account_e2ee_roots
FOR EACH ROW EXECUTE FUNCTION advance_peer_network_for_account_root();

-- +goose StatementBegin
CREATE FUNCTION advance_peer_network_for_account() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities
  SET config_generation = config_generation + 1, updated_at = now()
  WHERE user_id = NEW.id;
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER account_peer_network_generation
AFTER UPDATE OF status ON users FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION advance_peer_network_for_account();

-- +goose Down
DROP INDEX IF EXISTS user_machine_access_sessions_network_authority_idx;
DROP TRIGGER IF EXISTS account_peer_network_generation ON users;
DROP FUNCTION IF EXISTS advance_peer_network_for_account();
DROP TRIGGER IF EXISTS account_root_peer_network_generation ON account_e2ee_roots;
DROP FUNCTION IF EXISTS advance_peer_network_for_account_root();
DROP TRIGGER IF EXISTS account_key_peer_network_generation ON account_e2ee_keys;
DROP FUNCTION IF EXISTS advance_peer_network_for_account_key();
DROP TRIGGER IF EXISTS certificate_peer_network_generation ON peer_endpoint_certificates;
DROP FUNCTION IF EXISTS advance_peer_network_for_certificate();
DROP TRIGGER IF EXISTS machine_peer_network_generation ON user_machines;
DROP FUNCTION IF EXISTS advance_peer_network_for_machine();
DROP TRIGGER IF EXISTS environment_peer_network_generation ON control_environments;
DROP FUNCTION IF EXISTS advance_peer_network_for_environment();
DROP TRIGGER IF EXISTS cli_session_peer_network_generation ON cli_client_sessions;
DROP FUNCTION IF EXISTS advance_peer_network_for_cli_session();
DROP TRIGGER IF EXISTS user_machine_access_peer_network_generation ON user_machine_access_sessions;
DROP FUNCTION IF EXISTS advance_peer_network_for_access_session();
DROP TRIGGER IF EXISTS identity_peer_network_generation ON peer_network_identities;
DROP FUNCTION IF EXISTS advance_peer_network_for_identity();
DROP TABLE IF EXISTS peer_network_registration_operations;
DROP TABLE IF EXISTS peer_network_identities;
DROP SEQUENCE IF EXISTS peer_network_virtual_address_seq;
