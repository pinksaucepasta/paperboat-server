-- +goose Up
ALTER TABLE peer_network_identities ADD COLUMN relay_revocation_generation bigint NOT NULL DEFAULT 0 CHECK (relay_revocation_generation >= 0);
-- Preserve invalidations committed before this feed existed. Subsequent ordinary
-- refreshes leave this floor unchanged; domain mutations advance it explicitly.
UPDATE peer_network_identities SET relay_revocation_generation = config_generation;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_access_session() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities
  SET relay_revocation_generation = config_generation + 1, config_generation = config_generation + 1, updated_at = now()
  WHERE user_id = NEW.user_id
    AND endpoint_id IN (NEW.cli_client_session_id, NEW.user_machine_id);
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_identity() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET relay_revocation_generation = n.config_generation + 1, config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.user_id AND n.endpoint_id <> NEW.endpoint_id AND EXISTS (
    SELECT 1 FROM user_machine_access_sessions a
    WHERE a.user_id = NEW.user_id AND
      ((a.cli_client_session_id = NEW.endpoint_id AND a.user_machine_id = n.endpoint_id) OR
       (a.user_machine_id = NEW.endpoint_id AND a.cli_client_session_id = n.endpoint_id)));
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_cli_session() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET relay_revocation_generation = n.config_generation + 1, config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.user_id AND (n.endpoint_id = NEW.id OR EXISTS (
    SELECT 1 FROM user_machine_access_sessions a
    WHERE a.user_id = NEW.user_id AND a.cli_client_session_id = NEW.id
      AND a.user_machine_id = n.endpoint_id));
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_machine() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET relay_revocation_generation = n.config_generation + 1, config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.user_id AND (n.endpoint_id = NEW.id OR EXISTS (
    SELECT 1 FROM user_machine_access_sessions a
    WHERE a.user_id = NEW.user_id AND a.user_machine_id = NEW.id
      AND a.cli_client_session_id = n.endpoint_id));
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_environment() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET relay_revocation_generation = n.config_generation + 1, config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.owner_user_id AND EXISTS (
    SELECT 1 FROM user_machine_access_sessions a
    WHERE a.user_id = NEW.owner_user_id AND a.environment_id = NEW.id
      AND (a.cli_client_session_id = n.endpoint_id OR a.user_machine_id = n.endpoint_id));
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_certificate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET relay_revocation_generation = n.config_generation + 1, config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.user_id AND (n.endpoint_id = NEW.endpoint_id OR EXISTS (
    SELECT 1 FROM user_machine_access_sessions a
    WHERE a.user_id = NEW.user_id AND
      ((a.cli_client_session_id = NEW.endpoint_id AND a.user_machine_id = n.endpoint_id) OR
       (a.user_machine_id = NEW.endpoint_id AND a.cli_client_session_id = n.endpoint_id))));
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_account_key() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET relay_revocation_generation = n.config_generation + 1, config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.user_id;
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_account_root() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities
  SET relay_revocation_generation = config_generation + 1, config_generation = config_generation + 1, updated_at = now()
  WHERE user_id = NEW.user_id;
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_account() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities
  SET relay_revocation_generation = config_generation + 1, config_generation = config_generation + 1, updated_at = now()
  WHERE user_id = NEW.id;
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION fence_peer_network_local_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.wireguard_public_key,NEW.disco_public_key,NEW.quic_certificate_fingerprint,NEW.key_generation,NEW.revoked_at,NEW.endpoint_generation,NEW.machine_generation)
 IS DISTINCT FROM ROW(OLD.wireguard_public_key,OLD.disco_public_key,OLD.quic_certificate_fingerprint,OLD.key_generation,OLD.revoked_at,OLD.endpoint_generation,OLD.machine_generation) THEN
  NEW.config_generation := GREATEST(NEW.config_generation, OLD.config_generation + 1);
  NEW.relay_revocation_generation := NEW.config_generation;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER peer_network_local_identity_fence BEFORE UPDATE ON peer_network_identities FOR EACH ROW EXECUTE FUNCTION fence_peer_network_local_identity();
-- +goose Down
DROP TRIGGER peer_network_local_identity_fence ON peer_network_identities;
DROP FUNCTION fence_peer_network_local_identity();
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_access_session() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities
  SET config_generation = config_generation + 1, updated_at = now()
  WHERE user_id = NEW.user_id
    AND endpoint_id IN (NEW.cli_client_session_id, NEW.user_machine_id);
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_identity() RETURNS trigger
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
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_cli_session() RETURNS trigger
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
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_machine() RETURNS trigger
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
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_environment() RETURNS trigger
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
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_certificate() RETURNS trigger
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
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_account_key() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities n
  SET config_generation = n.config_generation + 1, updated_at = now()
  WHERE n.user_id = NEW.user_id;
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_account_root() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities
  SET config_generation = config_generation + 1, updated_at = now()
  WHERE user_id = NEW.user_id;
  RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_account() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities
  SET config_generation = config_generation + 1, updated_at = now()
  WHERE user_id = NEW.id;
  RETURN NEW;
END $$;
-- +goose StatementEnd
ALTER TABLE peer_network_identities DROP COLUMN relay_revocation_generation;
