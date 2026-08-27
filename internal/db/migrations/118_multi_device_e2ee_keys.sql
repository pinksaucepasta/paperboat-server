-- +goose Up

-- A user may trust more than one E2EE signing key. Account-level lifecycle
-- revocation remains represented by account_e2ee_roots; individual device
-- trust is represented here.
CREATE TABLE account_e2ee_keys (
  key_id text PRIMARY KEY CHECK (key_id ~ '^aek_[A-Za-z0-9_-]{16,128}$'),
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
  fingerprint bytea NOT NULL UNIQUE CHECK (octet_length(fingerprint) = 32),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  cli_client_session_id text REFERENCES cli_client_sessions(id) ON DELETE SET NULL,
  user_machine_id text REFERENCES user_machines(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  revocation_reason text CHECK (revocation_reason IS NULL OR revocation_reason IN ('device_removed','key_compromise','account_revoked')),
  CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at),
  UNIQUE (user_id, key_id),
  UNIQUE (user_id, fingerprint)
);

CREATE INDEX account_e2ee_keys_user_active_idx
  ON account_e2ee_keys (user_id, created_at, key_id)
  WHERE revoked_at IS NULL;

CREATE INDEX account_e2ee_keys_cli_session_idx
  ON account_e2ee_keys (cli_client_session_id)
  WHERE cli_client_session_id IS NOT NULL;

CREATE INDEX account_e2ee_keys_machine_idx
  ON account_e2ee_keys (user_machine_id)
  WHERE user_machine_id IS NOT NULL;

-- Preserve every currently trusted root as the first key for its account.
-- The key identifier is deterministic so clients can derive it from the
-- public key without another enrollment round trip.
INSERT INTO account_e2ee_keys
  (key_id, user_id, public_key, fingerprint, generation, created_at, updated_at,
   revoked_at, revocation_reason)
SELECT 'aek_' || encode(root.fingerprint, 'hex'), root.user_id, root.public_key,
       root.fingerprint, root.generation, root.created_at, root.updated_at,
       root.revoked_at,
       CASE WHEN root.revoked_at IS NULL THEN NULL ELSE 'account_revoked' END
FROM account_e2ee_roots root
ON CONFLICT (fingerprint) DO NOTHING;

ALTER TABLE peer_endpoint_certificates
  ADD COLUMN key_id text;

UPDATE peer_endpoint_certificates certificate
SET key_id = 'aek_' || encode(root.fingerprint, 'hex')
FROM account_e2ee_roots root
WHERE root.user_id = certificate.user_id;

ALTER TABLE peer_endpoint_certificates
  ALTER COLUMN key_id SET NOT NULL,
  ADD CONSTRAINT peer_endpoint_certificates_key_id_fkey
    FOREIGN KEY (key_id) REFERENCES account_e2ee_keys(key_id) ON DELETE RESTRICT;

-- Device-key revocation is distinct from revoking one endpoint certificate.
-- Preserve that reason on the dependent certificate tombstones so operators
-- can distinguish a removed device from an account-wide shutdown.
ALTER TABLE peer_endpoint_certificates
  DROP CONSTRAINT IF EXISTS peer_endpoint_certificates_revocation_reason_check,
  ADD CONSTRAINT peer_endpoint_certificates_revocation_reason_check
    CHECK (revocation_reason IS NULL OR revocation_reason IN ('endpoint_replaced', 'endpoint_removed', 'device_removed', 'account_revoked', 'key_compromise', 'certificate_superseded'));

CREATE INDEX peer_endpoint_certificates_key_idx
  ON peer_endpoint_certificates (key_id);

-- Revoking a device key is the server-side kill switch for every credential
-- derived from that key. This runs in the same transaction as the revocation,
-- so no newly issued or active peer credential can outlive its key.
CREATE OR REPLACE FUNCTION revoke_account_e2ee_key_dependents()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
    UPDATE peer_endpoint_certificates
    SET revoked_at = NEW.revoked_at,
        revocation_reason = CASE
          WHEN NEW.revocation_reason IN ('device_removed', 'key_compromise') THEN NEW.revocation_reason
          ELSE 'account_revoked'
        END
    WHERE key_id = NEW.key_id AND revoked_at IS NULL;

    UPDATE peer_signaling_grants grant_row
    SET revoked_at = NEW.revoked_at
    WHERE grant_row.intent_id IN (
      SELECT intent.id
      FROM peer_session_intents intent
      WHERE intent.controlling_certificate_fingerprint IN (
          SELECT fingerprint FROM peer_endpoint_certificates WHERE key_id = NEW.key_id
        )
        OR intent.controlled_certificate_fingerprint IN (
          SELECT fingerprint FROM peer_endpoint_certificates WHERE key_id = NEW.key_id
        )
    ) AND grant_row.revoked_at IS NULL;

    UPDATE peer_relay_allocations relay
    SET revoked_at = NEW.revoked_at
    WHERE relay.intent_id IN (
      SELECT intent.id
      FROM peer_session_intents intent
      WHERE intent.controlling_certificate_fingerprint IN (
          SELECT fingerprint FROM peer_endpoint_certificates WHERE key_id = NEW.key_id
        )
        OR intent.controlled_certificate_fingerprint IN (
          SELECT fingerprint FROM peer_endpoint_certificates WHERE key_id = NEW.key_id
        )
    ) AND relay.revoked_at IS NULL;

    UPDATE peer_session_intents intent
    SET state = 'revoked',
        revoked_at = NEW.revoked_at,
        revocation_reason = 'endpoint_revoked'
    WHERE intent.state = 'active'
      AND (
        intent.controlling_certificate_fingerprint IN (
          SELECT fingerprint FROM peer_endpoint_certificates WHERE key_id = NEW.key_id
        )
        OR intent.controlled_certificate_fingerprint IN (
          SELECT fingerprint FROM peer_endpoint_certificates WHERE key_id = NEW.key_id
        )
      );
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER account_e2ee_keys_revoke_dependents
AFTER UPDATE OF revoked_at ON account_e2ee_keys
FOR EACH ROW
EXECUTE FUNCTION revoke_account_e2ee_key_dependents();

-- Account-level revocation is propagated to every active device key through
-- the same dependent cleanup trigger.
CREATE OR REPLACE FUNCTION revoke_account_e2ee_keys_for_root()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
    UPDATE account_e2ee_keys
    SET revoked_at = NEW.revoked_at,
        revocation_reason = 'account_revoked',
        updated_at = NEW.updated_at
    WHERE user_id = NEW.user_id AND revoked_at IS NULL;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER account_e2ee_roots_revoke_keys
AFTER UPDATE OF revoked_at ON account_e2ee_roots
FOR EACH ROW
EXECUTE FUNCTION revoke_account_e2ee_keys_for_root();

-- A dashboard removal can revoke either the machine record or its CLI
-- session. Keep both paths authoritative and idempotent.
CREATE OR REPLACE FUNCTION revoke_account_e2ee_keys_for_cli_session()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.state <> 'revoked' AND NEW.state = 'revoked' THEN
    UPDATE account_e2ee_keys
    SET revoked_at = coalesce(revoked_at, NEW.revoked_at, now()),
        revocation_reason = coalesce(revocation_reason, 'device_removed'),
        updated_at = coalesce(NEW.revoked_at, now())
    WHERE cli_client_session_id = NEW.id AND revoked_at IS NULL;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER cli_client_sessions_revoke_e2ee_keys
AFTER UPDATE OF state ON cli_client_sessions
FOR EACH ROW
EXECUTE FUNCTION revoke_account_e2ee_keys_for_cli_session();

CREATE OR REPLACE FUNCTION revoke_account_e2ee_keys_for_machine()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL OR
     OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN
    UPDATE account_e2ee_keys
    SET revoked_at = coalesce(revoked_at, NEW.revoked_at, NEW.deleted_at, now()),
        revocation_reason = coalesce(revocation_reason, 'device_removed'),
        updated_at = coalesce(NEW.revoked_at, NEW.deleted_at, now())
    WHERE user_machine_id = NEW.id AND revoked_at IS NULL;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER user_machines_revoke_e2ee_keys
AFTER UPDATE OF revoked_at, deleted_at ON user_machines
FOR EACH ROW
EXECUTE FUNCTION revoke_account_e2ee_keys_for_machine();

-- +goose Down
DROP TRIGGER IF EXISTS user_machines_revoke_e2ee_keys ON user_machines;
DROP FUNCTION IF EXISTS revoke_account_e2ee_keys_for_machine();
DROP TRIGGER IF EXISTS cli_client_sessions_revoke_e2ee_keys ON cli_client_sessions;
DROP FUNCTION IF EXISTS revoke_account_e2ee_keys_for_cli_session();
DROP TRIGGER IF EXISTS account_e2ee_keys_revoke_dependents ON account_e2ee_keys;
DROP FUNCTION IF EXISTS revoke_account_e2ee_key_dependents();
DROP TRIGGER IF EXISTS account_e2ee_roots_revoke_keys ON account_e2ee_roots;
DROP FUNCTION IF EXISTS revoke_account_e2ee_keys_for_root();
DROP INDEX IF EXISTS peer_endpoint_certificates_key_idx;
ALTER TABLE peer_endpoint_certificates
  DROP CONSTRAINT IF EXISTS peer_endpoint_certificates_revocation_reason_check,
  ADD CONSTRAINT peer_endpoint_certificates_revocation_reason_check
    CHECK (revocation_reason IS NULL OR revocation_reason IN ('endpoint_replaced', 'endpoint_removed', 'account_revoked', 'key_compromise', 'certificate_superseded'));
ALTER TABLE peer_endpoint_certificates
  DROP CONSTRAINT IF EXISTS peer_endpoint_certificates_key_id_fkey,
  DROP COLUMN IF EXISTS key_id;
DROP INDEX IF EXISTS account_e2ee_keys_machine_idx;
DROP INDEX IF EXISTS account_e2ee_keys_cli_session_idx;
DROP INDEX IF EXISTS account_e2ee_keys_user_active_idx;
DROP TABLE IF EXISTS account_e2ee_keys;
