-- +goose Up

-- Built-in preview and managed tunnel hostnames are server-owned certificate targets.
-- Their identity is deliberately not a tunnel_domains, preview_domains, or
-- users row. Certificate rows use the explicit platform-wildcard target shape
-- so the existing encrypted store, edge distribution ledger, and wire
-- protocol can be reused. The trigger below binds those rows to this table.
CREATE TABLE tunnel_platform_certificate_targets (
  id text PRIMARY KEY,
  kind text NOT NULL,
  hostname text NOT NULL UNIQUE,
  account_id text NOT NULL,
  challenge_reference text NOT NULL,
  generation bigint NOT NULL DEFAULT 1,
  desired_state text NOT NULL DEFAULT 'active',
  certificate_state text NOT NULL DEFAULT 'pending',
  certificate_reference text,
  certificate_expires_at timestamptz,
  certificate_renewal_attempted_at timestamptz,
  certificate_failure_code text,
  retry_count integer NOT NULL DEFAULT 0,
  next_retry_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (id IN ('platform_cert_preview_v1','platform_cert_tunnel_v1')),
  CHECK (kind IN ('preview_wildcard','tunnel_wildcard')),
  CHECK ((id = 'platform_cert_preview_v1' AND kind = 'preview_wildcard')
      OR (id = 'platform_cert_tunnel_v1' AND kind = 'tunnel_wildcard')),
  CHECK (length(trim(hostname)) BETWEEN 3 AND 253 AND hostname = lower(hostname) AND hostname LIKE '*.%' AND hostname !~ '[.]$'),
  CHECK (account_id = 'platform_system_v1'),
  CHECK (length(trim(challenge_reference)) BETWEEN 1 AND 256 AND challenge_reference !~ E'[\\r\\n]'),
  CHECK (generation > 0),
  CHECK (desired_state IN ('active','revoked')),
  CHECK (certificate_state IN ('pending','failed','ready','revoked')),
  CHECK (certificate_reference IS NULL OR length(trim(certificate_reference)) BETWEEN 1 AND 256),
  CHECK (certificate_expires_at IS NULL OR certificate_expires_at > created_at),
  CHECK (certificate_failure_code IS NULL OR length(trim(certificate_failure_code)) BETWEEN 1 AND 128),
  CHECK (retry_count >= 0 AND retry_count <= 30),
  CHECK (next_retry_at IS NULL OR next_retry_at > updated_at),
  CHECK ((certificate_state = 'revoked') = (desired_state = 'revoked'))
);
CREATE INDEX tunnel_platform_certificate_targets_due
  ON tunnel_platform_certificate_targets(desired_state, next_retry_at, id)
  WHERE desired_state = 'active';

-- Platform DNS-01 is a distinct strategy because its TXT is written directly
-- in the server-owned zone. Keep delegated DNS-01 reserved for user-owned
-- domains and restore migration 136's check in the guarded Down path.
ALTER TABLE tunnel_certificate_records
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_strategy_check,
  ADD CONSTRAINT tunnel_certificate_records_strategy_check
    CHECK (strategy IN ('delegated_dns01','provided_reference','on_demand_leaf','wildcard_fallback','platform_dns01'));

-- Platform identities do not have a users row. Preserve the account deletion
-- cascade for ordinary certificate rows through a nullable shadow owner FK.
-- Existing rows are backfilled before the old account FK is removed.
ALTER TABLE tunnel_certificate_records
  ADD COLUMN user_account_id text REFERENCES users(id) ON DELETE CASCADE;
UPDATE tunnel_certificate_records SET user_account_id = account_id WHERE user_account_id IS NULL;
ALTER TABLE tunnel_certificate_records
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_account_id_fkey;
ALTER TABLE tunnel_certificate_records
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_target_xor_check,
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_target_kind_check,
  ADD CONSTRAINT tunnel_certificate_records_target_kind_check
    CHECK (target_kind IN ('durable_route','preview_lease','platform_wildcard')),
  ADD CONSTRAINT tunnel_certificate_records_target_xor_check
    CHECK (
      domain_id IS NOT NULL
      AND (
        (
          target_kind = 'durable_route'
          AND tunnel_id IS NOT NULL
          AND preview_id IS NULL
          AND preview_generation IS NULL
          AND preview_state IS NULL
          AND preview_expires_at IS NULL
        )
        OR (
          target_kind = 'preview_lease'
          AND tunnel_id IS NULL
          AND preview_id IS NOT NULL
          AND preview_generation > 0
          AND preview_state = 'active'
          AND preview_expires_at IS NOT NULL
        )
        OR (
          target_kind = 'platform_wildcard'
          AND tunnel_id IS NULL
          AND route_id IS NULL
          AND preview_id IS NULL
          AND preview_generation IS NULL
          AND preview_state IS NULL
          AND preview_expires_at IS NULL
          AND leaf_hostname IS NULL
        )
      )
    ),
  ADD CONSTRAINT tunnel_certificate_records_user_account_match_check
  CHECK ((target_kind = 'platform_wildcard' AND user_account_id IS NULL AND account_id = 'platform_system_v1')
      OR (target_kind <> 'platform_wildcard' AND user_account_id IS NOT NULL AND user_account_id = account_id)),
  ADD CONSTRAINT tunnel_certificate_records_target_strategy_check
  CHECK ((target_kind = 'platform_wildcard' AND strategy = 'platform_dns01')
      OR (target_kind <> 'platform_wildcard' AND strategy <> 'platform_dns01'));

-- Existing sqlc insert statements intentionally name their historical
-- columns only. Fill the shadow owner before the check/FK runs so ordinary
-- user-owned certificate writes retain their account deletion cascade.
-- +goose StatementBegin
CREATE FUNCTION tunnel_certificate_user_account_fill_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.target_kind <> 'platform_wildcard' AND NEW.user_account_id IS NULL THEN
    NEW.user_account_id := NEW.account_id;
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER tunnel_certificate_user_account_fill_v1
  BEFORE INSERT OR UPDATE ON tunnel_certificate_records
  FOR EACH ROW EXECUTE FUNCTION tunnel_certificate_user_account_fill_v1();

-- Replace the union guard from migration 146 with a third, server-owned
-- namespace. Platform rows carry the platform wildcard target kind and no
-- route/lease identity; their exact hostname/generation is checked against
-- this target projection.
DROP TRIGGER IF EXISTS tunnel_certificate_target_guard_v1 ON tunnel_certificate_records;
DROP FUNCTION IF EXISTS tunnel_certificate_target_guard_v1();
-- +goose StatementBegin
CREATE FUNCTION tunnel_certificate_target_guard_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.target_kind = 'platform_wildcard' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM tunnel_platform_certificate_targets AS platform
      WHERE platform.id = NEW.domain_id
        AND platform.account_id = NEW.account_id
        AND platform.hostname = NEW.hostname
        AND platform.generation = NEW.domain_generation
        AND NEW.tunnel_id IS NULL
        AND NEW.route_id IS NULL
        AND NEW.leaf_hostname IS NULL
    ) THEN
      RAISE EXCEPTION 'certificate platform target does not match target projection';
    END IF;
  ELSIF NEW.target_kind = 'durable_route' THEN
    IF NOT EXISTS (
      SELECT 1 FROM tunnel_domains AS d
      WHERE d.id = NEW.domain_id
        AND d.account_id = NEW.account_id
        AND d.tunnel_id = NEW.tunnel_id
    ) THEN
      RAISE EXCEPTION 'certificate durable target does not match domain';
    END IF;
  ELSIF NEW.target_kind = 'preview_lease' THEN
    IF NOT EXISTS (
      SELECT 1 FROM preview_domains AS d
      WHERE d.id = NEW.domain_id
        AND d.account_id = NEW.account_id
        AND d.preview_id = NEW.preview_id
    ) THEN
      RAISE EXCEPTION 'certificate preview target does not match domain';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER tunnel_certificate_target_guard_v1
  BEFORE INSERT OR UPDATE ON tunnel_certificate_records
  FOR EACH ROW EXECUTE FUNCTION tunnel_certificate_target_guard_v1();

DROP TRIGGER IF EXISTS tunnel_certificate_issuance_lock_target_guard_v1 ON tunnel_certificate_issuance_locks;
DROP FUNCTION IF EXISTS tunnel_certificate_issuance_lock_target_guard_v1();
-- +goose StatementBegin
CREATE FUNCTION tunnel_certificate_issuance_lock_target_guard_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM tunnel_domains WHERE id = NEW.domain_id)
     AND NOT EXISTS (SELECT 1 FROM preview_domains WHERE id = NEW.domain_id)
     AND NOT EXISTS (SELECT 1 FROM tunnel_platform_certificate_targets WHERE id = NEW.domain_id) THEN
    RAISE EXCEPTION 'certificate issuance lock target does not exist';
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER tunnel_certificate_issuance_lock_target_guard_v1
  BEFORE INSERT OR UPDATE ON tunnel_certificate_issuance_locks
  FOR EACH ROW EXECUTE FUNCTION tunnel_certificate_issuance_lock_target_guard_v1();

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM tunnel_certificate_records AS cert WHERE cert.domain_id IN (SELECT id FROM tunnel_platform_certificate_targets))
     OR EXISTS (SELECT 1 FROM tunnel_certificate_issuance_locks AS lock WHERE lock.domain_id IN (SELECT id FROM tunnel_platform_certificate_targets)) THEN
    RAISE EXCEPTION 'cannot remove platform certificate targets while platform certificate rows or locks exist';
  END IF;
END
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS tunnel_certificate_issuance_lock_target_guard_v1 ON tunnel_certificate_issuance_locks;
DROP FUNCTION IF EXISTS tunnel_certificate_issuance_lock_target_guard_v1();
DROP TRIGGER IF EXISTS tunnel_certificate_target_guard_v1 ON tunnel_certificate_records;
DROP FUNCTION IF EXISTS tunnel_certificate_target_guard_v1();
DROP TRIGGER IF EXISTS tunnel_certificate_user_account_fill_v1 ON tunnel_certificate_records;
DROP FUNCTION IF EXISTS tunnel_certificate_user_account_fill_v1();

-- Restore the migration-146 union guards before dropping the platform table.
-- +goose StatementBegin
CREATE FUNCTION tunnel_certificate_target_guard_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.target_kind = 'durable_route' THEN
    IF NOT EXISTS (
      SELECT 1 FROM tunnel_domains AS d
      WHERE d.id = NEW.domain_id
        AND d.account_id = NEW.account_id
        AND d.tunnel_id = NEW.tunnel_id
    ) THEN
      RAISE EXCEPTION 'certificate durable target does not match domain';
    END IF;
  ELSIF NEW.target_kind = 'preview_lease' THEN
    IF NOT EXISTS (
      SELECT 1 FROM preview_domains AS d
      WHERE d.id = NEW.domain_id
        AND d.account_id = NEW.account_id
        AND d.preview_id = NEW.preview_id
    ) THEN
      RAISE EXCEPTION 'certificate preview target does not match domain';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER tunnel_certificate_target_guard_v1
  BEFORE INSERT OR UPDATE ON tunnel_certificate_records
  FOR EACH ROW EXECUTE FUNCTION tunnel_certificate_target_guard_v1();

-- +goose StatementBegin
CREATE FUNCTION tunnel_certificate_issuance_lock_target_guard_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM tunnel_domains WHERE id = NEW.domain_id)
     AND NOT EXISTS (SELECT 1 FROM preview_domains WHERE id = NEW.domain_id) THEN
    RAISE EXCEPTION 'certificate issuance lock target does not exist';
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER tunnel_certificate_issuance_lock_target_guard_v1
  BEFORE INSERT OR UPDATE ON tunnel_certificate_issuance_locks
  FOR EACH ROW EXECUTE FUNCTION tunnel_certificate_issuance_lock_target_guard_v1();

ALTER TABLE tunnel_certificate_records
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_user_account_match_check,
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_target_strategy_check,
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_target_xor_check,
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_target_kind_check;
ALTER TABLE tunnel_certificate_records
  DROP COLUMN IF EXISTS user_account_id;
ALTER TABLE tunnel_certificate_records
  ADD CONSTRAINT tunnel_certificate_records_target_kind_check
    CHECK (target_kind IN ('durable_route','preview_lease')),
  ADD CONSTRAINT tunnel_certificate_records_target_xor_check
    CHECK (
      domain_id IS NOT NULL
      AND (
        (
          target_kind = 'durable_route'
          AND tunnel_id IS NOT NULL
          AND preview_id IS NULL
          AND preview_generation IS NULL
          AND preview_state IS NULL
          AND preview_expires_at IS NULL
        )
        OR (
          target_kind = 'preview_lease'
          AND tunnel_id IS NULL
          AND preview_id IS NOT NULL
          AND preview_generation > 0
          AND preview_state = 'active'
          AND preview_expires_at IS NOT NULL
        )
      )
    );
ALTER TABLE tunnel_certificate_records
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_strategy_check,
  ADD CONSTRAINT tunnel_certificate_records_strategy_check
    CHECK (strategy IN ('delegated_dns01','provided_reference','on_demand_leaf','wildcard_fallback'));
ALTER TABLE tunnel_certificate_records
  ADD CONSTRAINT tunnel_certificate_records_account_id_fkey
  FOREIGN KEY (account_id) REFERENCES users(id) ON DELETE CASCADE;

DROP INDEX IF EXISTS tunnel_platform_certificate_targets_due;
DROP TABLE IF EXISTS tunnel_platform_certificate_targets;
