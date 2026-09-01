-- +goose Up

-- Certificate rows are shared by durable tunnel routes and foreground preview
-- leases. The binding ID remains domain_id; target_kind and the matching target
-- columns make the owner namespace explicit and prevent a preview lease from
-- being interpreted as a durable tunnel route.
ALTER TABLE tunnel_certificate_records
  ALTER COLUMN domain_id DROP NOT NULL,
  ALTER COLUMN tunnel_id DROP NOT NULL,
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_domain_id_fkey;

ALTER TABLE tunnel_certificate_records
  ADD COLUMN target_kind text NOT NULL DEFAULT 'durable_route',
  ADD COLUMN route_id text,
  ADD COLUMN preview_id text,
  ADD COLUMN preview_generation bigint,
  ADD COLUMN preview_state text,
  ADD COLUMN preview_expires_at timestamptz;

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
    ),
  ADD CONSTRAINT tunnel_certificate_records_preview_lease_fk
    FOREIGN KEY (preview_id, account_id)
    REFERENCES preview_leases(id, account_id) ON DELETE CASCADE;

-- Locks use the binding ID as their key. The old tunnel-domain foreign key
-- would reject a valid preview-domain lock, so replace it with a union guard.
ALTER TABLE tunnel_certificate_issuance_locks
  DROP CONSTRAINT IF EXISTS tunnel_certificate_issuance_locks_domain_id_fkey;

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

CREATE INDEX tunnel_certificate_records_preview_target
  ON tunnel_certificate_records(preview_id, hostname, preview_generation, state)
  WHERE target_kind = 'preview_lease';
CREATE UNIQUE INDEX tunnel_certificate_records_preview_active_hostname
  ON tunnel_certificate_records(preview_id, hostname)
  WHERE target_kind = 'preview_lease' AND state = 'active';

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM tunnel_certificate_records WHERE target_kind = 'preview_lease')
     OR EXISTS (SELECT 1 FROM tunnel_certificate_issuance_locks AS l
                WHERE NOT EXISTS (SELECT 1 FROM tunnel_domains AS d WHERE d.id = l.domain_id)) THEN
    RAISE EXCEPTION 'cannot remove preview certificate targets while rows exist';
  END IF;
END
$$;
-- +goose StatementEnd

DROP INDEX IF EXISTS tunnel_certificate_records_preview_active_hostname;
DROP INDEX IF EXISTS tunnel_certificate_records_preview_target;
DROP TRIGGER IF EXISTS tunnel_certificate_issuance_lock_target_guard_v1 ON tunnel_certificate_issuance_locks;
DROP FUNCTION IF EXISTS tunnel_certificate_issuance_lock_target_guard_v1();
DROP TRIGGER IF EXISTS tunnel_certificate_target_guard_v1 ON tunnel_certificate_records;
DROP FUNCTION IF EXISTS tunnel_certificate_target_guard_v1();
ALTER TABLE tunnel_certificate_issuance_locks
  ADD CONSTRAINT tunnel_certificate_issuance_locks_domain_id_fkey
  FOREIGN KEY (domain_id) REFERENCES tunnel_domains(id) ON DELETE CASCADE;
ALTER TABLE tunnel_certificate_records
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_preview_lease_fk,
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_target_xor_check,
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_target_kind_check,
  DROP COLUMN IF EXISTS preview_expires_at,
  DROP COLUMN IF EXISTS preview_state,
  DROP COLUMN IF EXISTS preview_generation,
  DROP COLUMN IF EXISTS preview_id,
  DROP COLUMN IF EXISTS route_id,
  DROP COLUMN IF EXISTS target_kind,
  ALTER COLUMN domain_id SET NOT NULL,
  ALTER COLUMN tunnel_id SET NOT NULL,
  ADD CONSTRAINT tunnel_certificate_records_domain_id_fkey
  FOREIGN KEY (domain_id) REFERENCES tunnel_domains(id) ON DELETE CASCADE;
