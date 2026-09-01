-- +goose Up

-- Preview domains have lease-bound lifecycle and therefore remain separate
-- from durable tunnel_domains. Both tables share one global hostname
-- namespace through generation-safe transaction triggers below.
-- The composite foreign key below also proves that the preview and account
-- identities were read from the same lease row. Migration 125 owns the exact
-- preview_leases(id, account_id) unique constraint used by this reference.

CREATE TABLE preview_domains (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  preview_id text NOT NULL,
  preview_generation bigint NOT NULL,
  hostname text NOT NULL,
  match_type text NOT NULL,
  ownership_challenge_reference text NOT NULL,
  ownership_state text NOT NULL DEFAULT 'pending',
  dns_target text NOT NULL,
  observed_records jsonb NOT NULL DEFAULT '[]'::jsonb,
  dns_provider text NOT NULL DEFAULT 'generic',
  expected_records jsonb NOT NULL DEFAULT '[]'::jsonb,
  dns_last_checked_at timestamptz,
  dns_next_check_at timestamptz NOT NULL DEFAULT now(),
  dns_ttl_seconds integer,
  verification_attempts integer NOT NULL DEFAULT 0,
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
  quarantine_until timestamptz,
  CONSTRAINT preview_domains_preview_account_fk
    FOREIGN KEY (preview_id, account_id)
    REFERENCES preview_leases(id, account_id) ON DELETE CASCADE,
  CHECK (preview_generation > 0 AND generation > 0),
  CHECK (hostname = btrim(hostname) AND hostname = lower(hostname) AND hostname !~ '[.]$'),
  CHECK (
    (match_type = 'exact' AND hostname !~ '^[*][.]')
    OR (match_type = 'one_label_wildcard' AND hostname ~ '^[*][.][a-z0-9]')
  ),
  CHECK (ownership_state IN ('pending','verified','failed','expired','revoked')),
  CHECK (jsonb_typeof(observed_records) = 'array'),
  CHECK (jsonb_typeof(expected_records) = 'array'),
  CHECK (dns_provider IN ('generic','cloudflare','route53','google_cloud_dns','digitalocean','namecheap')),
  CHECK (dns_ttl_seconds IS NULL OR dns_ttl_seconds BETWEEN 30 AND 86400),
  CHECK (verification_attempts >= 0),
  CHECK (certificate_strategy IN ('managed','provided_reference','on_demand_leaf','none')),
  CHECK (certificate_state IN ('pending','issuing','ready','renewing','failed','expired','revoked','not_applicable')),
  CHECK ((certificate_strategy = 'none') = (certificate_state = 'not_applicable')),
  CHECK (caa_state IN ('unknown','ready','blocked','not_applicable')),
  CHECK (conflict_state IN ('clear','conflicted','quarantined')),
  CHECK ((conflict_state = 'quarantined') = (quarantine_until IS NOT NULL)),
  CHECK ((deleted_at IS NULL) OR (conflict_state = 'quarantined' AND quarantine_until IS NOT NULL))
);

CREATE UNIQUE INDEX preview_domains_live_hostname_unique
  ON preview_domains(hostname)
  WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX preview_domains_preview_hostname_live_unique
  ON preview_domains(preview_id, hostname)
  WHERE deleted_at IS NULL;
CREATE INDEX preview_domains_preview_state
  ON preview_domains(preview_id, ownership_state, certificate_state, hostname, id);
CREATE INDEX preview_domains_dns_due
  ON preview_domains(dns_next_check_at, id)
  WHERE deleted_at IS NULL AND ownership_state IN ('pending','failed','verified');
CREATE INDEX preview_domains_certificate_due
  ON preview_domains(certificate_expires_at, id)
  WHERE deleted_at IS NULL AND certificate_state IN ('pending','issuing','ready','renewing','failed');
CREATE INDEX preview_domains_quarantine_due
  ON preview_domains(quarantine_until, hostname, id)
  WHERE deleted_at IS NOT NULL AND conflict_state = 'quarantined';

-- PostgreSQL cannot express a unique index across two tables. Serialize only
-- claims for the same canonical hostname, then reject a live binding in the
-- other target family or another account's quarantine. Same-account reuse of
-- a withdrawn preview/tunnel binding remains possible without DNS churn.
-- +goose StatementBegin
CREATE FUNCTION enforce_preview_tunnel_domain_hostname_claim_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  candidate text := lower(trim(NEW.hostname));
  conflict_exists boolean;
BEGIN
  IF NEW.deleted_at IS NOT NULL THEN
    RETURN NEW;
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(candidate, 145));

  IF TG_TABLE_NAME = 'preview_domains' THEN
    SELECT EXISTS (
      SELECT 1
      FROM tunnel_domains AS other
      WHERE other.hostname = candidate
        AND (
          other.deleted_at IS NULL
          OR (other.account_id <> NEW.account_id AND other.quarantine_until > now())
        )
      UNION ALL
      SELECT 1
      FROM preview_domains AS other
      WHERE other.id <> NEW.id
        AND other.hostname = candidate
        AND (
          other.deleted_at IS NULL
          OR (other.account_id <> NEW.account_id AND other.quarantine_until > now())
        )
      LIMIT 1
    ) INTO conflict_exists;
  ELSE
    SELECT EXISTS (
      SELECT 1
      FROM preview_domains AS other
      WHERE other.hostname = candidate
        AND (
          other.deleted_at IS NULL
          OR (other.account_id <> NEW.account_id AND other.quarantine_until > now())
        )
      UNION ALL
      SELECT 1
      FROM tunnel_domains AS other
      WHERE other.id <> NEW.id
        AND other.hostname = candidate
        AND (
          other.deleted_at IS NULL
          OR (other.account_id <> NEW.account_id AND other.quarantine_until > now())
        )
      LIMIT 1
    ) INTO conflict_exists;
  END IF;

  IF conflict_exists THEN
    RAISE unique_violation USING
      CONSTRAINT = 'domain_bindings_live_hostname_unique',
      MESSAGE = 'custom domain hostname is already claimed';
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER preview_domains_global_hostname_claim_v1
  BEFORE INSERT OR UPDATE OF hostname, account_id, deleted_at, quarantine_until
  ON preview_domains
  FOR EACH ROW EXECUTE FUNCTION enforce_preview_tunnel_domain_hostname_claim_v1();

CREATE TRIGGER tunnel_domains_global_hostname_claim_v1
  BEFORE INSERT OR UPDATE OF hostname, account_id, deleted_at, quarantine_until
  ON tunnel_domains
  FOR EACH ROW EXECUTE FUNCTION enforce_preview_tunnel_domain_hostname_claim_v1();

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM preview_domains) THEN
    RAISE EXCEPTION 'cannot remove preview custom domains while bindings exist';
  END IF;
END
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS tunnel_domains_global_hostname_claim_v1 ON tunnel_domains;
DROP TRIGGER IF EXISTS preview_domains_global_hostname_claim_v1 ON preview_domains;
DROP FUNCTION IF EXISTS enforce_preview_tunnel_domain_hostname_claim_v1();
DROP TABLE preview_domains;
