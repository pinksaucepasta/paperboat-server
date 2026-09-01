-- +goose Up
ALTER TABLE tunnel_domains
  ADD COLUMN dns_provider text NOT NULL DEFAULT 'generic',
  ADD COLUMN expected_records jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN dns_last_checked_at timestamptz,
  ADD COLUMN dns_next_check_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN dns_ttl_seconds integer,
  ADD COLUMN verification_attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN quarantine_until timestamptz;

ALTER TABLE tunnel_domains
  DROP CONSTRAINT tunnel_domains_certificate_state_check,
  ADD CONSTRAINT tunnel_domains_certificate_state_check
    CHECK (certificate_state IN ('pending','issuing','ready','renewing','failed','expired','revoked','not_applicable'));

UPDATE tunnel_domains
SET quarantine_until = COALESCE(deleted_at, updated_at) + interval '7 days'
WHERE conflict_state = 'quarantined' AND quarantine_until IS NULL;

ALTER TABLE tunnel_domains
  ADD CONSTRAINT tunnel_domains_dns_provider_check
    CHECK (dns_provider IN ('generic','cloudflare','route53','google_cloud_dns','digitalocean','namecheap')),
  ADD CONSTRAINT tunnel_domains_expected_records_check
    CHECK (jsonb_typeof(expected_records) = 'array'),
  ADD CONSTRAINT tunnel_domains_dns_ttl_check
    CHECK (dns_ttl_seconds IS NULL OR dns_ttl_seconds BETWEEN 30 AND 86400),
  ADD CONSTRAINT tunnel_domains_verification_attempts_check
    CHECK (verification_attempts >= 0),
  ADD CONSTRAINT tunnel_domains_quarantine_check
    CHECK ((conflict_state = 'quarantined') = (quarantine_until IS NOT NULL));

ALTER TABLE tunnel_domains DROP CONSTRAINT tunnel_domains_hostname_key;
CREATE UNIQUE INDEX tunnel_domains_live_hostname_unique
  ON tunnel_domains(hostname)
  WHERE deleted_at IS NULL;
CREATE INDEX tunnel_domains_dns_due
  ON tunnel_domains(dns_next_check_at, id)
  WHERE deleted_at IS NULL
    AND ownership_state IN ('pending','failed');
CREATE INDEX tunnel_domains_quarantine_due
  ON tunnel_domains(quarantine_until, hostname, id)
  WHERE deleted_at IS NOT NULL AND conflict_state = 'quarantined';

UPDATE tunnel_domains
SET expected_records = jsonb_build_array(
      jsonb_build_object('name', hostname, 'type', 'CNAME', 'value', dns_target, 'ttl', 300)
    ),
    dns_next_check_at = updated_at
WHERE expected_records = '[]'::jsonb;

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (
    SELECT hostname FROM tunnel_domains GROUP BY hostname HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'cannot restore global hostname uniqueness while historical claims coexist';
  END IF;
END $$;
-- +goose StatementEnd

DROP INDEX IF EXISTS tunnel_domains_quarantine_due;
DROP INDEX IF EXISTS tunnel_domains_dns_due;
DROP INDEX IF EXISTS tunnel_domains_live_hostname_unique;
UPDATE tunnel_domains SET certificate_state = 'pending' WHERE certificate_state = 'issuing';
ALTER TABLE tunnel_domains
  DROP CONSTRAINT tunnel_domains_certificate_state_check,
  ADD CONSTRAINT tunnel_domains_certificate_state_check
    CHECK (certificate_state IN ('pending','ready','renewing','failed','expired','revoked','not_applicable'));
ALTER TABLE tunnel_domains ADD CONSTRAINT tunnel_domains_hostname_key UNIQUE (hostname);
ALTER TABLE tunnel_domains
  DROP CONSTRAINT IF EXISTS tunnel_domains_quarantine_check,
  DROP CONSTRAINT IF EXISTS tunnel_domains_verification_attempts_check,
  DROP CONSTRAINT IF EXISTS tunnel_domains_dns_ttl_check,
  DROP CONSTRAINT IF EXISTS tunnel_domains_expected_records_check,
  DROP CONSTRAINT IF EXISTS tunnel_domains_dns_provider_check,
  DROP COLUMN IF EXISTS quarantine_until,
  DROP COLUMN IF EXISTS verification_attempts,
  DROP COLUMN IF EXISTS dns_ttl_seconds,
  DROP COLUMN IF EXISTS dns_next_check_at,
  DROP COLUMN IF EXISTS dns_last_checked_at,
  DROP COLUMN IF EXISTS expected_records,
  DROP COLUMN IF EXISTS dns_provider;
