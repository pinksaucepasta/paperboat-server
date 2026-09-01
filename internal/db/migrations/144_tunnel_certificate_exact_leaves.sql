-- +goose Up

-- Exact on-demand certificates are children of a verified wildcard binding.
-- They share the encrypted certificate table so the existing distribution and
-- revocation ledger remains authoritative, but they have their own hostname
-- and generation namespace.  Migration 136 deliberately remains immutable.
ALTER TABLE tunnel_domains
  DROP CONSTRAINT IF EXISTS tunnel_domains_certificate_strategy_check;

ALTER TABLE tunnel_domains
  ADD CONSTRAINT tunnel_domains_certificate_strategy_check
    CHECK (certificate_strategy IN ('managed','provided_reference','on_demand_leaf','none'));

ALTER TABLE tunnel_certificate_records
  ADD COLUMN leaf_hostname text;

ALTER TABLE tunnel_certificate_records
  ADD CONSTRAINT tunnel_certificate_records_leaf_hostname_check
    CHECK (
      leaf_hostname IS NULL
      OR (
        strategy = 'on_demand_leaf'
        AND leaf_hostname = hostname
        AND leaf_hostname = lower(leaf_hostname)
        AND leaf_hostname !~ '[*]'
        AND leaf_hostname !~ '[.]$'
      )
    );

ALTER TABLE tunnel_certificate_records
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_domain_id_certificate_generation_key;

CREATE UNIQUE INDEX tunnel_certificate_records_domain_hostname_generation
  ON tunnel_certificate_records(domain_id, hostname, certificate_generation);

DROP INDEX IF EXISTS tunnel_certificate_records_active;
CREATE UNIQUE INDEX tunnel_certificate_records_active_domain_hostname
  ON tunnel_certificate_records(domain_id, hostname)
  WHERE state = 'active';

-- A leaf lookup is a hot path on the first SNI and on renewal.  The parent
-- wildcard remains selected by hostname as well, so sibling leaves cannot
-- accidentally satisfy one another.
CREATE INDEX tunnel_certificate_records_domain_hostname_state
  ON tunnel_certificate_records(domain_id, hostname, state, certificate_generation DESC);

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM tunnel_certificate_records WHERE leaf_hostname IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'cannot remove exact certificate leaves while leaf rows exist';
  END IF;
END
$$;
-- +goose StatementEnd

DROP INDEX IF EXISTS tunnel_certificate_records_domain_hostname_state;
DROP INDEX IF EXISTS tunnel_certificate_records_active_domain_hostname;
DROP INDEX IF EXISTS tunnel_certificate_records_domain_hostname_generation;
ALTER TABLE tunnel_certificate_records
  DROP CONSTRAINT IF EXISTS tunnel_certificate_records_leaf_hostname_check,
  DROP COLUMN IF EXISTS leaf_hostname,
  ADD CONSTRAINT tunnel_certificate_records_domain_id_certificate_generation_key
    UNIQUE (domain_id, certificate_generation);
ALTER TABLE tunnel_domains
  DROP CONSTRAINT IF EXISTS tunnel_domains_certificate_strategy_check,
  ADD CONSTRAINT tunnel_domains_certificate_strategy_check
    CHECK (certificate_strategy IN ('managed','provided_reference','none'));
