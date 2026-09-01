-- +goose Up

-- Public-domain certificates are server-owned artifacts.  The certificate and
-- private key columns contain envelope ciphertext only; the envelope master
-- key is resolved by the server from a reference and is never persisted here.
CREATE TABLE tunnel_certificate_records (
  id text PRIMARY KEY,
  domain_id text NOT NULL REFERENCES tunnel_domains(id) ON DELETE CASCADE,
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tunnel_id text NOT NULL,
  hostname text NOT NULL,
  domain_generation bigint NOT NULL,
  certificate_generation bigint NOT NULL,
  strategy text NOT NULL,
  state text NOT NULL DEFAULT 'staged',
  certificate_reference text NOT NULL,
  master_key_reference text NOT NULL,
  certificate_ciphertext bytea NOT NULL,
  private_key_ciphertext bytea NOT NULL,
  fingerprint bytea NOT NULL,
  issuer text NOT NULL,
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  renewal_at timestamptz NOT NULL,
  failure_code text,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (length(trim(id)) BETWEEN 3 AND 128),
  CHECK (length(trim(hostname)) BETWEEN 1 AND 253 AND hostname = lower(hostname) AND hostname !~ '[.]$'),
  CHECK (domain_generation > 0 AND certificate_generation > 0),
  CHECK (strategy IN ('delegated_dns01','provided_reference','on_demand_leaf','wildcard_fallback')),
  CHECK (state IN ('staged','active','superseded','revoked','expired','failed')),
  CHECK (length(trim(certificate_reference)) BETWEEN 1 AND 256),
  CHECK (length(trim(master_key_reference)) BETWEEN 1 AND 256 AND master_key_reference !~ E'[\\r\\n]'),
  CHECK (octet_length(certificate_ciphertext) BETWEEN 29 AND 16777216),
  CHECK (octet_length(private_key_ciphertext) BETWEEN 29 AND 16777216),
  CHECK (octet_length(fingerprint) = 32),
  CHECK (length(trim(issuer)) BETWEEN 1 AND 256),
  CHECK (expires_at > not_before AND renewal_at < expires_at),
  CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
  UNIQUE (domain_id, certificate_generation)
);
CREATE UNIQUE INDEX tunnel_certificate_records_active
  ON tunnel_certificate_records(domain_id)
  WHERE state = 'active';
CREATE INDEX tunnel_certificate_records_due
  ON tunnel_certificate_records(renewal_at, id)
  WHERE state = 'active';
CREATE INDEX tunnel_certificate_records_account
  ON tunnel_certificate_records(account_id, domain_id, certificate_generation DESC);

-- The lock is a durable lease rather than an in-process mutex.  It prevents
-- two server replicas from asking an ACME authority for the same replacement.
CREATE TABLE tunnel_certificate_issuance_locks (
  domain_id text PRIMARY KEY REFERENCES tunnel_domains(id) ON DELETE CASCADE,
  owner_id text NOT NULL,
  domain_generation bigint NOT NULL,
  lease_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (length(trim(owner_id)) BETWEEN 3 AND 128),
  CHECK (domain_generation > 0),
  CHECK (lease_until > updated_at)
);
CREATE INDEX tunnel_certificate_issuance_locks_expiry
  ON tunnel_certificate_issuance_locks(lease_until, domain_id);

-- Each edge gets its own readiness fence.  A new certificate must be staged
-- and observed ready on every selected edge before the old active record is
-- retired.
CREATE TABLE tunnel_certificate_edge_distributions (
  certificate_id text NOT NULL REFERENCES tunnel_certificate_records(id) ON DELETE CASCADE,
  edge_node_id text NOT NULL REFERENCES control_tunnel_nodes(id) ON DELETE RESTRICT,
  edge_process_epoch text NOT NULL,
  edge_assignment_generation bigint NOT NULL,
  state text NOT NULL DEFAULT 'staged',
  observed_certificate_generation bigint NOT NULL,
  observed_at timestamptz,
  failure_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (certificate_id, edge_node_id, edge_process_epoch),
  CHECK (length(trim(edge_process_epoch)) BETWEEN 8 AND 128 AND edge_process_epoch ~ '^[A-Za-z0-9_-]+$'),
  CHECK (edge_assignment_generation > 0),
  CHECK (state IN ('staged','ready','active','retired','failed')),
  CHECK (observed_certificate_generation > 0)
);
CREATE INDEX tunnel_certificate_edge_distributions_live
  ON tunnel_certificate_edge_distributions(edge_node_id, state, updated_at DESC);

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM tunnel_certificate_edge_distributions WHERE state IN ('staged','ready','active')
  ) OR EXISTS (
    SELECT 1 FROM tunnel_certificate_records WHERE state IN ('staged','active')
  ) THEN
    RAISE EXCEPTION 'cannot roll back tunnel certificates while live distribution exists';
  END IF;
END
$$;
-- +goose StatementEnd

DROP TABLE IF EXISTS tunnel_certificate_edge_distributions;
DROP TABLE IF EXISTS tunnel_certificate_issuance_locks;
DROP TABLE IF EXISTS tunnel_certificate_records;
