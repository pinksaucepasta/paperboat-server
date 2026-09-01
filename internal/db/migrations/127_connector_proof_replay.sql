-- +goose Up
-- Connector proofs are security metadata, not user-visible operations. Keep
-- their replay ledger separate from operations so retention and audit queries
-- cannot be polluted by authentication retries.
CREATE TABLE connector_proof_replays (
  account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tunnel_id text NOT NULL,
  connector_id text NOT NULL,
  credential_generation bigint NOT NULL,
  proof_kind text NOT NULL,
  nonce text NOT NULL,
  proof_digest bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, tunnel_id, connector_id, proof_kind, nonce),
  UNIQUE (account_id, tunnel_id, connector_id, proof_digest),
  FOREIGN KEY (tunnel_id, account_id)
    REFERENCES tunnels(id, account_id) ON DELETE CASCADE,
  FOREIGN KEY (connector_id, tunnel_id)
    REFERENCES tunnel_connectors(id, tunnel_id) ON DELETE CASCADE,
  CHECK (credential_generation > 0),
  CHECK (proof_kind IN ('auth', 'renew')),
  CHECK (length(trim(nonce)) BETWEEN 16 AND 128),
  CHECK (octet_length(proof_digest) = 32),
  CHECK (expires_at > created_at)
);

-- Expired rows are removed in bounded batches by the SQL adapter. Include the
-- scope columns in the index so cleanup does not scan unrelated connectors.
CREATE INDEX connector_proof_replays_expiry
  ON connector_proof_replays(expires_at, account_id, tunnel_id, connector_id);

-- +goose Down
-- Never discard a live replay ledger during rollback. A forward migration can
-- expire/delete rows deliberately before this guarded rollback is attempted.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM connector_proof_replays) THEN
    RAISE EXCEPTION 'cannot roll back connector proof replay ledger with retained rows';
  END IF;
END
$$;
DROP TABLE connector_proof_replays;
