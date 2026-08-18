-- +goose Up
CREATE TABLE release_authority_bundles (
  id text PRIMARY KEY,
  release_id text NOT NULL,
  version text NOT NULL,
  platform text NOT NULL,
  architecture text NOT NULL,
  action text NOT NULL,
  policy_revision bigint NOT NULL CHECK (policy_revision > 0),
  payload jsonb NOT NULL,
  payload_hash bytea NOT NULL UNIQUE,
  signatures jsonb NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  authority_request_id text NOT NULL,
  imported_by_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  imported_at timestamptz NOT NULL DEFAULT now(),
  CHECK (action IN ('promote','pause','quarantine','revoke')),
  CHECK (platform IN ('darwin','linux','windows')),
  CHECK (architecture IN ('amd64','arm64')),
  CHECK (expires_at > issued_at),
  UNIQUE (release_id, platform, architecture, policy_revision)
);
CREATE INDEX release_authority_bundles_latest ON release_authority_bundles(release_id, platform, architecture, policy_revision DESC);

CREATE TABLE release_authority_requests (
  id text PRIMARY KEY,
  action text NOT NULL,
  release_id text NOT NULL,
  version text NOT NULL,
  platform text NOT NULL,
  architecture text NOT NULL,
  policy_revision bigint NOT NULL CHECK (policy_revision > 0),
  rollout_percentage integer NOT NULL CHECK (rollout_percentage BETWEEN 0 AND 100),
  status text NOT NULL DEFAULT 'pending',
  requested_by_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  idempotency_key text NOT NULL,
  request_hash bytea NOT NULL,
  fulfilled_bundle_id text UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  fulfilled_at timestamptz,
  CHECK (action IN ('promote','pause','quarantine','revoke')),
  CHECK (status IN ('pending','fulfilled','cancelled')),
  UNIQUE (requested_by_user_id, idempotency_key)
);
ALTER TABLE release_authority_bundles ADD CONSTRAINT release_authority_bundles_request_fk FOREIGN KEY (authority_request_id) REFERENCES release_authority_requests(id) ON DELETE RESTRICT;

CREATE TABLE release_authority_import_operations (
  actor_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  idempotency_key text NOT NULL,
  request_hash bytea NOT NULL,
  bundle_id text NOT NULL REFERENCES release_authority_bundles(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (actor_user_id, idempotency_key),
  CHECK (length(trim(idempotency_key)) BETWEEN 8 AND 128)
);

-- +goose Down
DROP TABLE IF EXISTS release_authority_import_operations;
DROP TABLE IF EXISTS release_authority_bundles;
DROP TABLE IF EXISTS release_authority_requests;
