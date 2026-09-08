-- +goose Up
CREATE TABLE lazy_environment_identities (
  environment_id text PRIMARY KEY,
  environment_label text NOT NULL UNIQUE
    CHECK (environment_label ~ '^[a-z0-9]{16}$'),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE lazy_access_policies (
  id text PRIMARY KEY,
  hostname text NOT NULL UNIQUE
    CHECK (hostname = lower(hostname) AND hostname !~ '[:/\\\\[:cntrl:]]'),
  account_id text NOT NULL REFERENCES users(id),
  environment_id text NOT NULL,
  machine_id text NOT NULL REFERENCES user_machines(id),
  installation_generation bigint NOT NULL CHECK (installation_generation > 0),
  generation bigint NOT NULL CHECK (generation > 0),
  target_scheme text NOT NULL CHECK (target_scheme IN ('http','https','h2c')),
  target_address text NOT NULL CHECK (octet_length(target_address) BETWEEN 1 AND 512),
  access_mode text NOT NULL CHECK (access_mode IN ('private','team')),
  ownership_mode text NOT NULL CHECK (ownership_mode = 'persistent_port'),
  expires_at timestamptz NOT NULL,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, account_id)
);
CREATE UNIQUE INDEX lazy_access_policies_active_target
  ON lazy_access_policies(environment_id, target_scheme, target_address)
  WHERE deleted_at IS NULL;
CREATE INDEX lazy_access_policies_environment_active
  ON lazy_access_policies(environment_id, id) WHERE deleted_at IS NULL;

-- +goose Down
DROP TABLE lazy_access_policies;
DROP TABLE lazy_environment_identities;
