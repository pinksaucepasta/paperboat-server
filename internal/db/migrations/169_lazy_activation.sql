-- +goose Up
CREATE TABLE lazy_runtime_owners (
 machine_id text PRIMARY KEY REFERENCES user_machines(id) ON DELETE CASCADE,
 account_id text NOT NULL REFERENCES users(id),
 installation_generation bigint NOT NULL CHECK(installation_generation>0),
 boot_id text NOT NULL CHECK(length(boot_id) BETWEEN 16 AND 64),
 started_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL
);
CREATE TABLE lazy_activations (
 policy_id text PRIMARY KEY REFERENCES lazy_access_policies(id),
 policy_generation bigint NOT NULL CHECK(policy_generation>0),
 boot_id text NOT NULL,
 activation_id text NOT NULL UNIQUE,
 deadline timestamptz NOT NULL,
 preview_id text REFERENCES preview_leases(id),
 state text NOT NULL CHECK(state IN ('running','ready','failed')),
 error_code text NOT NULL DEFAULT '',
 cooldown_until timestamptz NOT NULL
);
CREATE TABLE lazy_activation_waiters (
 waiter_id text PRIMARY KEY,
 activation_id text NOT NULL REFERENCES lazy_activations(activation_id) ON DELETE CASCADE ON UPDATE CASCADE,
 expires_at timestamptz NOT NULL
);
CREATE INDEX lazy_activation_waiters_expiry ON lazy_activation_waiters(expires_at);
-- Explicit random labels remain permanently unique. Reserved lazy labels release
-- forwarding identity after termination; the policy table retains/tombstones names.
ALTER TABLE preview_leases DROP CONSTRAINT preview_leases_endpoint_key;
CREATE UNIQUE INDEX preview_leases_endpoint_reserved ON preview_leases(endpoint)
 WHERE terminal_state='active' OR endpoint !~ '^https://p[0-9]+-';
-- +goose Down
DROP INDEX preview_leases_endpoint_reserved;
ALTER TABLE preview_leases ADD UNIQUE(endpoint);
DROP TABLE lazy_activation_waiters;
DROP TABLE lazy_activations;
DROP TABLE lazy_runtime_owners;
