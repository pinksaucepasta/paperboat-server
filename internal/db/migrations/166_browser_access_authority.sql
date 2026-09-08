-- +goose Up
ALTER TABLE tunnels DROP CONSTRAINT tunnels_access_mode_check;
ALTER TABLE tunnels ADD CONSTRAINT tunnels_access_mode_check CHECK (access_mode IN ('public','private','team'));
ALTER TABLE preview_leases DROP CONSTRAINT preview_leases_access_mode_check;
ALTER TABLE preview_leases ADD CONSTRAINT preview_leases_access_mode_check CHECK (access_mode IN ('public','private','team'));
ALTER TABLE tunnel_edge_route_assignments DROP CONSTRAINT tunnel_edge_route_assignments_access_mode_check;
ALTER TABLE tunnel_edge_route_assignments ADD CONSTRAINT tunnel_edge_route_assignments_access_mode_check CHECK (access_mode IN ('public','private','team'));
ALTER TABLE preview_carrier_attachment_outbox DROP CONSTRAINT preview_carrier_attachment_outbox_access_mode_check;
ALTER TABLE preview_carrier_attachment_outbox ADD CONSTRAINT preview_carrier_attachment_outbox_access_mode_check CHECK (access_mode IN ('public','private','team'));

CREATE TABLE browser_access_transactions (
 transaction_id text PRIMARY KEY,
 state_hash bytea NOT NULL CHECK(octet_length(state_hash)=32),
 hostname text NOT NULL CHECK(hostname=lower(hostname) AND hostname !~ '[:/\\\\[:cntrl:]]'),
 return_path text NOT NULL CHECK(octet_length(return_path) BETWEEN 1 AND 2048),
 account_id text REFERENCES users(id) ON DELETE CASCADE,
 resource_kind text CHECK(resource_kind IN ('preview','tunnel')),
 resource_id text,
 resource_generation bigint CHECK(resource_generation > 0),
 preview_owner_session_id text,
 owner_account_id text REFERENCES users(id),
 access_mode text CHECK(access_mode IN ('private','team')),
 team_id text REFERENCES teams(team_id),
 team_generation bigint CHECK(team_generation > 0),
 membership_generation bigint CHECK(membership_generation > 0),
 binding_generation bigint CHECK(binding_generation > 0),
 grant_generation bigint CHECK(grant_generation > 0),
 trusted_session_id text REFERENCES sessions(id) ON DELETE CASCADE,
 trusted_session_version bigint CHECK(trusted_session_version>0),
 trusted_session_expires_at timestamptz,
 handoff_hash bytea UNIQUE CHECK(handoff_hash IS NULL OR octet_length(handoff_hash)=32),
 handoff_expires_at timestamptz,
 issued_at timestamptz,
 redeemed_at timestamptz,
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 CHECK((issued_at IS NULL) = (account_id IS NULL)),
 CHECK(issued_at IS NULL OR (resource_id IS NOT NULL AND handoff_hash IS NOT NULL AND handoff_expires_at>issued_at))
);
CREATE INDEX browser_access_transactions_expiry ON browser_access_transactions(expires_at,transaction_id);

CREATE TABLE browser_access_sessions (
 grant_id text PRIMARY KEY,
 token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
 account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 hostname text NOT NULL,
 resource_kind text NOT NULL CHECK(resource_kind IN ('preview','tunnel')),
 resource_id text NOT NULL,
 resource_generation bigint NOT NULL CHECK(resource_generation>0),
 preview_owner_session_id text,
 owner_account_id text NOT NULL REFERENCES users(id),
 access_mode text NOT NULL CHECK(access_mode IN ('private','team')),
 team_id text REFERENCES teams(team_id),
 team_generation bigint CHECK(team_generation>0), membership_generation bigint CHECK(membership_generation>0),
 binding_generation bigint CHECK(binding_generation>0), grant_generation bigint CHECK(grant_generation>0),
 trusted_session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 trusted_session_version bigint NOT NULL CHECK(trusted_session_version>0),
 trusted_session_expires_at timestamptz NOT NULL,
 issued_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL,
 absolute_expires_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 CHECK(expires_at<=absolute_expires_at AND expires_at<=trusted_session_expires_at),
 CHECK((access_mode='private' AND team_id IS NULL AND team_generation IS NULL AND membership_generation IS NULL AND binding_generation IS NULL AND grant_generation IS NULL)
    OR (access_mode='team' AND team_id IS NOT NULL AND team_generation IS NOT NULL AND membership_generation IS NOT NULL AND binding_generation IS NOT NULL AND grant_generation IS NOT NULL))
);
CREATE INDEX browser_access_sessions_expiry ON browser_access_sessions(expires_at,grant_id) WHERE revoked_at IS NULL;
CREATE INDEX browser_access_sessions_resource ON browser_access_sessions(resource_kind,resource_id,hostname) WHERE revoked_at IS NULL;

CREATE TABLE browser_machine_credentials (
 credential_id text PRIMARY KEY, token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
 account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, hostname text NOT NULL,
 resource_kind text NOT NULL CHECK(resource_kind IN ('preview','tunnel')), resource_id text NOT NULL,
 route_id text NOT NULL, action text NOT NULL CHECK(action='use'), resource_generation bigint NOT NULL CHECK(resource_generation>0),
 preview_owner_session_id text, owner_account_id text NOT NULL REFERENCES users(id), access_mode text NOT NULL CHECK(access_mode IN ('private','team')),
 team_id text REFERENCES teams(team_id), team_generation bigint, membership_generation bigint, binding_generation bigint, grant_generation bigint,
 issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'), revoked_at timestamptz,
 CHECK((access_mode='private' AND team_id IS NULL) OR (access_mode='team' AND team_id IS NOT NULL AND team_generation>0 AND membership_generation>0 AND binding_generation>0 AND grant_generation>0))
);
CREATE INDEX browser_machine_credentials_expiry ON browser_machine_credentials(expires_at,credential_id) WHERE revoked_at IS NULL;

-- +goose Down
DROP TABLE browser_machine_credentials;
DROP TABLE browser_access_sessions;
DROP TABLE browser_access_transactions;
ALTER TABLE preview_carrier_attachment_outbox DROP CONSTRAINT preview_carrier_attachment_outbox_access_mode_check;
ALTER TABLE preview_carrier_attachment_outbox ADD CONSTRAINT preview_carrier_attachment_outbox_access_mode_check CHECK (access_mode IN ('public','private'));
ALTER TABLE tunnel_edge_route_assignments DROP CONSTRAINT tunnel_edge_route_assignments_access_mode_check;
ALTER TABLE tunnel_edge_route_assignments ADD CONSTRAINT tunnel_edge_route_assignments_access_mode_check CHECK (access_mode IN ('public','private'));
ALTER TABLE preview_leases DROP CONSTRAINT preview_leases_access_mode_check;
ALTER TABLE preview_leases ADD CONSTRAINT preview_leases_access_mode_check CHECK (access_mode IN ('public','private'));
ALTER TABLE tunnels DROP CONSTRAINT tunnels_access_mode_check;
ALTER TABLE tunnels ADD CONSTRAINT tunnels_access_mode_check CHECK (access_mode IN ('public','private'));
