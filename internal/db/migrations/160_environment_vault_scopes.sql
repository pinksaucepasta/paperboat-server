-- +goose Up
CREATE TABLE environment_vault_personal_epochs (account_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, key_epoch bigint NOT NULL CHECK(key_epoch BETWEEN 1 AND 9007199254740991));
CREATE TABLE environment_vault_scopes (
 owner_kind text NOT NULL CHECK(owner_kind IN ('personal','team')),
 owner_id text NOT NULL, machine_id text NOT NULL DEFAULT '',
 key_epoch bigint NOT NULL CHECK(key_epoch BETWEEN 1 AND 9007199254740991),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 document_id text NOT NULL CHECK(document_id ~ '^sha256:[0-9a-f]{64}$'),
 envelope bytea NOT NULL CHECK(octet_length(envelope) BETWEEN 1 AND 264192),
 writer_public bytea NOT NULL CHECK(octet_length(writer_public)=32),
 PRIMARY KEY(owner_kind,owner_id,machine_id),
 CHECK(owner_kind='personal' OR machine_id='')
);
CREATE TABLE environment_vault_teams (
 team_id text PRIMARY KEY, owner_account text NOT NULL REFERENCES users(id),
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 key_epoch bigint NOT NULL CHECK(key_epoch BETWEEN 1 AND 9007199254740991)
);
CREATE TABLE environment_vault_team_members (
 team_id text NOT NULL REFERENCES environment_vault_teams(team_id) ON DELETE CASCADE,
 account_id text NOT NULL REFERENCES users(id),
 membership_generation bigint NOT NULL CHECK(membership_generation BETWEEN 1 AND 9007199254740991),
 role text NOT NULL CHECK(role IN ('owner','member')), active boolean NOT NULL,
 grant_epoch bigint NOT NULL CHECK(grant_epoch BETWEEN 0 AND 9007199254740991),
 PRIMARY KEY(team_id,account_id)
);
CREATE TABLE environment_vault_team_grants (
 team_id text NOT NULL, account_id text NOT NULL,
 membership_generation bigint NOT NULL, team_epoch bigint NOT NULL,
 recipient_vault_generation bigint NOT NULL, recipient_sharing_public bytea NOT NULL CHECK(octet_length(recipient_sharing_public)=32),
 document_id text NOT NULL CHECK(document_id ~ '^sha256:[0-9a-f]{64}$'),
 envelope bytea NOT NULL CHECK(octet_length(envelope) BETWEEN 1 AND 4096),
 sender_writer_public bytea NOT NULL CHECK(octet_length(sender_writer_public)=32),
 acknowledged boolean NOT NULL DEFAULT false,
 PRIMARY KEY(team_id,account_id),
 FOREIGN KEY(team_id,account_id) REFERENCES environment_vault_team_members(team_id,account_id) ON DELETE CASCADE
);
CREATE TABLE environment_vault_operations (
 account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 operation_id text NOT NULL, request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 result bytea NOT NULL CHECK(octet_length(result) BETWEEN 1 AND 2097152),
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(account_id,operation_id)
);
CREATE TABLE environment_vault_projection_fences (
 machine_id text PRIMARY KEY REFERENCES user_machines(id) ON DELETE CASCADE,
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991)
);
CREATE TABLE environment_vault_projection_sources (
 machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
 owner_kind text NOT NULL CHECK(owner_kind IN ('personal','team')), owner_id text NOT NULL,
 source_machine_id text NOT NULL DEFAULT '',
 PRIMARY KEY(machine_id,owner_kind,owner_id,source_machine_id)
);
CREATE INDEX environment_vault_projection_source_idx ON environment_vault_projection_sources(owner_kind,owner_id,source_machine_id);
-- +goose Down
DROP TABLE environment_vault_projection_sources;
DROP TABLE environment_vault_projection_fences;
DROP TABLE environment_vault_operations;
DROP TABLE environment_vault_team_grants;
DROP TABLE environment_vault_team_members;
DROP TABLE environment_vault_teams;
DROP TABLE environment_vault_scopes;
DROP TABLE environment_vault_personal_epochs;
