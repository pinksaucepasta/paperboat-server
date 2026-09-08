-- +goose Up
CREATE TABLE teams (
 team_id text PRIMARY KEY, owner_account text NOT NULL REFERENCES users(id),
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 deleted_at timestamptz
);
CREATE TABLE team_members (
 team_id text NOT NULL REFERENCES teams(team_id) ON DELETE CASCADE,
 account_id text NOT NULL REFERENCES users(id),
 membership_generation bigint NOT NULL CHECK(membership_generation BETWEEN 1 AND 9007199254740991),
 role text NOT NULL CHECK(role IN ('admin','member')), active boolean NOT NULL,
 PRIMARY KEY(team_id,account_id)
);
INSERT INTO teams SELECT team_id,owner_account,generation,NULL FROM environment_vault_teams;
INSERT INTO team_members SELECT team_id,account_id,membership_generation,'member',active FROM environment_vault_team_members;
CREATE TABLE team_resource_bindings (
 team_id text NOT NULL REFERENCES teams(team_id) ON DELETE CASCADE,
 resource_kind text NOT NULL CHECK(resource_kind IN ('env','preview','tunnel')),
 resource_id text NOT NULL, owner_account text NOT NULL REFERENCES users(id),
 active boolean NOT NULL DEFAULT true, generation bigint NOT NULL DEFAULT 1 CHECK(generation BETWEEN 1 AND 9007199254740991),
 PRIMARY KEY(team_id,resource_kind,resource_id)
);
CREATE TABLE team_resource_grants (
 team_id text NOT NULL, account_id text NOT NULL, resource_kind text NOT NULL, resource_id text NOT NULL,
 permission text NOT NULL, generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991), active boolean NOT NULL,
 PRIMARY KEY(team_id,account_id,resource_kind,resource_id),
 FOREIGN KEY(team_id,account_id) REFERENCES team_members(team_id,account_id) ON DELETE CASCADE,
 FOREIGN KEY(team_id,resource_kind,resource_id) REFERENCES team_resource_bindings(team_id,resource_kind,resource_id) ON DELETE CASCADE,
 CHECK((resource_kind='env' AND permission IN ('read','write')) OR (resource_kind IN ('preview','tunnel') AND permission IN ('use','manage')))
);
INSERT INTO team_resource_bindings SELECT team_id,'env',team_id,owner_account,true,1 FROM teams;
INSERT INTO team_resource_grants SELECT m.team_id,m.account_id,'env',m.team_id,'write',1,true FROM environment_vault_team_members m JOIN environment_vault_teams t USING(team_id) WHERE m.active AND m.grant_epoch=t.key_epoch;
ALTER TABLE environment_vault_teams ADD FOREIGN KEY(team_id) REFERENCES teams(team_id) ON DELETE CASCADE;
ALTER TABLE environment_vault_teams DROP COLUMN owner_account, DROP COLUMN generation;
ALTER TABLE environment_vault_team_members ADD FOREIGN KEY(team_id,account_id) REFERENCES team_members(team_id,account_id) ON DELETE CASCADE;
ALTER TABLE environment_vault_team_members DROP COLUMN role, DROP COLUMN active, DROP COLUMN membership_generation;
CREATE TABLE team_invitations (
 invitation_id text PRIMARY KEY, team_id text NOT NULL REFERENCES teams(team_id) ON DELETE CASCADE,
 recipient_account text NOT NULL REFERENCES users(id), created_by text NOT NULL REFERENCES users(id),
 expires_at timestamptz NOT NULL, accepted_at timestamptz, cancelled_at timestamptz,
 CHECK(accepted_at IS NULL OR cancelled_at IS NULL)
);
CREATE UNIQUE INDEX team_pending_invitation ON team_invitations(team_id,recipient_account) WHERE accepted_at IS NULL AND cancelled_at IS NULL;
CREATE TABLE team_operations (
 account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, operation_id text NOT NULL,
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 result bytea NOT NULL CHECK(octet_length(result) BETWEEN 1 AND 1024),
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(account_id,operation_id)
);
CREATE INDEX team_operations_recent ON team_operations(account_id,created_at DESC,operation_id DESC);
CREATE INDEX team_invitation_history ON team_invitations(team_id,(COALESCE(accepted_at,cancelled_at)) DESC,invitation_id DESC) WHERE accepted_at IS NOT NULL OR cancelled_at IS NOT NULL;
-- +goose Down
ALTER TABLE environment_vault_teams ADD COLUMN owner_account text REFERENCES users(id), ADD COLUMN generation bigint;
UPDATE environment_vault_teams v SET owner_account=t.owner_account,generation=t.generation FROM teams t WHERE t.team_id=v.team_id;
ALTER TABLE environment_vault_teams ALTER COLUMN owner_account SET NOT NULL, ALTER COLUMN generation SET NOT NULL;
ALTER TABLE environment_vault_team_members ADD COLUMN role text, ADD COLUMN active boolean, ADD COLUMN membership_generation bigint;
UPDATE environment_vault_team_members v SET role=CASE WHEN t.owner_account=v.account_id THEN 'owner' ELSE 'member' END,active=m.active,membership_generation=m.membership_generation FROM team_members m JOIN teams t USING(team_id) WHERE m.team_id=v.team_id AND m.account_id=v.account_id;
ALTER TABLE environment_vault_team_members ALTER COLUMN role SET NOT NULL, ALTER COLUMN active SET NOT NULL, ALTER COLUMN membership_generation SET NOT NULL;
ALTER TABLE environment_vault_team_members DROP CONSTRAINT environment_vault_team_members_team_id_account_id_fkey;
ALTER TABLE environment_vault_teams DROP CONSTRAINT environment_vault_teams_team_id_fkey;
DROP TABLE team_operations,team_invitations,team_resource_grants,team_resource_bindings,team_members,teams;
