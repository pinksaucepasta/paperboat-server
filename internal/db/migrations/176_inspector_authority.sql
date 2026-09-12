-- +goose Up
-- Inspector authority reuses team membership/binding/grant generations with
-- exact-match inspect/replay permissions. One grant row per action so each
-- action revokes independently; use/manage/view/login/membership imply neither
-- inspector action.
ALTER TABLE team_resource_grants DROP CONSTRAINT team_resource_grants_pkey;
ALTER TABLE team_resource_grants ADD PRIMARY KEY(team_id,account_id,resource_kind,resource_id,permission);
ALTER TABLE team_resource_grants DROP CONSTRAINT team_resource_grants_check;
ALTER TABLE team_resource_grants ADD CHECK((resource_kind='env' AND permission IN ('read','write')) OR (resource_kind IN ('preview','tunnel') AND permission IN ('use','manage','inspect','replay')));
-- Short-lived opaque inspector credentials, mirroring browser machine
-- credentials without the browser hostname dimension. The daemon presents the
-- token with its machine identity; the server re-resolves current authority on
-- every authorization, so revocation and generation changes fail closed on the
-- next operation. team_id NULL marks the owner path.
CREATE TABLE inspector_credentials (
 credential_id text PRIMARY KEY, token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
 account_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 resource_kind text NOT NULL CHECK(resource_kind IN ('preview','tunnel')), resource_id text NOT NULL,
 route_id text NOT NULL, action text NOT NULL CHECK(action IN ('inspect','replay')),
 resource_generation bigint NOT NULL CHECK(resource_generation>0),
 route_generation bigint NOT NULL CHECK(route_generation>0),
 target_generation bigint NOT NULL CHECK(target_generation>0),
 owner_account_id text NOT NULL REFERENCES users(id),
 team_id text REFERENCES teams(team_id) ON DELETE CASCADE,
 team_generation bigint, membership_generation bigint, binding_generation bigint, grant_generation bigint,
 issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'), revoked_at timestamptz,
 CHECK((team_id IS NULL) OR (team_id IS NOT NULL AND team_generation>0 AND membership_generation>0 AND binding_generation>0 AND grant_generation>0))
);
CREATE INDEX inspector_credentials_expiry ON inspector_credentials(expires_at,credential_id) WHERE revoked_at IS NULL;
CREATE INDEX inspector_credentials_account ON inspector_credentials(account_id,expires_at) WHERE revoked_at IS NULL;
-- +goose Down
DROP TABLE inspector_credentials;
DELETE FROM team_resource_grants WHERE permission IN ('inspect','replay');
ALTER TABLE team_resource_grants DROP CONSTRAINT team_resource_grants_pkey;
ALTER TABLE team_resource_grants ADD PRIMARY KEY(team_id,account_id,resource_kind,resource_id);
ALTER TABLE team_resource_grants DROP CONSTRAINT team_resource_grants_check;
ALTER TABLE team_resource_grants ADD CHECK((resource_kind='env' AND permission IN ('read','write')) OR (resource_kind IN ('preview','tunnel') AND permission IN ('use','manage')));
