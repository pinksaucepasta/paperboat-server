-- +goose Up
-- user_id remains the enrollment's cryptographic issuer; ownership is independent.
ALTER TABLE user_machines ADD COLUMN owner_team_id text REFERENCES teams(team_id);
CREATE INDEX user_machines_team_owner ON user_machines(owner_team_id) WHERE owner_team_id IS NOT NULL;
ALTER TABLE team_resource_bindings DROP CONSTRAINT team_resource_bindings_resource_kind_check;
ALTER TABLE team_resource_bindings ADD CONSTRAINT team_resource_bindings_resource_kind_check CHECK(resource_kind IN ('env','preview','tunnel','lazy_policy','machine'));
CREATE TABLE team_machine_grants (
 team_id text NOT NULL,
 resource_kind text NOT NULL DEFAULT 'machine' CHECK(resource_kind='machine'),
 machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
 audience text NOT NULL CHECK(audience IN ('all_members','selected_member')),
 account_id text,
 capabilities text[] NOT NULL CHECK(cardinality(capabilities) BETWEEN 1 AND 6 AND capabilities <@ ARRAY['terminal','exec','managed_ssh','files','preview_manage','tunnel_manage']::text[] AND array_position(capabilities,NULL) IS NULL),
 generation bigint NOT NULL DEFAULT 1 CHECK(generation BETWEEN 1 AND 9007199254740991),
 active boolean NOT NULL DEFAULT true,
 CHECK((audience='all_members' AND account_id IS NULL) OR (audience='selected_member' AND account_id IS NOT NULL)),
 FOREIGN KEY(team_id,resource_kind,machine_id) REFERENCES team_resource_bindings(team_id,resource_kind,resource_id) ON DELETE CASCADE,
 FOREIGN KEY(team_id,account_id) REFERENCES team_members(team_id,account_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX team_machine_grants_selected ON team_machine_grants(team_id,machine_id,account_id) WHERE audience='selected_member';
CREATE UNIQUE INDEX team_machine_grants_all ON team_machine_grants(team_id,machine_id) WHERE audience='all_members';

-- This predicate is also used by signed endpoint projections and revocation.
-- Device incoming toggles/readiness remain enforced by the operation's owner.
-- +goose StatementBegin
CREATE FUNCTION team_machine_capability_allowed(actor text, team text, machine text, capability text) RETURNS boolean
LANGUAGE sql STABLE SET search_path=paperboat,pg_catalog AS $$
 SELECT capability=ANY(ARRAY['terminal','exec','managed_ssh','files','preview_manage','tunnel_manage']) AND EXISTS (
  SELECT 1 FROM teams t JOIN team_members member USING(team_id)
  JOIN team_resource_bindings b USING(team_id)
  JOIN user_machines m ON m.id=b.resource_id
  JOIN team_machine_grants g ON g.team_id=b.team_id AND g.machine_id=m.id
  WHERE t.team_id=team AND t.deleted_at IS NULL AND member.account_id=actor AND member.active
   AND b.resource_kind='machine' AND b.active AND m.id=machine AND m.revoked_at IS NULL AND m.deleted_at IS NULL
   AND ((m.owner_team_id IS NULL AND b.owner_account=m.user_id) OR m.owner_team_id=t.team_id)
   AND g.active AND (g.audience='all_members' OR g.account_id=actor) AND capability=ANY(g.capabilities)
 );
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION machine_capability_allowed(actor text, machine text, capability text) RETURNS boolean
LANGUAGE sql STABLE SET search_path=paperboat,pg_catalog AS $$
 SELECT capability=ANY(ARRAY['terminal','exec','managed_ssh','files','preview_manage','tunnel_manage']) AND (
  EXISTS(SELECT 1 FROM user_machines WHERE id=machine AND user_id=actor AND owner_team_id IS NULL AND revoked_at IS NULL AND deleted_at IS NULL)
  OR EXISTS(SELECT 1 FROM team_resource_bindings b WHERE b.resource_kind='machine' AND b.resource_id=machine AND team_machine_capability_allowed(actor,b.team_id,machine,capability))
 );
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION machine_management_allowed(actor text, machine text) RETURNS boolean
LANGUAGE sql STABLE SET search_path=paperboat,pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM user_machines m WHERE m.id=machine AND m.deleted_at IS NULL AND (
  (m.owner_team_id IS NULL AND m.user_id=actor) OR EXISTS(SELECT 1 FROM teams t JOIN team_members member USING(team_id) WHERE t.team_id=m.owner_team_id AND t.deleted_at IS NULL AND member.account_id=actor AND member.active AND (t.owner_account=actor OR member.role='admin'))
 ));
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM user_machines WHERE owner_team_id IS NOT NULL) THEN
  RAISE EXCEPTION 'cannot remove team ownership while team-owned enrollment records exist';
 END IF;
END $$;
-- +goose StatementEnd
DROP FUNCTION machine_management_allowed(text,text);
DROP FUNCTION machine_capability_allowed(text,text,text);
DROP FUNCTION team_machine_capability_allowed(text,text,text,text);
DROP TABLE team_machine_grants;
DELETE FROM team_resource_bindings WHERE resource_kind='machine';
ALTER TABLE team_resource_bindings DROP CONSTRAINT team_resource_bindings_resource_kind_check;
ALTER TABLE team_resource_bindings ADD CONSTRAINT team_resource_bindings_resource_kind_check CHECK(resource_kind IN ('env','preview','tunnel','lazy_policy'));
ALTER TABLE user_machines DROP COLUMN owner_team_id;
