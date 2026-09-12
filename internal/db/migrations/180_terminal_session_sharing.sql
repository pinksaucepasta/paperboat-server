-- +goose Up
ALTER TABLE project_terminal_sessions ADD COLUMN owner_account text REFERENCES users(id);
UPDATE project_terminal_sessions s SET owner_account=p.user_id FROM projects p WHERE p.id=s.project_id;
ALTER TABLE project_terminal_sessions ALTER COLUMN owner_account SET NOT NULL;

ALTER TABLE team_resource_bindings DROP CONSTRAINT team_resource_bindings_resource_kind_check;
ALTER TABLE team_resource_bindings ADD CONSTRAINT team_resource_bindings_resource_kind_check
 CHECK(resource_kind IN ('env','preview','tunnel','lazy_policy','machine','terminal_session'));

CREATE TABLE team_terminal_session_grants (
 team_id text NOT NULL,
 resource_kind text NOT NULL DEFAULT 'terminal_session' CHECK(resource_kind='terminal_session'),
 terminal_session_id text NOT NULL,
 audience text NOT NULL CHECK(audience IN ('all_members','selected_member')),
 account_id text,
 role text NOT NULL CHECK(role IN ('viewer','interactive')),
 generation bigint NOT NULL DEFAULT 1 CHECK(generation BETWEEN 1 AND 9007199254740991),
 active boolean NOT NULL DEFAULT true,
 CHECK((audience='all_members' AND account_id IS NULL) OR (audience='selected_member' AND account_id IS NOT NULL)),
 FOREIGN KEY(team_id,resource_kind,terminal_session_id) REFERENCES team_resource_bindings(team_id,resource_kind,resource_id) ON DELETE CASCADE,
 FOREIGN KEY(team_id,account_id) REFERENCES team_members(team_id,account_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX team_terminal_session_grants_all ON team_terminal_session_grants(team_id,terminal_session_id) WHERE audience='all_members';
CREATE UNIQUE INDEX team_terminal_session_grants_selected ON team_terminal_session_grants(team_id,terminal_session_id,account_id) WHERE audience='selected_member';

ALTER TABLE user_machine_access_sessions
 ADD COLUMN terminal_session_id text,
 ADD COLUMN terminal_role text CHECK(terminal_role IN ('owner','viewer','interactive')),
 ADD COLUMN terminal_grant_generation bigint,
 ADD COLUMN terminal_binding_generation bigint,
 ADD COLUMN terminal_membership_generation bigint,
 ADD COLUMN terminal_team_generation bigint;
UPDATE user_machine_access_sessions SET terminal_session_id=operation_id,terminal_role='owner'
 WHERE 'terminal'=ANY(capabilities);

-- A selected row, including an inactive exclusion, takes precedence over the
-- all-member row. Regrant increments its generation and never revives old JTIs.
-- +goose StatementBegin
CREATE FUNCTION terminal_session_role(actor text, session text) RETURNS text
LANGUAGE sql STABLE SET search_path=paperboat,pg_catalog AS $$
 SELECT CASE
  WHEN EXISTS(SELECT 1 FROM user_machine_terminal_sessions s WHERE s.id=session AND s.owner_account=actor AND s.deleted_at IS NULL)
    OR EXISTS(SELECT 1 FROM project_terminal_sessions s WHERE s.id=session AND s.owner_account=actor AND s.deleted_at IS NULL) THEN 'owner'
  ELSE (SELECT CASE WHEN selected.account_id IS NOT NULL THEN CASE WHEN selected.active THEN selected.role END ELSE all_grant.role END
   FROM team_resource_bindings b
   JOIN teams t USING(team_id)
   JOIN team_members m ON m.team_id=b.team_id AND m.account_id=actor AND m.active
   LEFT JOIN team_terminal_session_grants selected ON selected.team_id=b.team_id AND selected.terminal_session_id=b.resource_id AND selected.audience='selected_member' AND selected.account_id=actor
   LEFT JOIN team_terminal_session_grants all_grant ON all_grant.team_id=b.team_id AND all_grant.terminal_session_id=b.resource_id AND all_grant.audience='all_members' AND all_grant.active
   WHERE b.resource_kind='terminal_session' AND b.resource_id=session AND b.active AND t.deleted_at IS NULL
    AND (selected.account_id IS NOT NULL OR all_grant.team_id IS NOT NULL)
   ORDER BY CASE WHEN selected.account_id IS NOT NULL THEN 0 ELSE 1 END LIMIT 1)
 END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION revoke_invalid_terminal_session_access() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE affected_team text; affected_session text; affected_account text; fence_all boolean := false; all_audience boolean := false;
BEGIN
 IF TG_TABLE_NAME='team_terminal_session_grants' THEN
  affected_team:=COALESCE(NEW.team_id,OLD.team_id); affected_session:=COALESCE(NEW.terminal_session_id,OLD.terminal_session_id);
  affected_account:=COALESCE(NEW.account_id,OLD.account_id); all_audience:=affected_account IS NULL;
 ELSIF TG_TABLE_NAME='team_resource_bindings' THEN affected_team:=COALESCE(NEW.team_id,OLD.team_id); affected_session:=COALESCE(NEW.resource_id,OLD.resource_id); fence_all:=true;
 ELSIF TG_TABLE_NAME='team_members' THEN affected_team:=COALESCE(NEW.team_id,OLD.team_id); affected_account:=COALESCE(NEW.account_id,OLD.account_id);
 ELSE affected_team:=COALESCE(NEW.team_id,OLD.team_id); fence_all:=true; END IF;
 UPDATE user_machine_access_sessions a SET state='revoked',revoked_at=now(),updated_at=now(),revocation_reason='terminal_session_permission_revoked'
 WHERE a.state='active' AND a.terminal_role IN ('viewer','interactive')
  AND (affected_team IS NULL OR a.team_id=affected_team) AND (affected_session IS NULL OR a.terminal_session_id=affected_session)
  AND (fence_all OR affected_account IS NULL OR a.user_id=affected_account)
  AND (TG_TABLE_NAME<>'team_terminal_session_grants' AND terminal_session_role(a.user_id,a.terminal_session_id) IS DISTINCT FROM a.terminal_role
   OR TG_TABLE_NAME='team_terminal_session_grants' AND (NOT all_audience OR NOT EXISTS(SELECT 1 FROM team_terminal_session_grants selected WHERE selected.team_id=a.team_id AND selected.terminal_session_id=a.terminal_session_id AND selected.audience='selected_member' AND selected.account_id=a.user_id)));
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER terminal_access_membership AFTER UPDATE OR DELETE ON team_members FOR EACH ROW EXECUTE FUNCTION revoke_invalid_terminal_session_access();
CREATE TRIGGER terminal_access_team AFTER UPDATE OR DELETE ON teams FOR EACH ROW EXECUTE FUNCTION revoke_invalid_terminal_session_access();
CREATE TRIGGER terminal_access_binding AFTER UPDATE OR DELETE ON team_resource_bindings FOR EACH ROW WHEN (OLD.resource_kind='terminal_session') EXECUTE FUNCTION revoke_invalid_terminal_session_access();
CREATE TRIGGER terminal_access_grant AFTER INSERT OR UPDATE OR DELETE ON team_terminal_session_grants FOR EACH ROW EXECUTE FUNCTION revoke_invalid_terminal_session_access();

-- +goose StatementBegin
CREATE FUNCTION revoke_unavailable_shared_terminal_target() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state<>'online' OR NOT NEW.online OR NEW.revoked_at IS NOT NULL OR NEW.deleted_at IS NOT NULL OR NOT NEW.configured_capabilities @> ARRAY['terminal_host'] OR NOT NEW.observed_capabilities @> ARRAY['terminal_host'] THEN
  UPDATE user_machine_access_sessions SET state='revoked',revoked_at=now(),updated_at=now(),revocation_reason='terminal_host_unavailable'
   WHERE user_machine_id=NEW.id AND state='active' AND terminal_role IN ('viewer','interactive');
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER terminal_access_target AFTER UPDATE OF state,online,revoked_at,deleted_at,configured_capabilities,observed_capabilities ON user_machines FOR EACH ROW EXECUTE FUNCTION revoke_unavailable_shared_terminal_target();

-- Session exit/close/delete ends sharing and lets the binding trigger fence
-- active attachments. Owner disconnect alone does not change session state.
-- +goose StatementBegin
CREATE FUNCTION end_terminal_sharing_with_session() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE session text;
BEGIN
 IF TG_OP='DELETE' THEN session:=OLD.id; ELSE session:=NEW.id; END IF;
 IF TG_OP='DELETE' THEN
  UPDATE team_resource_bindings SET active=false,generation=generation+1 WHERE resource_kind='terminal_session' AND resource_id=session AND active;
 ELSIF NEW.deleted_at IS NOT NULL OR NEW.desired_state IN ('closed','deleted') OR NEW.runtime_state IN ('closed','exited','deleted') THEN
  UPDATE team_resource_bindings SET active=false,generation=generation+1 WHERE resource_kind='terminal_session' AND resource_id=session AND active;
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER terminal_sharing_machine_session AFTER UPDATE OR DELETE ON user_machine_terminal_sessions FOR EACH ROW EXECUTE FUNCTION end_terminal_sharing_with_session();
CREATE TRIGGER terminal_sharing_project_session AFTER UPDATE OR DELETE ON project_terminal_sessions FOR EACH ROW EXECUTE FUNCTION end_terminal_sharing_with_session();

-- +goose Down
DROP TRIGGER terminal_access_target ON user_machines;
DROP FUNCTION revoke_unavailable_shared_terminal_target();
DROP TRIGGER terminal_sharing_project_session ON project_terminal_sessions;
DROP TRIGGER terminal_sharing_machine_session ON user_machine_terminal_sessions;
DROP FUNCTION end_terminal_sharing_with_session();
DROP TRIGGER terminal_access_grant ON team_terminal_session_grants;
DROP TRIGGER terminal_access_binding ON team_resource_bindings;
DROP TRIGGER terminal_access_team ON teams;
DROP TRIGGER terminal_access_membership ON team_members;
DROP FUNCTION revoke_invalid_terminal_session_access();
DROP FUNCTION terminal_session_role(text,text);
ALTER TABLE user_machine_access_sessions DROP COLUMN terminal_team_generation,DROP COLUMN terminal_membership_generation,DROP COLUMN terminal_binding_generation,DROP COLUMN terminal_grant_generation,DROP COLUMN terminal_role,DROP COLUMN terminal_session_id;
DROP TABLE team_terminal_session_grants;
DELETE FROM team_resource_bindings WHERE resource_kind='terminal_session';
ALTER TABLE team_resource_bindings DROP CONSTRAINT team_resource_bindings_resource_kind_check;
ALTER TABLE team_resource_bindings ADD CONSTRAINT team_resource_bindings_resource_kind_check CHECK(resource_kind IN ('env','preview','tunnel','lazy_policy','machine'));
ALTER TABLE project_terminal_sessions DROP COLUMN owner_account;
