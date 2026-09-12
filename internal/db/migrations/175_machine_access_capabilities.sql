-- +goose Up
ALTER TABLE user_machine_access_sessions
 ADD COLUMN team_id text REFERENCES teams(team_id),
 ADD COLUMN capabilities text[] NOT NULL DEFAULT '{}',
 ADD COLUMN operation_id text NOT NULL DEFAULT '';
UPDATE user_machine_access_sessions SET capabilities=
 CASE WHEN helper_terminal_session_id IS NOT NULL THEN ARRAY['terminal','private_access'] ELSE ARRAY[]::text[] END ||
 CASE WHEN helper_file_session_id IS NOT NULL THEN ARRAY['files'] ELSE ARRAY[]::text[] END;
ALTER TABLE user_machine_access_sessions ADD CONSTRAINT machine_access_capabilities_valid
 CHECK(cardinality(capabilities)<=7 AND capabilities <@ ARRAY['terminal','exec','managed_ssh','files','preview_manage','tunnel_manage','private_access']::text[]);

-- Both independently enrolled identities must observe withdrawal.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_access_session() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 UPDATE peer_network_identities n SET
  relay_revocation_generation=CASE WHEN TG_OP='INSERT' THEN relay_revocation_generation ELSE config_generation+1 END,
  config_generation=config_generation+1,updated_at=now()
 WHERE (n.user_id=NEW.user_id AND n.endpoint_id=NEW.cli_client_session_id)
 OR (n.endpoint_id=NEW.user_machine_id AND n.user_id=(SELECT user_id FROM user_machines WHERE id=NEW.user_machine_id));
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- Recheck current effective permissions, retaining alternate all/selected grants.
-- +goose StatementBegin
CREATE FUNCTION revoke_invalid_team_machine_access() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE affected_machine text; affected_team text;
BEGIN
 IF TG_TABLE_NAME='user_machines' THEN
  affected_machine := NEW.id;
 ELSE
  IF TG_OP='DELETE' THEN affected_team := OLD.team_id; ELSE affected_team := NEW.team_id; END IF;
 END IF;
 UPDATE user_machine_access_sessions a SET state='revoked',revoked_at=now(),updated_at=now(),revocation_reason='machine_permission_revoked'
 WHERE a.state='active' AND ((affected_machine IS NOT NULL AND a.user_machine_id=affected_machine) OR (affected_team IS NOT NULL AND a.team_id=affected_team)) AND (EXISTS(
  SELECT 1 FROM unnest(a.capabilities) capability
  WHERE CASE WHEN a.team_id IS NOT NULL THEN NOT team_machine_capability_allowed(a.user_id,a.team_id,a.user_machine_id,capability)
   ELSE NOT EXISTS(SELECT 1 FROM user_machines m WHERE m.id=a.user_machine_id AND m.user_id=a.user_id AND m.owner_team_id IS NULL AND m.revoked_at IS NULL AND m.deleted_at IS NULL) END)
 OR EXISTS(SELECT 1 FROM user_machines m WHERE m.id=a.user_machine_id AND
  (m.state IN ('revoked','disconnected','deleted')
   OR (a.capabilities && ARRAY['terminal','exec'] AND NOT m.configured_capabilities @> ARRAY['terminal_host'])
   OR ('managed_ssh'=ANY(a.capabilities) AND NOT m.configured_capabilities @> ARRAY['ssh_host'])
   OR ('files'=ANY(a.capabilities) AND NOT m.configured_capabilities @> ARRAY['file_receive']))));
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER team_machine_access_membership AFTER UPDATE OR DELETE ON team_members FOR EACH ROW EXECUTE FUNCTION revoke_invalid_team_machine_access();
CREATE TRIGGER team_machine_access_team AFTER UPDATE OR DELETE ON teams FOR EACH ROW EXECUTE FUNCTION revoke_invalid_team_machine_access();
CREATE TRIGGER team_machine_access_binding AFTER UPDATE OR DELETE ON team_resource_bindings FOR EACH ROW EXECUTE FUNCTION revoke_invalid_team_machine_access();
CREATE TRIGGER team_machine_access_grant AFTER UPDATE OR DELETE ON team_machine_grants FOR EACH ROW EXECUTE FUNCTION revoke_invalid_team_machine_access();
CREATE TRIGGER team_machine_access_owner AFTER UPDATE OF owner_team_id,configured_capabilities,state,revoked_at,deleted_at ON user_machines FOR EACH ROW
WHEN (OLD.owner_team_id IS DISTINCT FROM NEW.owner_team_id OR OLD.configured_capabilities IS DISTINCT FROM NEW.configured_capabilities OR OLD.state IS DISTINCT FROM NEW.state OR OLD.revoked_at IS DISTINCT FROM NEW.revoked_at OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at)
EXECUTE FUNCTION revoke_invalid_team_machine_access();

-- +goose Down
DROP TRIGGER team_machine_access_membership ON team_members;
DROP TRIGGER team_machine_access_team ON teams;
DROP TRIGGER team_machine_access_binding ON team_resource_bindings;
DROP TRIGGER team_machine_access_grant ON team_machine_grants;
DROP TRIGGER team_machine_access_owner ON user_machines;
DROP FUNCTION revoke_invalid_team_machine_access();
ALTER TABLE user_machine_access_sessions DROP CONSTRAINT machine_access_capabilities_valid,
 DROP COLUMN team_id,DROP COLUMN capabilities,DROP COLUMN operation_id;
