-- +goose Up
ALTER TABLE inspector_credentials ADD COLUMN native_cli_session_id text REFERENCES cli_client_sessions(id) ON DELETE CASCADE;
ALTER TABLE inspector_credentials ADD COLUMN native_machine_id text REFERENCES user_machines(id) ON DELETE CASCADE;
ALTER TABLE inspector_credentials ADD COLUMN native_machine_generation bigint CHECK(native_machine_generation > 0);
CREATE INDEX inspector_native_cli ON inspector_credentials(native_cli_session_id) WHERE revoked_at IS NULL;
CREATE INDEX inspector_native_machine ON inspector_credentials(native_machine_id) WHERE revoked_at IS NULL;
CREATE VIEW inspector_native_admissions AS
SELECT i.credential_id,i.account_id,i.owner_account_id,i.native_cli_session_id,i.native_machine_id,i.expires_at
FROM inspector_credentials i
JOIN cli_client_sessions c ON c.id=i.native_cli_session_id AND c.user_id=i.account_id AND c.state='active' AND c.revoked_at IS NULL
JOIN user_machines m ON m.id=i.native_machine_id AND m.user_id=i.owner_account_id AND m.installation_generation=i.native_machine_generation AND m.deleted_at IS NULL AND m.revoked_at IS NULL
JOIN users actor ON actor.id=i.account_id AND actor.status='active'
JOIN users owner ON owner.id=i.owner_account_id AND owner.status='active'
WHERE i.revoked_at IS NULL AND i.expires_at>now()
AND ((i.team_id IS NULL AND i.account_id=i.owner_account_id) OR EXISTS (
 SELECT 1 FROM teams t JOIN team_members tm ON tm.team_id=t.team_id AND tm.account_id=i.account_id JOIN team_resource_bindings b ON b.team_id=t.team_id AND b.resource_kind=i.resource_kind AND b.resource_id=i.resource_id JOIN team_resource_grants g ON g.team_id=t.team_id AND g.account_id=i.account_id AND g.resource_kind=i.resource_kind AND g.resource_id=i.resource_id AND g.permission=i.action
 WHERE t.team_id=i.team_id AND t.deleted_at IS NULL AND t.generation=i.team_generation AND tm.active AND tm.membership_generation=i.membership_generation AND b.active AND b.owner_account=i.owner_account_id AND b.generation=i.binding_generation AND g.active AND g.generation=i.grant_generation))
AND ((i.resource_kind='preview' AND EXISTS(SELECT 1 FROM preview_leases p JOIN preview_lease_carrier_attachments x ON x.preview_id=p.id AND x.account_id=p.account_id WHERE p.id=i.resource_id AND p.account_id=i.owner_account_id AND p.terminal_state='active' AND p.lease_deadline>now() AND (p.user_deadline IS NULL OR p.user_deadline>now()) AND x.state='ready' AND x.expires_at>now() AND x.host_id=i.native_machine_id AND x.route_generation=i.resource_generation AND x.route_generation=i.route_generation AND x.route_generation=i.target_generation))
 OR (i.resource_kind='tunnel' AND EXISTS(SELECT 1 FROM tunnels t JOIN tunnel_routes r ON r.tunnel_id=t.id  WHERE t.id=i.resource_id AND t.account_id=i.owner_account_id AND t.generation=i.resource_generation AND t.desired_state='active' AND t.deleted_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>now()) AND r.id=i.route_id AND r.generation=i.route_generation AND r.generation=i.target_generation AND r.desired_state='active' AND r.deleted_at IS NULL AND t.created_by_host_id=i.native_machine_id)));
-- +goose Down
DROP VIEW inspector_native_admissions;
DROP INDEX inspector_native_cli;
DROP INDEX inspector_native_machine;
ALTER TABLE inspector_credentials DROP COLUMN native_cli_session_id,DROP COLUMN native_machine_id,DROP COLUMN native_machine_generation;
