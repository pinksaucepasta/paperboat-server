-- +goose Up
-- Machine management grants do not grant public publication or lease renewal.
-- +goose StatementBegin
CREATE FUNCTION preview_management_allowed(actor text, preview text) RETURNS boolean
LANGUAGE sql STABLE SET search_path=paperboat,pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM preview_leases p JOIN user_machines m ON m.id=p.owner_device_id
 WHERE p.id=preview AND (
  (p.account_id=actor AND m.owner_team_id IS NULL AND m.user_id=actor)
  OR (p.access_mode IN ('private','team')
   AND m.configured_capabilities @> ARRAY['preview_launch']::text[]
   AND machine_capability_allowed(actor,m.id,'preview_manage'))
 ));
$$;
-- +goose StatementEnd
-- +goose Down
DROP FUNCTION preview_management_allowed(text,text);
