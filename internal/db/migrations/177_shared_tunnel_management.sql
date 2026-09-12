-- +goose Up
-- Management is separate from tunnel traffic access and public publication.
-- A machine grant cannot modify a multi-host tunnel through an ungranted host.
-- +goose StatementBegin
CREATE FUNCTION tunnel_management_allowed(actor text, tunnel text) RETURNS boolean
LANGUAGE sql STABLE SET search_path=paperboat,pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM tunnels t JOIN user_machines m ON m.id=t.created_by_host_id
 WHERE t.id=tunnel AND (
  (t.account_id=actor AND m.owner_team_id IS NULL AND m.user_id=actor)
  OR (t.access_mode IN ('private','team') AND t.deleted_at IS NULL
   AND m.configured_capabilities @> ARRAY['preview_launch']::text[]
   AND machine_capability_allowed(actor,m.id,'tunnel_manage')
   AND NOT EXISTS(SELECT 1 FROM tunnel_connectors c LEFT JOIN user_machines other ON other.id=c.host_id
    WHERE c.tunnel_id=t.id AND c.revoked_at IS NULL AND
     (other.id IS NULL OR NOT machine_capability_allowed(actor,other.id,'tunnel_manage') OR NOT other.configured_capabilities @> ARRAY['preview_launch']::text[]))
  )
 ));
$$;
-- +goose StatementEnd
-- +goose Down
DROP FUNCTION tunnel_management_allowed(text,text);
