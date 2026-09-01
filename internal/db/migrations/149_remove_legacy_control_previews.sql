-- +goose Up

-- The control_previews environment/descriptor model predates the canonical
-- lease-bound preview_tunnel_v1 resources. It is no longer reachable from the
-- server and must not remain as a second source of preview state.
DROP TABLE IF EXISTS control_preview_operations;
DROP TABLE IF EXISTS control_previews;
DROP TABLE IF EXISTS preview_url_records;

-- +goose Down
-- Intentionally irreversible. The removed environment/name descriptor schema
-- was unreleased compatibility state; canonical preview leases are created by
-- the preview_leases/tunnel_routes schema and must not be recreated here.
