-- +goose Up
ALTER TABLE user_machines
  ADD COLUMN IF NOT EXISTS provider_route_http_base_url text,
  ADD COLUMN IF NOT EXISTS provider_route_websocket_base_url text;

-- +goose Down
ALTER TABLE user_machines
  DROP COLUMN IF EXISTS provider_route_websocket_base_url,
  DROP COLUMN IF EXISTS provider_route_http_base_url;
