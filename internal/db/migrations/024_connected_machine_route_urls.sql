-- +goose Up
ALTER TABLE connected_machines
  ADD COLUMN IF NOT EXISTS agentunnel_http_base_url text,
  ADD COLUMN IF NOT EXISTS agentunnel_websocket_base_url text;

-- +goose Down
ALTER TABLE connected_machines
  DROP COLUMN IF EXISTS agentunnel_websocket_base_url,
  DROP COLUMN IF EXISTS agentunnel_http_base_url;
