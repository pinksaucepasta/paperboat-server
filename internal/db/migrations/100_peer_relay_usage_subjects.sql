-- +goose Up
ALTER TABLE control_usage_counters
  DROP CONSTRAINT control_usage_counters_route_id_fkey;

-- +goose Down
DELETE FROM control_usage_counters counters
WHERE NOT EXISTS (
  SELECT 1 FROM control_routes routes WHERE routes.id = counters.route_id
);
ALTER TABLE control_usage_counters
  ADD CONSTRAINT control_usage_counters_route_id_fkey
  FOREIGN KEY (route_id) REFERENCES control_routes(id) ON DELETE CASCADE;
