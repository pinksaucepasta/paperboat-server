-- +goose Up
ALTER TABLE control_connector_generations
  RENAME COLUMN helper_id TO machine_id;

ALTER TABLE control_connector_generations
  ADD COLUMN connector_id text NOT NULL DEFAULT 'runtime';

ALTER TABLE control_connector_generations
  DROP CONSTRAINT control_connector_generations_pkey,
  ADD CONSTRAINT control_connector_generations_pkey PRIMARY KEY (environment_id, connector_id);

UPDATE control_connector_generations connector
SET machine_id = machine.id
FROM user_machines machine
WHERE machine.environment_id = connector.environment_id
  AND machine.deleted_at IS NULL;

ALTER TABLE control_routes
  ADD COLUMN connector_id text NOT NULL DEFAULT 'runtime';

UPDATE control_routes route
SET connector_id = preview.preview_key
FROM control_previews preview
WHERE preview.route_id = route.id;

-- +goose Down
SELECT 1;
