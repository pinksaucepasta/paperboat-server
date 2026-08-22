-- The old session mode was the previous client-only machine behavior. Version
-- 111 is already applied in production, so canonicalize its remaining session
-- rows in a new forward migration instead of rewriting migration history.
-- +goose Up
ALTER TABLE user_machines DROP CONSTRAINT user_machines_setup_mode_check;

WITH converted AS (
  UPDATE user_machines
  SET setup_mode = 'client',
      setup_roles = ARRAY['interactive']::text[],
      configured_capabilities = ARRAY['file_receive','preview_launch']::text[],
      observed_capabilities = ARRAY(
        SELECT DISTINCT capability
        FROM unnest(observed_capabilities) AS capability
        WHERE capability IN ('file_receive','preview_launch')
        ORDER BY capability
      ),
      seat_state = 'released',
      state = CASE WHEN state IN ('revoked','deleted') THEN state ELSE 'offline' END,
      online = false,
      installation_generation = installation_generation + 1,
      updated_at = now(),
      version = version + 1
  WHERE setup_mode = 'session'
  RETURNING environment_id, state
)
UPDATE control_routes AS route
SET desired_state = 'attached',
    desired_revision = desired_revision + 1,
    version = version + 1,
    updated_at = now()
WHERE route.kind = 'runtime_https_wss'
  AND route.environment_id IN (
    SELECT environment_id FROM converted WHERE state NOT IN ('revoked','deleted')
  )
  AND route.desired_state IN ('detaching','detached');

ALTER TABLE user_machines
  ADD CONSTRAINT user_machines_setup_mode_check CHECK (setup_mode IN ('client','host'));

-- +goose Down
-- This data canonicalization is intentionally irreversible. The prior session
-- value is not distinguishable from client rows that existed before this migration.
SELECT 1;
