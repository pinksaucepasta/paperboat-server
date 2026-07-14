-- +goose Up

SET LOCAL search_path TO paperboat;

-- The old no-card free plan is replaced by the Polar-backed free-trial plan.
UPDATE subscriptions s
SET state = 'canceled', version = version + 1, updated_at = now()
FROM plan_versions pv
JOIN plans p ON p.id = pv.plan_id
WHERE s.active_plan_version_id = pv.id
  AND p.code = 'free'
  AND s.state IN ('active', 'trialing');

UPDATE plans
SET active = false, version = version + 1, updated_at = now()
WHERE code = 'free';

-- +goose Down
-- Forward-only migration.
