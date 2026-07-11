-- name: ListPlans :many
SELECT p.id, p.code, p.name, p.active, p.current_version_id, pv.included_credits::text, pv.included_storage_gb, pv.metadata, p.version
FROM plans p
JOIN plan_versions pv ON pv.id = p.current_version_id
ORDER BY p.code;

-- name: ListMachineTypes :many
SELECT id, code, name, vcpu, memory_mb, credit_weight::text, custom_shape_allowed, active, current_version_id, version
FROM machine_types
ORDER BY code;

-- name: ListPresets :many
SELECT id, code, name, description, active, current_version_id, version
FROM vm_presets
ORDER BY code;

-- name: ListIdleTimeouts :many
SELECT id, code, duration_seconds, active, version
FROM idle_timeout_options
ORDER BY duration_seconds;

-- name: ListRegions :many
SELECT id, code, name, enabled, version
FROM regions
ORDER BY code;

-- name: SyncRegion :exec
INSERT INTO regions (id, code, name, enabled)
VALUES ('reg_' || sqlc.arg(code), sqlc.arg(code), sqlc.arg(name), false)
ON CONFLICT (code) DO UPDATE SET
	name = EXCLUDED.name,
	enabled = regions.enabled AND sqlc.arg(provider_enabled),
	version = CASE WHEN (regions.name, regions.enabled) IS DISTINCT FROM (EXCLUDED.name, regions.enabled AND sqlc.arg(provider_enabled)) THEN regions.version + 1 ELSE regions.version END,
	updated_at = CASE WHEN (regions.name, regions.enabled) IS DISTINCT FROM (EXCLUDED.name, regions.enabled AND sqlc.arg(provider_enabled)) THEN now() ELSE regions.updated_at END;
