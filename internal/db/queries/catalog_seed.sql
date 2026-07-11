-- name: UpsertIdleTimeout :exec
INSERT INTO idle_timeout_options (id, code, duration_seconds, active)
VALUES ('ito_' || sqlc.arg(code), sqlc.arg(code), sqlc.arg(duration_seconds), sqlc.arg(active))
ON CONFLICT (code) DO UPDATE SET
	duration_seconds = EXCLUDED.duration_seconds,
	active = EXCLUDED.active,
	version = CASE WHEN (idle_timeout_options.duration_seconds, idle_timeout_options.active) IS DISTINCT FROM (EXCLUDED.duration_seconds, EXCLUDED.active) THEN idle_timeout_options.version + 1 ELSE idle_timeout_options.version END,
	updated_at = CASE WHEN (idle_timeout_options.duration_seconds, idle_timeout_options.active) IS DISTINCT FROM (EXCLUDED.duration_seconds, EXCLUDED.active) THEN now() ELSE idle_timeout_options.updated_at END;

-- name: UpsertCatalogRegion :exec
INSERT INTO regions (id, code, name, enabled, placement_policy)
VALUES ('reg_' || sqlc.arg(code), sqlc.arg(code), sqlc.arg(name), sqlc.arg(enabled), sqlc.arg(placement_policy)::jsonb)
ON CONFLICT (code) DO UPDATE SET
	name = EXCLUDED.name,
	enabled = EXCLUDED.enabled,
	placement_policy = EXCLUDED.placement_policy,
	version = CASE WHEN (regions.name, regions.enabled, regions.placement_policy) IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.enabled, EXCLUDED.placement_policy) THEN regions.version + 1 ELSE regions.version END,
	updated_at = CASE WHEN (regions.name, regions.enabled, regions.placement_policy) IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.enabled, EXCLUDED.placement_policy) THEN now() ELSE regions.updated_at END;

-- name: UpsertBillingProduct :exec
INSERT INTO billing_products (id, code, provider, provider_product_id, provider_price_id, catalog_type, catalog_ref, active)
VALUES ('bp_' || sqlc.arg(code), sqlc.arg(code), sqlc.arg(provider), sqlc.arg(provider_product_id), sqlc.arg(provider_price_id), sqlc.arg(catalog_type), sqlc.arg(catalog_ref), sqlc.arg(active))
ON CONFLICT (code) DO UPDATE SET
	provider = EXCLUDED.provider,
	provider_product_id = EXCLUDED.provider_product_id,
	provider_price_id = EXCLUDED.provider_price_id,
	catalog_type = EXCLUDED.catalog_type,
	catalog_ref = EXCLUDED.catalog_ref,
	active = EXCLUDED.active,
	version = CASE WHEN (billing_products.provider, billing_products.provider_product_id, billing_products.provider_price_id, billing_products.catalog_type, billing_products.catalog_ref, billing_products.active) IS DISTINCT FROM (EXCLUDED.provider, EXCLUDED.provider_product_id, EXCLUDED.provider_price_id, EXCLUDED.catalog_type, EXCLUDED.catalog_ref, EXCLUDED.active) THEN billing_products.version + 1 ELSE billing_products.version END,
	updated_at = CASE WHEN (billing_products.provider, billing_products.provider_product_id, billing_products.provider_price_id, billing_products.catalog_type, billing_products.catalog_ref, billing_products.active) IS DISTINCT FROM (EXCLUDED.provider, EXCLUDED.provider_product_id, EXCLUDED.provider_price_id, EXCLUDED.catalog_type, EXCLUDED.catalog_ref, EXCLUDED.active) THEN now() ELSE billing_products.updated_at END;

-- name: UpsertFeatureFlag :exec
INSERT INTO feature_flags (id, code, enabled, config)
VALUES ('ff_' || sqlc.arg(code), sqlc.arg(code), sqlc.arg(enabled), sqlc.arg(config)::jsonb)
ON CONFLICT (code) DO UPDATE SET
	enabled = EXCLUDED.enabled,
	config = EXCLUDED.config,
	version = CASE WHEN (feature_flags.enabled, feature_flags.config) IS DISTINCT FROM (EXCLUDED.enabled, EXCLUDED.config) THEN feature_flags.version + 1 ELSE feature_flags.version END,
	updated_at = CASE WHEN (feature_flags.enabled, feature_flags.config) IS DISTINCT FROM (EXCLUDED.enabled, EXCLUDED.config) THEN now() ELSE feature_flags.updated_at END;

-- name: InsertPlan :one
INSERT INTO plans (id, code, name, active)
VALUES ('plan_' || sqlc.arg(code), sqlc.arg(code), sqlc.arg(name), sqlc.arg(active))
ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code
RETURNING id, xmax = 0 AS inserted;

-- name: UpdatePlan :exec
UPDATE plans
SET name = sqlc.arg(name), active = sqlc.arg(active), current_version_id = sqlc.arg(current_version_id),
	version = CASE WHEN NOT sqlc.arg(inserted)::boolean AND (name, active, current_version_id) IS DISTINCT FROM (sqlc.arg(name), sqlc.arg(active), sqlc.arg(current_version_id)) THEN version + 1 ELSE version END,
	updated_at = CASE WHEN NOT sqlc.arg(inserted)::boolean AND (name, active, current_version_id) IS DISTINCT FROM (sqlc.arg(name), sqlc.arg(active), sqlc.arg(current_version_id)) THEN now() ELSE updated_at END
WHERE id = sqlc.arg(id);

-- name: LatestPlanVersion :one
SELECT id, version_number, included_credits::text AS included_credits, included_storage_gb, metadata::text AS metadata
FROM plan_versions WHERE plan_id = $1 ORDER BY version_number DESC LIMIT 1;

-- name: InsertPlanVersion :exec
INSERT INTO plan_versions (id, plan_id, version_number, included_credits, included_storage_gb, metadata)
VALUES (sqlc.arg(id), sqlc.arg(plan_id), sqlc.arg(version_number), sqlc.arg(included_credits)::numeric, sqlc.arg(included_storage_gb), sqlc.arg(metadata)::jsonb);

-- name: InsertMachineType :one
INSERT INTO machine_types (id, code, name, vcpu, memory_mb, credit_weight, custom_shape_allowed, active)
VALUES ('mt_' || sqlc.arg(code), sqlc.arg(code), sqlc.arg(name), sqlc.arg(vcpu), sqlc.arg(memory_mb), sqlc.arg(credit_weight)::numeric, sqlc.arg(custom_shape_allowed), sqlc.arg(active))
ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code
RETURNING id, xmax = 0 AS inserted;

-- name: UpdateMachineType :exec
UPDATE machine_types
SET name = sqlc.arg(name), vcpu = sqlc.arg(vcpu), memory_mb = sqlc.arg(memory_mb), credit_weight = sqlc.arg(credit_weight)::numeric,
	custom_shape_allowed = sqlc.arg(custom_shape_allowed), active = sqlc.arg(active), current_version_id = sqlc.arg(current_version_id),
	version = CASE WHEN NOT sqlc.arg(inserted)::boolean AND (name, vcpu, memory_mb, credit_weight, custom_shape_allowed, active, current_version_id) IS DISTINCT FROM (sqlc.arg(name), sqlc.arg(vcpu), sqlc.arg(memory_mb), sqlc.arg(credit_weight)::numeric, sqlc.arg(custom_shape_allowed), sqlc.arg(active), sqlc.arg(current_version_id)) THEN version + 1 ELSE version END,
	updated_at = CASE WHEN NOT sqlc.arg(inserted)::boolean AND (name, vcpu, memory_mb, credit_weight, custom_shape_allowed, active, current_version_id) IS DISTINCT FROM (sqlc.arg(name), sqlc.arg(vcpu), sqlc.arg(memory_mb), sqlc.arg(credit_weight)::numeric, sqlc.arg(custom_shape_allowed), sqlc.arg(active), sqlc.arg(current_version_id)) THEN now() ELSE updated_at END
WHERE id = sqlc.arg(id);

-- name: LatestMachineTypeVersion :one
SELECT id, version_number, vcpu, memory_mb, credit_weight::text AS credit_weight, metadata::text AS metadata
FROM machine_type_versions WHERE machine_type_id = $1 ORDER BY version_number DESC LIMIT 1;

-- name: InsertMachineTypeVersion :exec
INSERT INTO machine_type_versions (id, machine_type_id, version_number, vcpu, memory_mb, credit_weight, metadata)
VALUES (sqlc.arg(id), sqlc.arg(machine_type_id), sqlc.arg(version_number), sqlc.arg(vcpu), sqlc.arg(memory_mb), sqlc.arg(credit_weight)::numeric, sqlc.arg(metadata)::jsonb);

-- name: InsertPreset :one
INSERT INTO vm_presets (id, code, name, description, active)
VALUES ('preset_' || sqlc.arg(code), sqlc.arg(code), sqlc.arg(name), sqlc.arg(description), sqlc.arg(active))
ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code
RETURNING id, xmax = 0 AS inserted;

-- name: UpdatePreset :exec
UPDATE vm_presets
SET name = sqlc.arg(name), description = sqlc.arg(description), active = sqlc.arg(active), current_version_id = sqlc.arg(current_version_id),
	version = CASE WHEN NOT sqlc.arg(inserted)::boolean AND (name, description, active, current_version_id) IS DISTINCT FROM (sqlc.arg(name), sqlc.arg(description), sqlc.arg(active), sqlc.arg(current_version_id)) THEN version + 1 ELSE version END,
	updated_at = CASE WHEN NOT sqlc.arg(inserted)::boolean AND (name, description, active, current_version_id) IS DISTINCT FROM (sqlc.arg(name), sqlc.arg(description), sqlc.arg(active), sqlc.arg(current_version_id)) THEN now() ELSE updated_at END
WHERE id = sqlc.arg(id);

-- name: LatestPresetVersion :one
SELECT id, version_number, manifest::text AS manifest
FROM vm_preset_versions WHERE preset_id = $1 ORDER BY version_number DESC LIMIT 1;

-- name: InsertPresetVersion :exec
INSERT INTO vm_preset_versions (id, preset_id, version_number, manifest)
VALUES (sqlc.arg(id), sqlc.arg(preset_id), sqlc.arg(version_number), sqlc.arg(manifest)::jsonb);
