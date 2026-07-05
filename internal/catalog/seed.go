package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

var (
	codePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	decimal18Scale6 = regexp.MustCompile(`^\+?([0-9]{1,12})(?:\.([0-9]{1,6}))?$`)
	negativeDecimal = regexp.MustCompile(`^\s*-`)
)

type Seed struct {
	Plans           []Plan           `json:"plans"`
	MachineTypes    []MachineType    `json:"machine_types"`
	Presets         []Preset         `json:"presets"`
	IdleTimeouts    []IdleTimeout    `json:"idle_timeouts"`
	Regions         []Region         `json:"regions"`
	BillingProducts []BillingProduct `json:"billing_products"`
	FeatureFlags    []FeatureFlag    `json:"feature_flags"`
}

type Plan struct {
	Code              string          `json:"code"`
	Name              string          `json:"name"`
	IncludedCredits   string          `json:"included_credits"`
	IncludedStorageGB int             `json:"included_storage_gb"`
	Active            bool            `json:"active"`
	Metadata          json.RawMessage `json:"metadata"`
}

type MachineType struct {
	Code               string          `json:"code"`
	Name               string          `json:"name"`
	VCPU               int             `json:"vcpu"`
	MemoryMB           int             `json:"memory_mb"`
	CreditWeight       string          `json:"credit_weight"`
	CustomShapeAllowed bool            `json:"custom_shape_allowed"`
	Active             bool            `json:"active"`
	Metadata           json.RawMessage `json:"metadata"`
}

type Preset struct {
	Code        string          `json:"code"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Active      bool            `json:"active"`
	Manifest    json.RawMessage `json:"manifest"`
}

type IdleTimeout struct {
	Code            string `json:"code"`
	DurationSeconds int    `json:"duration_seconds"`
	Active          bool   `json:"active"`
}

type Region struct {
	Code            string          `json:"code"`
	Name            string          `json:"name"`
	Enabled         bool            `json:"enabled"`
	PlacementPolicy json.RawMessage `json:"placement_policy"`
}

type BillingProduct struct {
	Code              string `json:"code"`
	Provider          string `json:"provider"`
	ProviderProductID string `json:"provider_product_id"`
	ProviderPriceID   string `json:"provider_price_id"`
	CatalogType       string `json:"catalog_type"`
	CatalogRef        string `json:"catalog_ref"`
	Active            bool   `json:"active"`
}

type FeatureFlag struct {
	Code    string          `json:"code"`
	Enabled bool            `json:"enabled"`
	Config  json.RawMessage `json:"config"`
}

func LoadFile(path string) (Seed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Seed{}, fmt.Errorf("read catalog seed: %w", err)
	}
	var seed Seed
	if err := json.Unmarshal(b, &seed); err != nil {
		return Seed{}, fmt.Errorf("parse catalog seed: %w", err)
	}
	if err := seed.Validate(); err != nil {
		return Seed{}, err
	}
	return seed, nil
}

func (s Seed) Validate() error {
	var errs []error
	seen := map[string]map[string]struct{}{}
	checkCode := func(kind, code string) {
		if !codePattern.MatchString(code) {
			errs = append(errs, fmt.Errorf("%s code %q must match %s", kind, code, codePattern.String()))
			return
		}
		if seen[kind] == nil {
			seen[kind] = map[string]struct{}{}
		}
		if _, ok := seen[kind][code]; ok {
			errs = append(errs, fmt.Errorf("duplicate %s code %q", kind, code))
		}
		seen[kind][code] = struct{}{}
	}
	if len(s.Plans) == 0 {
		errs = append(errs, errors.New("at least one plan is required"))
	}
	for _, plan := range s.Plans {
		checkCode("plan", plan.Code)
		if strings.TrimSpace(plan.Name) == "" {
			errs = append(errs, fmt.Errorf("plan %q name is required", plan.Code))
		}
		if _, err := canonicalDecimal(plan.IncludedCredits); err != nil {
			errs = append(errs, fmt.Errorf("plan %q included_credits must be numeric: %w", plan.Code, err))
		}
		if plan.IncludedStorageGB < 0 {
			errs = append(errs, fmt.Errorf("plan %q included_storage_gb cannot be negative", plan.Code))
		}
		if !validJSON(plan.Metadata) {
			errs = append(errs, fmt.Errorf("plan %q metadata must be valid JSON object", plan.Code))
		}
	}
	if len(s.MachineTypes) == 0 {
		errs = append(errs, errors.New("at least one machine type is required"))
	}
	for _, machine := range s.MachineTypes {
		checkCode("machine type", machine.Code)
		if strings.TrimSpace(machine.Name) == "" || machine.VCPU <= 0 || machine.MemoryMB <= 0 {
			errs = append(errs, fmt.Errorf("machine type %q must have name, positive vcpu, and positive memory_mb", machine.Code))
		}
		weight, err := canonicalDecimal(machine.CreditWeight)
		if err != nil || weight == "0.000000" {
			errs = append(errs, fmt.Errorf("machine type %q credit_weight must be positive numeric", machine.Code))
		}
		if !validJSON(machine.Metadata) {
			errs = append(errs, fmt.Errorf("machine type %q metadata must be valid JSON object", machine.Code))
		}
	}
	for _, preset := range s.Presets {
		checkCode("preset", preset.Code)
		if strings.TrimSpace(preset.Name) == "" {
			errs = append(errs, fmt.Errorf("preset %q name is required", preset.Code))
		}
		if !validJSON(preset.Manifest) {
			errs = append(errs, fmt.Errorf("preset %q manifest must be valid JSON object", preset.Code))
		}
	}
	for _, timeout := range s.IdleTimeouts {
		checkCode("idle timeout", timeout.Code)
		if timeout.DurationSeconds <= 0 {
			errs = append(errs, fmt.Errorf("idle timeout %q duration_seconds must be positive", timeout.Code))
		}
	}
	for _, region := range s.Regions {
		checkCode("region", region.Code)
		if strings.TrimSpace(region.Name) == "" {
			errs = append(errs, fmt.Errorf("region %q name is required", region.Code))
		}
		if !validJSON(region.PlacementPolicy) {
			errs = append(errs, fmt.Errorf("region %q placement_policy must be valid JSON object", region.Code))
		}
	}
	for _, product := range s.BillingProducts {
		checkCode("billing product", product.Code)
		if product.Provider == "" || product.ProviderProductID == "" || product.ProviderPriceID == "" || product.CatalogType == "" || product.CatalogRef == "" {
			errs = append(errs, fmt.Errorf("billing product %q provider and catalog mapping fields are required", product.Code))
		}
	}
	for _, flag := range s.FeatureFlags {
		checkCode("feature flag", flag.Code)
		if !validJSON(flag.Config) {
			errs = append(errs, fmt.Errorf("feature flag %q config must be valid JSON object", flag.Code))
		}
	}
	return errors.Join(errs...)
}

func Apply(ctx context.Context, store *db.DB, seed Seed) error {
	if err := seed.Validate(); err != nil {
		return err
	}
	return store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		for _, plan := range seed.Plans {
			if err := upsertPlan(ctx, tx, plan); err != nil {
				return err
			}
		}
		for _, machine := range seed.MachineTypes {
			if err := upsertMachineType(ctx, tx, machine); err != nil {
				return err
			}
		}
		for _, preset := range seed.Presets {
			if err := upsertPreset(ctx, tx, preset); err != nil {
				return err
			}
		}
		for _, timeout := range seed.IdleTimeouts {
			if _, err := tx.Exec(ctx, `
INSERT INTO idle_timeout_options (id, code, duration_seconds, active)
VALUES ('ito_' || $1, $1, $2, $3)
ON CONFLICT (code) DO UPDATE SET
	duration_seconds = EXCLUDED.duration_seconds,
	active = EXCLUDED.active,
	version = CASE WHEN (idle_timeout_options.duration_seconds, idle_timeout_options.active) IS DISTINCT FROM (EXCLUDED.duration_seconds, EXCLUDED.active) THEN idle_timeout_options.version + 1 ELSE idle_timeout_options.version END,
	updated_at = CASE WHEN (idle_timeout_options.duration_seconds, idle_timeout_options.active) IS DISTINCT FROM (EXCLUDED.duration_seconds, EXCLUDED.active) THEN now() ELSE idle_timeout_options.updated_at END`,
				timeout.Code, timeout.DurationSeconds, timeout.Active); err != nil {
				return fmt.Errorf("upsert idle timeout %s: %w", timeout.Code, err)
			}
		}
		for _, region := range seed.Regions {
			policy := jsonDefault(region.PlacementPolicy)
			if _, err := tx.Exec(ctx, `
INSERT INTO regions (id, code, name, enabled, placement_policy)
VALUES ('reg_' || $1, $1, $2, $3, $4)
ON CONFLICT (code) DO UPDATE SET
	name = EXCLUDED.name,
	enabled = EXCLUDED.enabled,
	placement_policy = EXCLUDED.placement_policy,
	version = CASE WHEN (regions.name, regions.enabled, regions.placement_policy) IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.enabled, EXCLUDED.placement_policy) THEN regions.version + 1 ELSE regions.version END,
	updated_at = CASE WHEN (regions.name, regions.enabled, regions.placement_policy) IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.enabled, EXCLUDED.placement_policy) THEN now() ELSE regions.updated_at END`,
				region.Code, region.Name, region.Enabled, policy); err != nil {
				return fmt.Errorf("upsert region %s: %w", region.Code, err)
			}
		}
		for _, product := range seed.BillingProducts {
			if _, err := tx.Exec(ctx, `
INSERT INTO billing_products (id, code, provider, provider_product_id, provider_price_id, catalog_type, catalog_ref, active)
VALUES ('bp_' || $1, $1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (code) DO UPDATE SET
	provider = EXCLUDED.provider,
	provider_product_id = EXCLUDED.provider_product_id,
	provider_price_id = EXCLUDED.provider_price_id,
	catalog_type = EXCLUDED.catalog_type,
	catalog_ref = EXCLUDED.catalog_ref,
	active = EXCLUDED.active,
	version = CASE WHEN (billing_products.provider, billing_products.provider_product_id, billing_products.provider_price_id, billing_products.catalog_type, billing_products.catalog_ref, billing_products.active) IS DISTINCT FROM (EXCLUDED.provider, EXCLUDED.provider_product_id, EXCLUDED.provider_price_id, EXCLUDED.catalog_type, EXCLUDED.catalog_ref, EXCLUDED.active) THEN billing_products.version + 1 ELSE billing_products.version END,
	updated_at = CASE WHEN (billing_products.provider, billing_products.provider_product_id, billing_products.provider_price_id, billing_products.catalog_type, billing_products.catalog_ref, billing_products.active) IS DISTINCT FROM (EXCLUDED.provider, EXCLUDED.provider_product_id, EXCLUDED.provider_price_id, EXCLUDED.catalog_type, EXCLUDED.catalog_ref, EXCLUDED.active) THEN now() ELSE billing_products.updated_at END`,
				product.Code, product.Provider, product.ProviderProductID, product.ProviderPriceID, product.CatalogType, product.CatalogRef, product.Active); err != nil {
				return fmt.Errorf("upsert billing product %s: %w", product.Code, err)
			}
		}
		for _, flag := range seed.FeatureFlags {
			if _, err := tx.Exec(ctx, `
INSERT INTO feature_flags (id, code, enabled, config)
VALUES ('ff_' || $1, $1, $2, $3)
ON CONFLICT (code) DO UPDATE SET
	enabled = EXCLUDED.enabled,
	config = EXCLUDED.config,
	version = CASE WHEN (feature_flags.enabled, feature_flags.config) IS DISTINCT FROM (EXCLUDED.enabled, EXCLUDED.config) THEN feature_flags.version + 1 ELSE feature_flags.version END,
	updated_at = CASE WHEN (feature_flags.enabled, feature_flags.config) IS DISTINCT FROM (EXCLUDED.enabled, EXCLUDED.config) THEN now() ELSE feature_flags.updated_at END`,
				flag.Code, flag.Enabled, jsonDefault(flag.Config)); err != nil {
				return fmt.Errorf("upsert feature flag %s: %w", flag.Code, err)
			}
		}
		return nil
	})
}

func upsertPlan(ctx context.Context, tx *db.Tx, plan Plan) error {
	planID, inserted, err := insertPlan(ctx, tx, plan)
	if err != nil {
		return err
	}
	versionID, err := ensurePlanVersion(ctx, tx, planID, plan.Code, plan)
	if err != nil {
		return fmt.Errorf("upsert plan version %s: %w", plan.Code, err)
	}
	_, err = tx.Exec(ctx, `
UPDATE plans
SET
	name = $2,
	active = $3,
	current_version_id = $4,
	version = CASE WHEN NOT $5 AND (name, active, current_version_id) IS DISTINCT FROM ($2, $3, $4) THEN version + 1 ELSE version END,
	updated_at = CASE WHEN NOT $5 AND (name, active, current_version_id) IS DISTINCT FROM ($2, $3, $4) THEN now() ELSE updated_at END
WHERE id = $1`, planID, plan.Name, plan.Active, versionID, inserted)
	return err
}

func insertPlan(ctx context.Context, tx *db.Tx, plan Plan) (string, bool, error) {
	var planID string
	var inserted bool
	if err := tx.QueryRow(ctx, `
INSERT INTO plans (id, code, name, active)
VALUES ('plan_' || $1, $1, $2, $3)
ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code
RETURNING id, xmax = 0`, plan.Code, plan.Name, plan.Active).Scan(&planID, &inserted); err == nil {
		return planID, inserted, nil
	} else {
		return "", false, fmt.Errorf("insert plan %s: %w", plan.Code, err)
	}
}

func upsertMachineType(ctx context.Context, tx *db.Tx, machine MachineType) error {
	seedWeight, err := canonicalDecimal(machine.CreditWeight)
	if err != nil {
		return err
	}
	machineID, inserted, err := insertMachineType(ctx, tx, machine, seedWeight)
	if err != nil {
		return err
	}
	versionID, err := ensureMachineTypeVersion(ctx, tx, machineID, machine.Code, machine)
	if err != nil {
		return fmt.Errorf("upsert machine type version %s: %w", machine.Code, err)
	}
	_, err = tx.Exec(ctx, `
UPDATE machine_types
SET
	name = $2,
	vcpu = $3,
	memory_mb = $4,
	credit_weight = $5::numeric,
	custom_shape_allowed = $6,
	active = $7,
	current_version_id = $8,
	version = CASE WHEN NOT $9 AND (name, vcpu, memory_mb, credit_weight, custom_shape_allowed, active, current_version_id) IS DISTINCT FROM ($2, $3, $4, $5::numeric, $6, $7, $8) THEN version + 1 ELSE version END,
	updated_at = CASE WHEN NOT $9 AND (name, vcpu, memory_mb, credit_weight, custom_shape_allowed, active, current_version_id) IS DISTINCT FROM ($2, $3, $4, $5::numeric, $6, $7, $8) THEN now() ELSE updated_at END
WHERE id = $1`, machineID, machine.Name, machine.VCPU, machine.MemoryMB, seedWeight, machine.CustomShapeAllowed, machine.Active, versionID, inserted)
	return err
}

func insertMachineType(ctx context.Context, tx *db.Tx, machine MachineType, seedWeight string) (string, bool, error) {
	var machineID string
	var inserted bool
	if err := tx.QueryRow(ctx, `
INSERT INTO machine_types (id, code, name, vcpu, memory_mb, credit_weight, custom_shape_allowed, active)
VALUES ('mt_' || $1, $1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code
RETURNING id, xmax = 0`, machine.Code, machine.Name, machine.VCPU, machine.MemoryMB, seedWeight, machine.CustomShapeAllowed, machine.Active).Scan(&machineID, &inserted); err == nil {
		return machineID, inserted, nil
	} else {
		return "", false, fmt.Errorf("insert machine type %s: %w", machine.Code, err)
	}
}

func upsertPreset(ctx context.Context, tx *db.Tx, preset Preset) error {
	presetID, inserted, err := insertPreset(ctx, tx, preset)
	if err != nil {
		return err
	}
	versionID, err := ensurePresetVersion(ctx, tx, presetID, preset.Code, preset)
	if err != nil {
		return fmt.Errorf("upsert preset version %s: %w", preset.Code, err)
	}
	_, err = tx.Exec(ctx, `
UPDATE vm_presets
SET
	name = $2,
	description = $3,
	active = $4,
	current_version_id = $5,
	version = CASE WHEN NOT $6 AND (name, description, active, current_version_id) IS DISTINCT FROM ($2, $3, $4, $5) THEN version + 1 ELSE version END,
	updated_at = CASE WHEN NOT $6 AND (name, description, active, current_version_id) IS DISTINCT FROM ($2, $3, $4, $5) THEN now() ELSE updated_at END
WHERE id = $1`, presetID, preset.Name, preset.Description, preset.Active, versionID, inserted)
	return err
}

func insertPreset(ctx context.Context, tx *db.Tx, preset Preset) (string, bool, error) {
	var presetID string
	var inserted bool
	if err := tx.QueryRow(ctx, `
INSERT INTO vm_presets (id, code, name, description, active)
VALUES ('preset_' || $1, $1, $2, $3, $4)
ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code
RETURNING id, xmax = 0`, preset.Code, preset.Name, preset.Description, preset.Active).Scan(&presetID, &inserted); err == nil {
		return presetID, inserted, nil
	} else {
		return "", false, fmt.Errorf("insert preset %s: %w", preset.Code, err)
	}
}

func ensurePlanVersion(ctx context.Context, tx *db.Tx, planID, code string, plan Plan) (string, error) {
	var latestID, credits, metadata string
	var versionNumber, storageGB int
	err := tx.QueryRow(ctx, `
SELECT id, version_number, included_credits::text, included_storage_gb, metadata::text
FROM plan_versions
WHERE plan_id = $1
ORDER BY version_number DESC
LIMIT 1`, planID).Scan(&latestID, &versionNumber, &credits, &storageGB, &metadata)
	seedCredits, err := canonicalDecimal(plan.IncludedCredits)
	if err != nil {
		return "", err
	}
	if err == nil && credits == seedCredits && storageGB == plan.IncludedStorageGB && jsonEqual(metadata, jsonDefault(plan.Metadata)) {
		return latestID, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	nextVersion := versionNumber + 1
	if nextVersion == 0 {
		nextVersion = 1
	}
	versionID := fmt.Sprintf("planv_%s_%d", code, nextVersion)
	_, err = tx.Exec(ctx, `
INSERT INTO plan_versions (id, plan_id, version_number, included_credits, included_storage_gb, metadata)
VALUES ($1, $2, $3, $4, $5, $6)`,
		versionID, planID, nextVersion, seedCredits, plan.IncludedStorageGB, jsonDefault(plan.Metadata))
	return versionID, err
}

func ensureMachineTypeVersion(ctx context.Context, tx *db.Tx, machineID, code string, machine MachineType) (string, error) {
	var latestID, weight, metadata string
	var versionNumber, vcpu, memoryMB int
	err := tx.QueryRow(ctx, `
SELECT id, version_number, vcpu, memory_mb, credit_weight::text, metadata::text
FROM machine_type_versions
WHERE machine_type_id = $1
ORDER BY version_number DESC
LIMIT 1`, machineID).Scan(&latestID, &versionNumber, &vcpu, &memoryMB, &weight, &metadata)
	seedWeight, err := canonicalDecimal(machine.CreditWeight)
	if err != nil {
		return "", err
	}
	if err == nil && vcpu == machine.VCPU && memoryMB == machine.MemoryMB && weight == seedWeight && jsonEqual(metadata, jsonDefault(machine.Metadata)) {
		return latestID, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	nextVersion := versionNumber + 1
	if nextVersion == 0 {
		nextVersion = 1
	}
	versionID := fmt.Sprintf("mtv_%s_%d", code, nextVersion)
	_, err = tx.Exec(ctx, `
INSERT INTO machine_type_versions (id, machine_type_id, version_number, vcpu, memory_mb, credit_weight, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		versionID, machineID, nextVersion, machine.VCPU, machine.MemoryMB, seedWeight, jsonDefault(machine.Metadata))
	return versionID, err
}

func ensurePresetVersion(ctx context.Context, tx *db.Tx, presetID, code string, preset Preset) (string, error) {
	var latestID, manifest string
	var versionNumber int
	err := tx.QueryRow(ctx, `
SELECT id, version_number, manifest::text
FROM vm_preset_versions
WHERE preset_id = $1
ORDER BY version_number DESC
LIMIT 1`, presetID).Scan(&latestID, &versionNumber, &manifest)
	if err == nil && jsonEqual(manifest, jsonDefault(preset.Manifest)) {
		return latestID, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	nextVersion := versionNumber + 1
	if nextVersion == 0 {
		nextVersion = 1
	}
	versionID := fmt.Sprintf("presetv_%s_%d", code, nextVersion)
	_, err = tx.Exec(ctx, `
INSERT INTO vm_preset_versions (id, preset_id, version_number, manifest)
VALUES ($1, $2, $3, $4)`,
		versionID, presetID, nextVersion, jsonDefault(preset.Manifest))
	return versionID, err
}

func jsonDefault(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

func canonicalDecimal(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if negativeDecimal.MatchString(trimmed) {
		return "", fmt.Errorf("value must be finite and non-negative")
	}
	matches := decimal18Scale6.FindStringSubmatch(trimmed)
	if matches == nil {
		return "", fmt.Errorf("value must be a non-negative decimal with at most 12 integer digits and 6 fractional digits")
	}
	integer := strings.TrimPrefix(matches[1], "+")
	integer = strings.TrimLeft(integer, "0")
	if integer == "" {
		integer = "0"
	}
	fraction := matches[2]
	if fraction == "" {
		fraction = "0"
	}
	fraction = fraction + strings.Repeat("0", 6-len(fraction))
	return integer + "." + fraction, nil
}

func jsonEqual(left, right string) bool {
	var leftValue any
	var rightValue any
	if err := json.Unmarshal([]byte(left), &leftValue); err != nil {
		return left == right
	}
	if err := json.Unmarshal([]byte(right), &rightValue); err != nil {
		return left == right
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func validJSON(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var obj map[string]any
	return json.Unmarshal(raw, &obj) == nil
}
