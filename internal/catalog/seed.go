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
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
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
		q := tx.Queries()
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
			if err := q.UpsertIdleTimeout(ctx, dbsqlc.UpsertIdleTimeoutParams{Code: timeout.Code, DurationSeconds: int32(timeout.DurationSeconds), Active: timeout.Active}); err != nil {
				return fmt.Errorf("upsert idle timeout %s: %w", timeout.Code, err)
			}
		}
		for _, region := range seed.Regions {
			policy := jsonDefault(region.PlacementPolicy)
			if err := q.UpsertCatalogRegion(ctx, dbsqlc.UpsertCatalogRegionParams{Code: region.Code, Name: region.Name, Enabled: region.Enabled, PlacementPolicy: json.RawMessage(policy)}); err != nil {
				return fmt.Errorf("upsert region %s: %w", region.Code, err)
			}
		}
		for _, product := range seed.BillingProducts {
			if err := q.UpsertBillingProduct(ctx, dbsqlc.UpsertBillingProductParams{Code: product.Code, Provider: product.Provider, ProviderProductID: product.ProviderProductID, ProviderPriceID: product.ProviderPriceID, CatalogType: product.CatalogType, CatalogRef: product.CatalogRef, Active: product.Active}); err != nil {
				return fmt.Errorf("upsert billing product %s: %w", product.Code, err)
			}
		}
		for _, flag := range seed.FeatureFlags {
			if err := q.UpsertFeatureFlag(ctx, dbsqlc.UpsertFeatureFlagParams{Code: flag.Code, Enabled: flag.Enabled, Config: json.RawMessage(jsonDefault(flag.Config))}); err != nil {
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
	return tx.Queries().UpdatePlan(ctx, dbsqlc.UpdatePlanParams{ID: planID, Name: plan.Name, Active: plan.Active, CurrentVersionID: sql.NullString{String: versionID, Valid: true}, Inserted: inserted})
}

func insertPlan(ctx context.Context, tx *db.Tx, plan Plan) (string, bool, error) {
	row, err := tx.Queries().InsertPlan(ctx, dbsqlc.InsertPlanParams{Code: plan.Code, Name: plan.Name, Active: plan.Active})
	if err == nil {
		return row.ID, row.Inserted, nil
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
	return tx.Queries().UpdateMachineType(ctx, dbsqlc.UpdateMachineTypeParams{ID: machineID, Name: machine.Name, Vcpu: int32(machine.VCPU), MemoryMb: int32(machine.MemoryMB), CreditWeight: seedWeight, CustomShapeAllowed: machine.CustomShapeAllowed, Active: machine.Active, CurrentVersionID: sql.NullString{String: versionID, Valid: true}, Inserted: inserted})
}

func insertMachineType(ctx context.Context, tx *db.Tx, machine MachineType, seedWeight string) (string, bool, error) {
	row, err := tx.Queries().InsertMachineType(ctx, dbsqlc.InsertMachineTypeParams{Code: machine.Code, Name: machine.Name, Vcpu: int32(machine.VCPU), MemoryMb: int32(machine.MemoryMB), CreditWeight: seedWeight, CustomShapeAllowed: machine.CustomShapeAllowed, Active: machine.Active})
	if err == nil {
		return row.ID, row.Inserted, nil
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
	return tx.Queries().UpdatePreset(ctx, dbsqlc.UpdatePresetParams{ID: presetID, Name: preset.Name, Description: preset.Description, Active: preset.Active, CurrentVersionID: sql.NullString{String: versionID, Valid: true}, Inserted: inserted})
}

func insertPreset(ctx context.Context, tx *db.Tx, preset Preset) (string, bool, error) {
	row, err := tx.Queries().InsertPreset(ctx, dbsqlc.InsertPresetParams{Code: preset.Code, Name: preset.Name, Description: preset.Description, Active: preset.Active})
	if err == nil {
		return row.ID, row.Inserted, nil
	} else {
		return "", false, fmt.Errorf("insert preset %s: %w", preset.Code, err)
	}
}

func ensurePlanVersion(ctx context.Context, tx *db.Tx, planID, code string, plan Plan) (string, error) {
	latest, queryErr := tx.Queries().LatestPlanVersion(ctx, planID)
	seedCredits, err := canonicalDecimal(plan.IncludedCredits)
	if err != nil {
		return "", err
	}
	if queryErr == nil && latest.IncludedCredits == seedCredits && int(latest.IncludedStorageGb) == plan.IncludedStorageGB && jsonEqual(latest.Metadata, jsonDefault(plan.Metadata)) {
		return latest.ID, nil
	}
	if queryErr != nil && !errors.Is(queryErr, sql.ErrNoRows) {
		return "", queryErr
	}
	nextVersion := int(latest.VersionNumber) + 1
	if nextVersion == 0 {
		nextVersion = 1
	}
	versionID := fmt.Sprintf("planv_%s_%d", code, nextVersion)
	err = tx.Queries().InsertPlanVersion(ctx, dbsqlc.InsertPlanVersionParams{ID: versionID, PlanID: planID, VersionNumber: int32(nextVersion), IncludedCredits: seedCredits, IncludedStorageGb: int32(plan.IncludedStorageGB), Metadata: json.RawMessage(jsonDefault(plan.Metadata))})
	return versionID, err
}

func ensureMachineTypeVersion(ctx context.Context, tx *db.Tx, machineID, code string, machine MachineType) (string, error) {
	latest, queryErr := tx.Queries().LatestMachineTypeVersion(ctx, machineID)
	seedWeight, err := canonicalDecimal(machine.CreditWeight)
	if err != nil {
		return "", err
	}
	if queryErr == nil && int(latest.Vcpu) == machine.VCPU && int(latest.MemoryMb) == machine.MemoryMB && latest.CreditWeight == seedWeight && jsonEqual(latest.Metadata, jsonDefault(machine.Metadata)) {
		return latest.ID, nil
	}
	if queryErr != nil && !errors.Is(queryErr, sql.ErrNoRows) {
		return "", queryErr
	}
	nextVersion := int(latest.VersionNumber) + 1
	if nextVersion == 0 {
		nextVersion = 1
	}
	versionID := fmt.Sprintf("mtv_%s_%d", code, nextVersion)
	err = tx.Queries().InsertMachineTypeVersion(ctx, dbsqlc.InsertMachineTypeVersionParams{ID: versionID, MachineTypeID: machineID, VersionNumber: int32(nextVersion), Vcpu: int32(machine.VCPU), MemoryMb: int32(machine.MemoryMB), CreditWeight: seedWeight, Metadata: json.RawMessage(jsonDefault(machine.Metadata))})
	return versionID, err
}

func ensurePresetVersion(ctx context.Context, tx *db.Tx, presetID, code string, preset Preset) (string, error) {
	latest, err := tx.Queries().LatestPresetVersion(ctx, presetID)
	if err == nil && jsonEqual(latest.Manifest, jsonDefault(preset.Manifest)) {
		return latest.ID, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	nextVersion := int(latest.VersionNumber) + 1
	if nextVersion == 0 {
		nextVersion = 1
	}
	versionID := fmt.Sprintf("presetv_%s_%d", code, nextVersion)
	err = tx.Queries().InsertPresetVersion(ctx, dbsqlc.InsertPresetVersionParams{ID: versionID, PresetID: presetID, VersionNumber: int32(nextVersion), Manifest: json.RawMessage(jsonDefault(preset.Manifest))})
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
