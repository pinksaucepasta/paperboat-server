package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type Reader interface {
	ListPlans(context.Context) ([]PlanRecord, error)
	ListMachineTypes(context.Context) ([]MachineTypeRecord, error)
	ListPresets(context.Context) ([]PresetRecord, error)
	ListIdleTimeouts(context.Context) ([]IdleTimeoutRecord, error)
	ListRegions(context.Context) ([]RegionRecord, error)
}

type RegionWriter interface {
	SyncRegions(context.Context, []RegionRecord) error
}

type PlanRecord struct {
	ID                string
	Code              string
	Name              string
	Active            bool
	CurrentVersionID  string
	IncludedCredits   string
	IncludedStorageGB int
	Version           int64
}

type MachineTypeRecord struct {
	ID                 string
	Code               string
	Name               string
	VCPU               int
	MemoryMB           int
	CreditWeight       string
	CustomShapeAllowed bool
	Active             bool
	CurrentVersionID   string
	Version            int64
}

type PresetRecord struct {
	ID               string
	Code             string
	Name             string
	Description      string
	Active           bool
	CurrentVersionID string
	Version          int64
}

type IdleTimeoutRecord struct {
	ID              string
	Code            string
	DurationSeconds int
	Active          bool
	Version         int64
}

type RegionRecord struct {
	ID      string
	Code    string
	Name    string
	Enabled bool
	Version int64
}

type Repository struct {
	queryer *sql.DB
}

func NewRepository(queryer *sql.DB) *Repository {
	return &Repository{queryer: queryer}
}

func (r *Repository) ListPlans(ctx context.Context) ([]PlanRecord, error) {
	rs, err := r.queryer.QueryContext(ctx, `
SELECT p.id, p.code, p.name, p.active, p.current_version_id, pv.included_credits::text, pv.included_storage_gb, p.version
FROM paperboat.plans p
JOIN paperboat.plan_versions pv ON pv.id = p.current_version_id
ORDER BY p.code`)
	if err != nil {
		return nil, fmt.Errorf("list plans: %w", err)
	}
	defer rs.Close()
	var out []PlanRecord
	for rs.Next() {
		var record PlanRecord
		if err := rs.Scan(&record.ID, &record.Code, &record.Name, &record.Active, &record.CurrentVersionID, &record.IncludedCredits, &record.IncludedStorageGB, &record.Version); err != nil {
			return nil, fmt.Errorf("scan plan: %w", err)
		}
		out = append(out, record)
	}
	return out, rs.Err()
}

func (r *Repository) ListMachineTypes(ctx context.Context) ([]MachineTypeRecord, error) {
	rs, err := r.queryer.QueryContext(ctx, `
SELECT id, code, name, vcpu, memory_mb, credit_weight::text, custom_shape_allowed, active, current_version_id, version
FROM paperboat.machine_types
ORDER BY code`)
	if err != nil {
		return nil, fmt.Errorf("list machine types: %w", err)
	}
	defer rs.Close()
	var out []MachineTypeRecord
	for rs.Next() {
		var record MachineTypeRecord
		if err := rs.Scan(&record.ID, &record.Code, &record.Name, &record.VCPU, &record.MemoryMB, &record.CreditWeight, &record.CustomShapeAllowed, &record.Active, &record.CurrentVersionID, &record.Version); err != nil {
			return nil, fmt.Errorf("scan machine type: %w", err)
		}
		out = append(out, record)
	}
	return out, rs.Err()
}

func (r *Repository) ListPresets(ctx context.Context) ([]PresetRecord, error) {
	rs, err := r.queryer.QueryContext(ctx, `
SELECT id, code, name, description, active, current_version_id, version
FROM paperboat.vm_presets
ORDER BY code`)
	if err != nil {
		return nil, fmt.Errorf("list presets: %w", err)
	}
	defer rs.Close()
	var out []PresetRecord
	for rs.Next() {
		var record PresetRecord
		if err := rs.Scan(&record.ID, &record.Code, &record.Name, &record.Description, &record.Active, &record.CurrentVersionID, &record.Version); err != nil {
			return nil, fmt.Errorf("scan preset: %w", err)
		}
		out = append(out, record)
	}
	return out, rs.Err()
}

func (r *Repository) ListIdleTimeouts(ctx context.Context) ([]IdleTimeoutRecord, error) {
	rs, err := r.queryer.QueryContext(ctx, `
SELECT id, code, duration_seconds, active, version
FROM paperboat.idle_timeout_options
ORDER BY duration_seconds`)
	if err != nil {
		return nil, fmt.Errorf("list idle timeouts: %w", err)
	}
	defer rs.Close()
	var out []IdleTimeoutRecord
	for rs.Next() {
		var record IdleTimeoutRecord
		if err := rs.Scan(&record.ID, &record.Code, &record.DurationSeconds, &record.Active, &record.Version); err != nil {
			return nil, fmt.Errorf("scan idle timeout: %w", err)
		}
		out = append(out, record)
	}
	return out, rs.Err()
}

func (r *Repository) ListRegions(ctx context.Context) ([]RegionRecord, error) {
	rs, err := r.queryer.QueryContext(ctx, `
SELECT id, code, name, enabled, version
FROM paperboat.regions
ORDER BY code`)
	if err != nil {
		return nil, fmt.Errorf("list regions: %w", err)
	}
	defer rs.Close()
	var out []RegionRecord
	for rs.Next() {
		var record RegionRecord
		if err := rs.Scan(&record.ID, &record.Code, &record.Name, &record.Enabled, &record.Version); err != nil {
			return nil, fmt.Errorf("scan region: %w", err)
		}
		out = append(out, record)
	}
	return out, rs.Err()
}

func (r *Repository) SyncRegions(ctx context.Context, records []RegionRecord) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := r.queryer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sync regions: %w", err)
	}
	defer tx.Rollback()
	for _, record := range records {
		code := strings.ToLower(strings.TrimSpace(record.Code))
		name := strings.TrimSpace(record.Name)
		if code == "" || name == "" {
			continue
		}
		// Provider sync must never enable a region: whether a region is
		// offered to users is an operator decision made in the catalog
		// (seed-catalogs). New provider regions arrive disabled, and a
		// region deprecated at the provider is force-disabled.
		if _, err := tx.ExecContext(ctx, `
INSERT INTO paperboat.regions (id, code, name, enabled)
VALUES ('reg_' || $1, $1, $2, false)
ON CONFLICT (code) DO UPDATE SET
	name = EXCLUDED.name,
	enabled = regions.enabled AND $3,
	version = CASE WHEN (regions.name, regions.enabled) IS DISTINCT FROM (EXCLUDED.name, regions.enabled AND $3) THEN regions.version + 1 ELSE regions.version END,
	updated_at = CASE WHEN (regions.name, regions.enabled) IS DISTINCT FROM (EXCLUDED.name, regions.enabled AND $3) THEN now() ELSE regions.updated_at END`,
			code, name, record.Enabled); err != nil {
			return fmt.Errorf("sync region %s: %w", code, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sync regions: %w", err)
	}
	return nil
}
