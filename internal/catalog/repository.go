package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
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
	Metadata          json.RawMessage
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
	q       *dbsqlc.Queries
}

func NewRepository(queryer *sql.DB) *Repository {
	return &Repository{queryer: queryer, q: dbsqlc.New(queryer)}
}

func (r *Repository) ListPlans(ctx context.Context) ([]PlanRecord, error) {
	rows, err := r.q.ListPlans(ctx)
	if err != nil {
		return nil, fmt.Errorf("list plans: %w", err)
	}
	out := make([]PlanRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, PlanRecord{ID: row.ID, Code: row.Code, Name: row.Name, Active: row.Active, CurrentVersionID: row.CurrentVersionID.String, IncludedCredits: row.PvIncludedCredits, IncludedStorageGB: int(row.IncludedStorageGb), Metadata: row.Metadata, Version: row.Version})
	}
	return out, nil
}

func (r *Repository) ListMachineTypes(ctx context.Context) ([]MachineTypeRecord, error) {
	rows, err := r.q.ListMachineTypes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list machine types: %w", err)
	}
	out := make([]MachineTypeRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, MachineTypeRecord{ID: row.ID, Code: row.Code, Name: row.Name, VCPU: int(row.Vcpu), MemoryMB: int(row.MemoryMb), CreditWeight: row.CreditWeight, CustomShapeAllowed: row.CustomShapeAllowed, Active: row.Active, CurrentVersionID: row.CurrentVersionID.String, Version: row.Version})
	}
	return out, nil
}

func (r *Repository) ListPresets(ctx context.Context) ([]PresetRecord, error) {
	rows, err := r.q.ListPresets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list presets: %w", err)
	}
	out := make([]PresetRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, PresetRecord{ID: row.ID, Code: row.Code, Name: row.Name, Description: row.Description, Active: row.Active, CurrentVersionID: row.CurrentVersionID.String, Version: row.Version})
	}
	return out, nil
}

func (r *Repository) ListIdleTimeouts(ctx context.Context) ([]IdleTimeoutRecord, error) {
	rows, err := r.q.ListIdleTimeouts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list idle timeouts: %w", err)
	}
	out := make([]IdleTimeoutRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, IdleTimeoutRecord{ID: row.ID, Code: row.Code, DurationSeconds: int(row.DurationSeconds), Active: row.Active, Version: row.Version})
	}
	return out, nil
}

func (r *Repository) ListRegions(ctx context.Context) ([]RegionRecord, error) {
	rows, err := r.q.ListRegions(ctx)
	if err != nil {
		return nil, fmt.Errorf("list regions: %w", err)
	}
	out := make([]RegionRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, RegionRecord{ID: row.ID, Code: row.Code, Name: row.Name, Enabled: row.Enabled, Version: row.Version})
	}
	return out, nil
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
	qtx := r.q.WithTx(tx)
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
		if err := qtx.SyncRegion(ctx, dbsqlc.SyncRegionParams{Code: code, Name: name, ProviderEnabled: record.Enabled}); err != nil {
			return fmt.Errorf("sync region %s: %w", code, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sync regions: %w", err)
	}
	return nil
}
