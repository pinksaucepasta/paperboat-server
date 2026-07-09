package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/catalog"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
)

type fakeCatalogReader struct {
	plans        []catalog.PlanRecord
	machines     []catalog.MachineTypeRecord
	presets      []catalog.PresetRecord
	idleTimeouts []catalog.IdleTimeoutRecord
	regions      []catalog.RegionRecord
	err          error
}

func (f fakeCatalogReader) ListPlans(context.Context) ([]catalog.PlanRecord, error) {
	return f.plans, f.err
}

func (f fakeCatalogReader) ListMachineTypes(context.Context) ([]catalog.MachineTypeRecord, error) {
	return f.machines, f.err
}

func (f fakeCatalogReader) ListPresets(context.Context) ([]catalog.PresetRecord, error) {
	return f.presets, f.err
}

func (f fakeCatalogReader) ListIdleTimeouts(context.Context) ([]catalog.IdleTimeoutRecord, error) {
	return f.idleTimeouts, f.err
}

func (f fakeCatalogReader) ListRegions(context.Context) ([]catalog.RegionRecord, error) {
	return f.regions, f.err
}

type fakeRegionWriter struct {
	regions []catalog.RegionRecord
	err     error
}

func (f *fakeRegionWriter) SyncRegions(_ context.Context, regions []catalog.RegionRecord) error {
	f.regions = append([]catalog.RegionRecord(nil), regions...)
	return f.err
}

func TestCatalogPlansReturnsContractPayload(t *testing.T) {
	reader := fakeCatalogReader{plans: []catalog.PlanRecord{{
		Code:              "sailor",
		Name:              "Sailor",
		Active:            true,
		IncludedCredits:   "100",
		IncludedStorageGB: 50,
		Version:           7,
	}}}

	rec := httptest.NewRecorder()
	catalogPlans(reader).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/catalog/plans", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data []catalogPlanResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data) != 1 {
		t.Fatalf("plans = %d", len(payload.Data))
	}
	plan := payload.Data[0]
	if plan.Code != "sailor" || plan.Name != "Sailor" || !plan.Active || plan.IncludedCredits != "100" || plan.IncludedStorageGB != 50 || plan.Version != 7 {
		t.Fatalf("plan payload = %#v", plan)
	}
}

func TestCatalogEndpointsReturnInternalErrorWhenRepositoryFails(t *testing.T) {
	reader := fakeCatalogReader{err: errors.New("db down")}

	rec := httptest.NewRecorder()
	catalogRegions(reader, nil, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/catalog/regions", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error.Code != "internal_error" {
		t.Fatalf("error code = %q", payload.Error.Code)
	}
}

func TestCatalogRegionsSyncsFlyRegionsBeforeReturningCatalog(t *testing.T) {
	reader := fakeCatalogReader{regions: []catalog.RegionRecord{{
		Code:    "bom",
		Name:    "Mumbai, India",
		Enabled: true,
		Version: 2,
	}}}
	flyClient := fly.NewFakeClient()
	flyClient.Regions = []fly.Region{{Code: "bom", Name: "Mumbai, India"}, {Code: "old", Name: "Deprecated", Deprecated: true}}
	writer := &fakeRegionWriter{}

	rec := httptest.NewRecorder()
	catalogRegions(reader, flyClient, writer).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/catalog/regions", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if len(writer.regions) != 2 {
		t.Fatalf("synced regions = %#v", writer.regions)
	}
	if writer.regions[0].Code != "bom" || !writer.regions[0].Enabled || writer.regions[1].Enabled {
		t.Fatalf("synced region payload = %#v", writer.regions)
	}
	var payload struct {
		Data []catalogRegionResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data) != 1 || payload.Data[0].Code != "bom" || !payload.Data[0].Enabled {
		t.Fatalf("region payload = %#v", payload.Data)
	}
}

func TestCatalogRegionsFallsBackToCatalogWhenFlyFails(t *testing.T) {
	reader := fakeCatalogReader{regions: []catalog.RegionRecord{{
		Code:    "iad",
		Name:    "Ashburn, Virginia (US)",
		Enabled: true,
		Version: 1,
	}}}
	flyClient := fly.NewFakeClient()
	flyClient.FailOnce["ListRegions"] = errors.New("fly down")
	writer := &fakeRegionWriter{}

	rec := httptest.NewRecorder()
	catalogRegions(reader, flyClient, writer).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/catalog/regions", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if len(writer.regions) != 0 {
		t.Fatalf("unexpected sync = %#v", writer.regions)
	}
}

func TestCatalogMachineTypesReturnsContractPayload(t *testing.T) {
	reader := fakeCatalogReader{machines: []catalog.MachineTypeRecord{{
		Code:               "standard-1x",
		Name:               "Standard 1x",
		VCPU:               4,
		MemoryMB:           8192,
		CreditWeight:       "1",
		CustomShapeAllowed: false,
		Active:             true,
		Version:            3,
	}}}

	rec := httptest.NewRecorder()
	catalogMachineTypes(reader).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/catalog/machine-types", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data []catalogMachineTypeResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data) != 1 || payload.Data[0].Code != "standard-1x" || payload.Data[0].VCPU != 4 || !payload.Data[0].Active {
		t.Fatalf("machine type payload = %#v", payload.Data)
	}
}
