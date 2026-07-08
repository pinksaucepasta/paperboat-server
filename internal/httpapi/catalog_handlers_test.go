package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/catalog"
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
	catalogRegions(reader).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/catalog/regions", nil))

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
