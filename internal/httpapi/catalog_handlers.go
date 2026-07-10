package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/catalog"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
)

type catalogPlanResponse struct {
	Code              string          `json:"code"`
	Name              string          `json:"name"`
	Active            bool            `json:"active"`
	IncludedCredits   string          `json:"included_credits"`
	IncludedStorageGB int             `json:"included_storage_gb"`
	Metadata          json.RawMessage `json:"metadata"`
	Version           int64           `json:"version"`
}

type catalogMachineTypeResponse struct {
	Code               string `json:"code"`
	Name               string `json:"name"`
	VCPU               int    `json:"vcpu"`
	MemoryMB           int    `json:"memory_mb"`
	CreditWeight       string `json:"credit_weight"`
	CustomShapeAllowed bool   `json:"custom_shape_allowed"`
	Active             bool   `json:"active"`
	Version            int64  `json:"version"`
}

type catalogPresetResponse struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Active      bool   `json:"active"`
	Version     int64  `json:"version"`
}

type catalogIdleTimeoutResponse struct {
	Code            string `json:"code"`
	DurationSeconds int    `json:"duration_seconds"`
	Active          bool   `json:"active"`
	Version         int64  `json:"version"`
}

type catalogRegionResponse struct {
	Code    string `json:"code"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Version int64  `json:"version"`
}

func catalogPlans(reader catalog.Reader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		records, err := reader.ListPlans(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Catalog plans could not be loaded.")
			return
		}
		out := make([]catalogPlanResponse, 0, len(records))
		for _, record := range records {
			out = append(out, catalogPlanResponse{
				Code:              record.Code,
				Name:              record.Name,
				Active:            record.Active,
				IncludedCredits:   record.IncludedCredits,
				IncludedStorageGB: record.IncludedStorageGB,
				Metadata:          record.Metadata,
				Version:           record.Version,
			})
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})
}

func catalogMachineTypes(reader catalog.Reader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		records, err := reader.ListMachineTypes(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Catalog machine types could not be loaded.")
			return
		}
		out := make([]catalogMachineTypeResponse, 0, len(records))
		for _, record := range records {
			out = append(out, catalogMachineTypeResponse{
				Code:               record.Code,
				Name:               record.Name,
				VCPU:               record.VCPU,
				MemoryMB:           record.MemoryMB,
				CreditWeight:       record.CreditWeight,
				CustomShapeAllowed: record.CustomShapeAllowed,
				Active:             record.Active,
				Version:            record.Version,
			})
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})
}

func catalogPresets(reader catalog.Reader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		records, err := reader.ListPresets(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Catalog presets could not be loaded.")
			return
		}
		out := make([]catalogPresetResponse, 0, len(records))
		for _, record := range records {
			out = append(out, catalogPresetResponse{
				Code:        record.Code,
				Name:        record.Name,
				Description: record.Description,
				Active:      record.Active,
				Version:     record.Version,
			})
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})
}

func catalogIdleTimeouts(reader catalog.Reader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		records, err := reader.ListIdleTimeouts(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Catalog idle timeouts could not be loaded.")
			return
		}
		out := make([]catalogIdleTimeoutResponse, 0, len(records))
		for _, record := range records {
			out = append(out, catalogIdleTimeoutResponse{
				Code:            record.Code,
				DurationSeconds: record.DurationSeconds,
				Active:          record.Active,
				Version:         record.Version,
			})
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})
}

func catalogRegions(reader catalog.Reader, flyClient fly.Client, writer catalog.RegionWriter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if flyClient != nil && writer != nil {
			flyRegions, err := flyClient.ListRegions(r.Context())
			if err == nil {
				records := make([]catalog.RegionRecord, 0, len(flyRegions))
				for _, region := range flyRegions {
					if region.Code == "" || region.Name == "" {
						continue
					}
					records = append(records, catalog.RegionRecord{
						Code:    region.Code,
						Name:    region.Name,
						Enabled: !region.Deprecated,
					})
				}
				if len(records) > 0 {
					if err := writer.SyncRegions(r.Context(), records); err != nil {
						writeError(w, r, http.StatusInternalServerError, "internal_error", "Catalog regions could not be loaded.")
						return
					}
				}
			}
		}
		records, err := reader.ListRegions(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Catalog regions could not be loaded.")
			return
		}
		out := make([]catalogRegionResponse, 0, len(records))
		for _, record := range records {
			out = append(out, catalogRegionResponse{
				Code:    record.Code,
				Name:    record.Name,
				Enabled: record.Enabled,
				Version: record.Version,
			})
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})
}
