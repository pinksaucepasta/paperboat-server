package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
)

func projectsCreate(service *projects.Service) http.HandlerFunc {
	type request struct {
		Name            string   `json:"name"`
		RepositoryURL   string   `json:"repository_url"`
		DefaultBranch   string   `json:"default_branch"`
		StorageGB       int      `json:"storage_gb"`
		MachineTypeCode string   `json:"machine_type_code"`
		RegionCode      string   `json:"region_code"`
		PresetCodes     []string `json:"preset_codes"`
		IdleTimeoutCode string   `json:"idle_timeout_code"`
		SetupScript     string   `json:"setup_script"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		project, existed, err := service.Create(r.Context(), projects.CreateInput{
			UserID:          p.User.ID,
			IdempotencyKey:  r.Header.Get("Idempotency-Key"),
			Name:            body.Name,
			RepositoryURL:   body.RepositoryURL,
			DefaultBranch:   body.DefaultBranch,
			StorageGB:       body.StorageGB,
			MachineTypeCode: body.MachineTypeCode,
			RegionCode:      body.RegionCode,
			PresetCodes:     body.PresetCodes,
			IdleTimeoutCode: body.IdleTimeoutCode,
			SetupScript:     body.SetupScript,
		})
		if writeProjectError(w, r, err) {
			return
		}
		status := http.StatusCreated
		if existed {
			status = http.StatusOK
		}
		writeJSON(w, status, SuccessResponse{Data: project})
	}
}

func projectsList(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		projects, err := service.List(r.Context(), p.User.ID)
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: projects})
	}
}

func projectsGet(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		project, err := service.Get(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: project})
	}
}

func projectsUpdate(service *projects.Service) http.HandlerFunc {
	type request struct {
		StorageGB       *int      `json:"storage_gb"`
		MachineTypeCode *string   `json:"machine_type_code"`
		RegionCode      *string   `json:"region_code"`
		PresetCodes     *[]string `json:"preset_codes"`
		IdleTimeoutCode *string   `json:"idle_timeout_code"`
		SetupScript     *string   `json:"setup_script"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		project, err := service.Update(r.Context(), projects.UpdateInput{
			UserID:          p.User.ID,
			ProjectID:       r.PathValue("project_id"),
			StorageGB:       body.StorageGB,
			MachineTypeCode: body.MachineTypeCode,
			RegionCode:      body.RegionCode,
			PresetCodes:     body.PresetCodes,
			IdleTimeoutCode: body.IdleTimeoutCode,
			SetupScript:     body.SetupScript,
		})
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: project})
	}
}

func projectsDelete(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		project, err := service.Delete(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: project})
	}
}

func projectsStart(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		project, err := service.Start(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: project})
	}
}

func projectsStop(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		project, err := service.Stop(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: project})
	}
}

func projectsRestart(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		project, err := service.Restart(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: project})
	}
}

func projectsEvents(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		events, err := service.Events(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: events})
	}
}

func writeProjectError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, projects.ErrIdempotencyKeyRequired):
		writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required.")
	case errors.Is(err, projects.ErrIdempotencyConflict):
		writeError(w, r, http.StatusConflict, "idempotency_key_conflict", "Idempotency-Key conflicts with an existing project request.")
	case errors.Is(err, projects.ErrInvalidRepositoryURL):
		writeError(w, r, http.StatusBadRequest, "invalid_repository_url", "Repository URL must be an HTTPS git repository URL.")
	case errors.Is(err, projects.ErrInvalidStorage):
		writeError(w, r, http.StatusBadRequest, "invalid_storage", "Storage allocation must be positive.")
	case errors.Is(err, projects.ErrInvalidSetupScript):
		writeError(w, r, http.StatusBadRequest, "setup_script_too_large", "Setup script exceeds the configured size limit.")
	case errors.Is(err, projects.ErrCatalogUnavailable):
		writeError(w, r, http.StatusBadRequest, "catalog_unavailable", "One or more selected catalog entries are unavailable.")
	case errors.Is(err, projects.ErrInsufficientStorage), errors.Is(err, metering.ErrInsufficientStorage):
		writeError(w, r, http.StatusConflict, "insufficient_storage", "Project storage allocation exceeds available storage.")
	case errors.Is(err, projects.ErrInsufficientCredits):
		writeError(w, r, http.StatusConflict, "credits_exhausted", "Credits are too low to start this project.")
	case errors.Is(err, projects.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "project_not_found", "Project was not found.")
	case errors.Is(err, projects.ErrDeleted):
		writeError(w, r, http.StatusConflict, "project_deleted", "Deleted projects cannot be changed.")
	case errors.Is(err, projects.ErrInvalidState):
		writeError(w, r, http.StatusConflict, "invalid_project_state", "Project state does not allow this operation.")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
	}
	return true
}
