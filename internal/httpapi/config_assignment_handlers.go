package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

type configRepositoryResponse struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	ExternalRef string `json:"external_ref"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
}

type configAssignmentResponse struct {
	ID              string  `json:"id"`
	EnvironmentID   string  `json:"environment_id"`
	RepositoryID    *string `json:"repository_id,omitempty"`
	ConsentState    string  `json:"consent_state"`
	WarningRevision *string `json:"warning_revision,omitempty"`
	Version         int64   `json:"version"`
}

func repositoryResponse(item dbsqlc.ControlConfigRepository) configRepositoryResponse {
	return configRepositoryResponse{ID: item.ID, Provider: item.Provider, ExternalRef: item.ExternalRef, DisplayName: item.DisplayName, State: item.State}
}
func assignmentResponse(item dbsqlc.ControlConfigAssignment) configAssignmentResponse {
	var repo, warning *string
	if item.RepositoryID.Valid {
		value := item.RepositoryID.String
		repo = &value
	}
	if item.WarningRevision.Valid {
		value := item.WarningRevision.String
		warning = &value
	}
	return configAssignmentResponse{ID: item.ID, EnvironmentID: item.EnvironmentID, RepositoryID: repo, ConsentState: item.ConsentState, WarningRevision: warning, Version: item.Version}
}

func configRepositories(service *controlplane.ConfigAssignmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		items, err := service.ListRepositories(r.Context(), p.User.ID, 100, 0)
		if err != nil {
			writeError(w, r, 400, "validation_failed", "Repositories could not be listed.")
			return
		}
		out := make([]configRepositoryResponse, 0, len(items))
		for _, item := range items {
			out = append(out, repositoryResponse(item))
		}
		writeJSON(w, 200, SuccessResponse{Data: map[string]any{"items": out}})
	}
}

func configRepositoryConnect(service *controlplane.ConfigAssignmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		var in struct {
			Provider    string `json:"provider"`
			ExternalRef string `json:"external_ref"`
			DisplayName string `json:"display_name"`
		}
		if !decodeStrictJSON(w, r, &in) {
			return
		}
		item, err := service.ConnectRepository(r.Context(), p.User.ID, in.Provider, in.ExternalRef, in.DisplayName)
		if err != nil {
			writeError(w, r, 400, "validation_failed", "Repository is invalid.")
			return
		}
		writeJSON(w, 201, SuccessResponse{Data: repositoryResponse(item)})
	}
}

func configAssignmentGet(service *controlplane.ConfigAssignmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		item, err := service.Assignment(r.Context(), p.User.ID, r.PathValue("environment_id"))
		if err != nil {
			writeError(w, r, 404, "not_found_or_forbidden", "Environment was not found or is unavailable.")
			return
		}
		writeJSON(w, 200, SuccessResponse{Data: assignmentResponse(item)})
	}
}

func configAssignmentSet(service *controlplane.ConfigAssignmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		var in struct {
			RepositoryID    string `json:"repository_id"`
			WarningRevision string `json:"warning_revision"`
			ExpectedVersion int64  `json:"expected_version"`
		}
		if !decodeStrictJSON(w, r, &in) {
			return
		}
		item, err := service.Assign(r.Context(), p.User.ID, r.PathValue("environment_id"), in.RepositoryID, in.WarningRevision, in.ExpectedVersion)
		if err != nil {
			status, code := 400, "validation_failed"
			if errors.Is(err, controlplane.ErrAssignmentConflict) {
				status, code = 409, "version_conflict"
			}
			if errors.Is(err, controlplane.ErrAssignmentForbidden) {
				status, code = 404, "not_found_or_forbidden"
			}
			writeError(w, r, status, code, "Config assignment could not be changed.")
			return
		}
		writeJSON(w, 200, SuccessResponse{Data: assignmentResponse(item)})
	}
}

func configConsent(service *controlplane.ConfigAssignmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		var in struct {
			WarningRevision string `json:"warning_revision"`
			ExpectedVersion int64  `json:"expected_version"`
		}
		if !decodeStrictJSON(w, r, &in) {
			return
		}
		item, err := service.AcceptConsent(r.Context(), p.User.ID, r.PathValue("environment_id"), strings.TrimSpace(in.WarningRevision), in.ExpectedVersion)
		if err != nil {
			status, code := 400, "validation_failed"
			if errors.Is(err, controlplane.ErrAssignmentConflict) {
				status, code = 409, "version_conflict"
			}
			writeError(w, r, status, code, "Config consent could not be accepted.")
			return
		}
		writeJSON(w, 200, SuccessResponse{Data: assignmentResponse(item)})
	}
}

func configAssignmentClear(service *controlplane.ConfigAssignmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		v, _ := strconv.ParseInt(r.URL.Query().Get("expected_version"), 10, 64)
		if err := service.Clear(r.Context(), p.User.ID, r.PathValue("environment_id"), v); err != nil {
			status := 400
			if errors.Is(err, controlplane.ErrAssignmentConflict) {
				status = 409
			}
			writeError(w, r, status, "assignment_clear_failed", "Config assignment could not be cleared.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
