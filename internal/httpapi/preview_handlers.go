package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

type previewResponse struct {
	ID              string     `json:"id"`
	EnvironmentID   string     `json:"environment_id"`
	ProjectID       string     `json:"project_id,omitempty"`
	MachineID       string     `json:"machine_id,omitempty"`
	UserID          string     `json:"user_id,omitempty"`
	LogicalName     string     `json:"logical_name"`
	PreviewKey      string     `json:"preview_key"`
	URL             string     `json:"url"`
	TargetPort      int32      `json:"target_port"`
	State           string     `json:"state"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	RemovedAt       *time.Time `json:"removed_at,omitempty"`
	Version         int64      `json:"version"`
	EnvironmentName string     `json:"environment_name,omitempty"`
	EnvironmentKind string     `json:"environment_kind,omitempty"`
	OwnerEmail      string     `json:"owner_email,omitempty"`
}

func ownedPreviewList(service *controlplane.PreviewService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		items, err := service.ListOwned(r.Context(), principal.User.ID)
		if err != nil {
			previewError(w, r, err)
			return
		}
		out := make([]previewResponse, 0, len(items))
		for _, item := range items {
			out = append(out, newOwnedPreviewResponse(item))
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	}
}

func newOwnedPreviewResponse(item controlplane.OwnedPreview) previewResponse {
	response := newPreviewResponse(item.Preview)
	response.ProjectID = item.ProjectID
	response.EnvironmentName = item.EnvironmentName
	response.EnvironmentKind = item.EnvironmentKind
	response.OwnerEmail = item.OwnerEmail
	if item.MachineID.Valid {
		response.MachineID = item.MachineID.String
	}
	if item.UserID.Valid {
		response.UserID = item.UserID.String
	}
	return response
}

func ownedPreviewRevoke(service *controlplane.PreviewService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		operationKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if operationKey == "" {
			writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required.")
			return
		}
		item, err := service.RevokeOwned(r.Context(), principal.User.ID, operationKey, r.PathValue("preview_id"))
		if err != nil {
			previewError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: newPreviewResponse(item)})
	}
}

func newPreviewResponse(item dbsqlc.ControlPreview) previewResponse {
	response := previewResponse{ID: item.ID, EnvironmentID: item.EnvironmentID, LogicalName: item.LogicalName, PreviewKey: item.PreviewKey, URL: "https://" + item.PublicHost, TargetPort: item.TargetPort, State: item.State, Version: item.Version}
	if item.ExpiresAt.Valid {
		response.ExpiresAt = &item.ExpiresAt.Time
	}
	if item.RemovedAt.Valid {
		response.RemovedAt = &item.RemovedAt.Time
	}
	return response
}

func previewError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, controlplane.ErrPreviewDenied), errors.Is(err, controlplane.ErrPreviewRemoved):
		writeError(w, r, http.StatusNotFound, "not_found_or_forbidden", "Preview was not found.")
	case errors.Is(err, controlplane.ErrPreviewConflict):
		writeError(w, r, http.StatusConflict, "idempotency_key_conflict", "Idempotency-Key conflicts with an earlier preview operation.")
	case errors.Is(err, controlplane.ErrPreviewAcknowledgment):
		writeError(w, r, http.StatusBadRequest, "public_access_acknowledgement_required", "Public access acknowledgement is required for a new preview.")
	default:
		writeError(w, r, http.StatusBadRequest, "validation_failed", "Preview request is invalid.")
	}
}
