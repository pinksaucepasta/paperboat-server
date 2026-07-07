package httpapi

import (
	"errors"
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
)

func projectsConnect(service *agentunnel.Service, kind agentunnel.ConnectKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		response, err := service.Connect(r.Context(), agentunnel.ConnectInput{
			UserID:    p.User.ID,
			ProjectID: r.PathValue("project_id"),
			Kind:      kind,
		})
		if writeAccessError(w, r, err) {
			return
		}
		status := http.StatusOK
		if !response.Connectable {
			status = http.StatusAccepted
		}
		writeJSON(w, status, SuccessResponse{Data: response})
	}
}

func projectsConnectionStatus(service *agentunnel.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		response, err := service.Status(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeAccessError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
	}
}

func writeAccessError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, agentunnel.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "project_not_found", "Project was not found.")
	case errors.Is(err, agentunnel.ErrDeleted):
		writeError(w, r, http.StatusConflict, "project_deleted", "Deleted projects cannot be connected.")
	case errors.Is(err, agentunnel.ErrInvalidState):
		writeError(w, r, http.StatusConflict, "machine_not_ready", "Machine is not ready for connection.")
	case errors.Is(err, agentunnel.ErrInsufficientCredit):
		writeError(w, r, http.StatusConflict, "credits_exhausted", "Credits are too low to connect to this project.")
	case errors.Is(err, agentunnel.ErrTunnelUnavailable):
		writeError(w, r, http.StatusServiceUnavailable, "tunnel_unavailable", "The tunnel is not available yet.")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
	}
	return true
}
