package httpapi

import (
	"encoding/json"
	"errors"
	"io"
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
		clientSessionID := ""
		if p.Client != nil {
			clientSessionID = p.Client.SessionID
		}
		var body struct {
			TerminalSessionID string `json:"terminal_session_id"`
		}
		if kind == agentunnel.ConnectCLI && r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
				writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
				return
			}
		}
		response, err := service.Connect(r.Context(), agentunnel.ConnectInput{
			UserID:            p.User.ID,
			ProjectID:         r.PathValue("project_id"),
			Kind:              kind,
			ClientSessionID:   clientSessionID,
			TerminalSessionID: body.TerminalSessionID,
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
		response, err := service.Status(r.Context(), p.User.ID, r.PathValue("project_id"), r.URL.Query().Get("terminal_session_id"))
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
	case errors.Is(err, agentunnel.ErrTerminalSessionOperationPending):
		writeError(w, r, http.StatusConflict, "terminal_session_operation_pending", "Terminal session operation is pending. Retry shortly.")
	case errors.Is(err, agentunnel.ErrTerminalSessionNotFound):
		writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
	case errors.Is(err, agentunnel.ErrTerminalRuntimeUnavailable):
		writeError(w, r, http.StatusServiceUnavailable, "terminal_runtime_unavailable", "Terminal runtime is unavailable. Retry shortly.")
	case errors.Is(err, agentunnel.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "project_not_found", "Project was not found.")
	case errors.Is(err, agentunnel.ErrDeleted):
		writeError(w, r, http.StatusConflict, "project_deleted", "Deleted projects cannot be connected.")
	case errors.Is(err, agentunnel.ErrInvalidState):
		writeError(w, r, http.StatusConflict, "machine_not_ready", "Machine is not ready for connection.")
	case errors.Is(err, agentunnel.ErrMachineFailed):
		writeError(w, r, http.StatusConflict, "machine_failed", "The project machine failed to start.")
	case errors.Is(err, agentunnel.ErrInsufficientCredit):
		writeError(w, r, http.StatusConflict, "credits_exhausted", "Credits are too low to connect to this project.")
	case errors.Is(err, agentunnel.ErrTunnelUnavailable):
		writeError(w, r, http.StatusServiceUnavailable, "tunnel_unavailable", "The tunnel is not available yet.")
	case errors.Is(err, agentunnel.ErrProvider):
		writeError(w, r, http.StatusBadGateway, "provider_error", "The access provider rejected the connection request.")
	case errors.Is(err, agentunnel.ErrCredentialIssuerUnavailable):
		writeError(w, r, http.StatusNotImplemented, "credential_issuer_unavailable", "CLI papercode credential issuance is not available yet.")
	case errors.Is(err, agentunnel.ErrGitHubRequired):
		writeError(w, r, http.StatusConflict, "github_config_not_ready", "GitHub config is not ready for this project.")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
	}
	return true
}
