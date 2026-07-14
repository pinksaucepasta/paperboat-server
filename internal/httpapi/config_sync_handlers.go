package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/classifier"
	"github.com/pinksaucepasta/paperboat-server/internal/configsync"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
)

func configSyncStatus(repository *configsync.Repository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		status, err := repository.Account(r.Context(), principal.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: status})
	})
}

func machineConfigClassify(credentials *metering.RuntimeRepository, controller *classifier.Controller) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ProjectID  string                 `json:"project_id"`
			MachineID  string                 `json:"machine_id"`
			Candidates []classifier.Candidate `json:"candidates"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || body.ProjectID == "" || body.MachineID == "" {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Classification metadata is invalid.")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err := credentials.VerifyHeartbeatCredential(r.Context(), body.ProjectID, body.MachineID, token); err != nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Machine credential is invalid.")
			return
		}
		userID, err := controller.ProjectOwner(r.Context(), body.ProjectID)
		if err != nil {
			writeError(w, r, http.StatusForbidden, "forbidden", "Machine does not own this project.")
			return
		}
		response, err := controller.Classify(r.Context(), userID, body.Candidates)
		if errors.Is(err, classifier.ErrRateLimited) {
			writeError(w, r, http.StatusTooManyRequests, "rate_limited", "Classification request budget is exhausted.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Classification metadata is invalid.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
	}
}

func configSyncOverrides(repository *configsync.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := principalFromContext(r.Context())
		values, err := repository.ListOverrides(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, 500, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, 200, SuccessResponse{Data: values})
	}
}

func configSyncOverridePut(repository *configsync.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path     string `json:"path"`
			Decision string `json:"decision"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			writeError(w, r, 400, "invalid_request", "Override is invalid.")
			return
		}
		p, _ := principalFromContext(r.Context())
		err := repository.PutOverride(r.Context(), p.User.ID, body.Path, body.Decision)
		if errors.Is(err, configsync.ErrMandatoryExclusion) {
			writeError(w, r, 409, "mandatory_exclusion", "Mandatory safety exclusions cannot be overridden.")
			return
		}
		if err != nil {
			writeError(w, r, 400, "invalid_request", "Override is invalid.")
			return
		}
		writeJSON(w, 200, SuccessResponse{Data: map[string]any{"path": body.Path, "decision": body.Decision}})
	}
}

func configSyncOverrideDelete(repository *configsync.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path string `json:"path"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			writeError(w, r, 400, "invalid_request", "Override is invalid.")
			return
		}
		p, _ := principalFromContext(r.Context())
		if err := repository.DeleteOverride(r.Context(), p.User.ID, body.Path); err != nil {
			writeError(w, r, 400, "invalid_request", "Override is invalid.")
			return
		}
		writeJSON(w, 200, SuccessResponse{Data: map[string]any{"deleted": true}})
	}
}

func configSyncRecoveryExport(authService *auth.Service, repository *configsync.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := principalFromContext(r.Context())
		if err := authService.ValidateReauthProof(r, p.User.ID, "config_recovery_export"); err != nil {
			writeError(w, r, 401, "reauthentication_required", "Reauthentication is required to export the recovery key.")
			return
		}
		key, err := repository.ExportAccountKey(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, 500, "internal_error", "Internal server error.")
			return
		}
		authService.ClearReauthProofCookie(w)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, SuccessResponse{Data: map[string]any{"identity": key.Identity, "recipient": key.Recipient, "key_version": key.Version}})
	}
}

func configSyncKeyRotate(authService *auth.Service, repository *configsync.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := principalFromContext(r.Context())
		if err := authService.ValidateReauthProof(r, p.User.ID, "config_key_rotation"); err != nil {
			writeError(w, r, 401, "reauthentication_required", "Reauthentication is required to rotate the config key.")
			return
		}
		key, err := repository.RotateAccountKey(r.Context(), p.User.ID)
		if errors.Is(err, configsync.ErrRotationPending) {
			writeError(w, r, 409, "rotation_pending", "The previous config key rotation must finish before starting another.")
			return
		}
		if err != nil {
			writeError(w, r, 500, "internal_error", "Internal server error.")
			return
		}
		authService.ClearReauthProofCookie(w)
		writeJSON(w, 202, SuccessResponse{Data: map[string]any{"recipient": key.Recipient, "key_version": key.Version, "state": "pending_reencryption"}})
	}
}
