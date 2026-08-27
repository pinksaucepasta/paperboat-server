package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/access"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

func userMachinePairings(service *usermachines.Service) http.HandlerFunc {
	type request struct {
		Verifier                string          `json:"verifier"`
		EnrollmentToken         string          `json:"enrollment_token"`
		DisplayName             string          `json:"display_name"`
		Platform                string          `json:"platform"`
		Architecture            string          `json:"architecture"`
		WorkspaceRoot           string          `json:"workspace_root"`
		RuntimeVersions         json.RawMessage `json:"runtime_versions"`
		PublicIdentityKey       string          `json:"public_identity_key"`
		AcceptBetaPlatform      bool            `json:"accept_beta_platform,omitempty"`
		SSHUser                 string          `json:"ssh_user,omitempty"`
		SSHPort                 uint16          `json:"ssh_port,omitempty"`
		CanReuseRuntimeIdentity bool            `json:"can_reuse_runtime_identity,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		pairing, err := service.CreatePairing(r.Context(), usermachines.PairingInput{Verifier: body.Verifier, EnrollmentToken: body.EnrollmentToken, DisplayName: body.DisplayName, Platform: body.Platform, Architecture: body.Architecture, WorkspaceRoot: body.WorkspaceRoot, RuntimeVersions: body.RuntimeVersions, PublicIdentityKey: body.PublicIdentityKey, AcceptBetaPlatform: body.AcceptBetaPlatform, SSHUser: body.SSHUser, SSHPort: body.SSHPort, CanReuseRuntimeIdentity: body.CanReuseRuntimeIdentity})
		if err != nil {
			slog.Warn("invalid user-machine pairing", "error", err, "platform", body.Platform, "architecture", body.Architecture)
			writeError(w, r, http.StatusBadRequest, "invalid_user_machine_pairing", "Pairing details are invalid or unsupported.")
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: pairing})
	}
}

func machineSetup(service *usermachines.Service) http.HandlerFunc {
	type request struct {
		SetupMode          string          `json:"setup_mode"`
		DisplayName        string          `json:"display_name"`
		Platform           string          `json:"platform"`
		Architecture       string          `json:"architecture"`
		WorkspaceRoot      string          `json:"workspace_root"`
		PublicIdentityKey  string          `json:"public_identity_key"`
		RuntimeVersions    json.RawMessage `json:"runtime_versions"`
		AcceptBetaPlatform bool            `json:"accept_beta_platform,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok || principal.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body request
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		machine, err := service.Setup(r.Context(), principal.User.ID, usermachines.SetupInput{
			DisplayName: body.DisplayName, Platform: body.Platform, Architecture: body.Architecture,
			WorkspaceRoot: body.WorkspaceRoot, PublicIdentityKey: body.PublicIdentityKey,
			RuntimeVersions: body.RuntimeVersions, SetupMode: body.SetupMode,
			AcceptBetaPlatform: body.AcceptBetaPlatform,
		})
		switch {
		case errors.Is(err, usermachines.ErrInvalidSetup):
			writeError(w, r, http.StatusBadRequest, "invalid_machine_setup", "Machine setup details are invalid or unsupported.")
		case errors.Is(err, usermachines.ErrMachineIdentityConflict):
			writeError(w, r, http.StatusConflict, "machine_identity_conflict", "This machine identity is already registered to another account.")
		case errors.Is(err, usermachines.ErrMachineNameConflict):
			writeError(w, r, http.StatusConflict, "machine_name_conflict", "A machine with this name already exists. Choose another name.")
		case err != nil:
			writeError(w, r, http.StatusInternalServerError, "machine_setup_failed", "Unable to set up this machine.")
		default:
			writeJSON(w, http.StatusOK, SuccessResponse{Data: machine})
		}
	}
}

func authenticatedHostSetupInstallation(service *usermachines.Service) http.HandlerFunc {
	type request struct {
		Verifier                string                       `json:"verifier"`
		PublicIdentityKey       string                       `json:"public_identity_key"`
		InstallationGeneration  int64                        `json:"installation_generation"`
		SetupMode               string                       `json:"setup_mode"`
		Artifact                usermachines.MachineArtifact `json:"artifact"`
		SSHUser                 string                       `json:"ssh_user,omitempty"`
		SSHPort                 uint16                       `json:"ssh_port,omitempty"`
		CanReuseRuntimeIdentity bool                         `json:"can_reuse_runtime_identity,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok || principal.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body request
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		result, err := service.PrepareAuthenticatedHostSetup(r.Context(), principal.User.ID, principal.Client.SessionID, r.PathValue("machine_id"), usermachines.AuthenticatedHostSetupInput{
			OperationID: r.Header.Get("Idempotency-Key"), Verifier: body.Verifier,
			PublicIdentityKey: body.PublicIdentityKey, InstallationGeneration: body.InstallationGeneration,
			SetupMode: body.SetupMode, Artifact: body.Artifact, SSHUser: body.SSHUser, SSHPort: body.SSHPort,
			CanReuseRuntimeIdentity: body.CanReuseRuntimeIdentity,
		})
		switch {
		case errors.Is(err, usermachines.ErrInvalidHostSetupInstallation):
			writeError(w, r, http.StatusConflict, "host_setup_installation_invalid", "Host setup changed before installation material could be issued. Retry setup.")
		case errors.Is(err, usermachines.ErrHostSetupOperationConflict):
			writeError(w, r, http.StatusConflict, "idempotency_key_conflict", "Idempotency-Key conflicts with an existing Host setup request.")
		case errors.Is(err, usermachines.ErrProvisioningUnavailable):
			writeError(w, r, http.StatusServiceUnavailable, "host_setup_provisioning_unavailable", "Host setup provisioning is temporarily unavailable.")
		case err != nil:
			writeError(w, r, http.StatusInternalServerError, "host_setup_installation_failed", "Unable to prepare Host installation material.")
		default:
			noStore(w)
			writeJSON(w, http.StatusCreated, SuccessResponse{Data: result})
		}
	}
}

func userMachineEnrollmentStart(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body struct {
			Role  string `json:"role"`
			Shell string `json:"shell"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		if body.Role == "" {
			body.Role = "host"
		}
		if body.Shell == "" {
			body.Shell = "posix"
		}
		result, err := service.StartEnrollmentWithOptions(r.Context(), p.User.ID, r.Header.Get("Idempotency-Key"), usermachines.EnrollmentOptions{Role: body.Role, Shell: body.Shell})
		if err != nil {
			if errors.Is(err, usermachines.ErrIdempotencyKeyRequired) {
				writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "A valid Idempotency-Key header is required.")
				return
			}
			writeError(w, r, http.StatusInternalServerError, "user_machine_enrollment_start_failed", "Unable to start machine enrollment.")
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: result})
	}
}

func userMachineEnrollmentStatus(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		result, err := service.Enrollment(r.Context(), p.User.ID, r.PathValue("enrollment_id"))
		if err != nil {
			writeError(w, r, http.StatusNotFound, "user_machine_enrollment_not_found", "User-machine enrollment was not found.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
	}
}

func userMachineEnrollmentToken(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		token, err := service.EnrollmentToken(r.Context(), p.User.ID, r.PathValue("enrollment_id"))
		if err != nil {
			writeError(w, r, http.StatusGone, "user_machine_bootstrap_token_unavailable", "The enrollment token is unavailable or expired.")
			return
		}
		w.Header().Set("Cache-Control", "no-store, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Disposition", `attachment; filename="paperboat-enrollment-token.txt"`)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, token+"\n")
	}
}

func userMachineEnrollmentCancel(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		if err := service.CancelEnrollment(r.Context(), p.User.ID, r.PathValue("enrollment_id")); err != nil {
			writeError(w, r, http.StatusConflict, "user_machine_enrollment_not_cancellable", "User-machine enrollment cannot be cancelled in its current state.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]bool{"cancelled": true}})
	}
}

func userMachineEnrollmentRetry(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body struct {
			Role  string `json:"role"`
			Shell string `json:"shell"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Role == "" {
			body.Role = "host"
		}
		if body.Shell == "" {
			body.Shell = "posix"
		}
		result, err := service.RetryEnrollmentWithOptions(r.Context(), p.User.ID, r.PathValue("enrollment_id"), usermachines.EnrollmentOptions{Role: body.Role, Shell: body.Shell})
		if err != nil {
			writeError(w, r, http.StatusConflict, "user_machine_enrollment_not_retryable", "User-machine enrollment cannot be retried in its current state.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
	}
}

type userMachineInstallationConsumer interface {
	ConsumeInstallationForIdentityState(context.Context, string, string, bool) (json.RawMessage, error)
}

func userMachineInstallationConsume(service userMachineInstallationConsumer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Verifier          string `json:"verifier"`
			PublicIdentityKey string `json:"public_identity_key"`
			RuntimeEnrolled   bool   `json:"runtime_enrolled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		material, err := service.ConsumeInstallationForIdentityState(r.Context(), body.Verifier, body.PublicIdentityKey, body.RuntimeEnrolled)
		if err != nil {
			switch {
			case errors.Is(err, usermachines.ErrInstallationPending):
				writeError(w, r, http.StatusConflict, "user_machine_approval_pending", "UserMachine approval is pending.")
			case errors.Is(err, usermachines.ErrInstallationDenied):
				writeError(w, r, http.StatusForbidden, "user_machine_pairing_denied", "UserMachine pairing was denied.")
			case errors.Is(err, usermachines.ErrInstallationExpired):
				writeError(w, r, http.StatusGone, "user_machine_pairing_expired", "UserMachine pairing expired.")
			default:
				writeError(w, r, http.StatusGone, "user_machine_installation_unavailable", "Installation material is unavailable or has already been used.")
			}
			return
		}
		var data any
		if err := json.Unmarshal(material, &data); err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: data})
	}
}

func machinesList(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		limit, offset := 50, 0
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				limit = parsed
			}
		}
		if raw := r.URL.Query().Get("offset"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				offset = parsed
			}
		}
		items, total, err := service.List(r.Context(), p.User.ID, limit, offset)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to list machines.")
			return
		}
		var next any
		if offset+len(items) < total {
			value := offset + len(items)
			next = value
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"items": items, "pagination": map[string]any{"limit": limit, "offset": offset, "total": total, "next_offset": next}}})
	}
}

func userMachineOverview(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		overview, err := service.Overview(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to load machine usage.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: overview})
	}
}

func transferDestinationDefault(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		switch r.Method {
		case http.MethodGet:
			machine, err := service.TransferDestinationDefault(r.Context(), p.User.ID)
			if errors.Is(err, usermachines.ErrNotFound) {
				writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"configured": false, "machine": nil}})
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "transfer_destination_default_failed", "Unable to load the default transfer destination.")
				return
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"configured": true, "machine": machine}})
		case http.MethodPut:
			var body struct {
				MachineID string `json:"machine_id"`
			}
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&body); err != nil || strings.TrimSpace(body.MachineID) == "" {
				writeError(w, r, http.StatusBadRequest, "invalid_request", "A valid machine_id is required.")
				return
			}
			machine, err := service.SetTransferDestinationDefault(r.Context(), p.User.ID, body.MachineID)
			if errors.Is(err, usermachines.ErrTransferDestinationInvalid) {
				writeError(w, r, http.StatusConflict, "transfer_destination_unavailable", "The selected transfer destination is unavailable.")
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "transfer_destination_default_failed", "Unable to set the default transfer destination.")
				return
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"configured": true, "machine": machine}})
		case http.MethodDelete:
			if err := service.ClearTransferDestinationDefault(r.Context(), p.User.ID); err != nil {
				writeError(w, r, http.StatusInternalServerError, "transfer_destination_default_failed", "Unable to clear the default transfer destination.")
				return
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"configured": false, "machine": nil}})
		}
	}
}

func terminalSessionTransferDestination(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		sessionID := r.PathValue("session_id")
		switch r.Method {
		case http.MethodGet:
			machine, err := service.TerminalSessionTransferDestination(r.Context(), p.User.ID, sessionID)
			if errors.Is(err, usermachines.ErrNotFound) {
				writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"configured": false, "machine": nil}})
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "transfer_destination_session_failed", "Unable to load the session transfer destination.")
				return
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"configured": true, "machine": machine}})
		case http.MethodPut:
			var body struct {
				MachineID string `json:"machine_id"`
			}
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&body); err != nil || strings.TrimSpace(body.MachineID) == "" {
				writeError(w, r, http.StatusBadRequest, "invalid_request", "A valid machine_id is required.")
				return
			}
			machine, err := service.SetTerminalSessionTransferDestination(r.Context(), p.User.ID, sessionID, body.MachineID)
			if errors.Is(err, usermachines.ErrTransferDestinationInvalid) {
				writeError(w, r, http.StatusConflict, "transfer_destination_unavailable", "The session or selected transfer destination is unavailable.")
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "transfer_destination_session_failed", "Unable to set the session transfer destination.")
				return
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"configured": true, "machine": machine}})
		case http.MethodDelete:
			if err := service.ClearTerminalSessionTransferDestination(r.Context(), p.User.ID, sessionID); errors.Is(err, usermachines.ErrNotFound) {
				writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
				return
			} else if err != nil {
				writeError(w, r, http.StatusInternalServerError, "transfer_destination_session_failed", "Unable to clear the session transfer destination.")
				return
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"configured": false, "machine": nil}})
		}
	}
}

func terminalSessionTransferDestinations(service *usermachines.Service, hosted *access.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		sessionID := r.PathValue("session_id")
		var items []usermachines.UserMachine
		var err error
		if strings.HasPrefix(sessionID, "pts_") && hosted != nil {
			var ids []string
			ids, err = hosted.EligibleTerminalSessionTransferDestinationIDs(r.Context(), p.User.ID, p.Client.SessionID, sessionID)
			if err == nil {
				items, err = service.OwnedEligibleMachines(r.Context(), p.User.ID, ids)
			}
		} else {
			items, err = service.EligibleTerminalSessionTransferDestinations(r.Context(), p.User.ID, p.Client.SessionID, sessionID)
		}
		if errors.Is(err, usermachines.ErrTerminalSessionNotFound) {
			writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
			return
		}
		if errors.Is(err, access.ErrTerminalSessionNotFound) {
			writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
			return
		}
		if errors.Is(err, access.ErrTunnelUnavailable) || errors.Is(err, access.ErrTerminalRuntimeUnavailable) {
			writeError(w, r, http.StatusConflict, "machine_offline", "Session host is offline.")
			return
		}
		if errors.Is(err, usermachines.ErrProvisioningUnavailable) {
			writeError(w, r, http.StatusConflict, "machine_offline", "Session host is offline.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "transfer_destinations_unavailable", "Eligible transfer destinations are unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"items": items}})
	}
}

func userMachineGet(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		machine, err := service.Get(r.Context(), p.User.ID, r.PathValue("machine_id"))
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
			return
		}
		if errors.Is(err, usermachines.ErrTerminalSessionNotFound) {
			writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: machine})
	}
}

func userMachineRename(service *usermachines.Service) http.HandlerFunc {
	type request struct {
		DisplayName string `json:"display_name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		machine, err := service.Rename(r.Context(), p.User.ID, r.PathValue("machine_id"), body.DisplayName)
		switch {
		case errors.Is(err, usermachines.ErrInvalidMachineName):
			writeError(w, r, http.StatusBadRequest, "invalid_machine_name", "Machine name must be between 1 and 128 characters.")
		case errors.Is(err, usermachines.ErrMachineNameConflict):
			writeError(w, r, http.StatusConflict, "machine_name_conflict", "A machine with this name already exists. Choose another name.")
		case errors.Is(err, usermachines.ErrNotFound):
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
		case err != nil:
			writeError(w, r, http.StatusInternalServerError, "machine_rename_failed", "Unable to rename this machine.")
		default:
			writeJSON(w, http.StatusOK, SuccessResponse{Data: machine})
		}
	}
}

func userMachineConnectionDescriptor(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body struct {
			TerminalSessionID string `json:"terminal_session_id"`
			SourceMachineID   string `json:"source_machine_id"`
			CreateSession     *struct {
				Name           string `json:"name"`
				IdempotencyKey string `json:"idempotency_key"`
			} `json:"create_session"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		terminalSessionID := body.TerminalSessionID
		var created *usermachines.TerminalSession
		if body.CreateSession != nil {
			// create-and-connect collapses session creation and descriptor
			// issuance into one round trip. The idempotency key makes retried
			// requests resolve the same durable session.
			if terminalSessionID != "" || strings.TrimSpace(body.CreateSession.IdempotencyKey) == "" {
				writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must not mix terminal_session_id with create_session.")
				return
			}
			item, err := service.CreateConfiguredTerminalSession(r.Context(), p.User.ID, r.PathValue("machine_id"), body.CreateSession.Name, body.CreateSession.IdempotencyKey)
			if userMachineTerminalSessionError(w, r, err) {
				return
			}
			terminalSessionID = item.ID
			created = &item
		}
		response, err := service.ConnectTerminalSession(r.Context(), p.User.ID, body.SourceMachineID, r.PathValue("machine_id"), p.Client.SessionID, terminalSessionID)
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
			return
		}
		if errors.Is(err, usermachines.ErrTerminalSessionNotFound) {
			writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "connector_unavailable", "Machine credentials are unavailable.")
			return
		}
		if created != nil {
			writeJSON(w, http.StatusCreated, SuccessResponse{Data: map[string]any{"descriptor": response, "terminal_session": created}})
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
	}
}

func userMachineExecDescriptor(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body struct {
			SourceMachineID string `json:"source_machine_id"`
			OperationID     string `json:"operation_id"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must contain a valid source machine and operation ID.")
			return
		}
		response, err := service.ExecDescriptor(r.Context(), p.User.ID, body.SourceMachineID, r.PathValue("machine_id"), p.Client.SessionID, body.OperationID)
		if errors.Is(err, usermachines.ErrExecOperationInvalid) {
			writeError(w, r, http.StatusBadRequest, "invalid_operation_id", "Operation ID is invalid.")
			return
		}
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
			return
		}
		if errors.Is(err, usermachines.ErrMachineCapabilityUnavailable) {
			writeError(w, r, http.StatusConflict, "machine_not_ready", "Machine is not ready for execution.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "credential_unavailable", "Execution credentials are unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
	}
}

func userMachineSSHDescriptor(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body struct {
			SourceMachineID string `json:"source_machine_id"`
			OperationID     string `json:"operation_id"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must contain a valid source machine and operation ID.")
			return
		}
		response, err := service.SSHDescriptor(r.Context(), p.User.ID, body.SourceMachineID, r.PathValue("machine_id"), p.Client.SessionID, body.OperationID)
		if errors.Is(err, usermachines.ErrSSHOperationInvalid) {
			writeError(w, r, http.StatusBadRequest, "invalid_operation_id", "Operation ID is invalid.")
			return
		}
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
			return
		}
		if errors.Is(err, usermachines.ErrMachineCapabilityUnavailable) {
			writeError(w, r, http.StatusConflict, "machine_not_ready", "Machine is not ready for SSH.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "credential_unavailable", "SSH credentials are unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
	}
}

func userMachineFileTransferDescriptor(service *usermachines.Service, hosted *access.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body struct {
			SourceMachineID string `json:"source_machine_id"`
			SessionID       string `json:"session_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		var response any
		var err error
		if strings.HasPrefix(body.SessionID, "pts_") && hosted != nil {
			response, err = hosted.FileTransferDescriptor(r.Context(), access.TransferDescriptorRequest{UserID: p.User.ID, SourceMachineID: body.SourceMachineID, DestinationMachineID: r.PathValue("machine_id"), CLIClientSessionID: p.Client.SessionID, SessionID: body.SessionID})
		} else {
			response, err = service.FileTransferDescriptor(r.Context(), p.User.ID, body.SourceMachineID, r.PathValue("machine_id"), p.Client.SessionID, body.SessionID)
		}
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Source or destination machine was not found.")
			return
		}
		if errors.Is(err, usermachines.ErrTerminalSessionNotFound) {
			writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
			return
		}
		if errors.Is(err, usermachines.ErrMachineCapabilityUnavailable) {
			writeError(w, r, http.StatusConflict, "machine_capability_unavailable", "Destination machine cannot receive files.")
			return
		}
		if errors.Is(err, usermachines.ErrMachineOffline) {
			writeError(w, r, http.StatusConflict, "machine_offline", "Destination machine is offline.")
			return
		}
		if errors.Is(err, access.ErrTerminalSessionNotFound) {
			writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
			return
		}
		if errors.Is(err, access.ErrTunnelUnavailable) || errors.Is(err, access.ErrTerminalRuntimeUnavailable) {
			writeError(w, r, http.StatusConflict, "machine_offline", "Session host is offline.")
			return
		}
		if errors.Is(err, usermachines.ErrProvisioningUnavailable) {
			writeError(w, r, http.StatusConflict, "machine_offline", "Destination machine is offline.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "file_transfer_unavailable", "File transfer credentials are unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
	}
}

func userMachinePreviewLaunchDescriptor(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		response, err := service.PreviewLaunchDescriptor(r.Context(), p.User.ID, r.PathValue("machine_id"), p.Client.SessionID)
		switch {
		case errors.Is(err, usermachines.ErrNotFound):
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
		case errors.Is(err, usermachines.ErrMachineCapabilityUnavailable):
			writeError(w, r, http.StatusConflict, "machine_capability_unavailable", "Machine cannot launch previews.")
		case errors.Is(err, usermachines.ErrMachineOffline):
			writeError(w, r, http.StatusConflict, "machine_offline", "Machine is offline.")
		case errors.Is(err, usermachines.ErrProvisioningUnavailable):
			writeError(w, r, http.StatusConflict, "machine_offline", "Machine is offline.")
		case err != nil:
			writeError(w, r, http.StatusServiceUnavailable, "preview_launch_unavailable", "Preview launch credentials are unavailable.")
		default:
			writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
		}
	}
}

func userMachineConnectionReadiness(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		response, err := service.ConnectionReadinessForTerminalSession(r.Context(), p.User.ID, r.PathValue("machine_id"), r.URL.Query().Get("terminal_session_id"))
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
			return
		}
		if errors.Is(err, usermachines.ErrTerminalSessionNotFound) {
			writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "connector_unavailable", "Machine status is unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
	}
}

func userMachineTerminalSessionsList(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		items, err := service.ListTerminalSessions(r.Context(), p.User.ID, r.PathValue("machine_id"))
		if userMachineTerminalSessionError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"items": items, "pagination": map[string]any{"limit": len(items), "offset": 0, "total": len(items), "next_offset": nil}}})
	}
}

func userMachineTerminalSessionsCreate(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		item, err := service.CreateConfiguredTerminalSession(r.Context(), p.User.ID, r.PathValue("machine_id"), body.Name, r.Header.Get("Idempotency-Key"))
		if userMachineTerminalSessionError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: item})
	}
}

func userMachineTerminalSessionsRename(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		item, err := service.RenameTerminalSession(r.Context(), p.User.ID, r.PathValue("machine_id"), r.PathValue("session_id"), body.Name)
		if userMachineTerminalSessionError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: item})
	}
}

func userMachineTerminalSessionsClose(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		applied, err := service.CloseTerminalSession(r.Context(), p.User.ID, r.PathValue("machine_id"), r.PathValue("session_id"))
		if userMachineTerminalSessionError(w, r, err) {
			return
		}
		if !applied {
			writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]string{"operation_state": "pending"}})
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]string{"operation_state": "applied"}})
	}
}

func userMachineTerminalSessionsDelete(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		applied, err := service.DeleteTerminalSession(r.Context(), p.User.ID, r.PathValue("machine_id"), r.PathValue("session_id"))
		if userMachineTerminalSessionError(w, r, err) {
			return
		}
		if !applied {
			writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]string{"purge_state": "pending"}})
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]string{"purge_state": "purged"}})
	}
}

func userMachineTerminalSessionError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, usermachines.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
	case errors.Is(err, usermachines.ErrTerminalSessionNotFound):
		writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
	case errors.Is(err, usermachines.ErrTerminalSessionReserved):
		writeError(w, r, http.StatusConflict, "terminal_session_reserved", "The default terminal session cannot be changed this way.")
	case errors.Is(err, usermachines.ErrTerminalSessionLimit):
		writeError(w, r, http.StatusConflict, "terminal_session_limit_reached", "This machine has reached its terminal session limit.")
	case errors.Is(err, usermachines.ErrTerminalSessionConflict):
		writeError(w, r, http.StatusConflict, "terminal_session_name_conflict", "A terminal session already uses that name.")
	case errors.Is(err, usermachines.ErrTerminalSessionInvalidName):
		writeError(w, r, http.StatusBadRequest, "invalid_terminal_session_name", "Terminal session name is invalid.")
	case errors.Is(err, usermachines.ErrTerminalSessionIdempotency):
		writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required.")
	case errors.Is(err, usermachines.ErrMachineCapabilityUnavailable):
		writeError(w, r, http.StatusConflict, "machine_capability_unavailable", "This machine is not configured to host terminals.")
	case errors.Is(err, usermachines.ErrMachineOffline):
		writeError(w, r, http.StatusConflict, "machine_offline", "This terminal host is offline.")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
	}
	return true
}

func userMachineDisconnect(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		if err := service.Disconnect(r.Context(), p.User.ID, r.PathValue("machine_id")); err != nil {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]bool{"disconnected": true}})
	}
}

func machineUnpair(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok || principal.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		machine, err := service.Unpair(r.Context(), principal.User.ID, r.PathValue("machine_id"))
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "machine_not_found", "Machine was not found.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "machine_unpair_failed", "Unable to unpair this machine.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: machine})
	}
}

func userMachineDelete(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		if err := service.Delete(r.Context(), p.User.ID, r.PathValue("machine_id")); err != nil {
			if errors.Is(err, usermachines.ErrNotFound) {
				writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
				return
			}
			slog.Error("delete user machine failed", "error", err, "machine_id", r.PathValue("machine_id"))
			writeError(w, r, http.StatusInternalServerError, "user_machine_delete_failed", "Unable to delete this machine.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]bool{"deleted": true}})
	}
}
