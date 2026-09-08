package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/environment"
)

type environmentMachinePrincipalKey struct{}

type environmentMachinePrincipal struct {
	AccountID   string
	MachineID   string
	OperationID string
}

// environmentEnrollmentMachineOrHuman accepts the existing human/device
// authentication path or an existing signed machine-control proof. The raw
// body is restored after proof verification so both paths parse identical JSON.
func environmentEnrollmentMachineOrHuman(verifier machineEndpointProofVerifier, human, machine http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Proof")) == "" {
			human.ServeHTTP(w, r)
			return
		}
		if verifier == nil {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine identity proof was rejected.")
			return
		}
		maxBody := int64(32 << 10)
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		proof, proofErr := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Proof")))
		scheme, credential, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		if err != nil || int64(len(body)) > maxBody || proofErr != nil || len(proof) == 0 || !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(credential) == "" {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine identity proof was rejected.")
			return
		}
		claims, err := verifier.VerifyMachineRequest(r.Context(), strings.TrimSpace(credential), proof, r.Method, r.URL.Path, body)
		if err != nil || claims.UserID == "" || claims.MachineID == "" {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine identity proof was rejected.")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		ctx := context.WithValue(r.Context(), environmentMachinePrincipalKey{}, environmentMachinePrincipal{AccountID: claims.UserID, MachineID: claims.MachineID, OperationID: claims.OperationID})
		machine.ServeHTTP(w, r.WithContext(ctx))
	})
}

type environmentVariableAPI interface {
	PasswordVaultIssuer() string
	GetPasswordVault(context.Context, string) (environment.PasswordVaultHead, error)
	PutPasswordVault(context.Context, string, []byte) (environment.PasswordVaultHead, error)
}

func environmentPasswordVaultGet(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		head, err := service.GetPasswordVault(r.Context(), p.User.ID)
		if err != nil {
			if errors.Is(err, environment.ErrNotFound) {
				writeErrorDetails(w, r, http.StatusNotFound, "not_found", "ENV credential vault has not been initialized.", map[string]any{"issuer": service.PasswordVaultIssuer()})
				return
			}
			writeEnvironmentError(w, r, err)
			return
		}
		w.Header().Set("ETag", `"`+head.DocumentID+`"`)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: head})
	}
}

func environmentPasswordVaultPut(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		limitEnvironmentJSON(w, r, 360<<10)
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body struct {
			Envelope string `json:"envelope"`
		}
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		raw, err := environment.DecodeCanonicalBase64URL(body.Envelope, environment.MaximumPasswordVaultBytes)
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		head, err := service.PutPasswordVault(r.Context(), p.User.ID, raw)
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		w.Header().Set("ETag", `"`+head.DocumentID+`"`)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: head})
	}
}

func limitEnvironmentJSON(w http.ResponseWriter, r *http.Request, max int64) {
	r.Body = http.MaxBytesReader(w, r.Body, max)
}

func writeEnvironmentError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := 500, "internal_error", "ENV Injection operation failed."
	details := map[string]any{}
	switch {
	case errors.Is(err, environment.ErrProtocolInvalid), errors.Is(err, environment.ErrProtocolSignature), errors.Is(err, environment.ErrInvalidScope), errors.Is(err, environment.ErrInvalidName), errors.Is(err, environment.ErrLimitExceeded), errors.Is(err, environment.ErrObservationInvalid):
		status, code, message = 400, "validation_failed", "ENV Injection request is invalid."
	case errors.Is(err, environment.ErrPrecondition):
		status, code, message = 412, "precondition_failed", "ENV Injection precondition failed."
	case errors.Is(err, environment.ErrNotFound), errors.Is(err, environment.ErrMachineNotFound):
		status, code, message = 404, "not_found_or_forbidden", "ENV Injection resource was not found."
	case errors.Is(err, environment.ErrMachineNotHost):
		status, code, message = 422, "machine_not_host", "ENV Injection is available only for host machines."
	case errors.Is(err, environment.ErrVersionConflict):
		status, code, message = 409, "version_conflict", "ENV scope changed; fetch it and retry."
		var c *environment.VersionConflictError
		if errors.As(err, &c) {
			details["current_version"] = c.CurrentVersion
		}
	case errors.Is(err, environment.ErrPasswordVaultConflict):
		status, code, message = 409, "vault_conflict", "ENV password vault changed; fetch it and retry."
	case errors.Is(err, environment.ErrAuthorityConflict):
		status, code, message = 409, "authority_conflict", "ENV authority changed; fetch it and retry."
	case errors.Is(err, environment.ErrTransitionInProgress):
		status, code, message = 409, "transition_in_progress", "An ENV authority transition is already in progress."
	case errors.Is(err, environment.ErrOperationConflict):
		status, code, message = 409, "operation_conflict", "The ENV operation ID is already bound to different bytes."
	case errors.Is(err, environment.ErrKeyAuthorizationRequired):
		status, code, message = 409, "key_authorization_required", "A trusted ENV manager must authorize this key."
	case errors.Is(err, environment.ErrAuthorityFork), errors.Is(err, environment.ErrRootSetChanged):
		status, code, message = 409, "authority_fork", "ENV authority continuity could not be verified."
	case errors.Is(err, environment.ErrEnrollmentExpired):
		status, code, message = 409, "enrollment_expired", "ENV key enrollment expired."
	case errors.Is(err, environment.ErrRequesterMismatch):
		status, code, message = 403, "forbidden", "Only the enrollment requester may complete proof."
	}
	writeErrorDetails(w, r, status, code, message, details)
}
