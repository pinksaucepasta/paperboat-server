package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

func helperIdentityRenew(service *controlplane.EnrollmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		var input struct {
			OperationID string `json:"operation_id"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&input) != nil || decoder.Decode(&extra) != io.EOF || len(input.OperationID) < 8 || len(input.OperationID) > 128 {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		parts := strings.Fields(r.Header.Get("Authorization"))
		proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 16<<10 || proofErr != nil {
			noStore(w)
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Helper identity renewal is unavailable.")
			return
		}
		identity, err := service.Renew(r.Context(), parts[1], proof, body)
		if err != nil {
			status, code := http.StatusUnauthorized, "credential_invalid"
			if errors.Is(err, controlplane.ErrUsageOperationConflict) {
				status, code = http.StatusConflict, "operation_id_conflict"
			}
			noStore(w)
			writeError(w, r, status, code, "Helper identity renewal is unavailable.")
			return
		}
		noStore(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: identity})
	}
}

func helperEnrollmentIssue(service *controlplane.EnrollmentService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		grant, err := service.Issue(r.Context(), principal.User.ID, operationKey, r.PathValue("environment_id"), 10*time.Minute)
		if err != nil {
			if errors.Is(err, controlplane.ErrUsageOperationConflict) {
				writeError(w, r, http.StatusConflict, "idempotency_key_conflict", "Idempotency-Key conflicts with an existing enrollment request.")
				return
			}
			writeError(w, r, http.StatusNotFound, "not_found_or_forbidden", "Environment was not found or is unavailable.")
			return
		}
		noStore(w)
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: grant})
	})
}

func helperReplacement(service *controlplane.EnrollmentService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		var input struct {
			EdgePool string `json:"edge_pool"`
		}
		if !decodeStrictJSON(w, r, &input) {
			return
		}
		replacement, err := service.ReplaceHelper(r.Context(), principal.User.ID, operationKey, r.PathValue("environment_id"), r.PathValue("helper_id"), input.EdgePool)
		if err != nil {
			if errors.Is(err, controlplane.ErrUsageOperationConflict) {
				writeError(w, r, http.StatusConflict, "idempotency_key_conflict", "Idempotency-Key conflicts with an existing replacement request.")
				return
			}
			writeError(w, r, http.StatusNotFound, "not_found_or_forbidden", "Helper was not found or is unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: replacement})
	})
}

func helperEnrollmentExchange(service *controlplane.EnrollmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Credential string `json:"credential"`
			PublicKey  string `json:"public_key"`
		}
		if !decodeStrictJSON(w, r, &input) {
			return
		}
		publicKey, decodeErr := base64.RawURLEncoding.DecodeString(input.PublicKey)
		if decodeErr != nil {
			noStore(w)
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Helper enrollment is unavailable.")
			return
		}
		identity, err := service.Exchange(r.Context(), input.Credential, publicKey)
		if err != nil {
			status, code := http.StatusUnauthorized, "credential_invalid"
			if errors.Is(err, controlplane.ErrEnrollmentUsed) {
				status, code = http.StatusConflict, "credential_replayed"
			}
			noStore(w)
			writeError(w, r, status, code, "Helper enrollment is unavailable.")
			return
		}
		noStore(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: identity})
	}
}
