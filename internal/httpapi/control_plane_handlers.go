package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

func adminProvisionUsageKey(service *controlplane.EdgeService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		var input struct {
			KeyID      string    `json:"key_id"`
			EdgeNodeID string    `json:"edge_node_id"`
			PublicKey  string    `json:"public_key"`
			NotBefore  time.Time `json:"not_before"`
			ExpiresAt  time.Time `json:"expires_at"`
		}
		if idempotencyKey == "" || !decodeStrictJSON(w, r, &input) {
			if idempotencyKey == "" {
				writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required.")
			}
			return
		}
		publicKey, err := base64.RawURLEncoding.DecodeString(input.PublicKey)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Usage verification key is invalid.")
			return
		}
		err = service.ProvisionUsageKey(r.Context(), principal.User.ID, idempotencyKey, input.KeyID, input.EdgeNodeID, publicKey, input.NotBefore, input.ExpiresAt)
		if err != nil {
			if errors.Is(err, controlplane.ErrUsageOperationConflict) {
				writeError(w, r, http.StatusConflict, "idempotency_key_conflict", "Usage verification key conflicts with an existing key.")
				return
			}
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Usage verification key could not be provisioned.")
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: map[string]any{"key_id": input.KeyID, "edge_node_id": input.EdgeNodeID, "not_before": input.NotBefore, "expires_at": input.ExpiresAt}})
	})
}

func adminRevokeUsageKey(service *controlplane.EdgeService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		var input struct {
			Reason string `json:"reason"`
		}
		if idempotencyKey == "" || !decodeStrictJSON(w, r, &input) {
			if idempotencyKey == "" {
				writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required.")
			}
			return
		}
		if err := service.RevokeUsageKey(r.Context(), principal.User.ID, idempotencyKey, r.PathValue("key_id"), input.Reason, time.Now().UTC()); err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Usage verification key could not be revoked.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func adminRevokeSigningKey(service *controlplane.EdgeService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		var input struct {
			Reason string `json:"reason"`
		}
		if idempotencyKey == "" || !decodeStrictJSON(w, r, &input) {
			if idempotencyKey == "" {
				writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required.")
			}
			return
		}
		if err := service.RevokeSigningKey(r.Context(), principal.User.ID, idempotencyKey, r.PathValue("key_id"), input.Reason, time.Now().UTC()); err != nil {
			if errors.Is(err, controlplane.ErrUsageOperationConflict) {
				writeError(w, r, http.StatusConflict, "idempotency_key_conflict", "Idempotency-Key conflicts with an existing signing-key revocation.")
				return
			}
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Signing key could not be revoked.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func adminRecoverControlOperation(service *controlplane.OperationRecoveryService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if idempotencyKey == "" {
			writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required.")
			return
		}
		err := service.Recover(r.Context(), principal.User.ID, idempotencyKey, r.PathValue("operation_id"), time.Now().UTC())
		switch {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, controlplane.ErrRecoveryKeyConflict):
			writeError(w, r, http.StatusConflict, "idempotency_key_conflict", "Idempotency-Key conflicts with an existing recovery action.")
		case errors.Is(err, controlplane.ErrOperationNotDeadLettered):
			writeError(w, r, http.StatusConflict, "operation_not_recoverable", "Control operation is not dead-lettered.")
		default:
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Control operation recovery is unavailable.")
		}
	})
}
