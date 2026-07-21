package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

func adminRecoverHostedProviderOperation(service *controlplane.HostedProviderRecoveryService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if key == "" {
			writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required.")
			return
		}
		var input struct {
			Action            string `json:"action"`
			EvidenceReference string `json:"evidence_reference"`
		}
		if !decodeStrictJSON(w, r, &input) {
			return
		}
		if err := service.Recover(r.Context(), principal.User.ID, key, r.PathValue("operation_id"), input.Action, input.EvidenceReference); err != nil {
			switch {
			case errors.Is(err, controlplane.ErrRecoveryKeyConflict):
				writeError(w, r, http.StatusConflict, "idempotency_key_conflict", "Recovery key conflicts with an existing action.")
			case errors.Is(err, controlplane.ErrHostedProviderOperationNotRecoverable):
				writeError(w, r, http.StatusConflict, "operation_not_recoverable", "Hosted provider operation is not uncertain or is not a secret deletion.")
			default:
				writeError(w, r, http.StatusBadRequest, "invalid_request", "Hosted provider recovery request is invalid.")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
