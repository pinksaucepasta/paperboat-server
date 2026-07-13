package httpapi

import (
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/configsync"
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
