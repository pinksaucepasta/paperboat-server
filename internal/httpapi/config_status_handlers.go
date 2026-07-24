package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

const maxConfigStatusBytes = 256 << 10

func configStatusRecord(service *controlplane.ConfigStatusService, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, maxConfigStatusBytes+1))
		if err != nil || len(body) > maxConfigStatusBytes || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeError(w, r, http.StatusBadRequest, "status_invalid", "Configuration status is invalid.")
			return
		}
		var report controlplane.ConfigStatusReport
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&report) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
			writeError(w, r, http.StatusBadRequest, "status_invalid", "Configuration status is invalid.")
			return
		}
		proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
		identity, ok := bearerToken(r)
		if proofErr != nil || !ok {
			writeError(w, r, http.StatusUnauthorized, "status_invalid", "Configuration status authorization is invalid.")
			return
		}
		err = service.Record(r.Context(), identity, proof, body, r.Method, r.URL.Path, report)
		if errors.Is(err, controlplane.ErrConfigStatusStale) {
			writeError(w, r, http.StatusConflict, "status_revision_stale", "Configuration status revision is stale.")
			return
		}
		if err != nil {
			logger.WarnContext(r.Context(), "configuration status rejected",
				"reason", controlplane.ConfigStatusRejectionClass(err))
			writeError(w, r, http.StatusUnauthorized, "status_invalid", "Configuration status authorization is invalid.")
			return
		}
		noStore(w)
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]any{"sync_revision": report.SyncRevision}})
	}
}
