package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

func helperRevocations(edge *controlplane.EdgeService, identities *controlplane.EnrollmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var input struct{}
		var extra any
		if decoder.Decode(&input) != nil || decoder.Decode(&extra) != io.EOF {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		parts := strings.Fields(r.Header.Get("Authorization"))
		proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || proofErr != nil || len(proof) == 0 {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Helper identity is invalid.")
			return
		}
		if _, err = identities.VerifyHelperRequest(r.Context(), parts[1], proof, r.Method, r.URL.Path, body); err != nil {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Helper identity is invalid.")
			return
		}
		document, err := edge.Revocations(r.Context())
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Revocation state is temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			JTIs []string `json:"jtis"`
		}{JTIs: document.JTIs})
	}
}
