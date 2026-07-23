package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

func helperPreviewCredential(identities *controlplane.EnrollmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Preview credential request is invalid.")
			return
		}
		var input struct{}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Preview credential request is invalid.")
			return
		}
		proof, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Credential is invalid.")
			return
		}
		identityToken, _ := bearerToken(r)
		issued, err := identities.IssuePreviewCredential(r.Context(), identityToken, proof, body, r.Method, r.URL.Path)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Credential is invalid.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: issued})
	}
}
