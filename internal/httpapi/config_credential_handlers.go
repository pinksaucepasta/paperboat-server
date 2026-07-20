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

func configCredentialIssue(service *controlplane.ConfigCredentialService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if err != nil || len(body) > 1<<20 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request is invalid.")
			return
		}
		var input struct{}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request is invalid.")
			return
		}
		proof, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Credential is invalid.")
			return
		}
		result, err := service.Issue(r.Context(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), proof, body, r.Method, r.URL.Path)
		if err != nil {
			if errors.Is(err, controlplane.ErrConfigCredentialReplay) {
				writeError(w, r, http.StatusConflict, "operation_conflict", "Credential operation conflicts with an existing request.")
				return
			}
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Credential is invalid.")
			return
		}
		noStore(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
	}
}
