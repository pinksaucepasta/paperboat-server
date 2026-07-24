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

func hostedBootstrapGet(service *controlplane.HostedBootstrapService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeError(w, r, http.StatusBadRequest, "hosted_bootstrap_invalid", "Hosted bootstrap request is invalid.")
			return
		}
		var input struct{}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
			writeError(w, r, http.StatusBadRequest, "hosted_bootstrap_invalid", "Hosted bootstrap request is invalid.")
			return
		}
		proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
		identity, ok := bearerToken(r)
		if proofErr != nil || !ok {
			writeError(w, r, http.StatusUnauthorized, "hosted_bootstrap_invalid", "Hosted bootstrap authorization is invalid.")
			return
		}
		bootstrap, err := service.Get(r.Context(), identity, proof, body, r.Method, r.URL.Path)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "hosted_bootstrap_invalid", "Hosted bootstrap authorization is invalid.")
			return
		}
		noStore(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: bootstrap})
	}
}
