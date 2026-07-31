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

func configRuntimeGet(service *controlplane.ConfigRuntimeService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeError(w, r, http.StatusBadRequest, "runtime_invalid", "Configuration runtime request is invalid.")
			return
		}
		var input struct{}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
			writeError(w, r, http.StatusBadRequest, "runtime_invalid", "Configuration runtime request is invalid.")
			return
		}
		proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
		identity := strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Identity"))
		credential, ok := bearerToken(r)
		if proofErr != nil || identity == "" || !ok {
			writeError(w, r, http.StatusUnauthorized, "runtime_invalid", "Configuration runtime authorization is invalid.")
			return
		}
		descriptor, err := service.Get(r.Context(), identity, credential, proof, body, r.Method, r.URL.Path)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "runtime_invalid", "Configuration runtime authorization is invalid.")
			return
		}
		noStore(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: descriptor})
	}
}
