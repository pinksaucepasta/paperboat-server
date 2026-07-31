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

func configRepositoryAccessIssue(service *controlplane.ConfigRepositoryAccessService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeError(w, r, http.StatusBadRequest, "access_invalid", "Repository access request is invalid.")
			return
		}
		var input struct {
			OperationID string `json:"operation_id"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
			writeError(w, r, http.StatusBadRequest, "access_invalid", "Repository access request is invalid.")
			return
		}
		proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
		identity := strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Identity"))
		credential, credentialOK := bearerToken(r)
		if proofErr != nil || identity == "" || !credentialOK {
			writeError(w, r, http.StatusUnauthorized, "access_invalid", "Repository access authorization is invalid.")
			return
		}
		access, err := service.Issue(r.Context(), identity, credential, proof, body, r.Method, r.URL.Path, strings.TrimSpace(input.OperationID))
		switch {
		case errors.Is(err, controlplane.ErrConfigRepositoryAccessReplay):
			writeError(w, r, http.StatusConflict, "operation_conflict", "Repository access operation conflicts with an earlier request.")
			return
		case errors.Is(err, controlplane.ErrConfigRepositoryAccessUncertain):
			writeError(w, r, http.StatusServiceUnavailable, "access_uncertain", "Repository access issuance outcome is uncertain.")
			return
		case err != nil:
			writeError(w, r, http.StatusUnauthorized, "access_invalid", "Repository access authorization is invalid.")
			return
		}
		noStore(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: access})
	}
}
