package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/classifier"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

func configClassification(service *controlplane.ConfigClassificationService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
		if err != nil || len(body) > 64<<10 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeError(w, r, http.StatusBadRequest, "classification_invalid", "Classification metadata is invalid.")
			return
		}
		var input struct {
			Candidates []classifier.Candidate `json:"candidates"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
			writeError(w, r, http.StatusBadRequest, "classification_invalid", "Classification metadata is invalid.")
			return
		}
		proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
		identity := strings.TrimSpace(r.Header.Get("X-Paperboat-Helper-Identity"))
		credential, credentialOK := bearerToken(r)
		if proofErr != nil || identity == "" || !credentialOK {
			writeError(w, r, http.StatusUnauthorized, "classification_invalid", "Classification authorization is invalid.")
			return
		}
		response, err := service.Classify(r.Context(), identity, credential, proof, body, r.Method, r.URL.Path, input.Candidates)
		switch {
		case errors.Is(err, classifier.ErrRateLimited):
			writeError(w, r, http.StatusTooManyRequests, "rate_limited", "Classification request budget is exhausted.")
		case err != nil:
			writeError(w, r, http.StatusBadRequest, "classification_invalid", "Classification metadata is invalid.")
		default:
			noStore(w)
			writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
		}
	}
}
