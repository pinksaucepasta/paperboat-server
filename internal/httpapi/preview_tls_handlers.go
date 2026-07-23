package httpapi

import (
	"context"
	"net/http"
	"strings"
)

type previewCertificateAuthorizer interface {
	CanIssueCertificate(context.Context, string) (bool, error)
}

func previewTLSAsk(authorizer previewCertificateAuthorizer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := strings.TrimSpace(r.URL.Query().Get("domain"))
		allowed, err := authorizer.CanIssueCertificate(r.Context(), domain)
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "preview_certificate_check_unavailable", "Preview certificate authorization is unavailable.")
			return
		}
		if !allowed {
			writeError(w, r, http.StatusNotFound, "preview_not_found", "Preview is unavailable.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
