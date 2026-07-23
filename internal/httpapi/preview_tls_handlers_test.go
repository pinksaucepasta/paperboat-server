package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type previewCertificateAuthorizerFunc func(context.Context, string) (bool, error)

func (f previewCertificateAuthorizerFunc) CanIssueCertificate(ctx context.Context, domain string) (bool, error) {
	return f(ctx, domain)
}

func TestPreviewTLSAskAuthorizesOnlyKnownDomain(t *testing.T) {
	handler := previewTLSAsk(previewCertificateAuthorizerFunc(func(_ context.Context, domain string) (bool, error) {
		return domain == "known.preview.hexwagon.com", nil
	}))

	for _, test := range []struct {
		domain string
		status int
	}{{"known.preview.hexwagon.com", http.StatusNoContent}, {"unknown.preview.hexwagon.com", http.StatusNotFound}, {"", http.StatusNotFound}} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/previews/tls/ask?domain="+test.domain, nil))
		if recorder.Code != test.status {
			t.Fatalf("domain %q status=%d body=%s", test.domain, recorder.Code, recorder.Body.String())
		}
	}
}

func TestPreviewTLSAskFailsClosedWhenStorageUnavailable(t *testing.T) {
	handler := previewTLSAsk(previewCertificateAuthorizerFunc(func(context.Context, string) (bool, error) {
		return false, errors.New("database unavailable")
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/previews/tls/ask?domain=known.preview.hexwagon.com", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
