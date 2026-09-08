package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/environment"
)

func TestEnvironmentRouterExposesOnlyVaultReplacement(t *testing.T) {
	handler := NewRouter(Options{Auth: &auth.Service{}, EnvironmentVariables: &environment.Service{}})
	for _, route := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/v1/environment-vault", http.StatusUnauthorized},
		{"GET", "/v1/environment/scopes/personal/account", http.StatusUnauthorized},
		{"GET", "/v1/environment-variables", http.StatusNotFound},
		{"GET", "/v1/environment-scopes", http.StatusNotFound},
		{"GET", "/v1/environment-manifests/global", http.StatusNotFound},
		{"GET", "/v1/environment-authority", http.StatusNotFound},
		{"POST", "/v1/environment-authority/transitions", http.StatusNotFound},
		{"POST", "/v1/environment-key-enrollments", http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != route.status {
			t.Errorf("%s %s status=%d want=%d", route.method, route.path, response.Code, route.status)
		}
	}
}
