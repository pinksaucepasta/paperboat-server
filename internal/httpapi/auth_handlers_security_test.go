package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
)

func TestWorkOSCallbackRequiresExactTrustedOriginBeforeProcessing(t *testing.T) {
	service := auth.NewService(nil, nil, nil, []string{"test-key"}, true, "https://login.pprbt.dev")
	handler := workOSCallback(service)
	for _, tc := range []struct {
		name   string
		origin string
		code   int
	}{
		{name: "missing", code: http.StatusForbidden},
		{name: "different", origin: "https://evil.example", code: http.StatusForbidden},
		{name: "exact reaches body validation", origin: "https://login.pprbt.dev", code: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/v1/auth/workos/callback", strings.NewReader("not-json"))
			request.Header.Set("Origin", tc.origin)
			handler.ServeHTTP(recorder, request)
			if recorder.Code != tc.code {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestRequireAuthRejectsUnsafeRequestWithoutTrustedOrigin(t *testing.T) {
	service := auth.NewService(nil, nil, nil, nil, true, "https://login.pprbt.dev")
	handler := requireAuth(service, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler ran")
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/v1/resource", nil))
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), `"origin_failed"`) {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}
