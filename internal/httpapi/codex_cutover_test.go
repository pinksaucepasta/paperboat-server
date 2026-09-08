package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

func TestCodexSessionRoutesAreRemoved(t *testing.T) {
	router := NewRouter(Options{Config: config.Default()})
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/codex-sessions"},
		{http.MethodGet, "/v1/codex-sessions/codex_1/descriptor"},
		{http.MethodPost, "/v1/codex-sessions/codex_1/renew"},
		{http.MethodDelete, "/v1/codex-sessions/codex_1"},
	}
	for _, test := range tests {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want %d", test.method, test.path, recorder.Code, http.StatusNotFound)
		}
	}
}
