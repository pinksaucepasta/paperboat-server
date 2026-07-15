package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTerminalSessionMutationsRequirePrincipal(t *testing.T) {
	handlers := map[string]http.Handler{
		"rename": terminalSessionsRename(nil),
		"close":  terminalSessionsClose(nil),
		"delete": terminalSessionsDelete(nil),
	}
	for name, handler := range handlers {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/projects/prj_1/terminal-sessions/pts_1", nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d", response.Code)
			}
			var payload ErrorResponse
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload.Error.Code != "unauthenticated" {
				t.Fatalf("error code = %q", payload.Error.Code)
			}
		})
	}
}
