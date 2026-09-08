package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

type teamHTTPStub struct {
	teamAPI
	calls   int
	account string
	request teams.CreateRequest
}

func (s *teamHTTPStub) Create(_ context.Context, account string, in teams.CreateRequest) (teams.Team, error) {
	s.calls++
	s.account = account
	s.request = in
	return teams.Team{TeamID: in.TeamID, OwnerAccount: account}, nil
}
func TestTeamHTTPPrincipalAndStrictBody(t *testing.T) {
	s := &teamHTTPStub{}
	mux := http.NewServeMux()
	pass := func(h http.Handler) http.Handler { return h }
	registerTeamRoutes(mux, s, pass, pass)
	for _, tc := range []struct {
		name, body    string
		authenticated bool
		status        int
	}{
		{"anonymous", `{"operation_id":"op_a","team_id":"team_a"}`, false, 401},
		{"actor substitution", `{"operation_id":"op_a","team_id":"team_a","account_id":"victim"}`, true, 400},
		{"bounded body", `{"operation_id":"op_a","team_id":"` + strings.Repeat("a", 17<<10) + `"}`, true, 400},
		{"authenticated create", `{"operation_id":"op_a","team_id":"team_a"}`, true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/teams", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			if tc.authenticated {
				r = r.WithContext(context.WithValue(r.Context(), authContextKey{}, principal{User: auth.User{ID: "current_actor"}}))
			}
			w := httptest.NewRecorder()
			before := s.calls
			mux.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			if tc.status != 200 && s.calls != before {
				t.Fatal("invalid request reached service")
			}
		})
	}
	if s.calls != 1 || s.account != "current_actor" || s.request.TeamID != "team_a" {
		t.Fatal("authenticated principal or exact resource lost")
	}
}
