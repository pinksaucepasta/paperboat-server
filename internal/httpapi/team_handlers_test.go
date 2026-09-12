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

type machineTeamHTTPStub struct {
	teamAPI
	calls       int
	actor, team string
	grant       teams.MachineGrantRequest
	machine     teams.MachineRequest
}

func (s *machineTeamHTTPStub) GrantMachine(_ context.Context, actor, team string, in teams.MachineGrantRequest) (teams.Team, error) {
	s.calls++
	s.actor = actor
	s.team = team
	s.grant = in
	return teams.Team{TeamID: team}, nil
}
func (s *machineTeamHTTPStub) Machine(_ context.Context, actor, team string, in teams.MachineRequest) (teams.Team, error) {
	s.calls++
	s.actor = actor
	s.team = team
	s.machine = in
	return teams.Team{TeamID: team}, nil
}
func TestTeamMachineHTTPExactResourceAndActor(t *testing.T) {
	s := &machineTeamHTTPStub{}
	mux := http.NewServeMux()
	pass := func(h http.Handler) http.Handler { return h }
	registerTeamRoutes(mux, s, pass, pass)
	for _, tc := range []struct {
		path, body    string
		authenticated bool
		status        int
	}{
		{"/machine-grants", `{"operation_id":"grant","expected_generation":3,"machine_id":"machine_a","audience":"selected_member","account_id":"recipient","capabilities":["exec"],"active":true}`, true, 200},
		{"/machines", `{"operation_id":"share","expected_generation":4,"machine_id":"machine_a","action":"share"}`, true, 200},
		{"/machines", `{"operation_id":"share","expected_generation":4,"machine_id":"machine_a","action":"share","account_id":"victim"}`, true, 400},
		{"/machine-grants", `{"operation_id":"grant"}`, false, 401},
	} {
		r := httptest.NewRequest(http.MethodPost, "/v1/teams/team_a"+tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		if tc.authenticated {
			r = r.WithContext(context.WithValue(r.Context(), authContextKey{}, principal{User: auth.User{ID: "actor"}}))
		}
		w := httptest.NewRecorder()
		before := s.calls
		mux.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s: status %d want %d", tc.path, w.Code, tc.status)
		}
		if tc.status != 200 && s.calls != before {
			t.Fatal("invalid request reached machine service")
		}
	}
	if s.calls != 2 || s.actor != "actor" || s.team != "team_a" || s.grant.AccountID != "recipient" || len(s.grant.Capabilities) != 1 || s.grant.Capabilities[0] != "exec" || s.machine.MachineID != "machine_a" {
		t.Fatal("machine request authority or exact capability lost")
	}
}

type activityTeamHTTPStub struct {
	teamAPI
	calls               int
	actor, team, cursor string
	limit               int
	err                 error
}

func (s *activityTeamHTTPStub) Activity(_ context.Context, actor, team, cursor string, limit int) (teams.ActivityPage, error) {
	s.calls++
	s.actor = actor
	s.team = team
	s.cursor = cursor
	s.limit = limit
	return teams.ActivityPage{Items: []teams.ActivityItem{}}, s.err
}
func TestTeamActivityHTTP(t *testing.T) {
	s := &activityTeamHTTPStub{}
	mux := http.NewServeMux()
	pass := func(h http.Handler) http.Handler { return h }
	registerTeamRoutes(mux, s, pass, pass)
	for _, tc := range []struct {
		query         string
		authenticated bool
		err           error
		status        int
	}{
		{"", false, nil, 401}, {"?limit=201", true, nil, 400}, {"?limit=-1", true, nil, 400}, {"?limit=no", true, nil, 400},
		{"?limit=0", true, nil, 400}, {"?limit=2&cursor=bound", true, nil, 200}, {"", true, teams.ErrForbidden, 403}, {"", true, teams.ErrNotFound, 404},
	} {
		r := httptest.NewRequest(http.MethodGet, "/v1/teams/team_a/activity"+tc.query, nil)
		if tc.authenticated {
			r = r.WithContext(context.WithValue(r.Context(), authContextKey{}, principal{User: auth.User{ID: "current_actor"}}))
		}
		s.err = tc.err
		before := s.calls
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("query=%s status=%d want=%d", tc.query, w.Code, tc.status)
		}
		if tc.status == 400 || tc.status == 401 {
			if before != s.calls {
				t.Fatal("invalid request reached service")
			}
		}
		if tc.status == 200 && (s.actor != "current_actor" || s.team != "team_a" || s.limit != 2 || s.cursor != "bound") {
			t.Fatal("lost principal or pagination")
		}
	}
}
