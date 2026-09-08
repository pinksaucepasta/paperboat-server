package httpapi

import (
	"context"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/lazyaccess"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type lazyPolicyStub struct {
	LazyPolicyAPI
	calls   int
	account string
}

func (s *lazyPolicyStub) Upsert(_ context.Context, account string, in lazyaccess.UpsertRequest) (lazyaccess.Policy, error) {
	s.calls++
	s.account = account
	return lazyaccess.Policy{ID: "policy_fixture"}, nil
}
func TestLazyPolicyPrincipalAndBoundedJSON(t *testing.T) {
	s := &lazyPolicyStub{}
	mux := http.NewServeMux()
	pass := func(h http.Handler) http.Handler { return h }
	registerLazyPolicyRoutes(mux, s, pass, pass)
	for _, tc := range []struct {
		body          string
		authenticated bool
		status        int
	}{
		{`{}`, false, 401},
		{`{"account_id":"victim"}`, true, 400},
		{`{"machine_id":"a","machine_id":"b"}`, true, 400},
		{`{"machine_id":"` + strings.Repeat("a", 17<<10) + `"}`, true, 400},
		{`{"machine_id":"machine_fixture","target":{"scheme":"http","address":"127.0.0.1:3000"},"access_mode":"private"}`, true, 200},
	} {
		r := httptest.NewRequest(http.MethodPut, "/v1/lazy-policies", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		if tc.authenticated {
			r = r.WithContext(context.WithValue(r.Context(), authContextKey{}, principal{User: auth.User{ID: "owner_fixture"}}))
		}
		w := httptest.NewRecorder()
		before := s.calls
		mux.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("status=%d want=%d", w.Code, tc.status)
		}
		if tc.status != 200 && before != s.calls {
			t.Fatal("invalid request reached policy store")
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("policy response must not be cached")
		}
	}
	if s.calls != 1 || s.account != "owner_fixture" {
		t.Fatal("owner identity not taken from authenticated principal")
	}
}
