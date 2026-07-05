package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestAuthLoginMeCSRFLogoutAndAudit(t *testing.T) {
	store, router := newAuthIntegrationRouter(t)
	state := authState(t, router)
	login := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/workos/callback", strings.NewReader(`{"code":"workos_test:login@example.com:Login User","state":"`+state.Value+`"}`))
	req.AddCookie(state.Cookie)
	router.ServeHTTP(login, req)
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()

	me := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/me", nil)
	addCookies(req, cookies)
	router.ServeHTTP(me, req)
	if me.Code != http.StatusOK {
		t.Fatalf("me status = %d, body = %s", me.Code, me.Body.String())
	}
	if !strings.Contains(me.Body.String(), "login@example.com") {
		t.Fatalf("me body missing user email: %s", me.Body.String())
	}

	csrf := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/auth/csrf", nil)
	addCookies(req, cookies)
	router.ServeHTTP(csrf, req)
	if csrf.Code != http.StatusOK {
		t.Fatalf("csrf status = %d, body = %s", csrf.Code, csrf.Body.String())
	}
	csrfToken := csrfCookie(t, cookies)

	logout := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfToken)
	router.ServeHTTP(logout, req)
	if logout.Code != http.StatusOK {
		t.Fatalf("logout status = %d, body = %s", logout.Code, logout.Body.String())
	}

	var auditCount int
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT count(*) FROM paperboat.audit_events WHERE event_type IN ('auth.login', 'auth.logout')`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount < 2 {
		t.Fatalf("audit event count = %d, want at least 2", auditCount)
	}
}

func TestWorkOSCallbackRejectsMissingState(t *testing.T) {
	_, router := newAuthIntegrationRouter(t)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/workos/callback", strings.NewReader(`{"code":"workos_test:login@example.com:Login User"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("callback without state status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCookieWriteRequiresCSRFAndActiveEntitlement(t *testing.T) {
	store, router := newAuthIntegrationRouter(t)
	cookies := loginCookies(t, router, "workos_payment:payment@example.com:Payment User")

	missingCSRF := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects", strings.NewReader(`{}`))
	addCookies(req, cookies)
	router.ServeHTTP(missingCSRF, req)
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d, body = %s", missingCSRF.Code, missingCSRF.Body.String())
	}

	noPlan := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects", strings.NewReader(`{}`))
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(noPlan, req)
	if noPlan.Code != http.StatusPaymentRequired {
		t.Fatalf("no plan status = %d, body = %s", noPlan.Code, noPlan.Body.String())
	}

	userID := userIDByEmail(t, store, "payment@example.com")
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.subscriptions (id, user_id, provider, provider_subscription_id, state, current_period_end)
VALUES ($1, $2, 'polar', $3, 'active', $4)`,
		"sub_"+userID, userID, "polar_"+userID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	withPlan := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects", strings.NewReader(`{}`))
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(withPlan, req)
	if withPlan.Code != http.StatusNotImplemented {
		t.Fatalf("with plan status = %d, body = %s", withPlan.Code, withPlan.Body.String())
	}
}

func TestProjectOwnershipDeniesCrossUserAccess(t *testing.T) {
	store, router := newAuthIntegrationRouter(t)
	cookiesA := loginCookies(t, router, "workos_owner_a:owner-a@example.com:Owner A")
	_ = loginCookies(t, router, "workos_owner_b:owner-b@example.com:Owner B")
	userA := userIDByEmail(t, store, "owner-a@example.com")
	userB := userIDByEmail(t, store, "owner-b@example.com")
	projectID := "project_auth_owner_test_" + strings.ReplaceAll(userB, "_", "")
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.projects (id, user_id, name, state, idempotency_key)
VALUES ($1, $2, 'Other User Project', 'ready', $3)`, projectID, userB, "owner-test-"+projectID); err != nil {
		t.Fatal(err)
	}
	service := auth.NewService(store, audit.NewWriter(store), auth.FakeWorkOSVerifier{}, []string{"test-session-key"}, false)
	owns, err := service.OwnsProject(context.Background(), userA, projectID)
	if err != nil {
		t.Fatal(err)
	}
	if owns {
		t.Fatal("cross-user project ownership returned true")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	addCookies(req, cookiesA)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner A session status = %d", rec.Code)
	}
}

func newAuthIntegrationRouter(t *testing.T) (*db.DB, http.Handler) {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run auth integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	service := auth.NewService(store, audit.NewWriter(store), auth.FakeWorkOSVerifier{}, []string{"test-session-key"}, false)
	cfg := config.Default()
	return store, NewRouter(Options{
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessChecker: readinessFunc(func(context.Context) error {
			return nil
		}),
		Auth: service,
	})
}

func loginCookies(t *testing.T, router http.Handler, code string) []*http.Cookie {
	t.Helper()
	state := authState(t, router)
	body, _ := json.Marshal(map[string]string{"code": code, "state": state.Value})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/workos/callback", bytes.NewReader(body))
	req.AddCookie(state.Cookie)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	return rec.Result().Cookies()
}

type issuedState struct {
	Value  string
	Cookie *http.Cookie
}

func authState(t *testing.T, router http.Handler) issuedState {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/workos/state", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("state status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data struct {
			State string `json:"state"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == auth.OAuthStateCookieName {
			return issuedState{Value: payload.Data.State, Cookie: cookie}
		}
	}
	t.Fatal("missing oauth state cookie")
	return issuedState{}
}

func addCookies(req *http.Request, cookies []*http.Cookie) {
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
}

func csrfCookie(t *testing.T, cookies []*http.Cookie) string {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == auth.CSRFCookieName {
			return cookie.Value
		}
	}
	t.Fatal("missing csrf cookie")
	return ""
}

func userIDByEmail(t *testing.T, store *db.DB, email string) string {
	t.Helper()
	var id string
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT id FROM paperboat.users WHERE primary_email = $1 ORDER BY created_at DESC LIMIT 1`, email).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
