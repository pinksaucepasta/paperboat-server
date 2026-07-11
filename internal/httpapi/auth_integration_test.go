package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
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

func TestCSRFEndpointBootstrapsMissingCSRFCookie(t *testing.T) {
	_, router := newAuthIntegrationRouter(t)
	cookies := loginCookies(t, router, "workos_cli_csrf:cli-csrf@example.com:CLI CSRF")
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == auth.SessionCookieName {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("missing session cookie")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/csrf", nil)
	req.AddCookie(sessionCookie)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("csrf status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var gotCSRF, gotSession bool
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == auth.CSRFCookieName && cookie.Value != "" {
			gotCSRF = true
		}
		if cookie.Name == auth.SessionCookieName {
			gotSession = true
		}
	}
	if !gotCSRF || gotSession {
		t.Fatalf("expected csrf cookie without session rotation, got %#v", rec.Result().Cookies())
	}
	if !strings.Contains(rec.Body.String(), `"csrf_token"`) {
		t.Fatalf("csrf response missing token: %s", rec.Body.String())
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

func TestFreeEntitlementProvisionsCreditsAndStorage(t *testing.T) {
	store, router := newAuthIntegrationRouter(t)
	seedFreePlan(t, store, "10", 10)
	cookies := loginCookies(t, router, "workos_free:free@example.com:Free User")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	addCookies(req, cookies)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("free entitlement status = %d, body = %s", rec.Code, rec.Body.String())
	}

	userID := userIDByEmail(t, store, "free@example.com")
	var balance string
	var includedGB int
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT ca.balance::text, sa.included_gb
FROM paperboat.credit_accounts ca
JOIN paperboat.storage_accounts sa ON sa.user_id = ca.user_id
WHERE ca.user_id = $1`, userID).Scan(&balance, &includedGB); err != nil {
		t.Fatal(err)
	}
	if balance != "10.000000" || includedGB != 10 {
		t.Fatalf("free resources = balance %s storage %d", balance, includedGB)
	}

	again := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	addCookies(req, cookies)
	router.ServeHTTP(again, req)
	if again.Code != http.StatusNotImplemented {
		t.Fatalf("second free entitlement status = %d, body = %s", again.Code, again.Body.String())
	}
	var creditEntries, storageEntries int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.credit_ledger_entries WHERE account_id = (SELECT id FROM paperboat.credit_accounts WHERE user_id = $1)`, userID).Scan(&creditEntries); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.storage_ledger_entries WHERE account_id = (SELECT id FROM paperboat.storage_accounts WHERE user_id = $1)`, userID).Scan(&storageEntries); err != nil {
		t.Fatal(err)
	}
	if creditEntries != 1 || storageEntries != 1 {
		t.Fatalf("free ledger entries = credits %d storage %d, want 1/1", creditEntries, storageEntries)
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

func TestAdminBillingAdjustmentsRequireAdminAndWriteLedger(t *testing.T) {
	store, router := newAuthIntegrationRouter(t)
	adminCookies := loginCookies(t, router, "workos_admin:admin@example.com:Admin User")
	targetCookies := loginCookies(t, router, "workos_target:target@example.com:Target User")
	adminID := userIDByEmail(t, store, "admin@example.com")
	targetID := userIDByEmail(t, store, "target@example.com")
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.users SET role = 'admin' WHERE id = $1`, adminID); err != nil {
		t.Fatal(err)
	}

	denied := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+targetID+"/adjust-credits", strings.NewReader(`{"amount":"5","reason":"test"}`))
	addCookies(req, targetCookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, targetCookies))
	req.Header.Set("Idempotency-Key", "admin-denied-"+targetID)
	router.ServeHTTP(denied, req)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, body = %s", denied.Code, denied.Body.String())
	}

	credits := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/admin/users/"+targetID+"/adjust-credits", strings.NewReader(`{"amount":"7.5","reason":"support correction"}`))
	addCookies(req, adminCookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, adminCookies))
	req.Header.Set("Idempotency-Key", "admin-credit-"+targetID)
	router.ServeHTTP(credits, req)
	if credits.Code != http.StatusOK {
		t.Fatalf("credit adjustment status = %d, body = %s", credits.Code, credits.Body.String())
	}

	storage := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/admin/users/"+targetID+"/adjust-storage", strings.NewReader(`{"purchased_gb":3,"reason":"support correction"}`))
	addCookies(req, adminCookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, adminCookies))
	req.Header.Set("Idempotency-Key", "admin-storage-"+targetID)
	router.ServeHTTP(storage, req)
	if storage.Code != http.StatusOK {
		t.Fatalf("storage adjustment status = %d, body = %s", storage.Code, storage.Body.String())
	}

	var balance string
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT balance::text FROM paperboat.credit_accounts WHERE user_id = $1`, targetID).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if balance != "7.500000" {
		t.Fatalf("balance = %s", balance)
	}
	var purchased int
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT purchased_gb FROM paperboat.storage_accounts WHERE user_id = $1`, targetID).Scan(&purchased); err != nil {
		t.Fatal(err)
	}
	if purchased != 3 {
		t.Fatalf("purchased_gb = %d", purchased)
	}
}

func TestSafeIntegrationTestDSNRequiresTestLikeDatabaseName(t *testing.T) {
	for _, dsn := range []string{
		"postgres://user:pass@localhost/paperboat_test?sslmode=disable",
		"postgres://user:pass@localhost/paperboat_dev?sslmode=disable",
		"postgres://user:pass@localhost/paperboat_local?sslmode=disable",
	} {
		if !safeIntegrationTestDSN(dsn) {
			t.Fatalf("dsn %q should be considered safe for integration tests", dsn)
		}
	}
	for _, dsn := range []string{
		"postgres://user:pass@localhost/paperboat_prod?sslmode=disable",
		"postgres://user:pass@localhost/postgres?sslmode=disable",
		"not a dsn",
	} {
		if safeIntegrationTestDSN(dsn) {
			t.Fatalf("dsn %q should not be considered safe for integration tests", dsn)
		}
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
	resetIntegrationTables(t, store)
	auditWriter := audit.NewWriter(store)
	service := auth.NewService(store, auditWriter, auth.FakeWorkOSVerifier{}, []string{"test-session-key"}, false)
	deviceService := auth.NewDeviceService(store, auditWriter, config.Default().CLIAuth, []string{"test-device-hash-key"})
	billingService := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, auditWriter)
	cfg := config.Default()
	return store, NewRouter(Options{
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessChecker: readinessFunc(func(context.Context) error {
			return nil
		}),
		Auth:       service,
		DeviceAuth: deviceService,
		Billing:    billingService,
	})
}

func seedFreePlan(t *testing.T, store *db.DB, credits string, storageGB int) {
	t.Helper()
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.plans (id, code, name, active, current_version_id)
VALUES ('plan_free', 'free', 'Free', true, 'pv_free')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.plan_versions (id, plan_id, version_number, included_credits, included_storage_gb)
VALUES ('pv_free', 'plan_free', 1, $1::numeric, $2)`, credits, storageGB); err != nil {
		t.Fatal(err)
	}
}

func resetIntegrationTables(t *testing.T, store *db.DB) {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if !safeIntegrationTestDSN(dsn) && os.Getenv("PAPERBOAT_ALLOW_DESTRUCTIVE_TEST_DB_RESET") != "true" {
		t.Fatalf("refusing to truncate paperboat schema for unsafe PAPERBOAT_TEST_DATABASE_DSN; use a database name containing test/dev/local or set PAPERBOAT_ALLOW_DESTRUCTIVE_TEST_DB_RESET=true")
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
DO $$
DECLARE
	tables text;
BEGIN
	SELECT string_agg(format('%I.%I', schemaname, tablename), ', ')
	INTO tables
	FROM pg_tables
	WHERE schemaname = 'paperboat'
	  AND tablename NOT IN ('schema_migrations', 'goose_db_version');

	IF tables IS NOT NULL THEN
		EXECUTE 'TRUNCATE TABLE ' || tables || ' CASCADE';
	END IF;
END $$;`); err != nil {
		t.Fatal(err)
	}
}

func safeIntegrationTestDSN(dsn string) bool {
	u, err := url.Parse(dsn)
	if err != nil {
		return false
	}
	database := strings.Trim(strings.TrimSpace(u.Path), "/")
	if database == "" {
		return false
	}
	name := strings.ToLower(database)
	for _, marker := range []string{"test", "dev", "local"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
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
