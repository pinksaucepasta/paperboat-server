package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
)

var cliScopes = []string{"account:read", "clients:revoke", "projects:read", "projects:connect", "session:refresh"}

func TestDeviceAuthorizationApprovalBearerRefreshAndReplay(t *testing.T) {
	store, router := newAuthIntegrationRouter(t)
	cookies := loginCookies(t, router, "workos_device:device@example.com:Device User")
	if _, err := store.SQL().Exec(`INSERT INTO paperboat.auth_rate_limits(bucket_key,window_start,request_count) VALUES('expired-test',now()-interval '10 minutes',1)`); err != nil {
		t.Fatal(err)
	}
	grant := authorizeDevice(t, router)
	var expiredRateRows int
	if err := store.SQL().QueryRow(`SELECT count(*) FROM paperboat.auth_rate_limits WHERE bucket_key='expired-test'`).Scan(&expiredRateRows); err != nil {
		t.Fatal(err)
	}
	if expiredRateRows != 0 {
		t.Fatal("expired rate-limit window was not deleted")
	}
	requestDetails := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/device/requests/"+grant.UserCode, nil)
	addCookies(req, cookies)
	router.ServeHTTP(requestDetails, req)
	if requestDetails.Code != http.StatusOK {
		t.Fatalf("device request status=%d body=%s", requestDetails.Code, requestDetails.Body.String())
	}
	if requestDetails.Header().Get("Cache-Control") != "no-store" || requestDetails.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("device request cache headers=%q/%q", requestDetails.Header().Get("Cache-Control"), requestDetails.Header().Get("Pragma"))
	}
	if !strings.Contains(requestDetails.Body.String(), `"issuer":"http://127.0.0.1:8080"`) || !strings.Contains(requestDetails.Body.String(), `"email":"device-e2e@example.com"`) {
		t.Fatalf("device request omitted approval authority: %s", requestDetails.Body.String())
	}

	approve := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/device/requests/"+grant.UserCode+"/approve", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(approve, req)
	if approve.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", approve.Code, approve.Body.String())
	}

	tokens := pollDevice(t, router, grant.DeviceCode, http.StatusOK)
	me := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(me, req)
	if me.Code != http.StatusOK {
		t.Fatalf("me status=%d body=%s", me.Code, me.Body.String())
	}
	if !bytes.Contains(me.Body.Bytes(), []byte(`"email":"device@example.com"`)) {
		t.Fatalf("me body missing authenticated CLI user: %s", me.Body.String())
	}

	invalidMe := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	router.ServeHTTP(invalidMe, req)
	if invalidMe.Code != http.StatusUnauthorized {
		t.Fatalf("invalid bearer me status=%d body=%s", invalidMe.Code, invalidMe.Body.String())
	}

	list := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/auth/clients", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(list, req)
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	if bytes.Contains(list.Body.Bytes(), []byte(tokens.AccessToken)) || bytes.Contains(list.Body.Bytes(), []byte(tokens.RefreshToken)) {
		t.Fatal("client list leaked a token")
	}

	refreshed := refreshDevice(t, router, tokens.RefreshToken, http.StatusOK)
	refreshDevice(t, router, tokens.RefreshToken, http.StatusUnauthorized)
	revoked := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/auth/clients", nil)
	req.Header.Set("Authorization", "Bearer "+refreshed.AccessToken)
	router.ServeHTTP(revoked, req)
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("replayed family access status=%d body=%s", revoked.Code, revoked.Body.String())
	}

	var rawSecrets int
	if err := store.SQL().QueryRow(`SELECT count(*) FROM paperboat.device_grants WHERE device_code_hash=$1 OR user_code_hash=$2`, grant.DeviceCode, grant.UserCode).Scan(&rawSecrets); err != nil {
		t.Fatal(err)
	}
	if rawSecrets != 0 {
		t.Fatal("raw device or user code was persisted")
	}
}

func TestDeviceGrantPollConsumptionIsSingleUse(t *testing.T) {
	_, router := newAuthIntegrationRouter(t)
	cookies := loginCookies(t, router, "workos_race:race@example.com:Race User")
	grant := authorizeDevice(t, router)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/device/requests/"+grant.UserCode+"/approve", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status=%d", rec.Code)
	}
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(map[string]any{"client_id": "paperboat-cli", "device_code": grant.DeviceCode})
			r := httptest.NewRequest(http.MethodPost, "/api/auth/device/token", bytes.NewReader(body))
			r.RemoteAddr = "198.51.100.20:1234"
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			statuses <- w.Code
		}()
	}
	wg.Wait()
	close(statuses)
	success := 0
	failure := 0
	for status := range statuses {
		if status == http.StatusOK {
			success++
		} else if status == http.StatusBadRequest {
			failure++
		}
	}
	if success != 1 || failure != 1 {
		t.Fatalf("success=%d failure=%d", success, failure)
	}
}

func TestApprovedDevicePollEnforcesAccountRateLimit(t *testing.T) {
	store, router := newAuthIntegrationRouter(t)
	cookies := loginCookies(t, router, "workos_account_rate:account-rate@example.com:Account Rate")
	grant := authorizeDevice(t, router)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/device/requests/"+grant.UserCode+"/approve", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := store.SQL().Exec(`UPDATE paperboat.auth_rate_limits SET request_count=30 WHERE bucket_key LIKE 'account:%'`); err != nil {
		t.Fatal(err)
	}
	pollDevice(t, router, grant.DeviceCode, http.StatusTooManyRequests)
	var sessions int
	if err := store.SQL().QueryRow(`SELECT count(*) FROM paperboat.client_sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("client sessions=%d, want 0 after rate-limited poll", sessions)
	}
}

func TestApprovedGrantCannotCreateSessionAfterAccountSuspension(t *testing.T) {
	store, router := newAuthIntegrationRouter(t)
	cookies := loginCookies(t, router, "workos_grant_suspend:grant-suspend@example.com:Grant Suspend")
	grant := authorizeDevice(t, router)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/device/requests/"+grant.UserCode+"/approve", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", rec.Code, rec.Body.String())
	}
	userID := userIDByEmail(t, store, "grant-suspend@example.com")
	if _, err := store.SQL().Exec(`UPDATE paperboat.users SET status='suspended' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	pollDevice(t, router, grant.DeviceCode, http.StatusBadRequest)
	if _, err := store.SQL().Exec(`UPDATE paperboat.users SET status='active' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	pollDevice(t, router, grant.DeviceCode, http.StatusBadRequest)
	var sessions int
	if err := store.SQL().QueryRow(`SELECT count(*) FROM paperboat.client_sessions WHERE user_id=$1`, userID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("client sessions=%d want=0", sessions)
	}
	var state string
	if err := store.SQL().QueryRow(`SELECT state FROM paperboat.device_grants WHERE user_id=$1`, userID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "denied" {
		t.Fatalf("grant state=%q want denied", state)
	}
}

func TestUnknownRevokeTokenAndApprovalCodeMatchContract(t *testing.T) {
	_, router := newAuthIntegrationRouter(t)
	cookies := loginCookies(t, router, "workos_unknown_device:unknown-device@example.com:Unknown Device")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/token/revoke", nil)
	req.Header.Set("Authorization", "Bearer unknown-token")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown revoke token status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/auth/device/requests/NOPE-CODE", nil)
	addCookies(req, cookies)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown approval code status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBrowserLogoutKeepsCLIClientActiveAndDeleteReturnsNoContent(t *testing.T) {
	_, router := newAuthIntegrationRouter(t)
	cookies := loginCookies(t, router, "workos_logout_scope:logout-scope@example.com:Logout Scope")
	grant := authorizeDevice(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/device/requests/"+grant.UserCode+"/approve", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", rec.Code, rec.Body.String())
	}
	tokens := pollDevice(t, router, grant.DeviceCode, http.StatusOK)

	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("browser logout status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/auth/clients", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("CLI after browser logout status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/auth/clients/"+tokens.ClientSessionID, nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("delete status=%d body=%q, want empty 204", rec.Code, rec.Body.String())
	}
}

func TestAccountSuspensionPermanentlyRevokesCLIClients(t *testing.T) {
	store, router := newAuthIntegrationRouter(t)
	cookies := loginCookies(t, router, "workos_suspension:suspension@example.com:Suspension")
	grant := authorizeDevice(t, router)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/device/requests/"+grant.UserCode+"/approve", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", rec.Code, rec.Body.String())
	}
	tokens := pollDevice(t, router, grant.DeviceCode, http.StatusOK)
	userID := userIDByEmail(t, store, "suspension@example.com")
	if _, err := store.SQL().Exec(`UPDATE paperboat.users SET status='suspended' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().Exec(`UPDATE paperboat.users SET status='active' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/auth/clients", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("reactivated account reused old CLI token: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var state, reason string
	if err := store.SQL().QueryRow(`SELECT state,coalesce(revocation_reason,'') FROM paperboat.client_sessions WHERE id=$1`, tokens.ClientSessionID).Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	if state != "revoked" || reason != "account_suspended" {
		t.Fatalf("client state=%q reason=%q", state, reason)
	}
}

type deviceGrant struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
}
type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	ClientSessionID string `json:"client_session_id"`
}

func authorizeDevice(t *testing.T, router http.Handler) deviceGrant {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"client_id": "paperboat-cli", "client_label": "Test CLI", "device_type": "desktop", "os": "darwin", "scopes": cliScopes})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/device/authorize", bytes.NewReader(body))
	req.RemoteAddr = "198.51.100.10:1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Data deviceGrant `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data
}
func pollDevice(t *testing.T, router http.Handler, code string, want int) tokenResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"client_id": "paperboat-cli", "device_code": code})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/device/token", bytes.NewReader(body))
	req.RemoteAddr = "198.51.100.11:1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("poll status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
	}
	var envelope struct {
		Data tokenResponse `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &envelope)
	return envelope.Data
}
func refreshDevice(t *testing.T, router http.Handler, token string, want int) tokenResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/token/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("refresh status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
	}
	var envelope struct {
		Data tokenResponse `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &envelope)
	return envelope.Data
}

func authorizeCLI(t *testing.T, router http.Handler, cookies []*http.Cookie) tokenResponse {
	t.Helper()
	grant := authorizeDevice(t, router)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/device/requests/"+grant.UserCode+"/approve", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve CLI status=%d body=%s", rec.Code, rec.Body.String())
	}
	return pollDevice(t, router, grant.DeviceCode, http.StatusOK)
}
