package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	"github.com/pinksaucepasta/paperboat-server/internal/inspectaccess"
)

func TestInspectorBrowserCredentialRouteAuthAndCSRFPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := fmt.Sprint(now.UnixNano())
	owner, _, lease, _, _, _ := inspectorHTTPFixture(t, context.Background(), database, now, suffix)
	authService := auth.NewService(database, audit.NewWriter(database), auth.FakeWorkOSVerifier{}, []string{"inspector-browser-session-key"}, true, "https://login.pprbt.dev")
	router := NewRouter(Options{
		Config: config.Default(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Auth: authService,
		Inspector: &InspectorHandlers{Access: inspectaccess.NewService(database)},
	})
	// Login uses the real callback and session-cookie creation. This wrapper is
	// limited to login because the mutation assertions must control Origin.
	loginRouter := authTestOriginHandler{next: router}
	ownerCookies := loginCookies(t, loginRouter, owner+":"+owner+"@test.invalid:Inspector Owner")
	viewerCookies := loginCookies(t, loginRouter, "workos_inspector_viewer_"+suffix+":viewer-"+suffix+"@test.invalid:Viewer")
	t.Cleanup(func() {
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE primary_email=$1`, "viewer-"+suffix+"@test.invalid")
	})
	ownerCSRF := csrfCookie(t, ownerCookies)
	body := fmt.Sprintf(`{"resource_kind":"preview","resource_id":%q,"route_id":%q,"action":"inspect","ttl_seconds":60}`, lease, lease)

	issue := func(cookies []*http.Cookie, origin, csrf string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/inspector/credentials", bytes.NewBufferString(body))
		addCookies(req, cookies)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if csrf != "" {
			req.Header.Set(auth.CSRFHeaderName, csrf)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	revoke := func(id string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodDelete, "/v1/inspector/credentials/"+id, nil)
		addCookies(req, ownerCookies)
		req.Header.Set("Origin", "https://login.pprbt.dev")
		req.Header.Set(auth.CSRFHeaderName, ownerCSRF)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	credentialID := func(rec *httptest.ResponseRecorder) string {
		t.Helper()
		var envelope struct {
			Data struct {
				CredentialID string `json:"credential_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		return envelope.Data.CredentialID
	}

	success := issue(ownerCookies, "https://login.pprbt.dev", ownerCSRF)
	if success.Code != http.StatusOK || credentialID(success) == "" {
		t.Fatalf("owner issue=%d body=%s", success.Code, success.Body.String())
	}
	if rec := revoke(credentialID(success)); rec.Code != http.StatusOK {
		t.Fatalf("owner revoke=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := issue(viewerCookies, "https://login.pprbt.dev", csrfCookie(t, viewerCookies)); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer issue=%d body=%s", rec.Code, rec.Body.String())
	}
	for name, values := range map[string][2]string{
		"missing origin": {"", ownerCSRF},
		"wrong origin":   {"https://attacker.invalid", ownerCSRF},
		"missing csrf":   {"https://login.pprbt.dev", ""},
		"wrong csrf":     {"https://login.pprbt.dev", "wrong-token"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := issue(ownerCookies, values[0], values[1])
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if name == "missing csrf" || name == "wrong csrf" {
				if !strings.Contains(rec.Body.String(), `"code":"csrf_failed"`) {
					t.Fatalf("body=%s", rec.Body.String())
				}
			} else if !strings.Contains(rec.Body.String(), `"code":"origin_failed"`) {
				t.Fatalf("body=%s", rec.Body.String())
			}
		})
	}

	// The service caps active credentials at 128. Sequential issue/revoke must
	// release capacity rather than accumulating expired or revoked active rows.
	for i := 0; i < 129; i++ {
		rec := issue(ownerCookies, "https://login.pprbt.dev", ownerCSRF)
		if rec.Code != http.StatusOK {
			t.Fatalf("sequential issue %d=%d body=%s", i, rec.Code, rec.Body.String())
		}
		if revoked := revoke(credentialID(rec)); revoked.Code != http.StatusOK {
			t.Fatalf("sequential revoke %d=%d body=%s", i, revoked.Code, revoked.Body.String())
		}
	}
}

// TestInspectorBrowserLiveFixture is an opt-in process fixture for the remote
// dashboard check. It exposes only the real browser-authenticated inspector
// routes owned by this test; edge-node and machine-proof fixtures are separate.
func TestInspectorBrowserLiveFixture(t *testing.T) {
	readyPath := strings.TrimSpace(os.Getenv("PAPERBOAT_INSPECTOR_FIXTURE_READY"))
	stopPath := strings.TrimSpace(os.Getenv("PAPERBOAT_INSPECTOR_FIXTURE_STOP"))
	listenAddress := strings.TrimSpace(os.Getenv("PAPERBOAT_INSPECTOR_FIXTURE_LISTEN"))
	origin := strings.TrimSpace(os.Getenv("PAPERBOAT_INSPECTOR_FIXTURE_ORIGIN"))
	if readyPath == "" || stopPath == "" {
		t.Skip("set inspector fixture ready and stop paths")
	}
	if listenAddress == "" {
		listenAddress = "127.0.0.1:0"
	}
	if origin == "" {
		t.Fatal("PAPERBOAT_INSPECTOR_FIXTURE_ORIGIN is required")
	}
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := fmt.Sprint(now.UnixNano())
	owner, _, lease, tunnel, routeID, node := inspectorHTTPFixture(t, context.Background(), database, now, suffix)
	linked := newInspectorLinkedAuthority(t, database, now, suffix, owner, lease, tunnel, routeID, node)
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tlsListener := tls.NewListener(listener, linked.TLSConfig)
	accessService := inspectaccess.NewService(database)
	authService := auth.NewService(database, audit.NewWriter(database), auth.FakeWorkOSVerifier{}, []string{"inspector-live-session-key"}, false, origin)
	opts := Options{Config: config.Default(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Auth: authService, EdgeControl: linked.EdgeService.Handler(), Inspector: &InspectorHandlers{Access: accessService, Machine: linked.MachineVerifier}}
	if os.Getenv("PAPERBOAT_INSPECTOR_FIXTURE_NATIVE") == "1" {
		issuer := strings.TrimSpace(os.Getenv("PAPERBOAT_INSPECTOR_FIXTURE_NATIVE_ISSUER"))
		if issuer == "" {
			issuer = "https://" + listener.Addr().String()
		}
		configureInspectorNativeAuthority(t, database, linked, issuer, &opts)
	}
	router := NewRouter(opts)
	state := inspectorLiveAuthState(t, router)
	loginBody, _ := json.Marshal(map[string]string{"code": owner + ":" + owner + "@test.invalid:Inspector Owner", "state": state.Value})
	loginRequest := httptest.NewRequest(http.MethodPost, "/v1/auth/workos/callback", bytes.NewReader(loginBody))
	loginRequest.AddCookie(state.Cookie)
	loginRequest.Header.Set("Origin", origin)
	loginRecorder := httptest.NewRecorder()
	router.ServeHTTP(loginRecorder, loginRequest)
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("fixture login=%d", loginRecorder.Code)
	}
	cookies := loginRecorder.Result().Cookies()
	var sessionValue, csrfValue string
	for _, cookie := range cookies {
		if cookie.Name == auth.DevSessionCookieName {
			sessionValue = cookie.Value
		}
		if cookie.Name == auth.DevCSRFCookieName {
			csrfValue = cookie.Value
		}
	}
	if sessionValue == "" || csrfValue == "" {
		t.Fatal("fixture login returned incomplete development cookies")
	}
	descriptor := linked.Descriptor
	descriptor["base_url"] = "https://" + listener.Addr().String()
	descriptor["origin"] = origin
	descriptor["session_cookie_name"] = auth.DevSessionCookieName
	descriptor["session_cookie_value"] = sessionValue
	descriptor["csrf_header"] = auth.CSRFHeaderName
	descriptor["csrf_token"] = csrfValue
	descriptor["preview_id"] = lease
	descriptor["tunnel_id"] = tunnel
	descriptor["route_id"] = routeID
	file, err := os.OpenFile(readyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(file).Encode(descriptor); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: router, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(tlsListener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = os.Remove(readyPath)
	}()
	for {
		if _, err := os.Stat(stopPath); err == nil {
			return
		}
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Fatal(err)
			}
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func inspectorLiveAuthState(t *testing.T, router http.Handler) issuedState {
	t.Helper()
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/auth/workos/state", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("fixture auth state=%d", recorder.Code)
	}
	var payload struct {
		Data struct {
			State string `json:"state"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == auth.DevOAuthStateCookieName {
			return issuedState{Value: payload.Data.State, Cookie: cookie}
		}
	}
	t.Fatal("fixture missing development OAuth state cookie")
	return issuedState{}
}
