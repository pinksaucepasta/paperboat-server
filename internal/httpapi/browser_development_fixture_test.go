package httpapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/browseraccess"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// TestBrowserDevelopmentFixture is an explicit, short-lived development fixture
// for exercising the real trusted-dashboard issue handler against isolated
// PostgreSQL. It is not production-provider or PSL evidence.
func TestBrowserDevelopmentFixture(t *testing.T) {
	if os.Getenv("PAPERBOAT_BROWSER_DEV_FIXTURE") != "1" {
		t.Skip("set PAPERBOAT_BROWSER_DEV_FIXTURE=1")
	}
	dsn, output := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")), strings.TrimSpace(os.Getenv("PAPERBOAT_BROWSER_FIXTURE_FILE"))
	if dsn == "" || output == "" {
		t.Fatal("fixture DSN and output file are required")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if os.Getenv("PAPERBOAT_TEST_SCHEMA_READY") != "1" {
		if err = db.Migrate(ctx, store); err != nil {
			t.Fatal(err)
		}
	}
	origin := strings.TrimSpace(os.Getenv("PAPERBOAT_BROWSER_LOGIN_ORIGIN"))
	if origin == "" {
		t.Fatal("fixture browser login origin is required")
	}
	authService := auth.NewService(store, audit.NewWriter(store), auth.FakeWorkOSVerifier{}, []string{"task26-browser-development-fixture-key"}, false, origin)
	user, session, err := authService.VerifyCallback(ctx, auth.CallbackInput{Code: "task26_browser_fixture:task26-browser@test.invalid:Task 26 Browser Fixture"})
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	tunnel, route, host := "tun_browser_fixture_"+suffix, "rte_browser_fixture_"+suffix, "fixture-"+suffix+".tunnels.example.test"
	now := time.Now().UTC()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := store.SQL().ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO paperboat.tunnels(id,account_id,name,desired_state,access_mode,generation,stable_endpoint_id,stable_endpoint,created_by_host_id,created_by_actor_id,created_at,updated_at) VALUES($1,$2,$1,'active','private',3,$3,$4,'host',$2,$5,$5)`, tunnel, user.ID, strings.TrimSuffix(host, ".tunnels.example.test"), "https://"+host, now)
	exec(`INSERT INTO paperboat.tunnel_routes(id,tunnel_id,name,protocol,match_type,origin_scheme,origin_address,generation,desired_state,created_by_actor_id,updated_by_actor_id,created_at,updated_at) VALUES($1,$2,'web','http','catch_all','http','127.0.0.1:3000',7,'active',$3,$3,$4,$4)`, route, tunnel, user.ID, now)
	defer func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.tunnels WHERE id=$1`, tunnel)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=$1`, user.ID)
	}()
	accessService, err := browseraccess.NewService(store, "https://login.example.test")
	if err != nil {
		t.Fatal(err)
	}
	begin, err := accessService.Begin(ctx, browseraccess.BeginRequest{Host: host, ReturnPath: "/fixture-ok"})
	if err != nil {
		t.Fatal(err)
	}
	h := &BrowserAccessHandlers{Access: accessService}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/auth/workos/state", workOSState(authService))
	mux.HandleFunc("POST /v1/auth/workos/callback", workOSCallback(authService))
	mux.Handle("POST /v1/browser-access/issue", requireAuth(authService, requireCSRF(authService, http.HandlerFunc(h.Issue))))
	listenAddress := strings.TrimSpace(os.Getenv("PAPERBOAT_BROWSER_FIXTURE_LISTEN"))
	if listenAddress == "" {
		listenAddress = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	defer server.Shutdown(context.Background())
	go server.Serve(listener)
	fixture := map[string]string{"server_url": "http://" + listener.Addr().String(), "session_token": session.Token, "csrf_token": session.CSRFToken, "transaction_id": begin.TransactionID, "callback_origin": "https://" + host}
	raw, _ := json.Marshal(fixture)
	if err = os.WriteFile(output, raw, 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(output)
	duration := 3 * time.Minute
	if value := os.Getenv("PAPERBOAT_BROWSER_FIXTURE_DURATION"); value != "" {
		if parsed, e := time.ParseDuration(value); e == nil {
			duration = parsed
		}
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	<-timer.C
}
