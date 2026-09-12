package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

// Opt-in Hetzner fixture for the real dashboard. Only the upstream identity
// provider is substituted. Runtime snapshots use authenticated HTTPS to the
// separately held real terminal; no participant or API responses are fabricated.
func TestTask40ServeTerminalSharing(t *testing.T) {
	dir := os.Getenv("PAPERBOAT_TASK40_BROWSER_DIR")
	if dir == "" {
		t.Skip("private live browser fixture is opt-in")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute protected fixture directory required")
	}
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	address := os.Getenv("PAPERBOAT_TASK40_BROWSER_LISTEN")
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !strings.HasPrefix(host, "100.") {
		t.Fatal("private Tailscale listener required")
	}
	base, dashboard := "https://"+address, "http://100.95.70.63:3103"
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	secret := base64.RawURLEncoding.EncodeToString(key)
	clear(key)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := mint.New([]mint.Key{{ID: "task40-browser", PrivateKey: private}}, "task40-browser", mint.MaxProofTTL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.HTTP.PublicBaseURL = base
	writer := audit.NewWriter(store)
	accounts := auth.NewService(store, writer, auth.FakeWorkOSVerifier{}, []string{secret}, false, dashboard)
	devices := auth.NewDeviceService(store, writer, cfg.CLIAuth, []string{secret})
	machines := usermachines.New(store, writer, usermachines.Policy{}, nil)
	machines.ConfigureAccess(nil, base, 5*time.Minute)
	machines.ConfigureMachineControl(signer, base)
	router := NewRouter(Options{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Auth: accounts, DeviceAuth: devices, Teams: teams.NewService(store), Machines: machines, MintKeys: signer})
	type cookie struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type identity struct {
		AccountID string   `json:"account_id"`
		Cookies   []cookie `json:"cookies"`
	}
	login := func(name string) identity {
		email := "task40-" + name + fmt.Sprint(time.Now().UnixNano()) + "@example.test"
		stateRec := httptest.NewRecorder()
		router.ServeHTTP(stateRec, httptest.NewRequest("GET", "/v1/auth/workos/state", nil))
		if stateRec.Code != 200 {
			t.Fatalf("identity state status=%d", stateRec.Code)
		}
		var state struct {
			Data struct {
				State string `json:"state"`
			} `json:"data"`
		}
		if err := json.Unmarshal(stateRec.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]string{"state": state.Data.State, "code": "task40_" + email + ":" + email + ":" + name})
		req := httptest.NewRequest("POST", "/v1/auth/workos/callback", bytes.NewReader(body))
		req.Header.Set("Origin", dashboard)
		for _, c := range stateRec.Result().Cookies() {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("identity callback status=%d", rec.Code)
		}
		out := identity{AccountID: userIDByEmail(t, store, email)}
		for _, c := range rec.Result().Cookies() {
			if c.Value != "" {
				out.Cookies = append(out.Cookies, cookie{c.Name, c.Value})
			}
		}
		return out
	}
	owner, member := login("owner"), login("member")
	suffix := fmt.Sprint(time.Now().UnixNano())
	environment, machine, session, team, edge := "env40_"+suffix, "machine40_"+suffix, "ses40_"+suffix, "team40_"+suffix, "edge40_"+suffix
	defer store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_routes WHERE id=$1`, "route40_"+suffix)
	for _, q := range []struct {
		SQL  string
		Args []any
	}{
		{`INSERT INTO paperboat.control_environments(id,workspace_id,owner_user_id) VALUES($1,$1,$2)`, []any{environment, owner.AccountID}},
		{`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,configured_capabilities,observed_capabilities,installation_generation) VALUES($1,$2,$3,'Task 40 terminal','linux','amd64','/workspace','online','occupied',true,ARRAY['terminal_host'],ARRAY['terminal_host'],1)`, []any{machine, owner.AccountID, environment}},
		{`INSERT INTO paperboat.user_machine_terminal_sessions(id,user_machine_id,terminal_id,name,launch_cwd,owner_account,runtime_state) VALUES($1,$2,$1,'task40-shared','/workspace',$3,'running')`, []any{session, machine, owner.AccountID}},
		{`INSERT INTO paperboat.teams(team_id,owner_account,generation) VALUES($1,$2,1)`, []any{team, owner.AccountID}},
		{`INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'admin',true),($1,$3,1,'member',true)`, []any{team, owner.AccountID, member.AccountID}},
		{`INSERT INTO paperboat.control_tunnel_nodes(id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at) VALUES($1,'task40','1.0',$1,'ready',true,now())`, []any{edge}},
		{`INSERT INTO paperboat.control_connector_generations(environment_id,machine_id,generation,edge_pool,edge_node_id,state) VALUES($1,$2,1,'task40',$3,'admitted')`, []any{environment, machine, edge}},
	} {
		if _, err := store.SQL().ExecContext(ctx, q.SQL, q.Args...); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, value any) {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(raw)
		if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	token, err := signer.SignCredential(mint.CredentialInput{Issuer: base, Audience: "paperboat-machine", Subject: owner.AccountID, JTI: "jti40_" + suffix, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "terminal_operation", Scopes: []string{"terminal:operate"}, EnvironmentID: environment, MachineID: machine, UserID: owner.AccountID, AccountID: owner.AccountID, CLIClientSessionID: "task40-owner", SessionID: session})
	if err != nil {
		t.Fatal(err)
	}
	write("runtime.json", map[string]any{"issuer": base, "key_id": "task40-browser", "public_key": base64.RawURLEncoding.EncodeToString(public), "owner_token": token, "environment_id": environment, "machine_id": machine, "session_id": session, "account_id": owner.AccountID, "listen_address": "100.95.70.63:15442"})
	t.Log("runtime configuration ready")
	deadline := time.Now().Add(4 * time.Minute)
	var runtime struct {
		PublicHost string `json:"public_host"`
		CertPEM    string `json:"cert_pem"`
	}
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "runtime-ready.json"))
		if err == nil {
			if err = json.Unmarshal(raw, &runtime); err != nil {
				t.Fatal(err)
			}
			break
		}
		if !os.IsNotExist(err) || time.Now().After(deadline) {
			t.Fatal("real runtime readiness unavailable")
		}
		time.Sleep(time.Second)
	}
	if runtime.PublicHost != "100.95.70.63:15442" {
		t.Fatal("unexpected runtime route")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(runtime.CertPEM)) {
		t.Fatal("runtime certificate unavailable")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	machines.ConfigureTerminalSessions(20, signer, &http.Client{Transport: transport, Timeout: 10 * time.Second})
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes(id,environment_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation) VALUES($1,$2,'runtime_https_wss',$3,'127.0.0.1',15442,1,1,$4,1)`, "route40_"+suffix, environment, runtime.PublicHost, edge); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/auth/workos/") {
			http.NotFound(w, r)
			return
		}
		router.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() {
		done <- server.ServeTLS(listener, filepath.Join(dir, "tls-cert.pem"), filepath.Join(dir, "tls-key.pem"))
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	write("browser.json", map[string]any{"base_url": dashboard, "api_url": base, "session_id": session, "team_id": team, "owner": owner, "member": member})
	t.Log("authenticated browser fixture ready")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatalf("private listener stopped: %v", err)
		case <-ticker.C:
			if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
				return
			}
		}
	}
}
