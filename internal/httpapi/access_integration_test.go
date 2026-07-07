package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	pbgithub "github.com/pinksaucepasta/paperboat-server/internal/github"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
)

func TestAccessConnectIssuesPapercodeDescriptorAndRecordsSession(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "access@example.com")
	cookies := loginCookies(t, router, "workos_seed_access@example.com:access@example.com:Access User")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/papercode-connect", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"access_endpoint"`) || strings.Contains(rec.Body.String(), "agentunnel-machine-token") {
		t.Fatalf("unexpected descriptor body: %s", rec.Body.String())
	}
	var sessions int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.access_sessions WHERE project_id = $1 AND session_type = 'papercode'`, projectID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("access sessions = %d, want 1", sessions)
	}
	retry := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/papercode-connect", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(retry, req)
	if retry.Code != http.StatusOK {
		t.Fatalf("second connect status = %d, body = %s", retry.Code, retry.Body.String())
	}
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.access_sessions WHERE project_id = $1 AND session_type = 'papercode'`, projectID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 2 {
		t.Fatalf("access sessions after rapid reconnect = %d, want 2", sessions)
	}
	var events int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.connection_events WHERE project_id = $1 AND result = 'approved'`, projectID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 2 {
		t.Fatalf("approved events = %d, want 2", events)
	}
}

func TestAccessConnectRequiresEntitlementBeforeProviderSideEffects(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "no-entitlement@example.com")
	cookies := loginCookies(t, router, "workos_seed_no-entitlement@example.com:no-entitlement@example.com:No Entitlement")
	userID := userIDByEmail(t, store, "no-entitlement@example.com")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.subscriptions WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resources int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.agentunnel_resources WHERE project_id = $1`, projectID).Scan(&resources); err != nil {
		t.Fatal(err)
	}
	if resources != 0 {
		t.Fatalf("agentunnel resources = %d, want 0 before entitlement", resources)
	}
}

func TestAccessConnectDeniesWrongOwnerAndRecordsDenial(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "owner@example.com")
	otherCookies := loginCookies(t, router, "workos_other:other@example.com:Other User")
	otherID := userIDByEmail(t, store, "other@example.com")
	grantActiveSubscription(t, store, otherID)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/connect", nil)
	addCookies(req, otherCookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, otherCookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var denials int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.connection_events WHERE user_id = $1 AND project_id = $2 AND result = 'denied'`, otherID, projectID).Scan(&denials); err != nil {
		t.Fatal(err)
	}
	if denials != 1 {
		t.Fatalf("denial events = %d, want 1", denials)
	}
}

func TestAccessConnectDoesNotStartWhenTunnelUnavailable(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouterWithClient(t, "offline@example.com", agentunnel.DisabledClient{})
	cookies := loginCookies(t, router, "workos_seed_offline@example.com:offline@example.com:Offline User")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.agentunnel_resources WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state = 'stopped' WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var state string
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT state FROM paperboat.projects WHERE id = $1`, projectID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "stopped" {
		t.Fatalf("project state = %q, want stopped", state)
	}
	var jobs int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.orchestration_jobs WHERE aggregate_id = $1 AND job_type = 'project.start'`, projectID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("start jobs = %d, want 0", jobs)
	}
}

func TestAccessConnectQueuesStartWhenStoppedTunnelIsOffline(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouterWithClient(t, "resume@example.com", offlineAccessClient{})
	cookies := loginCookies(t, router, "workos_seed_resume@example.com:resume@example.com:Resume User")
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state = 'stopped' WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	insertAccessResource(t, store, projectID)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var state string
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT state FROM paperboat.projects WHERE id = $1`, projectID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "starting" {
		t.Fatalf("project state = %q, want starting", state)
	}
	var jobs int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.orchestration_jobs WHERE aggregate_id = $1 AND job_type = 'project.start'`, projectID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 {
		t.Fatalf("start jobs = %d, want 1", jobs)
	}
}

func newAccessIntegrationRouter(t *testing.T, email string) (*db.DB, http.Handler, string) {
	return newAccessIntegrationRouterWithClient(t, email, agentunnel.FakeClient{BaseURL: "https://agentunnel.example"})
}

func newAccessIntegrationRouterWithClient(t *testing.T, email string, client agentunnel.Client) (*db.DB, http.Handler, string) {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run access integration tests")
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
	seedAccessCatalogs(t, store)

	cfg := config.Default()
	cfg.Secrets.EncryptionKey = "test-access-encryption-key-for-phase-nine"
	cfg.Providers.Agentunnel.BaseURL = "https://agentunnel.example"
	auditWriter := audit.NewWriter(store)
	authService := auth.NewService(store, auditWriter, auth.FakeWorkOSVerifier{}, []string{"test-session-key"}, false)
	billingService := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, auditWriter)
	githubService := pbgithub.NewService(store, auditWriter, &pbgithub.FakeClient{}, cfg)
	projectService := projects.NewService(store, auditWriter, cfg)
	accessService := agentunnel.NewService(store, projectService, client, auditWriter, cfg)
	router := NewRouter(Options{
		Config:           cfg,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessChecker: readinessFunc(func(context.Context) error { return nil }),
		Auth:             authService,
		Billing:          billingService,
		GitHub:           githubService,
		Projects:         projectService,
		Agentunnel:       accessService,
	})
	cookies := loginCookies(t, router, "workos_seed_"+email+":"+email+":Access Owner")
	userID := userIDByEmail(t, store, email)
	grantActiveSubscription(t, store, userID)
	grantAccessCreditsAndStorage(t, store, userID)
	project, _, err := projectService.Create(context.Background(), projects.CreateInput{
		UserID:          userID,
		IdempotencyKey:  "access-project-" + email,
		Name:            "Access Project",
		RepositoryURL:   "https://github.com/paperboat/access.git",
		DefaultBranch:   "main",
		StorageGB:       4,
		MachineTypeCode: "standard-1x",
		RegionCode:      "iad",
		PresetCodes:     []string{"codex"},
		IdleTimeoutCode: "15m",
	})
	if err != nil {
		t.Fatal(err)
	}
	applyAccessProjectConfig(t, store, project.ID)
	_ = cookies
	return store, router, project.ID
}

func seedAccessCatalogs(t *testing.T, store *db.DB) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.machine_types (id, code, name, vcpu, memory_mb, credit_weight, active, current_version_id) VALUES ('mt_standard_1x', 'standard-1x', 'Standard 1x', 4, 8192, 1, true, 'mtv_standard_1x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.machine_type_versions (id, machine_type_id, version_number, vcpu, memory_mb, credit_weight) VALUES ('mtv_standard_1x', 'mt_standard_1x', 1, 4, 8192, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.vm_presets (id, code, name, active, current_version_id) VALUES ('preset_codex', 'codex', 'Codex', true, 'presetv_codex')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.vm_preset_versions (id, preset_id, version_number, manifest) VALUES ('presetv_codex', 'preset_codex', 1, '{}'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.regions (id, code, name, enabled) VALUES ('region_iad', 'iad', 'Ashburn', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.idle_timeout_options (id, code, duration_seconds, active) VALUES ('idle_15m', '15m', 900, true)`); err != nil {
		t.Fatal(err)
	}
}

func grantAccessCreditsAndStorage(t *testing.T, store *db.DB, userID string) {
	t.Helper()
	if _, err := store.SQL().ExecContext(context.Background(), `INSERT INTO paperboat.credit_accounts (id, user_id, balance) VALUES ($1, $2, 10) ON CONFLICT (user_id) DO UPDATE SET balance = 10`, "cred_access_"+userID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `INSERT INTO paperboat.storage_accounts (id, user_id, included_gb) VALUES ($1, $2, 20) ON CONFLICT (user_id) DO UPDATE SET included_gb = 20`, "stor_access_"+userID, userID); err != nil {
		t.Fatal(err)
	}
}

func applyAccessProjectConfig(t *testing.T, store *db.DB, projectID string) {
	t.Helper()
	if _, err := store.SQL().ExecContext(context.Background(), `
UPDATE paperboat.project_runtime_configs
SET applied_config_hash = desired_config_hash,
    applied_storage_gb = 4,
    applied_machine_type_version_id = machine_type_version_id,
    applied_preset_version_ids = preset_version_ids,
    applied_setup_script_ref = setup_script_ref,
    applied_idle_timeout_option_id = idle_timeout_option_id,
    applied_region_id = region_id,
    pending_restart_apply = false
WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state = 'running' WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
}

func insertAccessResource(t *testing.T, store *db.DB, projectID string) {
	t.Helper()
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.agentunnel_resources (id, project_id, tunnel_id, client_id, resource_id, metadata)
VALUES ($1, $2, $3, $4, $5, '{"http_base_url":"https://agentunnel.example/projects/test","websocket_base_url":"wss://agentunnel.example/projects/test","ssh_host":"ssh.agentunnel.example","ssh_port":25432}'::jsonb)
ON CONFLICT (project_id) DO NOTHING`, "agr_"+projectID, projectID, "tun_"+projectID, "cli_"+projectID, "res_"+projectID); err != nil {
		t.Fatal(err)
	}
}

type offlineAccessClient struct{}

func (offlineAccessClient) EnsureProjectResources(context.Context, agentunnel.ProjectRef) (agentunnel.ResourceDescriptor, error) {
	return agentunnel.ResourceDescriptor{}, agentunnel.ErrTunnelUnavailable
}

func (offlineAccessClient) Status(context.Context, agentunnel.ResourceDescriptor) (agentunnel.TunnelStatus, error) {
	return agentunnel.TunnelStatus{Ready: false, Status: "offline", Reason: "CLIENT_OFFLINE"}, nil
}
