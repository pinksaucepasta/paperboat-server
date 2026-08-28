package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pinksaucepasta/paperboat-server/internal/access"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	pbgithub "github.com/pinksaucepasta/paperboat-server/internal/github"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

func TestConnectionReadinessDoesNotRequireConfigRepoReadiness(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "status-no-config@example.com")
	insertAccessResource(t, store, projectID)
	cookies := loginCookies(t, router, "workos_seed_status-no-config@example.com:status-no-config@example.com:Status No Config")
	userID := userIDByEmail(t, store, "status-no-config@example.com")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.github_config_repositories WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, accessReadinessURL(projectID), nil)
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"connectable":true`) {
		t.Fatalf("expected connectable status, body = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "github_config_not_ready") {
		t.Fatalf("status leaked CLI-only readiness reason: %s", rec.Body.String())
	}
}

func TestConnectionReadinessRetainsSelectedTerminalSession(t *testing.T) {
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "status-selected-session@example.com", access.FakeClient{BaseURL: "https://access.example"}, nil)
	insertAccessResource(t, store, projectID)
	cookies := loginCookies(t, router, "workos_seed_status-selected-session@example.com:status-selected-session@example.com:Status Selected")
	const sessionID = "pts_status_selected"
	const terminalID = "term_status_selected"
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.project_terminal_sessions (id, project_id, terminal_id, name)
VALUES ($1, $2, $3, 'api')`, sessionID, projectID, terminalID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/projects/"+projectID+"/connection-readiness?terminal_session_id="+sessionID, nil)
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", rec.Code, rec.Body.String())
	}
	status, err := accessService.Status(context.Background(), userIDByEmail(t, store, "status-selected-session@example.com"), projectID, sessionID)
	if err != nil || status.Terminal["terminal_id"] != terminalID {
		t.Fatalf("selected terminal status = %#v, err = %v", status.Terminal, err)
	}
}

func TestConnectionReadinessWaitsForTerminalSessionReconciliation(t *testing.T) {
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "status-terminal-reconcile@example.com", access.FakeClient{BaseURL: "https://access.example"}, nil)
	insertAccessResource(t, store, projectID)
	cookies := loginCookies(t, router, "workos_seed_status-terminal-reconcile@example.com:status-terminal-reconcile@example.com:Status Reconcile")
	calls := 0
	accessService.SetBeforeConnect(func(context.Context, string, string) error {
		calls++
		return errors.New("terminal operation pending")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, accessReadinessURL(projectID), nil)
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || calls != 1 {
		t.Fatalf("status=%d reconciliation calls=%d body=%s", rec.Code, calls, rec.Body.String())
	}
	for _, want := range []string{`"connectable":false`, `"status":"helper_starting"`, `"reason":"terminal_session_operation_pending"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("connection status missing %s: %s", want, rec.Body.String())
		}
	}
}

func TestConnectionReadinessSurfacesLatestStopReason(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "status-stop-reason@example.com")
	insertAccessResource(t, store, projectID)
	cookies := loginCookies(t, router, "workos_seed_status-stop-reason@example.com:status-stop-reason@example.com:Status Stop")
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state = 'stopped' WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.project_events (id, project_id, event_type, message, metadata)
VALUES ($2, $1, 'project.stop_queued.credit_exhausted', 'stopped for test', '{}'::jsonb)`, projectID, "pevt_stop_reason_"+projectID); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, accessReadinessURL(projectID), nil)
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"connectable":false`) || !strings.Contains(rec.Body.String(), `"reason":"credit_exhausted"`) {
		t.Fatalf("expected credit stop reason in status, body = %s", rec.Body.String())
	}
}

func TestRuntimeObservationRequiresProjectMachineCredential(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "heartbeat@example.com")
	const machineID = "fly_machine_heartbeat"
	const machineToken = "project-scoped-machine-token"
	seedHeartbeatMachineCredential(t, store, projectID, machineID, machineToken)

	body := `{"environment_id":"` + projectID + `","resource_id":"` + machineID + `","sampled_at":"2026-07-06T12:00:05Z","reporter_version":"test"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, body = %s", rec.Code, rec.Body.String())
	}

	otherProjectBody := strings.Replace(body, projectID, "other-project", 1)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(otherProjectBody))
	req.Header.Set("Authorization", "Bearer "+machineToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong project status = %d, body = %s", rec.Code, rec.Body.String())
	}

	wrongMachineBody := strings.Replace(body, machineID, "stale-machine", 1)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(wrongMachineBody))
	req.Header.Set("Authorization", "Bearer "+machineToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong machine status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+machineToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("valid heartbeat status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestRuntimeObservationAuxiliaryRejectionStillMarksMachineOnline(t *testing.T) {
	store, _, projectID := newAccessIntegrationRouter(t, "heartbeat-auxiliary@example.com")
	var machineID string
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT id FROM paperboat.user_machines WHERE environment_id=$1`, projectID).Scan(&machineID); err != nil {
		t.Fatal(err)
	}
	const machineToken = "project-scoped-auxiliary-machine-token"
	seedHeartbeatMachineCredential(t, store, projectID, machineID, machineToken)
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.user_machines SET state='offline',online=false,last_seen_at=now()-interval '1 hour' WHERE id=$1`, machineID); err != nil {
		t.Fatal(err)
	}

	machines := usermachines.New(store, audit.NewWriter(store), usermachines.Policy{}, nil)
	sampledAt := time.Now().UTC().Truncate(time.Second)
	body := fmt.Sprintf(`{"environment_id":%q,"resource_id":%q,"sampled_at":%q,"availability":{"schema":"paperboat.availability-policy/v1","mode":"allow_sleep","version":1,"status":"applied","observed_at":%q,"host_service_version":"2026.08.29.1","host_service_scope":"system","update_rollbacks":0,"update_health":"healthy"}}`, projectID, machineID, sampledAt.Format(time.RFC3339), sampledAt.Add(-time.Second).Format(time.RFC3339))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+machineToken)
	started := time.Now().UTC().Add(-time.Second)
	runtimeObservation(metering.NewRuntimeRepository(store, "test-access-encryption-key-for-access-tests"), nil, 2, machines).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || !strings.Contains(recorder.Body.String(), `"code":"availability_observation_stale"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var state string
	var online bool
	var lastSeen time.Time
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT state,online,last_seen_at FROM paperboat.user_machines WHERE id=$1`, machineID).Scan(&state, &online, &lastSeen); err != nil {
		t.Fatal(err)
	}
	if state != "online" || !online || lastSeen.Before(started) {
		t.Fatalf("heartbeat state=%s online=%v last_seen_at=%s", state, online, lastSeen)
	}
}

func TestConfigSyncStatusEndpointAuthorizationAndEntitlement(t *testing.T) {
	store, router, _ := newAccessIntegrationRouter(t, "config-status@example.com")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/config-sync/status", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", recorder.Code)
	}

	cookies := loginCookies(t, router, "workos_seed_config-status@example.com:config-status@example.com:Config Status")
	userID := userIDByEmail(t, store, "config-status@example.com")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.subscriptions WHERE user_id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/config-sync/status", nil)
	addCookies(request, cookies)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("unentitled status = %d %s", recorder.Code, recorder.Body.String())
	}
	grantActiveSubscription(t, store, userID)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/v1/config-sync/status", nil)
	addCookies(request, cookies)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"state":"disabled"`) ||
		!strings.Contains(recorder.Body.String(), `"mode":"disabled"`) ||
		!strings.Contains(recorder.Body.String(), `"profile":"hosted"`) ||
		strings.Contains(recorder.Body.String(), `"resource_id"`) {
		t.Fatalf("canonical status response = %d %s", recorder.Code, recorder.Body.String())
	}

	cliTokens := authorizeCLI(t, router, cookies)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/v1/config-sync/status", nil)
	request.Header.Set("Authorization", "Bearer "+cliTokens.AccessToken)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("CLI bearer status = %d %s", recorder.Code, recorder.Body.String())
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.cli_client_sessions SET scopes=ARRAY['projects:read']::text[] WHERE id=$1`, cliTokens.CLIClientSessionID); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/v1/config-sync/status", nil)
	request.Header.Set("Authorization", "Bearer "+cliTokens.AccessToken)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), `"code":"insufficient_scope"`) {
		t.Fatalf("missing account:read status = %d %s", recorder.Code, recorder.Body.String())
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
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resources int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.provider_routes WHERE project_id = $1`, projectID).Scan(&resources); err != nil {
		t.Fatal(err)
	}
	if resources != 0 {
		t.Fatalf("provider_route resources = %d, want 0 before entitlement", resources)
	}
}

func TestProjectConnectionDescriptorIssuesHelperDescriptorWithScopedAuth(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "cli-ready@example.com")
	cookies := loginCookies(t, router, "workos_seed_cli-ready@example.com:cli-ready@example.com:CLI Ready")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	addCookies(req, cookies)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie CLI connect status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"terminal"`) ||
		!strings.Contains(rec.Body.String(), `"wss":"wss://`) ||
		!strings.Contains(rec.Body.String(), `"websocket_ticket"`) ||
		!strings.Contains(rec.Body.String(), `"file_transfer"`) ||
		strings.Contains(rec.Body.String(), `"upload"`) ||
		strings.Contains(rec.Body.String(), "provider_route-machine-token") {
		t.Fatalf("unexpected body = %s", rec.Body.String())
	}
	var sessions int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.access_sessions WHERE project_id = $1 AND session_type = 'cli'`, projectID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("cli access sessions = %d, want 1", sessions)
	}
}

func TestProjectConnectionDescriptorUsesCanonicalHostedHelperRoute(t *testing.T) {
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "cli-canonical@example.com", access.FakeClient{BaseURL: "https://legacy.invalid"}, nil)
	cookies := loginCookies(t, router, "workos_seed_cli-canonical@example.com:cli-canonical@example.com:CLI Canonical")
	userID := userIDByEmail(t, store, "cli-canonical@example.com")
	signer, err := mint.NewEphemeral(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	accessService.ConfigureCanonicalAccess(signer)
	seedHostedHelperRoute(t, store, projectID, userID, "hosted-canonical.example.test")
	var hostedMachineID string
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT user_machine_id FROM paperboat.fly_machines WHERE project_id=$1`, projectID).Scan(&hostedMachineID); err != nil {
		t.Fatal(err)
	}
	tokens := authorizeCLI(t, router, cookies)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(`{"source_machine_id":"source_`+projectID+`","terminal_session_id":"`+accessTerminalSessionID(projectID)+`"}`))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Data struct {
			Terminal     map[string]any `json:"terminal"`
			FileTransfer map[string]any `json:"file_transfer"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	terminalEndpoints, _ := envelope.Data.Terminal["endpoints"].(map[string]any)
	if terminalEndpoints["wss"] != "wss://hosted-canonical.example.test/v1/runtime" || envelope.Data.FileTransfer["endpoint"] != "https://hosted-canonical.example.test/v1/file-transfers" {
		t.Fatalf("canonical endpoints missing: %s", rec.Body.String())
	}
	var revokedJTIs []string
	for class, descriptor := range map[string]map[string]any{"terminal_operation": envelope.Data.Terminal, "file_transfer": envelope.Data.FileTransfer} {
		authValue, _ := descriptor["auth"].(map[string]any)
		token, _ := authValue["token"].(string)
		claims, verifyErr := signer.VerifyCredential(token, config.NormalizeIssuer(config.Default().HTTP.PublicBaseURL), class, time.Now().UTC())
		if verifyErr != nil {
			t.Fatalf("verify %s: %v", class, verifyErr)
		}
		if claims.EnvironmentID != projectID || claims.UserID != userID || claims.MachineID != hostedMachineID || claims.CLIClientSessionID != tokens.CLIClientSessionID || claims.SessionID != accessTerminalSessionID(projectID) {
			t.Fatalf("%s bindings=%#v", class, claims)
		}
		revokedJTIs = append(revokedJTIs, claims.JTI)
	}
	var persistedHTTPBaseURL string
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT http_base_url FROM paperboat.access_sessions WHERE project_id = $1 AND session_type = 'cli'`, projectID).Scan(&persistedHTTPBaseURL); err != nil {
		t.Fatal(err)
	}
	if persistedHTTPBaseURL != "https://hosted-canonical.example.test" {
		t.Fatalf("access session http_base_url = %q", persistedHTTPBaseURL)
	}
	var legacyResources int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.provider_routes WHERE project_id=$1`, projectID).Scan(&legacyResources); err != nil {
		t.Fatal(err)
	}
	if legacyResources != 0 {
		t.Fatalf("legacy EnvironmentAccess resources=%d, want 0", legacyResources)
	}
	if err := accessService.RevokeClientSessions(context.Background(), tokens.CLIClientSessionID, "test_revoked"); err != nil {
		t.Fatal(err)
	}
	document, err := controlplane.NewEdgeService(store, "test-edge-credential").Revocations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range revokedJTIs {
		if !slices.Contains(document.JTIs, want) {
			t.Fatalf("revocation document omitted %q: %#v", want, document.JTIs)
		}
	}
}

func TestCLIClientRevocationRevokesLinkedAccessSessions(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "cli-client-revoke@example.com")
	cookies := loginCookies(t, router, "workos_seed_cli-client-revoke@example.com:cli-client-revoke@example.com:CLI Revoke")
	grant := authorizeDevice(t, router)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/device/requests/"+grant.UserCode+"/approve", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", rec.Code, rec.Body.String())
	}
	tokens := pollDevice(t, router, grant.DeviceCode, http.StatusOK)

	req = httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	var linked string
	if err := store.SQL().QueryRow(`SELECT coalesce(cli_client_session_id,'') FROM paperboat.access_sessions WHERE project_id=$1 AND session_type='cli' ORDER BY created_at DESC LIMIT 1`, projectID).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked != tokens.CLIClientSessionID {
		t.Fatalf("linked client session=%q want=%q", linked, tokens.CLIClientSessionID)
	}

	req = httptest.NewRequest(http.MethodDelete, "/v1/auth/cli-client-sessions/"+tokens.CLIClientSessionID, nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	assertAccessSessionState(t, store, projectID, "revoked", "user_revoked")
}

func TestCLIClientRevocationPersistsBeforeHelperDelivery(t *testing.T) {
	issuer := &recordingLifecycleCredentialIssuer{issue: testLifecycleCredentials()}
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "cli-revoke-retry@example.com", access.FakeClient{BaseURL: "https://access.example"}, issuer)
	cookies := loginCookies(t, router, "workos_seed_cli-revoke-retry@example.com:cli-revoke-retry@example.com:CLI Revoke Retry")
	tokens := authorizeCLI(t, router, cookies)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}

	issuer.revokeErr = errors.New("helper unavailable")
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/v1/auth/cli-client-sessions/"+tokens.CLIClientSessionID, nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code < 500 {
		t.Fatalf("delete status=%d body=%s, want downstream failure", rec.Code, rec.Body.String())
	}

	var state string
	var helperRevoked bool
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT state, helper_revoked_at IS NOT NULL
FROM paperboat.access_sessions
WHERE project_id=$1 AND session_type='cli'`, projectID).Scan(&state, &helperRevoked); err != nil {
		t.Fatal(err)
	}
	if state != "revoked" || helperRevoked {
		t.Fatalf("access session state=%q helper_revoked=%v, want revoked/false", state, helperRevoked)
	}
	var pending int
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT count(*) FROM paperboat.access_sessions
WHERE project_id=$1 AND state='revoked' AND helper_revoked_at IS NULL
AND helper_terminal_session_id IS NOT NULL AND helper_file_session_id IS NOT NULL`, projectID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending helper revocations=%d, want 1", pending)
	}

	issuer.revokeErr = nil
	if err := accessService.RetryPendingHelperRevocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(issuer.revocations) != 2 {
		t.Fatalf("revocation attempts=%d, want initial delivery and retry", len(issuer.revocations))
	}
	for index, revocation := range issuer.revocations {
		if revocation.HTTPBaseURL != "https://access.example/projects/"+projectID {
			t.Fatalf("revocation %d HTTP base URL=%q", index, revocation.HTTPBaseURL)
		}
	}
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT helper_revoked_at IS NOT NULL FROM paperboat.access_sessions WHERE project_id=$1 AND session_type='cli'`, projectID).Scan(&helperRevoked); err != nil {
		t.Fatal(err)
	}
	if !helperRevoked {
		t.Fatal("successful retry did not mark helper revocation propagated")
	}
}

func TestHelperRevocationRetryContinuesAfterIndependentFailure(t *testing.T) {
	issuer := &recordingLifecycleCredentialIssuer{issue: testLifecycleCredentials()}
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "cli-retry-continues@example.com", access.FakeClient{BaseURL: "https://access.example"}, issuer)
	cookies := loginCookies(t, router, "workos_seed_cli-retry-continues@example.com:cli-retry-continues@example.com:CLI Retry Continues")
	tokens := authorizeCLI(t, router, cookies)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	issuer.revokeErr = errors.New("helper unavailable")
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/v1/auth/cli-client-sessions/"+tokens.CLIClientSessionID, nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code < 500 {
		t.Fatalf("delete status=%d body=%s, want downstream failure", rec.Code, rec.Body.String())
	}

	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.helper_revocation_outbox
(id,user_id,project_id,cli_client_session_id,http_base_url,session_ids,reason)
SELECT 'pro_independent', user_id, $1, $2, 'https://access.example', ARRAY['independent-session']::text[], 'logout'
FROM paperboat.projects WHERE id=$1`, projectID, tokens.CLIClientSessionID); err != nil {
		t.Fatal(err)
	}
	issuer.revokeErr = nil
	issuer.revokeFunc = func(input access.CredentialRevocationInput) error {
		if slices.Contains(input.SessionIDs, "helper-terminal-session") {
			return errors.New("first environment unavailable")
		}
		return nil
	}
	if err := accessService.RetryPendingHelperRevocations(context.Background()); err == nil {
		t.Fatal("retry error=nil, want failed environment error")
	}
	var propagated bool
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT propagated_at IS NOT NULL FROM paperboat.helper_revocation_outbox WHERE id='pro_independent'`).Scan(&propagated); err != nil {
		t.Fatal(err)
	}
	if !propagated {
		t.Fatal("independent revocation was blocked by an earlier failure")
	}
}

func TestProjectConnectionDescriptorRevokesCredentialsWhenAccessSessionPersistenceFails(t *testing.T) {
	issuer := &recordingLifecycleCredentialIssuer{issue: testLifecycleCredentials(), revokeErr: errors.New("helper unavailable")}
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "cli-persist-fails@example.com", access.FakeClient{BaseURL: "https://access.example"}, issuer)
	cookies := loginCookies(t, router, "workos_seed_cli-persist-fails@example.com:cli-persist-fails@example.com:CLI Persist Fails")
	tokens := authorizeCLI(t, router, cookies)

	if _, err := store.SQL().ExecContext(context.Background(), `
CREATE OR REPLACE FUNCTION paperboat.reject_access_session_insert() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced access session insert failure'; END $$;
CREATE TRIGGER reject_access_session_insert
BEFORE INSERT ON paperboat.access_sessions
FOR EACH ROW EXECUTE FUNCTION paperboat.reject_access_session_insert()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DROP TRIGGER IF EXISTS reject_access_session_insert ON paperboat.access_sessions`)
		_, _ = store.SQL().ExecContext(context.Background(), `DROP FUNCTION IF EXISTS paperboat.reject_access_session_insert()`)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code < 500 {
		t.Fatalf("connect status=%d body=%s, want persistence failure", rec.Code, rec.Body.String())
	}
	if len(issuer.revocations) != 1 {
		t.Fatalf("credential cleanup calls=%d, want 1", len(issuer.revocations))
	}
	revocation := issuer.revocations[0]
	if revocation.Reason != "access_session_persistence_failed" {
		t.Fatalf("cleanup reason=%q", revocation.Reason)
	}
	if strings.Join(revocation.SessionIDs, ",") != "helper-terminal-session,helper-file-session" {
		t.Fatalf("cleanup session IDs=%v", revocation.SessionIDs)
	}
	var sessions int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.access_sessions WHERE project_id=$1`, projectID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("persisted access sessions=%d, want 0", sessions)
	}
	var pending int
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT count(*) FROM paperboat.helper_revocation_outbox
WHERE project_id=$1 AND propagated_at IS NULL`, projectID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending orphaned credential revocations=%d, want 1", pending)
	}

	issuer.revokeErr = nil
	if err := accessService.RetryPendingHelperRevocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(issuer.revocations) != 2 {
		t.Fatalf("credential cleanup calls after retry=%d, want 2", len(issuer.revocations))
	}
	var propagated bool
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT propagated_at IS NOT NULL FROM paperboat.helper_revocation_outbox WHERE project_id=$1`, projectID).Scan(&propagated); err != nil {
		t.Fatal(err)
	}
	if !propagated {
		t.Fatal("successful orphaned credential retry was not marked propagated")
	}
}

func TestLogoutRevokesActiveAccessSessions(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "logout-revokes@example.com")
	cookies := loginCookies(t, router, "workos_seed_logout-revokes@example.com:logout-revokes@example.com:Logout Revokes")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, body = %s", rec.Code, rec.Body.String())
	}
	assertAccessSessionState(t, store, projectID, "revoked", "logout")
}

func TestProjectStopRevokesActiveAccessSessions(t *testing.T) {
	client := &recordingAccessClient{Client: access.FakeClient{BaseURL: "https://access.example"}}
	store, router, projectID := newAccessIntegrationRouterWithClient(t, "stop-revokes@example.com", client)
	cookies := loginCookies(t, router, "workos_seed_stop-revokes@example.com:stop-revokes@example.com:Stop Revokes")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/stop", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("stop status = %d, body = %s", rec.Code, rec.Body.String())
	}
	assertAccessSessionState(t, store, projectID, "revoked", "machine_stop")
	if client.cleanupAction != "suspend" || client.cleanupReason != "machine_stop" {
		t.Fatalf("cleanup action=%q reason=%q, want suspend/machine_stop", client.cleanupAction, client.cleanupReason)
	}
}

func TestProjectStopCleansTunnelWhenHelperRevocationFails(t *testing.T) {
	client := &recordingAccessClient{Client: access.FakeClient{BaseURL: "https://access.example"}}
	issuer := &recordingLifecycleCredentialIssuer{issue: testLifecycleCredentials()}
	store, router, _, projectID := newAccessIntegrationRouterWithService(t, "stop-helper-fails@example.com", client, issuer)
	cookies := loginCookies(t, router, "workos_seed_stop-helper-fails@example.com:stop-helper-fails@example.com:Stop Helper Fails")
	tokens := authorizeCLI(t, router, cookies)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	issuer.revokeErr = errors.New("helper unavailable")
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/stop", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("stop status=%d body=%s", rec.Code, rec.Body.String())
	}
	if client.cleanupAction != "suspend" || client.cleanupReason != "machine_stop" {
		t.Fatalf("cleanup action=%q reason=%q, want suspend/machine_stop", client.cleanupAction, client.cleanupReason)
	}
	assertAccessSessionState(t, store, projectID, "revoked", "machine_stop")
}

func TestProjectStopRevokesLocalSessionWhenProviderCleanupFails(t *testing.T) {
	client := &failingCleanupAccessClient{Client: access.FakeClient{BaseURL: "https://access.example"}}
	store, router, projectID := newAccessIntegrationRouterWithClient(t, "stop-cleanup-fails@example.com", client)
	cookies := loginCookies(t, router, "workos_seed_stop-cleanup-fails@example.com:stop-cleanup-fails@example.com:Stop Cleanup Fails")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/stop", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("stop status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var state string
	var revoked bool
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT state, revoked_at IS NOT NULL
FROM paperboat.access_sessions
WHERE project_id = $1
ORDER BY created_at DESC
LIMIT 1`, projectID).Scan(&state, &revoked); err != nil {
		t.Fatal(err)
	}
	if state != "revoked" || !revoked {
		t.Fatalf("access session state = %q revoked=%v, want revoked revoked=true", state, revoked)
	}
}

func TestProjectStopRetriesFailedProviderCleanup(t *testing.T) {
	client := &retryableCleanupAccessClient{Client: access.FakeClient{BaseURL: "https://access.example"}, err: errors.New("provider_route cleanup failed")}
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "stop-cleanup-retry@example.com", client, nil)
	cookies := loginCookies(t, router, "workos_seed_stop-cleanup-retry@example.com:stop-cleanup-retry@example.com:Stop Cleanup Retry")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/stop", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("stop status=%d body=%s", rec.Code, rec.Body.String())
	}
	var pending int
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT count(*) FROM paperboat.provider_route_cleanup_outbox
WHERE project_id=$1 AND propagated_at IS NULL`, projectID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending tunnel cleanups=%d, want 1", pending)
	}
	client.err = nil
	if err := accessService.RetryPendingHelperRevocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.calls != 2 {
		t.Fatalf("cleanup calls=%d, want immediate attempt and retry", client.calls)
	}
	var propagated bool
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT propagated_at IS NOT NULL FROM paperboat.provider_route_cleanup_outbox WHERE project_id=$1`, projectID).Scan(&propagated); err != nil {
		t.Fatal(err)
	}
	if !propagated {
		t.Fatal("successful tunnel cleanup retry was not marked propagated")
	}
}

func TestProjectDeleteRevokesActiveAccessSessions(t *testing.T) {
	client := &recordingAccessClient{Client: access.FakeClient{BaseURL: "https://access.example"}}
	store, router, projectID := newAccessIntegrationRouterWithClient(t, "delete-revokes@example.com", client)
	cookies := loginCookies(t, router, "workos_seed_delete-revokes@example.com:delete-revokes@example.com:Delete Revokes")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/v1/projects/"+projectID, nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("delete status = %d, body = %s", rec.Code, rec.Body.String())
	}
	assertAccessSessionState(t, store, projectID, "revoked", "project_delete")
	if client.cleanupAction != "close" || client.cleanupReason != "project_delete" {
		t.Fatalf("cleanup action=%q reason=%q, want close/project_delete", client.cleanupAction, client.cleanupReason)
	}
}

func TestProjectConnectionDescriptorRequiresGitHubConfigBeforeProviderSideEffects(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "github-not-ready@example.com")
	cookies := loginCookies(t, router, "workos_seed_github-not-ready@example.com:github-not-ready@example.com:GitHub Not Ready")
	userID := userIDByEmail(t, store, "github-not-ready@example.com")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.github_config_repositories WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.provider_routes WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "github_config_not_ready") {
		t.Fatalf("unexpected body = %s", rec.Body.String())
	}
	var resources int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.provider_routes WHERE project_id = $1`, projectID).Scan(&resources); err != nil {
		t.Fatal(err)
	}
	if resources != 0 {
		t.Fatalf("provider_route resources = %d, want 0 before github/config readiness", resources)
	}
}

func TestProjectConnectionDescriptorRequiresCredentialIssuerBeforeProviderSideEffects(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouterWithAccessService(t, "cli-unavailable@example.com", access.FakeClient{BaseURL: "https://access.example"}, access.DisabledCredentialIssuer{})
	cookies := loginCookies(t, router, "workos_seed_cli-unavailable@example.com:cli-unavailable@example.com:CLI Unavailable")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.provider_routes WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state = 'stopped' WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "credential_issuer_unavailable") {
		t.Fatalf("unexpected body = %s", rec.Body.String())
	}
	var resources int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.provider_routes WHERE project_id = $1`, projectID).Scan(&resources); err != nil {
		t.Fatal(err)
	}
	if resources != 0 {
		t.Fatalf("provider_route resources = %d, want 0 before credential issuer readiness", resources)
	}
	var jobs int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.orchestration_jobs WHERE aggregate_id = $1 AND job_type = 'project.start'`, projectID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("start jobs = %d, want 0 before credential issuer readiness", jobs)
	}
}

func TestProjectConnectionDescriptorRequiresCredentialPreflightBeforeProviderSideEffects(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouterWithAccessService(t, "cli-issue-fails@example.com", access.FakeClient{BaseURL: "https://access.example"}, failingIssueCredentialIssuer{})
	cookies := loginCookies(t, router, "workos_seed_cli-issue-fails@example.com:cli-issue-fails@example.com:CLI Issue Fails")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.provider_routes WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state = 'stopped' WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resources int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.provider_routes WHERE project_id = $1`, projectID).Scan(&resources); err != nil {
		t.Fatal(err)
	}
	if resources != 0 {
		t.Fatalf("provider_route resources = %d, want 0 before credential issuance succeeds", resources)
	}
	var jobs int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.orchestration_jobs WHERE aggregate_id = $1 AND job_type = 'project.start'`, projectID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("start jobs = %d, want 0 before credential issuance succeeds", jobs)
	}
}

func TestProjectConnectionDescriptorPersistsFailedPartialIssuanceCleanup(t *testing.T) {
	issuer := &partialCleanupFailureCredentialIssuer{}
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "cli-partial-cleanup@example.com", access.FakeClient{BaseURL: "https://access.example"}, issuer)
	cookies := loginCookies(t, router, "workos_seed_cli-partial-cleanup@example.com:cli-partial-cleanup@example.com:CLI Partial Cleanup")
	tokens := authorizeCLI(t, router, cookies)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	var sessionIDs []string
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT session_ids FROM paperboat.helper_revocation_outbox
WHERE project_id=$1 AND propagated_at IS NULL`, projectID).Scan(pgtype.NewMap().SQLScanner(&sessionIDs)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(sessionIDs, ",") != "partial-terminal-session,partial-file-session" {
		t.Fatalf("outbox session IDs=%v", sessionIDs)
	}
	if err := accessService.RetryPendingHelperRevocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(issuer.revocations) != 1 || issuer.revocations[0].Reason != "partial_credential_issuance_failed" {
		t.Fatalf("retry revocations=%#v", issuer.revocations)
	}
}

func TestAccessConnectDeniesWrongOwnerAndRecordsDenial(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "owner@example.com")
	otherCookies := loginCookies(t, router, "workos_other:other@example.com:Other User")
	otherID := userIDByEmail(t, store, "other@example.com")
	grantActiveSubscription(t, store, otherID)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, otherCookies).AccessToken)
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
	store, router, projectID := newAccessIntegrationRouterWithClient(t, "offline@example.com", access.DisabledClient{})
	cookies := loginCookies(t, router, "workos_seed_offline@example.com:offline@example.com:Offline User")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.provider_routes WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state = 'stopped' WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
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
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/connection-descriptor", strings.NewReader(accessDescriptorBody(projectID)))
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
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
	return newAccessIntegrationRouterWithClient(t, email, access.FakeClient{BaseURL: "https://access.example"})
}

func newAccessIntegrationRouterWithClient(t *testing.T, email string, client access.Client) (*db.DB, http.Handler, string) {
	return newAccessIntegrationRouterWithAccessService(t, email, client, nil)
}

func newAccessIntegrationRouterWithAccessService(t *testing.T, email string, client access.Client, issuer access.CredentialIssuer) (*db.DB, http.Handler, string) {
	store, router, _, projectID := newAccessIntegrationRouterWithService(t, email, client, issuer)
	return store, router, projectID
}

func newAccessIntegrationRouterWithService(t *testing.T, email string, client access.Client, issuer access.CredentialIssuer) (*db.DB, http.Handler, *access.Service, string) {
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
	cfg.Secrets.EncryptionKey = "test-access-encryption-key-for-access-tests"
	cfg.ConfigSync.SummaryLimit = 2
	auditWriter := audit.NewWriter(store)
	authService := auth.NewService(store, auditWriter, auth.FakeWorkOSVerifier{}, []string{"test-session-key"}, false)
	billingService := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, auditWriter)
	githubService := pbgithub.NewService(store, auditWriter, &pbgithub.FakeClient{}, cfg)
	projectService := projects.NewService(store, auditWriter, cfg)
	accessService := access.NewService(store, projectService, client, auditWriter, cfg)
	if issuer != nil {
		accessService = access.NewServiceWithCredentials(store, projectService, client, issuer, auditWriter, cfg)
	}
	deviceService := auth.NewDeviceService(store, auditWriter, cfg.CLIAuth, []string{"test-session-key"})
	deviceService.SetDownstreamRevoker(accessService)
	configStatuses := controlplane.NewConfigStatusService(store, nil, auditWriter, cfg.ConfigSync.SummaryLimit)
	configStatuses.SetAccountPolicy(cfg.ConfigSync)
	router := NewRouter(Options{
		Config:            cfg,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessChecker:  readinessFunc(func(context.Context) error { return nil }),
		Auth:              authService,
		DeviceAuth:        deviceService,
		Billing:           billingService,
		GitHub:            githubService,
		Projects:          projectService,
		EnvironmentAccess: accessService,
		MeteringRepo:      metering.NewRuntimeRepository(store, cfg.Secrets.EncryptionKey),
		ConfigStatuses:    configStatuses,
	})
	cookies := loginCookies(t, router, "workos_seed_"+email+":"+email+":Access Owner")
	userID := userIDByEmail(t, store, email)
	grantActiveSubscription(t, store, userID)
	grantAccessCreditsAndStorage(t, store, userID)
	grantGitHubConfigReady(t, store, userID)
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
	})
	if err != nil {
		t.Fatal(err)
	}
	applyAccessProjectConfig(t, store, project.ID)
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.project_terminal_sessions (id, project_id, terminal_id, name)
VALUES ($1, $2, $3, 'integration')`, accessTerminalSessionID(project.ID), project.ID, "term_"+project.ID); err != nil {
		t.Fatal(err)
	}
	_ = cookies
	return store, router, accessService, project.ID
}

func accessTerminalSessionID(projectID string) string {
	return "pts_" + projectID
}

func accessReadinessURL(projectID string) string {
	return "/v1/projects/" + projectID + "/connection-readiness?terminal_session_id=" + accessTerminalSessionID(projectID)
}

func accessDescriptorBody(projectID string) string {
	return `{"terminal_session_id":"` + accessTerminalSessionID(projectID) + `"}`
}

func grantGitHubConfigReady(t *testing.T, store *db.DB, userID string) {
	t.Helper()
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.github_oauth_tokens (id, user_id, token_ciphertext, scopes, provider_account_login, last_validated_at)
VALUES ($1, $2, '\x00'::bytea, ARRAY['repo']::text[], 'paperboat-test-user', now())
ON CONFLICT (user_id) DO UPDATE SET revoked_at = NULL, expires_at = NULL, last_validated_at = now()`,
		"ght_access_"+userID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.github_config_repositories (id, user_id, provider_repo_id, owner, name, default_branch, clone_url, html_url, private, provisioned_at)
VALUES ($1, $2, $3, 'paperboat-test-user', 'paperboat-config', 'main', 'https://github.com/paperboat-test-user/paperboat-config.git', 'https://github.com/paperboat-test-user/paperboat-config', true, now())
ON CONFLICT (user_id) DO UPDATE SET provisioned_at = now()`,
		"ghcr_access_"+userID, userID, "repo_access_"+userID); err != nil {
		t.Fatal(err)
	}
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
INSERT INTO paperboat.provider_routes (id, project_id, tunnel_id, client_id, resource_id, metadata)
VALUES ($1, $2, $3, $4, $5, '{"http_base_url":"https://access.example/projects/test","websocket_base_url":"wss://access.example/projects/test"}'::jsonb)
ON CONFLICT (project_id) DO NOTHING`, "agr_"+projectID, projectID, "tun_"+projectID, "cli_"+projectID, "res_"+projectID); err != nil {
		t.Fatal(err)
	}
}

func seedHostedHelperRoute(t *testing.T, store *db.DB, projectID, userID, publicHost string) {
	t.Helper()
	ctx := context.Background()
	helperID, edgeID := "helper_"+projectID, "edge_"+projectID
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$1,$2,'active') ON CONFLICT (id) DO UPDATE SET desired_state='active',owner_user_id=EXCLUDED.owner_user_id`, []any{projectID, userID}},
		{`INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Source machine','darwin','arm64','/Users/source','online','occupied',true)`, []any{"source_" + projectID, userID, "source_env_" + projectID}},
		{`INSERT INTO paperboat.fly_machines (id,project_id,user_machine_id,fly_machine_id,state,image_ref,region) SELECT $1,$2,m.id,$3,'running','image','iad' FROM paperboat.user_machines m WHERE m.environment_id=$2 AND m.machine_kind='hosted' ON CONFLICT (project_id) DO UPDATE SET fly_machine_id=EXCLUDED.fly_machine_id,state=EXCLUDED.state`, []any{"flm_" + projectID, projectID, "machine_" + projectID}},
		{`INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, []any{helperID, projectID}},
		{`INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at) VALUES ($1,'development','1.0',$2,'ready',true,now())`, []any{edgeID, "epoch_" + projectID}},
		{`INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,generation,edge_pool,edge_node_id,state) SELECT $1,m.id,1,'development',$2,'admitted' FROM paperboat.user_machines m WHERE m.environment_id=$1`, []any{projectID, edgeID}},
		{`INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation) VALUES ($1,$2,'runtime_https_wss',$3,'127.0.0.1',8080,1,1,$4,1)`, []any{"route_" + projectID, projectID, publicHost, edgeID}},
	}
	for _, statement := range statements {
		if _, err := store.SQL().ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func assertAccessSessionState(t *testing.T, store *db.DB, projectID, wantState, wantReason string) {
	t.Helper()
	var state string
	var revoked bool
	var descriptor string
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT state, revoked_at IS NOT NULL, descriptor::text
FROM paperboat.access_sessions
WHERE project_id = $1
ORDER BY created_at DESC
LIMIT 1`, projectID).Scan(&state, &revoked, &descriptor); err != nil {
		t.Fatal(err)
	}
	if state != wantState || !revoked {
		t.Fatalf("access session state = %q revoked=%v, want %q revoked=true", state, revoked, wantState)
	}
	if !strings.Contains(descriptor, `"revocation_reason": "`+wantReason+`"`) && !strings.Contains(descriptor, `"revocation_reason":"`+wantReason+`"`) {
		t.Fatalf("descriptor missing revocation reason %q: %s", wantReason, descriptor)
	}
}

func seedHeartbeatMachineCredential(t *testing.T, store *db.DB, projectID, machineID, token string) {
	t.Helper()
	ciphertext, err := secrets.Encrypt("test-access-encryption-key-for-access-tests", token)
	if err != nil {
		t.Fatal(err)
	}
	encoded := fmt.Sprintf("%x", ciphertext)
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.fly_machines (id, project_id, user_machine_id, fly_machine_id, state, image_ref, region)
SELECT $1, $2, m.id, $3, 'running', 'image', 'iad' FROM paperboat.user_machines m
WHERE m.environment_id=$2 AND m.machine_kind='hosted'
ON CONFLICT (project_id) DO UPDATE SET fly_machine_id = EXCLUDED.fly_machine_id, state = EXCLUDED.state`,
		"flm_heartbeat_"+projectID, projectID, machineID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.provider_routes (id, project_id, tunnel_id, client_id, resource_id, metadata)
VALUES ($1, $2, $3, $4, $5, jsonb_build_object('machine_token_ciphertext', $6::text))
ON CONFLICT (project_id) DO UPDATE SET metadata = jsonb_build_object('machine_token_ciphertext', $6::text)`,
		"agr_heartbeat_"+projectID, projectID, "tun_heartbeat_"+projectID, "cli_heartbeat_"+projectID, "res_heartbeat_"+projectID, encoded); err != nil {
		t.Fatal(err)
	}
}

type offlineAccessClient struct{}

func (offlineAccessClient) EnsureProjectResources(context.Context, access.ProjectRef) (access.ResourceDescriptor, error) {
	return access.ResourceDescriptor{}, access.ErrTunnelUnavailable
}

func (offlineAccessClient) ReattachProjectResources(_ context.Context, _ access.ProjectRef, resource access.ResourceDescriptor) (access.ResourceDescriptor, error) {
	resource.ClientID = "cli_replacement"
	resource.MachineToken = "replacement-token"
	return resource, nil
}

func (offlineAccessClient) Status(context.Context, access.ResourceDescriptor) (access.TunnelStatus, error) {
	return access.TunnelStatus{Ready: false, Status: "offline", Reason: "CLIENT_OFFLINE"}, nil
}

func (offlineAccessClient) CleanupProjectResources(context.Context, access.ResourceDescriptor, string, string) error {
	return nil
}

type recordingAccessClient struct {
	access.Client
	cleanupAction string
	cleanupReason string
}

func (c *recordingAccessClient) CleanupProjectResources(ctx context.Context, resource access.ResourceDescriptor, action, reason string) error {
	c.cleanupAction = action
	c.cleanupReason = reason
	return c.Client.CleanupProjectResources(ctx, resource, action, reason)
}

type failingCleanupAccessClient struct {
	access.Client
}

type retryableCleanupAccessClient struct {
	access.Client
	err   error
	calls int
}

func (c *retryableCleanupAccessClient) CleanupProjectResources(context.Context, access.ResourceDescriptor, string, string) error {
	c.calls++
	return c.err
}

func (c *failingCleanupAccessClient) CleanupProjectResources(context.Context, access.ResourceDescriptor, string, string) error {
	return errors.New("provider_route cleanup failed")
}

type failingIssueCredentialIssuer struct{}

func (failingIssueCredentialIssuer) CheckCLI(context.Context, access.CredentialInput) error {
	return errors.New("credential issuer transient failure")
}

func (failingIssueCredentialIssuer) IssueCLI(context.Context, access.CredentialInput) (access.CLICredentials, error) {
	return access.CLICredentials{}, errors.New("credential issuer transient failure")
}

func (failingIssueCredentialIssuer) RevokeCLI(context.Context, access.CredentialRevocationInput) error {
	return nil
}

type partialCleanupFailureCredentialIssuer struct {
	revocations []access.CredentialRevocationInput
}

func (*partialCleanupFailureCredentialIssuer) CheckCLI(context.Context, access.CredentialInput) error {
	return nil
}

func (*partialCleanupFailureCredentialIssuer) IssueCLI(context.Context, access.CredentialInput) (access.CLICredentials, error) {
	return access.CLICredentials{
		TerminalSessionID: "partial-terminal-session",
		FileSessionID:     "partial-file-session",
	}, errors.New("issuance and cleanup failed")
}

func (i *partialCleanupFailureCredentialIssuer) RevokeCLI(_ context.Context, input access.CredentialRevocationInput) error {
	i.revocations = append(i.revocations, input)
	return nil
}

type recordingLifecycleCredentialIssuer struct {
	issue       access.CLICredentials
	revokeErr   error
	revokeFunc  func(access.CredentialRevocationInput) error
	revocations []access.CredentialRevocationInput
}

func (i *recordingLifecycleCredentialIssuer) CheckCLI(context.Context, access.CredentialInput) error {
	return nil
}

func (i *recordingLifecycleCredentialIssuer) IssueCLI(context.Context, access.CredentialInput) (access.CLICredentials, error) {
	return i.issue, nil
}

func (i *recordingLifecycleCredentialIssuer) RevokeCLI(_ context.Context, input access.CredentialRevocationInput) error {
	i.revocations = append(i.revocations, input)
	if i.revokeFunc != nil {
		return i.revokeFunc(input)
	}
	return i.revokeErr
}

func testLifecycleCredentials() access.CLICredentials {
	return access.CLICredentials{
		TerminalAuth:      map[string]any{"type": "bearer", "token": "terminal-token"},
		FileTransferAuth:  map[string]any{"type": "bearer", "token": "file-token"},
		TerminalSessionID: "helper-terminal-session",
		FileSessionID:     "helper-file-session",
	}
}
