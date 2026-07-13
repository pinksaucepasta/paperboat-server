package httpapi

import (
	"context"
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

	"github.com/lib/pq"
	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	pbsync "github.com/pinksaucepasta/paperboat-server/internal/configsync"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	pbgithub "github.com/pinksaucepasta/paperboat-server/internal/github"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
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
	var previewURL string
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT public_url FROM paperboat.preview_url_records WHERE project_id = $1 AND preview_key = 'papercode'`, projectID).Scan(&previewURL); err != nil {
		t.Fatal(err)
	}
	if previewURL == "" {
		t.Fatal("preview URL record was not persisted")
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
	var eventSessionID, eventMetadata string
	if err := store.SQL().QueryRowContext(context.Background(), `
		SELECT access_session_id, metadata::text FROM paperboat.connection_events
		WHERE project_id = $1 AND result = 'approved' ORDER BY created_at DESC LIMIT 1`, projectID).Scan(&eventSessionID, &eventMetadata); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{projectID, eventSessionID, "agentunnel_tunnel_id", "agentunnel_client_id", "environment_id"} {
		if !strings.Contains(eventMetadata, value) {
			t.Fatalf("connection event lacks correlation %q: %s", value, eventMetadata)
		}
	}
	if strings.Contains(eventMetadata, "token") || strings.Contains(eventMetadata, previewURL) {
		t.Fatalf("connection event contains credential or route URL: %s", eventMetadata)
	}
}

func TestPapercodeConnectDoesNotRequireConfigRepoReadiness(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "papercode-no-config@example.com")
	cookies := loginCookies(t, router, "workos_seed_papercode-no-config@example.com:papercode-no-config@example.com:Papercode No Config")
	userID := userIDByEmail(t, store, "papercode-no-config@example.com")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.github_config_repositories WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/papercode-connect", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"access_endpoint"`) {
		t.Fatalf("unexpected descriptor body: %s", rec.Body.String())
	}
}

func TestConnectionStatusDoesNotRequireConfigRepoReadiness(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "status-no-config@example.com")
	insertAccessResource(t, store, projectID)
	cookies := loginCookies(t, router, "workos_seed_status-no-config@example.com:status-no-config@example.com:Status No Config")
	userID := userIDByEmail(t, store, "status-no-config@example.com")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.github_config_repositories WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/projects/"+projectID+"/connection-status", nil)
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

func TestConnectionStatusDoesNotRecordActivity(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "status-no-activity@example.com")
	cookies := loginCookies(t, router, "workos_seed_status-no-activity@example.com:status-no-activity@example.com:Status No Activity")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.project_activity_markers WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/projects/"+projectID+"/connection-status", nil)
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", rec.Code, rec.Body.String())
	}
	var markers int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.project_activity_markers WHERE project_id = $1`, projectID).Scan(&markers); err != nil {
		t.Fatal(err)
	}
	if markers != 0 {
		t.Fatalf("activity markers = %d, want 0", markers)
	}
}

func TestConnectionStatusSurfacesLatestStopReason(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "status-stop-reason@example.com")
	insertAccessResource(t, store, projectID)
	cookies := loginCookies(t, router, "workos_seed_status-stop-reason@example.com:status-stop-reason@example.com:Status Stop")
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state = 'stopped' WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.project_events (id, project_id, event_type, message, metadata)
VALUES ($2, $1, 'project.stop_queued.idle_timeout', 'stopped for test', '{}'::jsonb)`, projectID, "pevt_stop_reason_"+projectID); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/projects/"+projectID+"/connection-status", nil)
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"connectable":false`) || !strings.Contains(rec.Body.String(), `"reason":"idle_timeout"`) {
		t.Fatalf("expected idle stop reason in status, body = %s", rec.Body.String())
	}
}

func TestMachineActivityHeartbeatRequiresProjectMachineCredential(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "heartbeat@example.com")
	const machineID = "fly_machine_heartbeat"
	const machineToken = "project-scoped-machine-token"
	seedHeartbeatMachineCredential(t, store, projectID, machineID, machineToken)

	body := `{"project_id":"` + projectID + `","machine_id":"` + machineID + `","last_activity_at":"2026-07-06T12:00:00Z","sampled_at":"2026-07-06T12:00:05Z","reporter_version":"test","signals":{"input":"2026-07-06T12:00:00Z"},"config_sync":{"state":"warning","last_attempt_at":"2026-07-06T12:00:04Z","last_successful_sync_at":"2026-07-06T11:59:00Z","remote_commit":"abc123","pending_path_count":3,"skipped":[{"path":".config/a","bytes":6,"reason":"max_file_bytes"},{"path":".config/b","bytes":7,"reason":"max_file_bytes"},{"path":".config/c","bytes":8,"reason":"max_file_bytes"}],"conflicts":[],"error_code":"","error_message":"","max_file_bytes":10,"max_batch_bytes":20,"policy_revision":"test-policy","updated_at":"2026-07-06T12:00:04Z"}}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, body = %s", rec.Code, rec.Body.String())
	}

	otherProjectBody := strings.Replace(body, projectID, "other-project", 1)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(otherProjectBody))
	req.Header.Set("Authorization", "Bearer "+machineToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong project status = %d, body = %s", rec.Code, rec.Body.String())
	}

	wrongMachineBody := strings.Replace(body, machineID, "stale-machine", 1)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(wrongMachineBody))
	req.Header.Set("Authorization", "Bearer "+machineToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong machine status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+machineToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("valid heartbeat status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var recordedMachine string
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT machine_id FROM paperboat.project_activity_markers WHERE project_id = $1`, projectID).Scan(&recordedMachine); err != nil {
		t.Fatal(err)
	}
	if recordedMachine != machineID {
		t.Fatalf("recorded machine = %q, want %q", recordedMachine, machineID)
	}
	var syncState, policyRevision string
	var pending, skippedCount int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT state,pending_path_count,jsonb_array_length(skipped),policy_revision FROM paperboat.config_sync_statuses WHERE project_id=$1 AND machine_id=$2`, projectID, machineID).Scan(&syncState, &pending, &skippedCount, &policyRevision); err != nil {
		t.Fatal(err)
	}
	if syncState != "warning" || pending != 3 || skippedCount != 2 || policyRevision != "test-policy" {
		t.Fatalf("persisted sync status = state:%s pending:%d skipped:%d policy:%s", syncState, pending, skippedCount, policyRevision)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.config_sync_statuses SET received_at='epoch'::timestamptz WHERE project_id=$1 AND machine_id=$2`, projectID, machineID); err != nil {
		t.Fatal(err)
	}

	older := strings.Replace(body, `"sampled_at":"2026-07-06T12:00:05Z"`, `"sampled_at":"2026-07-06T11:00:05Z"`, 1)
	older = strings.Replace(older, `"updated_at":"2026-07-06T12:00:04Z"`, `"updated_at":"2026-07-06T11:00:04Z"`, 1)
	older = strings.Replace(older, `"state":"warning"`, `"state":"healthy"`, 1)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(older))
	req.Header.Set("Authorization", "Bearer "+machineToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("older heartbeat status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var receiptRefreshed bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT state,received_at > now()-interval '1 minute' FROM paperboat.config_sync_statuses WHERE project_id=$1 AND machine_id=$2`, projectID, machineID).Scan(&syncState, &receiptRefreshed); err != nil {
		t.Fatal(err)
	}
	if syncState != "warning" {
		t.Fatalf("older heartbeat replaced newer sync state with %q", syncState)
	}
	if !receiptRefreshed {
		t.Fatal("older status heartbeat did not refresh its server receipt time")
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.config_sync_statuses SET state='error',status_updated_at=now()+interval '1 hour' WHERE project_id=$1 AND machine_id=$2`, projectID, machineID); err != nil {
		t.Fatal(err)
	}
	corrected := strings.Replace(body, `"sampled_at":"2026-07-06T12:00:05Z"`, `"sampled_at":"2026-07-06T12:01:05Z"`, 1)
	corrected = strings.Replace(corrected, `"updated_at":"2026-07-06T12:00:04Z"`, `"updated_at":"2026-07-06T12:01:04Z"`, 1)
	corrected = strings.Replace(corrected, `"state":"warning"`, `"state":"healthy"`, 1)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(corrected))
	req.Header.Set("Authorization", "Bearer "+machineToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("clock-corrected heartbeat status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT state FROM paperboat.config_sync_statuses WHERE project_id=$1 AND machine_id=$2`, projectID, machineID).Scan(&syncState); err != nil {
		t.Fatal(err)
	}
	if syncState != "healthy" {
		t.Fatalf("future timestamp froze corrected sync state at %q", syncState)
	}
}

func TestConfigSyncStatusEndpointAuthorizationAndStaleMachineSemantics(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "config-status@example.com")
	const machineID = "fly_machine_config_status"
	const machineToken = "config-status-machine-token"
	seedHeartbeatMachineCredential(t, store, projectID, machineID, machineToken)
	body := `{"project_id":"` + projectID + `","machine_id":"` + machineID + `","last_activity_at":"2026-07-06T12:00:00Z","sampled_at":"2026-07-06T12:00:05Z","reporter_version":"test","signals":{},"config_sync":{"state":"conflict","last_successful_sync_at":"2026-07-06T11:59:00Z","remote_commit":"def456","pending_path_count":1,"skipped":[],"conflicts":[{"path":".config/tool.json","reason":"concurrent_update"}],"max_file_bytes":10,"max_batch_bytes":20,"policy_revision":"test-policy","updated_at":"2026-07-06T12:00:04Z"}}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+machineToken)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("heartbeat status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/config-sync/status", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", recorder.Code)
	}

	cookies := loginCookies(t, router, "workos_seed_config-status@example.com:config-status@example.com:Config Status")
	userID := userIDByEmail(t, store, "config-status@example.com")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.subscriptions WHERE user_id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/config-sync/status", nil)
	addCookies(request, cookies)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("unentitled status = %d %s", recorder.Code, recorder.Body.String())
	}
	grantActiveSubscription(t, store, userID)
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state='running' WHERE id=$1`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.config_sync_statuses SET heartbeat_at=now()+interval '1 day',received_at=now(),status_observed_at=now(),skipped='null'::jsonb,conflicts='null'::jsonb WHERE project_id=$1 AND machine_id=$2`, projectID, machineID); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/config-sync/status", nil)
	addCookies(request, cookies)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"state":"conflict"`) || !strings.Contains(recorder.Body.String(), `"skipped":[]`) || !strings.Contains(recorder.Body.String(), `"conflicts":[]`) {
		t.Fatalf("fresh skewed response = %d %s", recorder.Code, recorder.Body.String())
	}

	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.config_sync_statuses SET status_observed_at=now()-interval '10 minutes' WHERE project_id=$1 AND machine_id=$2`, projectID, machineID); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/config-sync/status", nil)
	addCookies(request, cookies)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"state":"offline"`) || !strings.Contains(recorder.Body.String(), `"last_result_state":"conflict"`) || !strings.Contains(recorder.Body.String(), `"web_url":"https://github.com/paperboat-test-user/paperboat-config"`) {
		t.Fatalf("stale running response = %d %s", recorder.Code, recorder.Body.String())
	}

	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.config_sync_statuses SET status_observed_at=now(),received_at=now()-interval '10 minutes' WHERE project_id=$1 AND machine_id=$2`, projectID, machineID); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/config-sync/status", nil)
	addCookies(request, cookies)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"state":"offline"`) || !strings.Contains(recorder.Body.String(), `"last_result_state":"conflict"`) {
		t.Fatalf("stale receipt response = %d %s", recorder.Code, recorder.Body.String())
	}

	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state='stopped' WHERE id=$1`, projectID); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/config-sync/status", nil)
	addCookies(request, cookies)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"state":"idle"`) || !strings.Contains(recorder.Body.String(), `"last_result_state":"conflict"`) {
		t.Fatalf("stopped response = %d %s", recorder.Code, recorder.Body.String())
	}

	const replacementMachineID = "fly_machine_config_status_replacement"
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.fly_machines SET fly_machine_id=$2 WHERE project_id=$1`, projectID, replacementMachineID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state='running' WHERE id=$1`, projectID); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/config-sync/status", nil)
	addCookies(request, cookies)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"machine_id":"`+replacementMachineID+`"`) || strings.Contains(recorder.Body.String(), `"machine_id":"`+machineID+`"`) || strings.Contains(recorder.Body.String(), `"last_result_state":"conflict"`) {
		t.Fatalf("replacement machine response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestProjectActivityCallbackRecordsPapercodeAndCLIActivity(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "client-activity@example.com")
	cookies := loginCookies(t, router, "workos_seed_client-activity@example.com:client-activity@example.com:Client Activity")
	body := `{"source":"papercode_activity","observed_at":"2026-07-06T12:03:00Z","metadata":{"event":"editor_input"}}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/activity", strings.NewReader(body))
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("activity status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var source string
	var metadata string
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT source, metadata::text FROM paperboat.project_activity_markers WHERE project_id = $1`, projectID).Scan(&source, &metadata); err != nil {
		t.Fatal(err)
	}
	if source != "papercode_activity" {
		t.Fatalf("activity source = %q, want papercode_activity", source)
	}
	if !strings.Contains(metadata, "client_observed_at") {
		t.Fatalf("metadata did not preserve client observed time: %s", metadata)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/activity", strings.NewReader(`{"source":"cli_activity","metadata":{"event":"terminal_input"}}`))
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("cli activity status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT source FROM paperboat.project_activity_markers WHERE project_id = $1`, projectID).Scan(&source); err != nil {
		t.Fatal(err)
	}
	if source != "cli_activity" {
		t.Fatalf("activity source = %q, want cli_activity", source)
	}

	tokens := authorizeCLI(t, router, cookies)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/activity", strings.NewReader(`{"source":"cli_activity","metadata":{"event":"agent_output"}}`))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("bearer CLI activity status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestProjectActivityCallbackRequiresCSRF(t *testing.T) {
	_, router, projectID := newAccessIntegrationRouter(t, "activity-csrf@example.com")
	cookies := loginCookies(t, router, "workos_seed_activity-csrf@example.com:activity-csrf@example.com:Activity CSRF")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/activity", strings.NewReader(`{"source":"papercode_activity"}`))
	addCookies(req, cookies)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("activity without csrf status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestProjectActivityCallbackRejectsUnapprovedSource(t *testing.T) {
	_, router, projectID := newAccessIntegrationRouter(t, "bad-activity@example.com")
	cookies := loginCookies(t, router, "workos_seed_bad-activity@example.com:bad-activity@example.com:Bad Activity")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/activity", strings.NewReader(`{"source":"browser_ping"}`))
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("activity status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_activity_source") {
		t.Fatalf("expected invalid_activity_source, body = %s", rec.Body.String())
	}
}

func TestProjectKeepAliveRequiresCSRF(t *testing.T) {
	_, router, projectID := newAccessIntegrationRouter(t, "keepalive-csrf@example.com")
	cookies := loginCookies(t, router, "workos_seed_keepalive-csrf@example.com:keepalive-csrf@example.com:Keepalive CSRF")
	body := `{"duration_seconds":3600}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/keep-alive", strings.NewReader(body))
	addCookies(req, cookies)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/keep-alive", strings.NewReader(body))
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("with csrf status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestProjectKeepAliveRejectsZeroDurationUnlessClear(t *testing.T) {
	_, router, projectID := newAccessIntegrationRouter(t, "keepalive-zero@example.com")
	cookies := loginCookies(t, router, "workos_seed_keepalive-zero@example.com:keepalive-zero@example.com:Keepalive Zero")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/keep-alive", strings.NewReader(`{"duration_seconds":0}`))
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("zero duration status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/keep-alive", strings.NewReader(`{"clear":true}`))
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear status = %d, body = %s", rec.Code, rec.Body.String())
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
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
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

func TestCLIConnectIssuesPapercodeDescriptorWithScopedAuth(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "cli-ready@example.com")
	cookies := loginCookies(t, router, "workos_seed_cli-ready@example.com:cli-ready@example.com:CLI Ready")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	addCookies(req, cookies)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie CLI connect status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"terminal"`) ||
		!strings.Contains(rec.Body.String(), `"papercode_websocket"`) ||
		!strings.Contains(rec.Body.String(), `"websocket_ticket"`) ||
		!strings.Contains(rec.Body.String(), `"upload"`) ||
		strings.Contains(rec.Body.String(), "agentunnel-machine-token") {
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

func TestCLIClientRevocationRevokesLinkedAccessSessions(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "cli-client-revoke@example.com")
	cookies := loginCookies(t, router, "workos_cli_client_revoke:cli-client-revoke@example.com:CLI Revoke")
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

	req = httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	var linked string
	if err := store.SQL().QueryRow(`SELECT coalesce(client_session_id,'') FROM paperboat.access_sessions WHERE project_id=$1 AND session_type='cli' ORDER BY created_at DESC LIMIT 1`, projectID).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked != tokens.ClientSessionID {
		t.Fatalf("linked client session=%q want=%q", linked, tokens.ClientSessionID)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/auth/clients/"+tokens.ClientSessionID, nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	assertAccessSessionState(t, store, projectID, "revoked", "user_revoked")
}

func TestCLIClientRevocationPersistsBeforePapercodeDelivery(t *testing.T) {
	issuer := &recordingLifecycleCredentialIssuer{issue: testLifecycleCredentials()}
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "cli-revoke-retry@example.com", agentunnel.FakeClient{BaseURL: "https://agentunnel.example"}, issuer)
	cookies := loginCookies(t, router, "workos_cli_revoke_retry:cli-revoke-retry@example.com:CLI Revoke Retry")
	tokens := authorizeCLI(t, router, cookies)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}

	issuer.revokeErr = errors.New("papercode unavailable")
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/auth/clients/"+tokens.ClientSessionID, nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code < 500 {
		t.Fatalf("delete status=%d body=%s, want downstream failure", rec.Code, rec.Body.String())
	}

	var state string
	var papercodeRevoked bool
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT state, papercode_revoked_at IS NOT NULL
FROM paperboat.access_sessions
WHERE project_id=$1 AND session_type='cli'`, projectID).Scan(&state, &papercodeRevoked); err != nil {
		t.Fatal(err)
	}
	if state != "revoked" || papercodeRevoked {
		t.Fatalf("access session state=%q papercode_revoked=%v, want revoked/false", state, papercodeRevoked)
	}
	var pending int
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT count(*) FROM paperboat.access_sessions
WHERE project_id=$1 AND state='revoked' AND papercode_revoked_at IS NULL
AND papercode_terminal_session_id IS NOT NULL AND papercode_file_session_id IS NOT NULL`, projectID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending papercode revocations=%d, want 1", pending)
	}

	issuer.revokeErr = nil
	if err := accessService.RetryPendingPapercodeRevocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(issuer.revocations) != 2 {
		t.Fatalf("revocation attempts=%d, want initial delivery and retry", len(issuer.revocations))
	}
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT papercode_revoked_at IS NOT NULL FROM paperboat.access_sessions WHERE project_id=$1 AND session_type='cli'`, projectID).Scan(&papercodeRevoked); err != nil {
		t.Fatal(err)
	}
	if !papercodeRevoked {
		t.Fatal("successful retry did not mark papercode revocation propagated")
	}
}

func TestPapercodeRevocationRetryContinuesAfterIndependentFailure(t *testing.T) {
	issuer := &recordingLifecycleCredentialIssuer{issue: testLifecycleCredentials()}
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "cli-retry-continues@example.com", agentunnel.FakeClient{BaseURL: "https://agentunnel.example"}, issuer)
	cookies := loginCookies(t, router, "workos_cli_retry_continues:cli-retry-continues@example.com:CLI Retry Continues")
	tokens := authorizeCLI(t, router, cookies)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	issuer.revokeErr = errors.New("papercode unavailable")
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/auth/clients/"+tokens.ClientSessionID, nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code < 500 {
		t.Fatalf("delete status=%d body=%s, want downstream failure", rec.Code, rec.Body.String())
	}

	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.papercode_revocation_outbox
(id,user_id,project_id,client_session_id,http_base_url,session_ids,reason)
SELECT 'pro_independent', user_id, $1, $2, 'https://agentunnel.example', ARRAY['independent-session']::text[], 'logout'
FROM paperboat.projects WHERE id=$1`, projectID, tokens.ClientSessionID); err != nil {
		t.Fatal(err)
	}
	issuer.revokeErr = nil
	issuer.revokeFunc = func(input agentunnel.CredentialRevocationInput) error {
		if slices.Contains(input.SessionIDs, "papercode-terminal-session") {
			return errors.New("first environment unavailable")
		}
		return nil
	}
	if err := accessService.RetryPendingPapercodeRevocations(context.Background()); err == nil {
		t.Fatal("retry error=nil, want failed environment error")
	}
	var propagated bool
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT propagated_at IS NOT NULL FROM paperboat.papercode_revocation_outbox WHERE id='pro_independent'`).Scan(&propagated); err != nil {
		t.Fatal(err)
	}
	if !propagated {
		t.Fatal("independent revocation was blocked by an earlier failure")
	}
}

func TestCLIConnectRevokesCredentialsWhenAccessSessionPersistenceFails(t *testing.T) {
	issuer := &recordingLifecycleCredentialIssuer{issue: testLifecycleCredentials(), revokeErr: errors.New("papercode unavailable")}
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "cli-persist-fails@example.com", agentunnel.FakeClient{BaseURL: "https://agentunnel.example"}, issuer)
	cookies := loginCookies(t, router, "workos_cli_persist_fails:cli-persist-fails@example.com:CLI Persist Fails")
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
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
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
	if strings.Join(revocation.SessionIDs, ",") != "papercode-terminal-session,papercode-file-session" {
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
SELECT count(*) FROM paperboat.papercode_revocation_outbox
WHERE project_id=$1 AND propagated_at IS NULL`, projectID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending orphaned credential revocations=%d, want 1", pending)
	}

	issuer.revokeErr = nil
	if err := accessService.RetryPendingPapercodeRevocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(issuer.revocations) != 2 {
		t.Fatalf("credential cleanup calls after retry=%d, want 2", len(issuer.revocations))
	}
	var propagated bool
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT propagated_at IS NOT NULL FROM paperboat.papercode_revocation_outbox WHERE project_id=$1`, projectID).Scan(&propagated); err != nil {
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
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/papercode-connect", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, body = %s", rec.Code, rec.Body.String())
	}
	assertAccessSessionState(t, store, projectID, "revoked", "logout")
}

func TestProjectStopRevokesActiveAccessSessions(t *testing.T) {
	client := &recordingAccessClient{Client: agentunnel.FakeClient{BaseURL: "https://agentunnel.example"}}
	store, router, projectID := newAccessIntegrationRouterWithClient(t, "stop-revokes@example.com", client)
	cookies := loginCookies(t, router, "workos_seed_stop-revokes@example.com:stop-revokes@example.com:Stop Revokes")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/papercode-connect", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/stop", nil)
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

func TestProjectStopCleansTunnelWhenPapercodeRevocationFails(t *testing.T) {
	client := &recordingAccessClient{Client: agentunnel.FakeClient{BaseURL: "https://agentunnel.example"}}
	issuer := &recordingLifecycleCredentialIssuer{issue: testLifecycleCredentials()}
	store, router, _, projectID := newAccessIntegrationRouterWithService(t, "stop-papercode-fails@example.com", client, issuer)
	cookies := loginCookies(t, router, "workos_stop_papercode_fails:stop-papercode-fails@example.com:Stop Papercode Fails")
	tokens := authorizeCLI(t, router, cookies)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	issuer.revokeErr = errors.New("papercode unavailable")
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/stop", nil)
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
	client := &failingCleanupAccessClient{Client: agentunnel.FakeClient{BaseURL: "https://agentunnel.example"}}
	store, router, projectID := newAccessIntegrationRouterWithClient(t, "stop-cleanup-fails@example.com", client)
	cookies := loginCookies(t, router, "workos_seed_stop-cleanup-fails@example.com:stop-cleanup-fails@example.com:Stop Cleanup Fails")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/papercode-connect", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/stop", nil)
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
	client := &retryableCleanupAccessClient{Client: agentunnel.FakeClient{BaseURL: "https://agentunnel.example"}, err: errors.New("agentunnel cleanup failed")}
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "stop-cleanup-retry@example.com", client, nil)
	cookies := loginCookies(t, router, "workos_stop_cleanup_retry:stop-cleanup-retry@example.com:Stop Cleanup Retry")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/papercode-connect", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/stop", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("stop status=%d body=%s", rec.Code, rec.Body.String())
	}
	var pending int
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT count(*) FROM paperboat.agentunnel_cleanup_outbox
WHERE project_id=$1 AND propagated_at IS NULL`, projectID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending tunnel cleanups=%d, want 1", pending)
	}
	client.err = nil
	if err := accessService.RetryPendingPapercodeRevocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.calls != 2 {
		t.Fatalf("cleanup calls=%d, want immediate attempt and retry", client.calls)
	}
	var propagated bool
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT propagated_at IS NOT NULL FROM paperboat.agentunnel_cleanup_outbox WHERE project_id=$1`, projectID).Scan(&propagated); err != nil {
		t.Fatal(err)
	}
	if !propagated {
		t.Fatal("successful tunnel cleanup retry was not marked propagated")
	}
}

func TestProjectDeleteRevokesActiveAccessSessions(t *testing.T) {
	client := &recordingAccessClient{Client: agentunnel.FakeClient{BaseURL: "https://agentunnel.example"}}
	store, router, projectID := newAccessIntegrationRouterWithClient(t, "delete-revokes@example.com", client)
	cookies := loginCookies(t, router, "workos_seed_delete-revokes@example.com:delete-revokes@example.com:Delete Revokes")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/papercode-connect", nil)
	addCookies(req, cookies)
	req.Header.Set(auth.CSRFHeaderName, csrfCookie(t, cookies))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/projects/"+projectID, nil)
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

func TestCLIConnectRequiresGitHubConfigBeforeProviderSideEffects(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouter(t, "github-not-ready@example.com")
	cookies := loginCookies(t, router, "workos_seed_github-not-ready@example.com:github-not-ready@example.com:GitHub Not Ready")
	userID := userIDByEmail(t, store, "github-not-ready@example.com")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.github_config_repositories WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.agentunnel_resources WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "github_config_not_ready") {
		t.Fatalf("unexpected body = %s", rec.Body.String())
	}
	var resources int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.agentunnel_resources WHERE project_id = $1`, projectID).Scan(&resources); err != nil {
		t.Fatal(err)
	}
	if resources != 0 {
		t.Fatalf("agentunnel resources = %d, want 0 before github/config readiness", resources)
	}
}

func TestCLIConnectRequiresCredentialIssuerBeforeProviderSideEffects(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouterWithAccessService(t, "cli-unavailable@example.com", agentunnel.FakeClient{BaseURL: "https://agentunnel.example"}, agentunnel.DisabledCredentialIssuer{})
	cookies := loginCookies(t, router, "workos_seed_cli-unavailable@example.com:cli-unavailable@example.com:CLI Unavailable")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.agentunnel_resources WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state = 'stopped' WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "credential_issuer_unavailable") {
		t.Fatalf("unexpected body = %s", rec.Body.String())
	}
	var resources int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.agentunnel_resources WHERE project_id = $1`, projectID).Scan(&resources); err != nil {
		t.Fatal(err)
	}
	if resources != 0 {
		t.Fatalf("agentunnel resources = %d, want 0 before credential issuer readiness", resources)
	}
	var jobs int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.orchestration_jobs WHERE aggregate_id = $1 AND job_type = 'project.start'`, projectID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("start jobs = %d, want 0 before credential issuer readiness", jobs)
	}
}

func TestCLIConnectRequiresCredentialIssueBeforeProviderSideEffects(t *testing.T) {
	store, router, projectID := newAccessIntegrationRouterWithAccessService(t, "cli-issue-fails@example.com", agentunnel.FakeClient{BaseURL: "https://agentunnel.example"}, failingIssueCredentialIssuer{})
	cookies := loginCookies(t, router, "workos_seed_cli-issue-fails@example.com:cli-issue-fails@example.com:CLI Issue Fails")
	if _, err := store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.agentunnel_resources WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.projects SET state = 'stopped' WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	req.Header.Set("Authorization", "Bearer "+authorizeCLI(t, router, cookies).AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("connect status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resources int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.agentunnel_resources WHERE project_id = $1`, projectID).Scan(&resources); err != nil {
		t.Fatal(err)
	}
	if resources != 0 {
		t.Fatalf("agentunnel resources = %d, want 0 before credential issuance succeeds", resources)
	}
	var jobs int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.orchestration_jobs WHERE aggregate_id = $1 AND job_type = 'project.start'`, projectID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("start jobs = %d, want 0 before credential issuance succeeds", jobs)
	}
}

func TestCLIConnectPersistsFailedPartialIssuanceCleanup(t *testing.T) {
	issuer := &partialCleanupFailureCredentialIssuer{}
	store, router, accessService, projectID := newAccessIntegrationRouterWithService(t, "cli-partial-cleanup@example.com", agentunnel.FakeClient{BaseURL: "https://agentunnel.example"}, issuer)
	cookies := loginCookies(t, router, "workos_cli_partial_cleanup:cli-partial-cleanup@example.com:CLI Partial Cleanup")
	tokens := authorizeCLI(t, router, cookies)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/cli-connect", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("connect status=%d body=%s", rec.Code, rec.Body.String())
	}
	var sessionIDs []string
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT session_ids FROM paperboat.papercode_revocation_outbox
WHERE project_id=$1 AND propagated_at IS NULL`, projectID).Scan(pq.Array(&sessionIDs)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(sessionIDs, ",") != "partial-terminal-session,partial-file-session" {
		t.Fatalf("outbox session IDs=%v", sessionIDs)
	}
	if err := accessService.RetryPendingPapercodeRevocations(context.Background()); err != nil {
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
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/papercode-connect", nil)
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
	req := httptest.NewRequest(http.MethodPost, "/api/projects/"+projectID+"/papercode-connect", nil)
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
	return newAccessIntegrationRouterWithAccessService(t, email, client, nil)
}

func newAccessIntegrationRouterWithAccessService(t *testing.T, email string, client agentunnel.Client, issuer agentunnel.CredentialIssuer) (*db.DB, http.Handler, string) {
	store, router, _, projectID := newAccessIntegrationRouterWithService(t, email, client, issuer)
	return store, router, projectID
}

func newAccessIntegrationRouterWithService(t *testing.T, email string, client agentunnel.Client, issuer agentunnel.CredentialIssuer) (*db.DB, http.Handler, *agentunnel.Service, string) {
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
	cfg.ConfigSync.SummaryLimit = 2
	cfg.Providers.Agentunnel.BaseURL = "https://agentunnel.example"
	auditWriter := audit.NewWriter(store)
	authService := auth.NewService(store, auditWriter, auth.FakeWorkOSVerifier{}, []string{"test-session-key"}, false)
	billingService := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, auditWriter)
	githubService := pbgithub.NewService(store, auditWriter, &pbgithub.FakeClient{}, cfg)
	projectService := projects.NewService(store, auditWriter, cfg)
	accessService := agentunnel.NewService(store, projectService, client, auditWriter, cfg)
	if issuer != nil {
		accessService = agentunnel.NewServiceWithCredentials(store, projectService, client, issuer, auditWriter, cfg)
	}
	deviceService := auth.NewDeviceService(store, auditWriter, cfg.CLIAuth, []string{"test-session-key"})
	deviceService.SetDownstreamRevoker(accessService)
	router := NewRouter(Options{
		Config:           cfg,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessChecker: readinessFunc(func(context.Context) error { return nil }),
		Auth:             authService,
		DeviceAuth:       deviceService,
		Billing:          billingService,
		GitHub:           githubService,
		Projects:         projectService,
		Agentunnel:       accessService,
		MeteringRepo:     metering.NewRuntimeRepository(store, cfg.Secrets.EncryptionKey),
		ConfigSync:       pbsync.NewRepository(store, cfg.ConfigSync),
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
		IdleTimeoutCode: "15m",
	})
	if err != nil {
		t.Fatal(err)
	}
	applyAccessProjectConfig(t, store, project.ID)
	_ = cookies
	return store, router, accessService, project.ID
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
VALUES ($1, $2, $3, $4, $5, '{"http_base_url":"https://agentunnel.example/projects/test","websocket_base_url":"wss://agentunnel.example/projects/test"}'::jsonb)
ON CONFLICT (project_id) DO NOTHING`, "agr_"+projectID, projectID, "tun_"+projectID, "cli_"+projectID, "res_"+projectID); err != nil {
		t.Fatal(err)
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
	ciphertext, err := secrets.Encrypt("test-access-encryption-key-for-phase-nine", token)
	if err != nil {
		t.Fatal(err)
	}
	encoded := fmt.Sprintf("%x", ciphertext)
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.fly_machines (id, project_id, fly_machine_id, state, image_ref, region)
VALUES ($1, $2, $3, 'running', 'image', 'iad')
ON CONFLICT (project_id) DO UPDATE SET fly_machine_id = EXCLUDED.fly_machine_id, state = EXCLUDED.state`,
		"flm_heartbeat_"+projectID, projectID, machineID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.agentunnel_resources (id, project_id, tunnel_id, client_id, resource_id, metadata)
VALUES ($1, $2, $3, $4, $5, jsonb_build_object('machine_token_ciphertext', $6::text))
ON CONFLICT (project_id) DO UPDATE SET metadata = jsonb_build_object('machine_token_ciphertext', $6::text)`,
		"agr_heartbeat_"+projectID, projectID, "tun_heartbeat_"+projectID, "cli_heartbeat_"+projectID, "res_heartbeat_"+projectID, encoded); err != nil {
		t.Fatal(err)
	}
}

type offlineAccessClient struct{}

func (offlineAccessClient) EnsureProjectResources(context.Context, agentunnel.ProjectRef) (agentunnel.ResourceDescriptor, error) {
	return agentunnel.ResourceDescriptor{}, agentunnel.ErrTunnelUnavailable
}

func (offlineAccessClient) ReattachProjectResources(_ context.Context, _ agentunnel.ProjectRef, resource agentunnel.ResourceDescriptor) (agentunnel.ResourceDescriptor, error) {
	resource.ClientID = "cli_replacement"
	resource.MachineToken = "replacement-token"
	return resource, nil
}

func (offlineAccessClient) Status(context.Context, agentunnel.ResourceDescriptor) (agentunnel.TunnelStatus, error) {
	return agentunnel.TunnelStatus{Ready: false, Status: "offline", Reason: "CLIENT_OFFLINE"}, nil
}

func (offlineAccessClient) CleanupProjectResources(context.Context, agentunnel.ResourceDescriptor, string, string) error {
	return nil
}

type recordingAccessClient struct {
	agentunnel.Client
	cleanupAction string
	cleanupReason string
}

func (c *recordingAccessClient) CleanupProjectResources(ctx context.Context, resource agentunnel.ResourceDescriptor, action, reason string) error {
	c.cleanupAction = action
	c.cleanupReason = reason
	return c.Client.CleanupProjectResources(ctx, resource, action, reason)
}

type failingCleanupAccessClient struct {
	agentunnel.Client
}

type retryableCleanupAccessClient struct {
	agentunnel.Client
	err   error
	calls int
}

func (c *retryableCleanupAccessClient) CleanupProjectResources(context.Context, agentunnel.ResourceDescriptor, string, string) error {
	c.calls++
	return c.err
}

func (c *failingCleanupAccessClient) CleanupProjectResources(context.Context, agentunnel.ResourceDescriptor, string, string) error {
	return errors.New("agentunnel cleanup failed")
}

type failingIssueCredentialIssuer struct{}

func (failingIssueCredentialIssuer) CheckCLI(context.Context, agentunnel.CredentialInput) error {
	return nil
}

func (failingIssueCredentialIssuer) IssueCLI(context.Context, agentunnel.CredentialInput) (agentunnel.CLICredentials, error) {
	return agentunnel.CLICredentials{}, errors.New("credential issuer transient failure")
}

func (failingIssueCredentialIssuer) RevokeCLI(context.Context, agentunnel.CredentialRevocationInput) error {
	return nil
}

type partialCleanupFailureCredentialIssuer struct {
	revocations []agentunnel.CredentialRevocationInput
}

func (*partialCleanupFailureCredentialIssuer) CheckCLI(context.Context, agentunnel.CredentialInput) error {
	return nil
}

func (*partialCleanupFailureCredentialIssuer) IssueCLI(context.Context, agentunnel.CredentialInput) (agentunnel.CLICredentials, error) {
	return agentunnel.CLICredentials{
		TerminalSessionID: "partial-terminal-session",
		FileSessionID:     "partial-file-session",
	}, errors.New("issuance and cleanup failed")
}

func (i *partialCleanupFailureCredentialIssuer) RevokeCLI(_ context.Context, input agentunnel.CredentialRevocationInput) error {
	i.revocations = append(i.revocations, input)
	return nil
}

type recordingLifecycleCredentialIssuer struct {
	issue       agentunnel.CLICredentials
	revokeErr   error
	revokeFunc  func(agentunnel.CredentialRevocationInput) error
	revocations []agentunnel.CredentialRevocationInput
}

func (i *recordingLifecycleCredentialIssuer) CheckCLI(context.Context, agentunnel.CredentialInput) error {
	return nil
}

func (i *recordingLifecycleCredentialIssuer) IssueCLI(context.Context, agentunnel.CredentialInput) (agentunnel.CLICredentials, error) {
	return i.issue, nil
}

func (i *recordingLifecycleCredentialIssuer) RevokeCLI(_ context.Context, input agentunnel.CredentialRevocationInput) error {
	i.revocations = append(i.revocations, input)
	if i.revokeFunc != nil {
		return i.revokeFunc(input)
	}
	return i.revokeErr
}

func testLifecycleCredentials() agentunnel.CLICredentials {
	return agentunnel.CLICredentials{
		TerminalAuth:      map[string]any{"type": "bearer", "token": "terminal-token"},
		UploadAuth:        map[string]any{"type": "bearer", "token": "file-token"},
		TerminalSessionID: "papercode-terminal-session",
		FileSessionID:     "papercode-file-session",
	}
}
