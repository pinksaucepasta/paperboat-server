package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/metering"
)

type fakeHeartbeatRepository struct {
	verifyErr error
	recordErr error
	recorded  *metering.ActivityHeartbeat
}

type fakeActivityIdentity struct {
	token, projectID, machineID string
	proof, body                 []byte
	err                         error
}

func (f *fakeActivityIdentity) VerifyActivityHeartbeat(_ context.Context, token string, proof, body []byte, projectID, machineID string) error {
	f.token, f.proof, f.body, f.projectID, f.machineID = token, append([]byte(nil), proof...), append([]byte(nil), body...), projectID, machineID
	return f.err
}

func (f *fakeHeartbeatRepository) VerifyHeartbeatCredential(context.Context, string, string, string) error {
	return f.verifyErr
}

func (f *fakeHeartbeatRepository) RecordHeartbeat(_ context.Context, heartbeat metering.ActivityHeartbeat) error {
	f.recorded = &heartbeat
	return f.recordErr
}

func TestActivityHeartbeatValidatesSanitizesAndBoundsConfigStatus(t *testing.T) {
	repository := &fakeHeartbeatRepository{}
	body := `{
		"project_id":"prj_test","machine_id":"machine_test",
		"last_activity_at":"2026-07-14T01:00:00Z","sampled_at":"2026-07-14T01:00:01Z",
		"reporter_version":"test","signals":{},
		"config_sync":{"state":"error","pending_path_count":3,
		"skipped":[{"path":".config/a","bytes":6,"reason":"Too Large"},{"path":".config/b","bytes":7,"reason":"Too Large"},{"path":".config/c","bytes":8,"reason":"Too Large"}],
		"conflicts":[],"error_code":"Git Auth Failed!","error_message":"request https://example.test/?token=secret failed",
		"max_file_bytes":10,"max_batch_bytes":20,"policy_revision":"revision-one","updated_at":"2026-07-14T01:00:00Z"}
	}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer machine-token")
	activityHeartbeat(repository, nil, 2).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if repository.recorded == nil || repository.recorded.ConfigSync == nil {
		t.Fatal("config sync heartbeat was not recorded")
	}
	status := repository.recorded.ConfigSync
	if len(status.Skipped) != 2 || status.ErrorCode != "git_auth_failed" || strings.Contains(status.ErrorMessage, "secret") {
		t.Fatalf("normalized status = %#v", status)
	}
}

func TestActivityHeartbeatUsesProofBoundHelperIdentity(t *testing.T) {
	repository := &fakeHeartbeatRepository{verifyErr: errors.New("legacy verifier must not run")}
	identity := &fakeActivityIdentity{}
	body := `{"project_id":"prj_test","machine_id":"machine_test","last_activity_at":"2026-07-14T01:00:00Z","sampled_at":"2026-07-14T01:00:01Z","signals":{}}`
	request := httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer helper-identity")
	request.Header.Set("X-Paperboat-Helper-Proof", "cHJvb2Y")
	recorder := httptest.NewRecorder()
	activityHeartbeat(repository, identity, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || identity.token != "helper-identity" || string(identity.proof) != "proof" || string(identity.body) != body || identity.projectID != "prj_test" || identity.machineID != "machine_test" {
		t.Fatalf("status=%d identity=%#v", recorder.Code, identity)
	}
}

func TestActivityHeartbeatRejectsUnsafeSummaryAndWrongCredential(t *testing.T) {
	validPrefix := `{"project_id":"prj_test","machine_id":"machine_test","last_activity_at":"2026-07-14T01:00:00Z","sampled_at":"2026-07-14T01:00:01Z","config_sync":`
	missingTimestamp := validPrefix + `{"state":"healthy","pending_path_count":0,"max_file_bytes":10,"max_batch_bytes":20,"policy_revision":"1"}}`
	repository := &fakeHeartbeatRepository{}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(missingTimestamp))
	request.Header.Set("Authorization", "Bearer machine-token")
	activityHeartbeat(repository, nil, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || repository.recorded != nil {
		t.Fatalf("missing status timestamp = %d recorded=%v", recorder.Code, repository.recorded != nil)
	}

	unsafe := validPrefix + `{"state":"warning","pending_path_count":1,"skipped":[{"path":"../secret","reason":"unsafe"}],"conflicts":[],"max_file_bytes":10,"max_batch_bytes":20,"policy_revision":"1","updated_at":"2026-07-14T01:00:00Z"}}`
	repository = &fakeHeartbeatRepository{}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(unsafe))
	request.Header.Set("Authorization", "Bearer machine-token")
	activityHeartbeat(repository, nil, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || repository.recorded != nil {
		t.Fatalf("unsafe summary status = %d recorded=%v", recorder.Code, repository.recorded != nil)
	}

	repository = &fakeHeartbeatRepository{verifyErr: metering.ErrInvalidHeartbeatCredential}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(strings.TrimSuffix(validPrefix, `"config_sync":`)+`"signals":{}}`))
	request.Header.Set("Authorization", "Bearer wrong")
	activityHeartbeat(repository, nil, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong credential status = %d", recorder.Code)
	}
}

func TestActivityHeartbeatRepositoryFailureIsInternalError(t *testing.T) {
	repository := &fakeHeartbeatRepository{recordErr: errors.New("database unavailable")}
	body := `{"project_id":"prj_test","machine_id":"machine_test","last_activity_at":"2026-07-14T01:00:00Z","sampled_at":"2026-07-14T01:00:01Z","signals":{}}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer machine-token")
	activityHeartbeat(repository, nil, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("repository failure status = %d", recorder.Code)
	}
}

func TestActivityHeartbeatReportsConfigStatusNewerThanItsSample(t *testing.T) {
	repository := &fakeHeartbeatRepository{}
	body := `{"project_id":"prj_test","machine_id":"machine_test","last_activity_at":"2026-07-14T01:00:00Z","sampled_at":"2026-07-14T01:00:01Z","signals":{},"config_sync":{"state":"healthy","pending_path_count":0,"max_file_bytes":10,"max_batch_bytes":20,"policy_revision":"1","updated_at":"2026-07-14T02:00:00Z"}}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/machine/activity-heartbeat", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer machine-token")
	activityHeartbeat(repository, nil, 10).ServeHTTP(recorder, request)
	sampledAt := time.Date(2026, 7, 14, 1, 0, 1, 0, time.UTC)
	if recorder.Code != http.StatusAccepted || repository.recorded == nil || repository.recorded.ConfigSync == nil || repository.recorded.ConfigSync.State != "error" || repository.recorded.ConfigSync.ErrorCode != "status_clock_invalid" || repository.recorded.ConfigSync.UpdatedAt.After(sampledAt) {
		t.Fatalf("future config status = %d recorded=%#v", recorder.Code, repository.recorded)
	}
}

func TestNormalizeConfigStatusTimestampPreservesAgeAcrossClockSkew(t *testing.T) {
	serverNow := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	for _, skew := range []time.Duration{-time.Hour, time.Hour} {
		sampledAt := serverNow.Add(skew)
		statusUpdated := sampledAt.Add(-5 * time.Minute)
		ordered, observed, valid := normalizeStatusTimestamps(statusUpdated, sampledAt, serverNow)
		if !valid || !observed.Equal(serverNow.Add(-5*time.Minute)) {
			t.Fatalf("skew %s: observed timestamp = %s valid=%v", skew, observed, valid)
		}
		if skew < 0 && !ordered.Equal(statusUpdated) {
			t.Fatalf("clock-behind ordering timestamp = %s, want source %s", ordered, statusUpdated)
		}
		if skew > 0 && !ordered.Equal(observed) {
			t.Fatalf("clock-ahead ordering timestamp = %s, want corrected %s", ordered, observed)
		}
	}
}
