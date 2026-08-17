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
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

type fakeRuntimeObservationRepository struct {
	verifyErr error
	recordErr error
	recorded  *metering.RuntimeObservation
}

type fakeRuntimeIdentity struct {
	token, projectID, machineID string
	proof, body                 []byte
	err                         error
}

type fakeUpdateObservationRepository struct {
	recorded *usermachines.UpdateObservation
	err      error
}

func (f *fakeUpdateObservationRepository) RecordUpdateObservation(_ context.Context, _, _ string, observation usermachines.UpdateObservation) error {
	f.recorded = &observation
	return f.err
}

func (f *fakeRuntimeIdentity) VerifyRuntimeObservation(_ context.Context, token string, proof, body []byte, projectID, machineID string) error {
	f.token, f.proof, f.body, f.projectID, f.machineID = token, append([]byte(nil), proof...), append([]byte(nil), body...), projectID, machineID
	return f.err
}

func (f *fakeRuntimeObservationRepository) VerifyHeartbeatCredential(context.Context, string, string, string) error {
	return f.verifyErr
}

func (f *fakeRuntimeObservationRepository) RecordRuntimeObservation(_ context.Context, observation metering.RuntimeObservation) error {
	f.recorded = &observation
	return f.recordErr
}

func TestRuntimeObservationRejectsObsoleteConfigStatus(t *testing.T) {
	repository := &fakeRuntimeObservationRepository{}
	body := `{
		"environment_id":"prj_test","resource_id":"machine_test",
		"sampled_at":"2026-07-14T01:00:01Z",
		"reporter_version":"test",
		"config_sync":{"state":"error","pending_path_count":3,
		"skipped":[{"path":".config/a","bytes":6,"reason":"Too Large"},{"path":".config/b","bytes":7,"reason":"Too Large"},{"path":".config/c","bytes":8,"reason":"Too Large"}],
		"conflicts":[],"error_code":"Git Auth Failed!","error_message":"request https://example.test/?token=secret failed",
		"max_file_bytes":10,"max_batch_bytes":20,"policy_revision":"revision-one","updated_at":"2026-07-14T01:00:00Z"}
	}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer machine-token")
	runtimeObservation(repository, nil, 2).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if repository.recorded != nil {
		t.Fatal("obsolete config sync heartbeat was recorded")
	}
}

func TestRuntimeObservationUsesProofBoundHelperIdentity(t *testing.T) {
	repository := &fakeRuntimeObservationRepository{verifyErr: errors.New("legacy verifier must not run")}
	identity := &fakeRuntimeIdentity{}
	body := `{"environment_id":"prj_test","resource_id":"machine_test","sampled_at":"2026-07-14T01:00:01Z"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer helper-identity")
	request.Header.Set("X-Paperboat-Machine-Proof", "cHJvb2Y")
	recorder := httptest.NewRecorder()
	runtimeObservation(repository, identity, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || identity.token != "helper-identity" || string(identity.proof) != "proof" || string(identity.body) != body || identity.projectID != "prj_test" || identity.machineID != "machine_test" {
		t.Fatalf("status=%d identity=%#v", recorder.Code, identity)
	}
}

func TestRuntimeObservationAcceptsFreshRelayLatencyVector(t *testing.T) {
	repository := &fakeRuntimeObservationRepository{}
	body := `{"environment_id":"prj_test","resource_id":"machine_test","sampled_at":"2026-08-06T12:00:01Z","runtime_diagnostics":{"capabilities":[],"worker_generation":4,"os_boot_id":"boot-1","worker_service_scope":"system","connector_state":"ready","connector_generation":2,"observed_at":"2026-08-06T12:00:01Z"},"relay_latency":{"generation":7,"observed_at":"2026-08-06T12:00:00Z","samples":[{"region":"fsn1","rtt_ms":18}]}}`
	request := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer machine-token")
	recorder := httptest.NewRecorder()
	runtimeObservation(repository, nil, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || repository.recorded == nil || repository.recorded.RelayLatency == nil || repository.recorded.RelayLatency.Generation != 7 {
		t.Fatalf("status=%d observation=%#v body=%s", recorder.Code, repository.recorded, recorder.Body.String())
	}
}

func TestRuntimeObservationRecordsSignedUpdateObservation(t *testing.T) {
	repository := &fakeRuntimeObservationRepository{}
	updates := &fakeUpdateObservationRepository{}
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	body := `{"environment_id":"prj_test","resource_id":"machine_test","sampled_at":"2026-08-06T12:00:01Z","update":{"schema":"paperboat.update-observation/v1","state":"healthy","current_version":"2026.08.18.1","channel":"stable","operation_id":"update-op-0001","installation_generation":2,"worker_generation":4,"os_boot_id":"boot-1","rollback_count":0,"observed_at":"` + now.Format(time.RFC3339) + `"}}`
	request := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer machine-token")
	recorder := httptest.NewRecorder()
	runtimeObservation(repository, nil, 10, updates).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || updates.recorded == nil || !strings.Contains(recorder.Body.String(), `"update_observation_recorded":true`) {
		t.Fatalf("status=%d update=%#v body=%s", recorder.Code, updates.recorded, recorder.Body.String())
	}
}

func TestRuntimeObservationIgnoresStaleUpdateObservation(t *testing.T) {
	repository := &fakeRuntimeObservationRepository{}
	updates := &fakeUpdateObservationRepository{err: usermachines.ErrUpdateObservationStale}
	body := `{"environment_id":"prj_test","resource_id":"machine_test","sampled_at":"2026-08-06T12:00:01Z","update":{"schema":"paperboat.update-observation/v1","state":"healthy","current_version":"2026.08.18.1","channel":"stable","operation_id":"update-op-0001","installation_generation":2,"worker_generation":4,"os_boot_id":"boot-1","rollback_count":0,"observed_at":"2026-08-06T12:00:00Z"}}`
	request := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer machine-token")
	recorder := httptest.NewRecorder()
	runtimeObservation(repository, nil, 10, updates).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || !strings.Contains(recorder.Body.String(), `"update_observation_recorded":false`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRuntimeObservationRejectsStaleOrUnfencedRelayLatencyVector(t *testing.T) {
	for name, body := range map[string]string{
		"missing runtime generation": `{"environment_id":"prj_test","resource_id":"machine_test","sampled_at":"2026-08-06T12:00:01Z","relay_latency":{"generation":1,"observed_at":"2026-08-06T12:00:00Z","samples":[{"region":"fsn1","rtt_ms":18}]}}`,
		"stale":                      `{"environment_id":"prj_test","resource_id":"machine_test","sampled_at":"2026-08-06T12:06:01Z","runtime_diagnostics":{"capabilities":[],"worker_generation":4,"os_boot_id":"boot-1","worker_service_scope":"system","connector_state":"ready","connector_generation":2,"observed_at":"2026-08-06T12:06:01Z"},"relay_latency":{"generation":1,"observed_at":"2026-08-06T12:00:00Z","samples":[{"region":"fsn1","rtt_ms":18}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			repository := &fakeRuntimeObservationRepository{}
			request := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer machine-token")
			recorder := httptest.NewRecorder()
			runtimeObservation(repository, nil, 10).ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest || repository.recorded != nil {
				t.Fatalf("status=%d observation=%#v", recorder.Code, repository.recorded)
			}
		})
	}
}

func TestRuntimeObservationRejectsUnsafeSummaryAndWrongCredential(t *testing.T) {
	validPrefix := `{"environment_id":"prj_test","resource_id":"machine_test","sampled_at":"2026-07-14T01:00:01Z","config_sync":`
	missingTimestamp := validPrefix + `{"state":"healthy","pending_path_count":0,"max_file_bytes":10,"max_batch_bytes":20,"policy_revision":"1"}}`
	repository := &fakeRuntimeObservationRepository{}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(missingTimestamp))
	request.Header.Set("Authorization", "Bearer machine-token")
	runtimeObservation(repository, nil, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || repository.recorded != nil {
		t.Fatalf("missing status timestamp = %d recorded=%v", recorder.Code, repository.recorded != nil)
	}

	unsafe := validPrefix + `{"state":"warning","pending_path_count":1,"skipped":[{"path":"../secret","reason":"unsafe"}],"conflicts":[],"max_file_bytes":10,"max_batch_bytes":20,"policy_revision":"1","updated_at":"2026-07-14T01:00:00Z"}}`
	repository = &fakeRuntimeObservationRepository{}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(unsafe))
	request.Header.Set("Authorization", "Bearer machine-token")
	runtimeObservation(repository, nil, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || repository.recorded != nil {
		t.Fatalf("unsafe summary status = %d recorded=%v", recorder.Code, repository.recorded != nil)
	}

	repository = &fakeRuntimeObservationRepository{verifyErr: metering.ErrInvalidHeartbeatCredential}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(`{"environment_id":"prj_test","resource_id":"machine_test","sampled_at":"2026-07-14T01:00:01Z"}`))
	request.Header.Set("Authorization", "Bearer wrong")
	runtimeObservation(repository, nil, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong credential status = %d", recorder.Code)
	}
}

func TestRuntimeObservationRepositoryFailureIsInternalError(t *testing.T) {
	repository := &fakeRuntimeObservationRepository{recordErr: errors.New("database unavailable")}
	body := `{"environment_id":"prj_test","resource_id":"machine_test","sampled_at":"2026-07-14T01:00:01Z"}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer machine-token")
	runtimeObservation(repository, nil, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("repository failure status = %d", recorder.Code)
	}
}

func TestRuntimeObservationReportsDuplicateMachineIdentity(t *testing.T) {
	repository := &fakeRuntimeObservationRepository{recordErr: metering.ErrDuplicateMachineIdentity}
	request := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(`{"environment_id":"prj_test","resource_id":"machine_test","sampled_at":"2026-07-14T01:00:01Z"}`))
	request.Header.Set("Authorization", "Bearer machine-token")
	recorder := httptest.NewRecorder()
	runtimeObservation(repository, nil, 10).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"code":"duplicate_machine_identity"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
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

func TestValidObservedCapabilitiesRejectsUnknownAndDuplicates(t *testing.T) {
	if !validObservedCapabilities([]string{"file_receive", "preview_launch"}) {
		t.Fatal("receive capabilities should be valid")
	}
	for _, capabilities := range [][]string{{"terminal"}, {"file_receive", "file_receive"}} {
		if validObservedCapabilities(capabilities) {
			t.Fatalf("capabilities %v should be invalid", capabilities)
		}
	}
}
