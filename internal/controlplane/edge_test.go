package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/observability"
)

func TestUsageErrorResponseClassifiesPermanentAndRetryableFailures(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		status    int
		code      string
		retryable bool
	}{
		{name: "invalid report", err: fmt.Errorf("wrapped: %w", ErrInvalidUsageReport), status: http.StatusBadRequest, code: "invalid_request"},
		{name: "invalid signature", err: ErrUsageSignature, status: http.StatusBadRequest, code: "credential_invalid"},
		{name: "operation conflict", err: ErrUsageOperationConflict, status: http.StatusConflict, code: "operation_conflict"},
		{name: "storage failure", err: errors.New("database unavailable"), status: http.StatusServiceUnavailable, code: "control_unavailable", retryable: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, code, retryable, retryAfterMS := usageErrorResponse(tt.err)
			if status != tt.status || code != tt.code || retryable != tt.retryable {
				t.Fatalf("response = (%d, %q, %t), want (%d, %q, %t)", status, code, retryable, tt.status, tt.code, tt.retryable)
			}
			if (retryAfterMS > 0) != retryable {
				t.Fatalf("retry_after_ms = %d, retryable = %t", retryAfterMS, retryable)
			}
		})
	}
}

func TestEdgeHandlerRejectsUnauthorizedAndUnknownRoutes(t *testing.T) {
	service := NewEdgeService(nil, "edge-control-credential-01234567890123456789")
	request := httptest.NewRequest(http.MethodPost, "/v1/nodes/register", strings.NewReader(`{}`)).WithContext(observability.WithRequestID(context.Background(), "req_edge_test"))
	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", response.Code)
	}
	var envelope map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope["code"] != "unauthenticated" || envelope["requestId"] != "req_edge_test" || envelope["retryable"] != false {
		t.Fatalf("error envelope = %#v, %v", envelope, err)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/unknown", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer edge-control-credential-01234567890123456789")
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d", response.Code)
	}
}

func TestEdgeAssignmentSerializesRevokedAsBoolean(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_") + time.Now().Format("150405.000000000")
	environment, helper, node := "env_"+suffix, "helper_"+suffix, "node_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id) VALUES ($1,$2)`, environment, "workspace_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch) VALUES ($1,'default','1.0',$2)`, node, "process_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, helper, environment); err != nil {
		t.Fatal(err)
	}
	machineID := seedConnectorTestMachine(t, store, environment)
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,edge_pool,edge_node_id,state) VALUES ($1,$2,'default',$3,'pending')`, environment, machineID, node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_connector_generations WHERE environment_id=$1`, environment)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_helpers WHERE environment_id=$1`, environment)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_tunnel_nodes WHERE id=$1`, node)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_environments WHERE id=$1`, environment)
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/edge/assignments/current", strings.NewReader(`{"environment_id":"`+environment+`","machine_id":"`+machineID+`","connector_id":"runtime"}`))
	request.Header.Set("Authorization", "Bearer edge-control-test")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	NewEdgeService(store, "edge-control-test").Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Revoked any `json:"revoked"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Revoked != false {
		t.Fatalf("assignment=%s err=%v", response.Body.String(), err)
	}
}

func TestEdgeHandlerRejectsUnknownAndTrailingJSON(t *testing.T) {
	service := NewEdgeService(nil, "edge-control-credential-01234567890123456789")
	for _, body := range []string{
		`{"edge_node_id":"node","unknown":true}`,
		`{"edge_node_id":"node"}{"edge_node_id":"other"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/edge/routes/desired-state", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer edge-control-credential-01234567890123456789")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		service.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %q status = %d", body, response.Code)
		}
	}
}
