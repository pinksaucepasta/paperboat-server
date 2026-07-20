package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/observability"
)

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
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,helper_id,edge_pool,edge_node_id,state) VALUES ($1,$2,'default',$3,'pending')`, environment, helper, node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_connector_generations WHERE environment_id=$1`, environment)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_helpers WHERE environment_id=$1`, environment)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_tunnel_nodes WHERE id=$1`, node)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_environments WHERE id=$1`, environment)
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/assignment/current", strings.NewReader(`{"environment_id":"`+environment+`","helper_id":"`+helper+`"}`))
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
		request := httptest.NewRequest(http.MethodPost, "/v1/routes/desired", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer edge-control-credential-01234567890123456789")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		service.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %q status = %d", body, response.Code)
		}
	}
}
