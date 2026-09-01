package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
)

// Embedding the production interface keeps this handler test focused on wire
// parsing and status/error contracts. Each test overrides only the operation
// it exercises; uncalled methods cannot accidentally become a second fake API.
type resourceAPIStub struct {
	tunnelv1.ResourceAPI
	createRouteFn        func(context.Context, previewtunnelapi.RequestContext, string, tunnelv1.RouteCreateRequest) (tunnelv1.RouteMutationResult, error)
	patchRouteFn         func(context.Context, previewtunnelapi.RequestContext, string, string, tunnelv1.RoutePatchRequest) (tunnelv1.RouteMutationResult, error)
	drainConnectorFn     func(context.Context, previewtunnelapi.RequestContext, string, string, tunnelv1.ResourceMutationInput) (tunnelv1.ConnectorMutationResult, error)
	domainInstructionsFn func(context.Context, previewtunnelapi.RequestContext, string, string) (tunnelv1.DNSInstructions, error)
	tunnelLogsFn         func(context.Context, previewtunnelapi.RequestContext, string, string, int) (tunnelv1.LogPage, error)
	createRouteInput     tunnelv1.RouteCreateRequest
}

func (s *resourceAPIStub) CreateRoute(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID string, input tunnelv1.RouteCreateRequest) (tunnelv1.RouteMutationResult, error) {
	s.createRouteInput = input
	return s.createRouteFn(ctx, request, tunnelID, input)
}

func (s *resourceAPIStub) PatchRoute(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, routeID string, input tunnelv1.RoutePatchRequest) (tunnelv1.RouteMutationResult, error) {
	return s.patchRouteFn(ctx, request, tunnelID, routeID, input)
}

func (s *resourceAPIStub) DrainConnector(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, connectorID string, input tunnelv1.ResourceMutationInput) (tunnelv1.ConnectorMutationResult, error) {
	return s.drainConnectorFn(ctx, request, tunnelID, connectorID, input)
}

func (s *resourceAPIStub) DomainInstructions(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, domainID string) (tunnelv1.DNSInstructions, error) {
	return s.domainInstructionsFn(ctx, request, tunnelID, domainID)
}

func (s *resourceAPIStub) ListTunnelLogs(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, cursor string, limit int) (tunnelv1.LogPage, error) {
	return s.tunnelLogsFn(ctx, request, tunnelID, cursor, limit)
}

func resourceRouteMutationForHandler() tunnelv1.RouteMutationResult {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	return tunnelv1.RouteMutationResult{
		Route:     tunnelv1.RouteView{Schema: tunnelv1.Schema, Kind: "route", ID: "rte_1", TunnelID: "tun_1", Name: "wild", Protocol: "http", HostMatch: tunnelv1.RouteHostMatch{Type: "one_label_wildcard", Hostname: "*.example.com", WildcardLabels: intPtr(1)}, Origin: tunnelv1.RouteOrigin{Scheme: "http", Address: "127.0.0.1:3000", PreserveHost: true}, Priority: 100, ConnectTimeoutMS: 10000, IdleTimeoutMS: 90000, MaxConcurrentStreams: 128, DesiredState: "active", Generation: 1, ETag: previewtunnelapi.ETag("route", "rte_1", 1)},
		Operation: previewtunnelapi.Operation{Schema: tunnelv1.Schema, Kind: "operation", ID: "op_1", ResourceKind: "route", ResourceID: "rte_1", Phase: "ready", State: "succeeded", Progress: 100, CorrelationID: "corr_1", CreatedAt: now, UpdatedAt: now},
		Changed:   true,
	}
}

func intPtr(value int) *int {
	return &value
}

func resourceConnectorMutationForHandler() tunnelv1.ConnectorMutationResult {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	return tunnelv1.ConnectorMutationResult{
		Connector: tunnelv1.ConnectorView{Schema: tunnelv1.Schema, Kind: "connector", ID: "con_1", TunnelID: "tun_1", HostID: "host_1", CredentialReference: "keychain://paperboat/connector", RotationGeneration: 1, DesiredState: "draining", ProtocolVersion: "1.0", DrainState: "draining", Generation: 2, ETag: previewtunnelapi.ETag("connector", "con_1", 2)},
		Operation: previewtunnelapi.Operation{Schema: tunnelv1.Schema, Kind: "operation", ID: "op_1", ResourceKind: "connector", ResourceID: "con_1", Phase: "draining", State: "running", Progress: 60, CorrelationID: "corr_1", CreatedAt: now, UpdatedAt: now},
		Changed:   true,
	}
}

func TestTunnelResourceRouteCreateNormalizesWildcardWireInput(t *testing.T) {
	service := &resourceAPIStub{createRouteFn: func(_ context.Context, _ previewtunnelapi.RequestContext, tunnelID string, input tunnelv1.RouteCreateRequest) (tunnelv1.RouteMutationResult, error) {
		if tunnelID != "tun_1" {
			t.Fatalf("tunnel id = %q", tunnelID)
		}
		return resourceRouteMutationForHandler(), nil
	}}
	body := []byte(`{"name":"wild","protocol":"http","host_match":{"type":"one_label_wildcard","hostname":"*.Example.COM","wildcard_labels":1},"origin":{"scheme":"http","address":"127.0.0.1:3000","preserve_host":true}}`)
	request := tunnelHandlerRequest(http.MethodPost, "/v1/tunnels/tun_1/routes", body)
	request.SetPathValue("tunnel_id", "tun_1")
	request.Header.Set("Idempotency-Key", "route_create_1")
	response := httptest.NewRecorder()
	tunnelResourceRouteCreate(service).ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if service.createRouteInput.MatchType != "one_label_wildcard" || service.createRouteInput.WildcardSuffix != "Example.COM" || service.createRouteInput.Hostname != "" {
		t.Fatalf("wildcard service input = %+v", service.createRouteInput)
	}
	if bytes.Contains(response.Body.Bytes(), []byte(`"wildcard_suffix"`)) || !bytes.Contains(response.Body.Bytes(), []byte(`"hostname":"*.example.com"`)) {
		t.Fatalf("wire response leaked DB wildcard shape: %s", response.Body.String())
	}
}

func TestTunnelResourceMutationsRejectUnknownEmptyBodiesAndInvalidETags(t *testing.T) {
	service := &resourceAPIStub{
		patchRouteFn: func(context.Context, previewtunnelapi.RequestContext, string, string, tunnelv1.RoutePatchRequest) (tunnelv1.RouteMutationResult, error) {
			return resourceRouteMutationForHandler(), nil
		},
		drainConnectorFn: func(context.Context, previewtunnelapi.RequestContext, string, string, tunnelv1.ResourceMutationInput) (tunnelv1.ConnectorMutationResult, error) {
			return resourceConnectorMutationForHandler(), nil
		},
	}
	tests := []struct {
		name       string
		handler    http.Handler
		method     string
		path       string
		body       string
		ifMatch    string
		wantStatus int
		wantCode   string
	}{
		{name: "unknown delete field", handler: tunnelResourceConnectorDrain(service), method: http.MethodPost, path: "/v1/tunnels/tun_1/connectors/con_1/drain", body: `{"secret":1}`, ifMatch: previewtunnelapi.ETag("connector", "con_1", 1), wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "missing if match", handler: tunnelResourceConnectorDrain(service), method: http.MethodPost, path: "/v1/tunnels/tun_1/connectors/con_1/drain", body: `{}`, wantStatus: http.StatusPreconditionRequired, wantCode: "if_match_required"},
		{name: "malformed if match", handler: tunnelResourceRoutePatch(service), method: http.MethodPatch, path: "/v1/tunnels/tun_1/routes/rte_1", body: `{}`, ifMatch: "not-an-etag", wantStatus: http.StatusBadRequest, wantCode: "invalid_etag"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := tunnelHandlerRequest(test.method, test.path, []byte(test.body))
			request.SetPathValue("tunnel_id", "tun_1")
			request.SetPathValue("route_id", "rte_1")
			request.SetPathValue("connector_id", "con_1")
			request.Header.Set("Idempotency-Key", "mutation_1")
			if test.ifMatch != "" {
				request.Header.Set("If-Match", test.ifMatch)
			}
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			var envelope ErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode error: %v; body=%s", err, response.Body.String())
			}
			if envelope.Error.Code != test.wantCode {
				t.Fatalf("error code = %q, body=%s", envelope.Error.Code, response.Body.String())
			}
		})
	}
}

func TestTunnelResourceDNSInstructionsAndLogsExposeTypedOutcomes(t *testing.T) {
	service := &resourceAPIStub{
		domainInstructionsFn: func(context.Context, previewtunnelapi.RequestContext, string, string) (tunnelv1.DNSInstructions, error) {
			return tunnelv1.DNSInstructions{}, tunnelv1.ErrDNSInstructionsUnavailable
		},
		tunnelLogsFn: func(context.Context, previewtunnelapi.RequestContext, string, string, int) (tunnelv1.LogPage, error) {
			return tunnelv1.LogPage{Items: []tunnelv1.LogEntry{{Schema: tunnelv1.Schema, Kind: "log_entry", ID: "log_1", TunnelID: "tun_1", Level: "info", Component: "control", Code: "route_updated", Message: "route persisted", Metadata: map[string]any{"attempt": 2}, CorrelationID: "corr_1", OccurredAt: time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC), Cursor: "1"}}}, nil
		},
	}
	request := tunnelHandlerRequest(http.MethodGet, "/v1/tunnels/tun_1/domains/dom_1/instructions", nil)
	request.SetPathValue("tunnel_id", "tun_1")
	request.SetPathValue("domain_id", "dom_1")
	response := httptest.NewRecorder()
	tunnelResourceDomainInstructions(service).ServeHTTP(response, request)
	if response.Code != http.StatusNotImplemented || !bytes.Contains(response.Body.Bytes(), []byte(`"code":"dns_instructions_unavailable"`)) {
		t.Fatalf("DNS response = %d %s", response.Code, response.Body.String())
	}

	request = tunnelHandlerRequest(http.MethodGet, "/v1/tunnels/tun_1/logs?limit=20", nil)
	request.SetPathValue("tunnel_id", "tun_1")
	response = httptest.NewRecorder()
	tunnelResourceTunnelLogs(service).ServeHTTP(response, request)
	if response.Code != http.StatusOK || bytes.Contains(response.Body.Bytes(), []byte(`"next_cursor"`)) {
		t.Fatalf("tail log page = %d %s", response.Code, response.Body.String())
	}
}

func TestTunnelResourceConflictIsMappedWithoutLeakingStorageDetails(t *testing.T) {
	service := &resourceAPIStub{createRouteFn: func(context.Context, previewtunnelapi.RequestContext, string, tunnelv1.RouteCreateRequest) (tunnelv1.RouteMutationResult, error) {
		return tunnelv1.RouteMutationResult{}, fmt.Errorf("constraint tunnel_routes_tunnel_id_name_key: %w", tunnelv1.ErrRouteConflict)
	}}
	body := []byte(`{"name":"route","protocol":"http","host_match":{"type":"catch_all"},"origin":{"scheme":"http","address":"127.0.0.1:3000","preserve_host":true}}`)
	request := tunnelHandlerRequest(http.MethodPost, "/v1/tunnels/tun_1/routes", body)
	request.SetPathValue("tunnel_id", "tun_1")
	request.Header.Set("Idempotency-Key", "route_conflict_1")
	response := httptest.NewRecorder()
	tunnelResourceRouteCreate(service).ServeHTTP(response, request)
	if response.Code != http.StatusConflict || bytes.Contains(response.Body.Bytes(), []byte("tunnel_routes_tunnel_id_name_key")) || !bytes.Contains(response.Body.Bytes(), []byte(`"code":"route_conflict"`)) {
		t.Fatalf("conflict response = %d %s", response.Code, response.Body.String())
	}
}

func TestTunnelResourceServiceErrorsDoNotExposeSecrets(t *testing.T) {
	service := &resourceAPIStub{patchRouteFn: func(context.Context, previewtunnelapi.RequestContext, string, string, tunnelv1.RoutePatchRequest) (tunnelv1.RouteMutationResult, error) {
		return tunnelv1.RouteMutationResult{}, errors.New("Bearer secret-value")
	}}
	request := tunnelHandlerRequest(http.MethodPatch, "/v1/tunnels/tun_1/routes/rte_1", []byte(`{"name":"route"}`))
	request.SetPathValue("tunnel_id", "tun_1")
	request.SetPathValue("route_id", "rte_1")
	request.Header.Set("Idempotency-Key", "route_secret_1")
	request.Header.Set("If-Match", previewtunnelapi.ETag("route", "rte_1", 1))
	response := httptest.NewRecorder()
	tunnelResourceRoutePatch(service).ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || bytes.Contains(response.Body.Bytes(), []byte("secret-value")) {
		t.Fatalf("secret-bearing error response = %d %s", response.Code, response.Body.String())
	}
}

func TestWriteConnectorActivationReturnsAuthoritativeGenerations(t *testing.T) {
	response := httptest.NewRecorder()
	activation := &tunnelv1.ConnectorActivation{
		Schema: tunnelv1.Schema, Kind: "connector_activation", AccountID: "acct_1", TunnelID: "tun_1",
		ConnectorID: "con_1", HostID: "host_1", StableEndpointID: "11111111-1111-4111-8111-111111111111", CredentialGeneration: 3,
		ProcessGeneration: 7, Operation: previewtunnelapi.Operation{Schema: tunnelv1.Schema, Kind: "operation", ID: "op_1", ResourceKind: "connector", ResourceID: "con_1", Phase: "connecting", State: "running"},
	}
	writeConnectorActivation(response, tunnelv1.ConnectorMutationResult{Activation: activation})
	if response.Code != http.StatusAccepted || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d headers=%v", response.Code, response.Header())
	}
	var envelope struct {
		Data tunnelv1.ConnectorActivation `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Kind != "connector_activation" || envelope.Data.AccountID != "acct_1" || envelope.Data.ConnectorID != "con_1" || envelope.Data.StableEndpointID != "11111111-1111-4111-8111-111111111111" || envelope.Data.CredentialGeneration != 3 || envelope.Data.ProcessGeneration != 7 || envelope.Data.Operation.ID != "op_1" {
		t.Fatalf("activation = %+v", envelope.Data)
	}
}
