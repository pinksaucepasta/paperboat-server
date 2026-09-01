package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
)

type tunnelAPIStub struct {
	createResult tunnelv1.MutationResult
	createErr    error
	patchResult  tunnelv1.MutationResult
	patchErr     error
	stateResult  tunnelv1.MutationResult
	stateErr     error
	createReq    previewtunnelapi.RequestContext
	patchReq     tunnelv1.PatchTunnelRequest
}

func (s *tunnelAPIStub) CreateTunnel(_ context.Context, request previewtunnelapi.RequestContext, _ tunnelv1.CreateTunnelRequest) (tunnelv1.MutationResult, error) {
	s.createReq = request
	return s.createResult, s.createErr
}

func (s *tunnelAPIStub) ListTunnels(context.Context, previewtunnelapi.RequestContext, string, int) (tunnelv1.TunnelPage, error) {
	return tunnelv1.TunnelPage{}, nil
}

func (s *tunnelAPIStub) GetTunnel(context.Context, previewtunnelapi.RequestContext, string) (tunnelv1.TunnelView, error) {
	return tunnelv1.TunnelView{}, nil
}

func (s *tunnelAPIStub) PatchTunnel(_ context.Context, request previewtunnelapi.RequestContext, _ string, input tunnelv1.PatchTunnelRequest) (tunnelv1.MutationResult, error) {
	s.patchReq = input
	s.patchReq.MutationInput = input.MutationInput
	s.patchReq.Name = input.Name
	s.patchReq.AccessMode = input.AccessMode
	s.patchReq.ExpiresAt = input.ExpiresAt
	_ = request
	return s.patchResult, s.patchErr
}

func (s *tunnelAPIStub) PauseTunnel(context.Context, previewtunnelapi.RequestContext, string, tunnelv1.MutationInput) (tunnelv1.MutationResult, error) {
	return s.stateResult, s.stateErr
}

func (s *tunnelAPIStub) ResumeTunnel(context.Context, previewtunnelapi.RequestContext, string, tunnelv1.MutationInput) (tunnelv1.MutationResult, error) {
	return s.stateResult, s.stateErr
}

func (s *tunnelAPIStub) DeleteTunnel(context.Context, previewtunnelapi.RequestContext, string, tunnelv1.MutationInput) (tunnelv1.MutationResult, error) {
	return s.stateResult, s.stateErr
}

func (s *tunnelAPIStub) Status(context.Context, previewtunnelapi.RequestContext, string) (tunnelv1.HealthView, error) {
	return tunnelv1.HealthView{}, nil
}

type tunnelIdentityVerifier struct {
	claims controlplane.MachineRequestClaims
	err    error
	called bool
}

func (v *tunnelIdentityVerifier) VerifyMachineRequest(_ context.Context, identity string, proof []byte, method, path string, body []byte) (controlplane.MachineRequestClaims, error) {
	v.called = true
	if identity != "signed-machine-identity" || string(proof) != "signed-proof" || method != http.MethodPost || path != "/v1/tunnels" || len(body) == 0 {
		return controlplane.MachineRequestClaims{}, errors.New("unexpected verifier input")
	}
	return v.claims, v.err
}

func tunnelHandlerRequest(method, path string, body []byte) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	client := auth.ClientPrincipal{SessionID: "cli_1", Scopes: []string{"tunnels:read", "tunnels:write"}}
	ctx := context.WithValue(request.Context(), authContextKey{}, principal{
		User: auth.User{ID: "acct_1", Role: auth.RoleUser}, Client: &client,
	})
	ctx = observability.WithRequestID(ctx, "req_1")
	ctx = observability.WithCorrelationID(ctx, "corr_1")
	return request.WithContext(ctx)
}

func tunnelMachineHandlerRequest(method, path string, body []byte) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	ctx := observability.WithRequestID(request.Context(), "req_1")
	ctx = observability.WithCorrelationID(ctx, "corr_1")
	return request.WithContext(ctx)
}

func tunnelMutationResult(state, phase string) tunnelv1.MutationResult {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	return tunnelv1.MutationResult{
		Tunnel: tunnelv1.TunnelView{
			Schema: tunnelv1.Schema, Kind: "tunnel", ID: "tun_1", AccountID: "acct_1", Name: "demo",
			DesiredState: tunnelv1.DesiredActive, AccessMode: tunnelv1.AccessPublic, Generation: 1,
			ETag: previewtunnelapi.ETag("tunnel", "tun_1", 1), StableEndpointID: "11111111-1111-4111-8111-111111111111",
			StableEndpoint: "https://11111111-1111-4111-8111-111111111111.tunnels.example.test", CreatedByHostID: "machine_1",
			CreatedByActorID: "acct_1", SummaryCode: "pending", CreatedAt: now, UpdatedAt: now,
		},
		Operation: previewtunnelapi.Operation{
			Schema: tunnelv1.Schema, Kind: "operation", ID: "op_1", ResourceKind: "tunnel", ResourceID: "tun_1",
			Phase: phase, State: state, Progress: 40, CorrelationID: "corr_1", CreatedAt: now, UpdatedAt: now,
		},
	}
}

func decodeTunnelHandlerBody(t *testing.T, response *httptest.ResponseRecorder) map[string]json.RawMessage {
	t.Helper()
	var envelope struct {
		Data  map[string]json.RawMessage `json:"data"`
		Error map[string]json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("response is not JSON: %v; body=%s", err, response.Body.String())
	}
	if envelope.Data != nil {
		return envelope.Data
	}
	return envelope.Error
}

func TestTunnelCreateUsesSignedMachineIdentityAndOperationBinding(t *testing.T) {
	body := []byte(`{"name":"demo","origin":{"scheme":"http","address":"127.0.0.1:3000"}}`)
	service := &tunnelAPIStub{createResult: tunnelMutationResult("running", "connecting")}
	verifier := &tunnelIdentityVerifier{claims: controlplane.MachineRequestClaims{
		UserID: "acct_1", MachineID: "machine_1", InstallationGeneration: 3, OperationID: "op_create_1",
	}}
	request := tunnelMachineHandlerRequest(http.MethodPost, "/v1/tunnels", body)
	request.Header.Set("Idempotency-Key", "op_create_1")
	request.Header.Set("Authorization", "Bearer signed-machine-identity")
	request.Header.Set("X-Paperboat-Machine-Identity", "signed-machine-identity")
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("signed-proof")))
	response := httptest.NewRecorder()
	tunnelCreate(service, verifier).ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !verifier.called {
		t.Fatalf("status=%d verifier_called=%v body=%s", response.Code, verifier.called, response.Body.String())
	}
	if service.createReq.Actor.AccountID != "acct_1" || service.createReq.Actor.ActorID != "acct_1" || service.createReq.Actor.DeviceID != "machine_1" || service.createReq.Actor.HostID != "machine_1" || service.createReq.Actor.Role != "user" || len(service.createReq.Actor.Scopes) != 1 || service.createReq.Actor.Scopes[0] != "tunnels:write" {
		t.Fatalf("host identity was not derived from signed claims: %+v", service.createReq.Actor)
	}
	data := decodeTunnelHandlerBody(t, response)
	var kind string
	if err := json.Unmarshal(data["kind"], &kind); err != nil || kind != "operation" {
		t.Fatalf("running mutation wire resource kind = %q, body=%s", kind, response.Body.String())
	}
	if _, exposed := data["replayed"]; exposed {
		t.Fatalf("internal replay field leaked: %s", response.Body.String())
	}
}

func TestTunnelCreateRejectsProofReplayUnderDifferentIdempotencyKey(t *testing.T) {
	body := []byte(`{"name":"demo","origin":{"scheme":"http","address":"127.0.0.1:3000"}}`)
	service := &tunnelAPIStub{createResult: tunnelMutationResult("running", "connecting")}
	verifier := &tunnelIdentityVerifier{claims: controlplane.MachineRequestClaims{
		UserID: "acct_1", MachineID: "machine_1", InstallationGeneration: 3, OperationID: "op_signed",
	}}
	request := tunnelMachineHandlerRequest(http.MethodPost, "/v1/tunnels", body)
	request.Header.Set("Idempotency-Key", "op_different")
	request.Header.Set("Authorization", "Bearer signed-machine-identity")
	request.Header.Set("X-Paperboat-Machine-Identity", "signed-machine-identity")
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("signed-proof")))
	response := httptest.NewRecorder()
	tunnelCreate(service, verifier).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || service.createReq.Actor.AccountID != "" {
		t.Fatalf("replayed proof status=%d request=%+v body=%s", response.Code, service.createReq, response.Body.String())
	}
	var payload ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Error.Code != "machine_identity_invalid" {
		t.Fatalf("replay error=%+v body=%s", payload.Error, response.Body.String())
	}
}

func TestTunnelCreateRejectsMissingOrInvalidMachineProof(t *testing.T) {
	body := []byte(`{"name":"demo","origin":{"scheme":"http","address":"127.0.0.1:3000"}}`)
	for _, test := range []struct {
		name  string
		proof string
	}{
		{name: "missing", proof: ""},
		{name: "invalid encoding", proof: "not-base64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &tunnelAPIStub{createResult: tunnelMutationResult("running", "connecting")}
			verifier := &tunnelIdentityVerifier{claims: controlplane.MachineRequestClaims{
				UserID: "acct_1", MachineID: "machine_1", InstallationGeneration: 3, OperationID: "op_create_1",
			}}
			request := tunnelMachineHandlerRequest(http.MethodPost, "/v1/tunnels", body)
			request.Header.Set("Idempotency-Key", "op_create_1")
			request.Header.Set("Authorization", "Bearer signed-machine-identity")
			request.Header.Set("X-Paperboat-Machine-Identity", "signed-machine-identity")
			if test.proof != "" {
				request.Header.Set("X-Paperboat-Machine-Proof", test.proof)
			}
			response := httptest.NewRecorder()
			tunnelCreate(service, verifier).ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || verifier.called || service.createReq.Actor.AccountID != "" {
				t.Fatalf("status=%d verifier_called=%v request=%+v body=%s", response.Code, verifier.called, service.createReq, response.Body.String())
			}
			var payload ErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Error.Code != "machine_identity_invalid" {
				t.Fatalf("error=%+v body=%s", payload.Error, response.Body.String())
			}
		})
	}
}

func TestTunnelCreateRejectsAuthenticatedClientWithoutMachineProof(t *testing.T) {
	service := &tunnelAPIStub{createResult: tunnelMutationResult("running", "connecting")}
	request := tunnelHandlerRequest(http.MethodPost, "/v1/tunnels", []byte(`{"name":"demo","origin":{"scheme":"http","address":"127.0.0.1:3000"}}`))
	request.Header.Set("Idempotency-Key", "op_create_1")
	response := httptest.NewRecorder()
	tunnelCreate(service, &tunnelIdentityVerifier{}).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || service.createReq.Actor.AccountID != "" {
		t.Fatalf("status=%d request=%+v body=%s", response.Code, service.createReq, response.Body.String())
	}
	var payload ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Error.Code != "machine_identity_required" {
		t.Fatalf("error=%+v body=%s", payload.Error, response.Body.String())
	}
}

func TestTunnelMalformedDocumentsReturnTypedBadRequest(t *testing.T) {
	service := &tunnelAPIStub{}
	for _, test := range []struct {
		name    string
		handler http.Handler
		path    string
		body    string
	}{
		{name: "create unknown field", handler: tunnelCreate(service, &tunnelIdentityVerifier{}), path: "/v1/tunnels", body: `{"name":"demo","unexpected":true}`},
		{name: "patch unknown field", handler: tunnelPatch(service), path: "/v1/tunnels/tun_1", body: `{"unexpected":true}`},
		{name: "state nonempty", handler: tunnelPause(service), path: "/v1/tunnels/tun_1/pause", body: `{"unexpected":true}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := tunnelHandlerRequest(http.MethodPost, test.path, []byte(test.body))
			if test.name == "patch unknown field" {
				request.Method = http.MethodPatch
			}
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var payload ErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Error.Code != "invalid_request" {
				t.Fatalf("typed error=%+v body=%s", payload.Error, response.Body.String())
			}
		})
	}
}

func TestTunnelPatchDistinguishesExplicitExpiryRemovalAndReturnsCanonicalOperation(t *testing.T) {
	service := &tunnelAPIStub{patchResult: tunnelMutationResult("running", "connecting")}
	request := tunnelHandlerRequest(http.MethodPatch, "/v1/tunnels/tun_1", []byte(`{"expires_at":null}`))
	request.SetPathValue("tunnel_id", "tun_1")
	request.Header.Set("If-Match", previewtunnelapi.ETag("tunnel", "tun_1", 1))
	request.Header.Set("Idempotency-Key", "op_patch_1")
	response := httptest.NewRecorder()
	tunnelPatch(service).ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !service.patchReq.ExpirySet || service.patchReq.ExpiresAt != nil {
		t.Fatalf("status=%d patch=%+v body=%s", response.Code, service.patchReq, response.Body.String())
	}
	data := decodeTunnelHandlerBody(t, response)
	var kind string
	if err := json.Unmarshal(data["kind"], &kind); err != nil || kind != "operation" {
		t.Fatalf("wire kind=%q body=%s", kind, response.Body.String())
	}
}
