package privateaccess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

func testClock() time.Time { return time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC) }

func testRequest(now time.Time) Request {
	return Request{AccountID: "acct_1", ResourceKind: ResourcePreview, ResourceID: "preview_1", RouteID: "route_1", Audience: AudiencePreviewHTTP,
		DeviceID: "machine_1", SessionID: "installation_3", InstallationGeneration: 3, ExpiresAt: now.Add(30 * time.Second), Nonce: "nonce_1", OperationID: "operation_1",
		CarrierSessionID: "carrier_session_1", RouteGeneration: 4, SessionGeneration: 5, ProcessGeneration: 6, ConfigGeneration: 7, AssignmentGeneration: 8,
		EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_001", Protocol: ProtocolHTTP, Method: "GET", Host: "preview.example.test", Path: "/api/v1",
		IdempotencyKey: "operation_issue_1", RequestID: "req_001", CorrelationID: "corr_001"}
}

func testBinding(now time.Time) Binding {
	return Binding{AccountID: "acct_1", ResourceKind: ResourcePreview, ResourceID: "preview_1", RouteID: "route_1", OperationID: "operation_1", CarrierSessionID: "carrier_session_1",
		OwnerDeviceID: "machine_1", OwnerSessionID: "owner_session_1", RouteGeneration: 4, SessionGeneration: 5, ProcessGeneration: 6, ConfigGeneration: 7, AssignmentGeneration: 8,
		Protocol: ProtocolHTTP, AccessMode: "private", State: "ready", ExpiresAt: now.Add(time.Minute), Hostname: "preview.example.test", PathPrefix: "/api", EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_001"}
}

type fakeResolver struct {
	binding Binding
	err     error
	calls   int
}

func (f *fakeResolver) ResolvePrivate(context.Context, Lookup) (Binding, error) {
	f.calls++
	return f.binding, f.err
}

type fakeEdge struct {
	identity EdgeIdentity
	err      error
}

func (f fakeEdge) VerifyEdgeRequest(context.Context, *http.Request, []byte) (EdgeIdentity, error) {
	return f.identity, f.err
}

type fakeMachineRequest struct {
	claims      controlplane.MachineRequestClaims
	err         error
	credential  string
	proof, body []byte
}

func (f *fakeMachineRequest) VerifyMachineControlRequest(_ context.Context, credential string, proof []byte, _, _ string, body []byte) (controlplane.MachineRequestClaims, error) {
	f.credential = credential
	f.proof = append([]byte(nil), proof...)
	f.body = append([]byte(nil), body...)
	return f.claims, f.err
}

type fakeMachineState struct {
	err      error
	calls    int
	identity Identity
}

func (f *fakeMachineState) VerifyCurrentMachine(_ context.Context, identity Identity, _ time.Time) error {
	f.calls++
	f.identity = identity
	return f.err
}

type fakeGrant struct {
	request Request
	token   string
}

func (f *fakeGrant) MintGrant(_ context.Context, r Request, _ time.Time) (string, error) {
	f.request = r
	if f.token == "" {
		f.token = "signed_grant"
	}
	return f.token, nil
}
func (f *fakeGrant) VerifyGrant(_ context.Context, token string, _ time.Time) (Request, error) {
	if token != f.token {
		return Request{}, ErrIdentityUnavailable
	}
	return f.request, nil
}

func TestMachineGrantThenEdgeAuthorize(t *testing.T) {
	now := testClock()
	resolver := &fakeResolver{binding: testBinding(now)}
	grants := &fakeGrant{}
	state := &fakeMachineState{}
	service, err := NewService(resolver, nil, Config{Now: testClock, GrantMinter: grants, GrantVerifier: grants, MachineState: state})
	if err != nil {
		t.Fatal(err)
	}
	machine := &fakeMachineRequest{claims: controlplane.MachineRequestClaims{UserID: "acct_1", MachineID: "machine_1", InstallationGeneration: 3, SessionGeneration: 5, CredentialJTI: "mcc_current_1", OperationID: "operation_issue_1"}}
	grantHandler, err := NewGrantHTTPHandler(service, machine)
	if err != nil {
		t.Fatal(err)
	}
	r := testRequest(now)
	issue := GrantIssueRequest{ResourceKind: r.ResourceKind, ResourceID: r.ResourceID, RouteID: r.RouteID, Audience: r.Audience, ExpiresAt: r.ExpiresAt, Nonce: r.Nonce, OperationID: r.OperationID, CarrierSessionID: r.CarrierSessionID, RouteGeneration: r.RouteGeneration, SessionGeneration: r.SessionGeneration, ProcessGeneration: r.ProcessGeneration, ConfigGeneration: r.ConfigGeneration, AssignmentGeneration: r.AssignmentGeneration, EdgeNodeID: r.EdgeNodeID, EdgeProcessEpoch: r.EdgeProcessEpoch, Protocol: r.Protocol, Method: r.Method, Host: r.Host, Path: r.Path, IdempotencyKey: r.IdempotencyKey, RequestID: r.RequestID, CorrelationID: r.CorrelationID}
	body, _ := json.Marshal(issue)
	req := httptest.NewRequest(http.MethodPost, GrantPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer machine_control_token")
	req.Header.Set("X-Paperboat-Machine-Identity", "machine_control_token")
	req.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("proof")))
	rec := httptest.NewRecorder()
	grantHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("grant status/body=%d/%s", rec.Code, rec.Body.String())
	}
	if machine.credential != "machine_control_token" || !bytes.Equal(machine.body, body) {
		t.Fatal("machine verifier did not receive exact credential/body")
	}
	authorize, err := NewHTTPHandler(service, fakeEdge{identity: EdgeIdentity{NodeID: "edge_1", ProcessEpoch: "epoch_001"}})
	if err != nil {
		t.Fatal(err)
	}
	authReq := httptest.NewRequest(http.MethodPost, AuthorizePath, bytes.NewReader(mustJSON(t, grants.request)))
	authReq.Header.Set("Content-Type", "application/json")
	authReq.Header.Set("X-Paperboat-Private-Access-Grant", grants.token)
	authRec := httptest.NewRecorder()
	authorize.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusOK {
		t.Fatalf("authorize status/body=%d/%s", authRec.Code, authRec.Body.String())
	}
	if state.calls != 1 || state.identity.DeviceID != "machine_1" || state.identity.SessionID != "mcc_current_1" || state.identity.InstallationGeneration != 3 {
		t.Fatalf("state check=%#v calls=%d", state.identity, state.calls)
	}
}

func TestEdgeAuthorizeRejectsRequestThatDoesNotMatchSignedGrant(t *testing.T) {
	now := testClock()
	signed := testRequest(now)
	grants := &fakeGrant{request: signed, token: "signed_grant"}
	service, err := NewService(&fakeResolver{binding: testBinding(now)}, nil, Config{Now: testClock, GrantVerifier: grants, MachineState: &fakeMachineState{}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHTTPHandler(service, fakeEdge{identity: EdgeIdentity{NodeID: "edge_1", ProcessEpoch: "epoch_001"}})
	if err != nil {
		t.Fatal(err)
	}
	submitted := signed
	submitted.Path = "/api/different"
	request := httptest.NewRequest(http.MethodPost, AuthorizePath, bytes.NewReader(mustJSON(t, submitted)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Paperboat-Private-Access-Grant", grants.token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status/body=%d/%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), signed.ResourceID) || strings.Contains(recorder.Body.String(), signed.RouteID) {
		t.Fatalf("denial disclosed signed binding: %s", recorder.Body.String())
	}
}

func TestAuthorizeStatusMapping(t *testing.T) {
	now := testClock()
	r := testRequest(now)
	grants := &fakeGrant{request: r, token: "grant"}
	for _, tc := range []struct {
		name        string
		stateErr    error
		resolverErr error
		want        int
	}{{"revoked", newDenied(ReasonDeviceRevoked), nil, http.StatusUnauthorized}, {"denied", nil, newDenied(ReasonWrongRoute), http.StatusForbidden}, {"unavailable", ErrIdentityUnavailable, nil, http.StatusServiceUnavailable}} {
		t.Run(tc.name, func(t *testing.T) {
			service, _ := NewService(&fakeResolver{binding: testBinding(now), err: tc.resolverErr}, nil, Config{Now: testClock, GrantVerifier: grants, MachineState: &fakeMachineState{err: tc.stateErr}})
			h, _ := NewHTTPHandler(service, fakeEdge{identity: EdgeIdentity{NodeID: "edge_1", ProcessEpoch: "epoch_001"}})
			req := httptest.NewRequest(http.MethodPost, AuthorizePath, bytes.NewReader(mustJSON(t, r)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Paperboat-Private-Access-Grant", "grant")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status/body=%d/%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
