package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
)

type enrollmentHTTPAPIStub struct {
	tunnelv1.ResourceAPI
	issueCalls      int
	issueRequest    previewtunnelapi.RequestContext
	exchangeCalls   int
	exchangeRequest previewtunnelapi.RequestContext
	exchangeInput   tunnelv1.EnrollmentExchangeRequest
}

func (s *enrollmentHTTPAPIStub) IssueEnrollment(_ context.Context, request previewtunnelapi.RequestContext, tunnelID string, input tunnelv1.EnrollmentRequest) (tunnelv1.EnrollmentResult, error) {
	s.issueCalls++
	s.issueRequest = request
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	return tunnelv1.EnrollmentResult{
		Schema: tunnelv1.Schema, Kind: "connector_enrollment", ID: "enr_1", TunnelID: tunnelID, HostID: input.HostID,
		Operation: previewtunnelapi.Operation{Schema: tunnelv1.Schema, Kind: "operation", ID: "op_1", ResourceKind: "connector", ResourceID: "enr_1", Phase: "ready", State: "succeeded", Progress: 100, CreatedAt: now, UpdatedAt: now},
		Token:     "pbce_test_token", ExpiresAt: now.Add(10 * time.Minute), Capabilities: append([]string(nil), input.Capabilities...),
	}, nil
}

func (s *enrollmentHTTPAPIStub) ExchangeEnrollment(_ context.Context, request previewtunnelapi.RequestContext, input tunnelv1.EnrollmentExchangeRequest) (tunnelv1.ConnectorMutationResult, error) {
	s.exchangeCalls++
	s.exchangeRequest = request
	s.exchangeInput = input
	return tunnelv1.ConnectorMutationResult{}, nil
}

type enrollmentMachineVerifier struct {
	claims   controlplane.MachineRequestClaims
	err      error
	identity string
	proof    []byte
	method   string
	path     string
	body     []byte
	called   bool
}

func (v *enrollmentMachineVerifier) VerifyMachineRequest(_ context.Context, identity string, proof []byte, method, path string, body []byte) (controlplane.MachineRequestClaims, error) {
	v.called = true
	v.identity, v.proof, v.method, v.path, v.body = identity, append([]byte(nil), proof...), method, path, append([]byte(nil), body...)
	if v.err != nil {
		return controlplane.MachineRequestClaims{}, v.err
	}
	return v.claims, nil
}

func enrollmentMachineRequest(method, path string, body []byte) *http.Request {
	request := tunnelMachineHandlerRequest(method, path, body)
	request.Header.Set("Authorization", "Bearer machine-control")
	request.Header.Set("X-Paperboat-Machine-Identity", "machine-control")
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("machine-proof")))
	return request
}

func enrollmentIssueBody() []byte {
	return []byte(`{"host_id":"machine_1","capabilities":["http"],"ttl_seconds":60}`)
}

func TestTunnelConnectorEnrollmentIssueUsesExactMachineActor(t *testing.T) {
	service := &enrollmentHTTPAPIStub{}
	verifier := &enrollmentMachineVerifier{claims: controlplane.MachineRequestClaims{UserID: "acct_1", MachineID: "machine_1", InstallationGeneration: 7, OperationID: "enrollment_issue_1"}}
	body := enrollmentIssueBody()
	request := enrollmentMachineRequest(http.MethodPost, "/v1/tunnels/tun_1/connectors/enrollments", body)
	request.SetPathValue("tunnel_id", "tun_1")
	request.Header.Set("Idempotency-Key", "enrollment_issue_1")
	response := httptest.NewRecorder()
	tunnelResourceIssueEnrollment(service, verifier).ServeHTTP(response, request)

	if response.Code != http.StatusCreated || service.issueCalls != 1 || !verifier.called {
		t.Fatalf("status=%d calls=%d verifier_called=%v body=%s", response.Code, service.issueCalls, verifier.called, response.Body.String())
	}
	if verifier.identity != "machine-control" || !bytes.Equal(verifier.proof, []byte("machine-proof")) || verifier.method != http.MethodPost || verifier.path != "/v1/tunnels/tun_1/connectors/enrollments" || !bytes.Equal(verifier.body, body) {
		t.Fatalf("machine proof inputs changed: identity=%q proof=%q method=%q path=%q body=%q", verifier.identity, verifier.proof, verifier.method, verifier.path, verifier.body)
	}
	actor := service.issueRequest.Actor
	if actor.AccountID != "acct_1" || actor.ActorID != "acct_1" || actor.DeviceID != "machine_1" || actor.HostID != "machine_1" || actor.Role != "user" || len(actor.Scopes) != 1 || actor.Scopes[0] != "tunnels:write" {
		t.Fatalf("issue actor was not derived from machine claims: %+v", actor)
	}
	if strings.Contains(response.Body.String(), "machine-proof") {
		t.Fatalf("response leaked machine proof: %s", response.Body.String())
	}
}

func TestTunnelConnectorEnrollmentIssueRejectsClientSession(t *testing.T) {
	service := &enrollmentHTTPAPIStub{}
	request := tunnelHandlerRequest(http.MethodPost, "/v1/tunnels/tun_1/connectors/enrollments", enrollmentIssueBody())
	request.SetPathValue("tunnel_id", "tun_1")
	request.Header.Set("Idempotency-Key", "enrollment_issue_1")
	response := httptest.NewRecorder()
	tunnelResourceIssueEnrollment(service, &enrollmentMachineVerifier{}).ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || service.issueCalls != 0 || !strings.Contains(response.Body.String(), `"code":"machine_identity_required"`) {
		t.Fatalf("client-session issue status=%d calls=%d body=%s", response.Code, service.issueCalls, response.Body.String())
	}
}

func TestTunnelConnectorEnrollmentIssueRejectsInvalidMachineBinding(t *testing.T) {
	tests := []struct {
		name   string
		claims controlplane.MachineRequestClaims
		err    error
		setup  func(*http.Request)
		status int
		code   string
	}{
		{
			name: "proof verifier failure", claims: controlplane.MachineRequestClaims{}, err: errors.New("invalid proof"),
			status: http.StatusUnauthorized, code: "machine_identity_invalid",
		},
		{
			name: "wrong host", claims: controlplane.MachineRequestClaims{UserID: "acct_1", MachineID: "machine_2", InstallationGeneration: 7, OperationID: "enrollment_issue_1"},
			status: http.StatusForbidden, code: "connector_access_forbidden",
		},
		{
			name: "wrong bearer identity", claims: controlplane.MachineRequestClaims{UserID: "acct_1", MachineID: "machine_1", InstallationGeneration: 7, OperationID: "enrollment_issue_1"},
			setup:  func(request *http.Request) { request.Header.Set("Authorization", "Bearer another-machine") },
			status: http.StatusUnauthorized, code: "machine_identity_invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &enrollmentHTTPAPIStub{}
			verifier := &enrollmentMachineVerifier{claims: test.claims, err: test.err}
			request := enrollmentMachineRequest(http.MethodPost, "/v1/tunnels/tun_1/connectors/enrollments", enrollmentIssueBody())
			request.SetPathValue("tunnel_id", "tun_1")
			request.Header.Set("Idempotency-Key", "enrollment_issue_1")
			if test.setup != nil {
				test.setup(request)
			}
			response := httptest.NewRecorder()
			tunnelResourceIssueEnrollment(service, verifier).ServeHTTP(response, request)
			if response.Code != test.status || service.issueCalls != 0 || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, service.issueCalls, response.Body.String())
			}
		})
	}
}

func TestTunnelConnectorEnrollmentIssueRejectsPrincipalAccountMismatch(t *testing.T) {
	service := &enrollmentHTTPAPIStub{}
	verifier := &enrollmentMachineVerifier{claims: controlplane.MachineRequestClaims{UserID: "acct_1", MachineID: "machine_1", InstallationGeneration: 7, OperationID: "enrollment_issue_1"}}
	request := enrollmentMachineRequest(http.MethodPost, "/v1/tunnels/tun_1/connectors/enrollments", enrollmentIssueBody())
	request.SetPathValue("tunnel_id", "tun_1")
	request.Header.Set("Idempotency-Key", "enrollment_issue_1")
	ctx := context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "acct_2", Role: auth.RoleUser}})
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	tunnelResourceIssueEnrollment(service, verifier).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || service.issueCalls != 0 || !strings.Contains(response.Body.String(), `"code":"forbidden"`) {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, service.issueCalls, response.Body.String())
	}
}

func TestTunnelConnectorEnrollmentExchangeStillRequiresCredentialProof(t *testing.T) {
	service := &enrollmentHTTPAPIStub{}
	verifier := &enrollmentMachineVerifier{claims: controlplane.MachineRequestClaims{UserID: "acct_1", MachineID: "machine_1", InstallationGeneration: 7, OperationID: "enrollment_exchange_1"}}
	document := map[string]any{
		"token": "pbce_one_time", "host_id": "machine_1", "protocol_version": "1.0",
		"credential_reference": "keychain://paperboat/connector", "credential_thumbprint": "ed25519:test",
		"credential_verifier_algorithm": "ed25519", "credential_verifier_public_key": "invalid", "credential_proof": "invalid",
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	request := enrollmentMachineRequest(http.MethodPost, "/v1/tunnels/tun_1/connectors/enrollments/exchange", body)
	request.SetPathValue("tunnel_id", "tun_1")
	request.Header.Set("Idempotency-Key", "enrollment_exchange_1")
	response := httptest.NewRecorder()
	tunnelResourceExchangeEnrollment(service, verifier).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || service.exchangeCalls != 0 || !strings.Contains(response.Body.String(), `"code":"connector_credential_proof_invalid"`) {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, service.exchangeCalls, response.Body.String())
	}
}

func TestTunnelConnectorEnrollmentAuthRejectsClientSession(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	request := tunnelHandlerRequest(http.MethodPost, "/v1/tunnels/tun_1/connectors/enrollments", enrollmentIssueBody())
	response := httptest.NewRecorder()
	tunnelConnectorEnrollmentAuth(next).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || called || !strings.Contains(response.Body.String(), `"code":"machine_identity_required"`) {
		t.Fatalf("status=%d called=%v body=%s", response.Code, called, response.Body.String())
	}
}
