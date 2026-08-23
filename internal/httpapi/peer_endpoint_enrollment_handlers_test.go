package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

type machineProofVerifierFunc func(context.Context, string, []byte, string, string, []byte) (controlplane.MachineRequestClaims, error)

type cliEndpointRequesterFunc func(context.Context, peeridentity.CLIEndpointRequest) (peeridentity.EndpointEnrollmentRequest, error)

func (f cliEndpointRequesterFunc) RequestCLIEndpoint(ctx context.Context, request peeridentity.CLIEndpointRequest) (peeridentity.EndpointEnrollmentRequest, error) {
	return f(ctx, request)
}

func TestCLIEndpointRequestBindsAuthenticatedSessionAndKeys(t *testing.T) {
	noise := bytes.Repeat([]byte{1}, 32)
	quic := bytes.Repeat([]byte{2}, 32)
	var got peeridentity.CLIEndpointRequest
	request := httptest.NewRequest(http.MethodPost, "/v1/e2ee/endpoint-requests", strings.NewReader(`{"operation_id":"operation_cli_01","endpoint_id":"cli_session_01","generation":1,"noise_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","quic_public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}`))
	request.Header.Set("Idempotency-Key", "operation_cli_01")
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}, Client: &auth.ClientPrincipal{SessionID: "cli_session_01"}}))
	response := httptest.NewRecorder()
	cliEndpointRequest(cliEndpointRequesterFunc(func(_ context.Context, value peeridentity.CLIEndpointRequest) (peeridentity.EndpointEnrollmentRequest, error) {
		got = value
		return peeridentity.EndpointEnrollmentRequest{ID: "per_0123456789abcdef", UserID: value.UserID, EndpointID: value.EndpointID, Generation: value.Generation, Role: peeridentity.RoleCLI, State: "pending", NoisePublicKey: value.NoisePublicKey, QUICPublicKey: value.QUICPublicKey, CreatedAt: value.Now, ExpiresAt: value.Now.Add(time.Minute)}, nil
	})).ServeHTTP(response, request)
	if response.Code != http.StatusCreated || got.UserID != "account_01" || got.EndpointID != "cli_session_01" || got.Generation != 1 || !bytes.Equal(got.NoisePublicKey[:], noise) || !bytes.Equal(got.QUICPublicKey[:], quic) {
		t.Fatalf("status=%d request=%+v body=%s", response.Code, got, response.Body.String())
	}
}

func TestCLIEndpointRequestRejectsSessionImpersonation(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/e2ee/endpoint-requests", strings.NewReader(`{"operation_id":"operation_cli_01","endpoint_id":"other_session","generation":1,"noise_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","quic_public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}`))
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}, Client: &auth.ClientPrincipal{SessionID: "cli_session_01"}}))
	response := httptest.NewRecorder()
	cliEndpointRequest(cliEndpointRequesterFunc(func(context.Context, peeridentity.CLIEndpointRequest) (peeridentity.EndpointEnrollmentRequest, error) {
		t.Fatal("requester called")
		return peeridentity.EndpointEnrollmentRequest{}, nil
	})).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCLIEndpointRequestReturnsFulfilledReplayState(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/e2ee/endpoint-requests", strings.NewReader(`{"operation_id":"operation_cli_01","endpoint_id":"cli_session_01","generation":1,"noise_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","quic_public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}`))
	request.Header.Set("Idempotency-Key", "operation_cli_01")
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}, Client: &auth.ClientPrincipal{SessionID: "cli_session_01"}}))
	response := httptest.NewRecorder()
	cliEndpointRequest(cliEndpointRequesterFunc(func(_ context.Context, value peeridentity.CLIEndpointRequest) (peeridentity.EndpointEnrollmentRequest, error) {
		return peeridentity.EndpointEnrollmentRequest{ID: "per_0123456789abcdef", UserID: value.UserID, EndpointID: value.EndpointID, Generation: value.Generation, Role: peeridentity.RoleCLI, State: "fulfilled", NoisePublicKey: value.NoisePublicKey, QUICPublicKey: value.QUICPublicKey, CreatedAt: value.Now.Add(-10 * time.Minute), ExpiresAt: value.Now.Add(-5 * time.Minute)}, nil
	})).ServeHTTP(response, request)
	var envelope struct {
		Data endpointEnrollmentDocument `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || response.Code != http.StatusCreated || envelope.Data.State != "fulfilled" {
		t.Fatalf("status=%d data=%+v err=%v body=%s", response.Code, envelope.Data, err, response.Body.String())
	}
}

func TestCLIEndpointRequestRequiresMatchingIdempotencyKey(t *testing.T) {
	for _, test := range []struct {
		name   string
		header string
	}{
		{name: "missing"},
		{name: "different", header: "operation_cli_other"},
		{name: "surrounding whitespace", header: " operation_cli_01"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/e2ee/endpoint-requests", strings.NewReader(`{"operation_id":"operation_cli_01","endpoint_id":"cli_session_01","generation":1,"noise_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","quic_public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}`))
			if test.header != "" {
				request.Header.Set("Idempotency-Key", test.header)
			}
			request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}, Client: &auth.ClientPrincipal{SessionID: "cli_session_01"}}))
			response := httptest.NewRecorder()
			called := false
			cliEndpointRequest(cliEndpointRequesterFunc(func(context.Context, peeridentity.CLIEndpointRequest) (peeridentity.EndpointEnrollmentRequest, error) {
				called = true
				return peeridentity.EndpointEnrollmentRequest{}, nil
			})).ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || called {
				t.Fatalf("status=%d called=%t body=%s", response.Code, called, response.Body.String())
			}
		})
	}
}

func (f machineProofVerifierFunc) VerifyMachineRequest(ctx context.Context, credential string, proof []byte, method, path string, body []byte) (controlplane.MachineRequestClaims, error) {
	return f(ctx, credential, proof, method, path, body)
}

type machineStatusReader struct {
	certificate peeridentity.Certificate
	root        peeridentity.AccountRoot
	err         error
}

func (s machineStatusReader) Get(context.Context, string, string, uint64, time.Time) (peeridentity.Certificate, error) {
	return s.certificate, s.err
}
func (s machineStatusReader) Root(context.Context, string) (peeridentity.AccountRoot, error) {
	return s.root, s.err
}

func TestMachineEndpointStatusReturnsOnlyApprovedPublicAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, _, _ := ed25519.GenerateKey(nil)
	raw := bytes.Repeat([]byte{7}, 172)
	rootFingerprint := sha256.Sum256(rootPublic)
	fingerprint := sha256.Sum256(raw)
	reader := machineStatusReader{root: peeridentity.AccountRoot{PublicKey: rootPublic, Fingerprint: rootFingerprint, Generation: 1}, certificate: peeridentity.Certificate{AccountID: "account_01", Role: peeridentity.RoleMachine, EndpointID: "machine_01", Generation: 3, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), RootFingerprint: rootFingerprint, Fingerprint: fingerprint, Raw: raw}}
	body := []byte(`{"operation_id":"operation_status_01","generation":3}`)
	verifier := machineProofVerifierFunc(func(_ context.Context, credential string, proof []byte, method, path string, exactBody []byte) (controlplane.MachineRequestClaims, error) {
		if credential != strings.Repeat("t", 32) || string(proof) != "proof" || method != http.MethodPost || path != "/v1/machine-peer-identity/status" || !bytes.Equal(exactBody, body) {
			t.Fatal("machine proof inputs changed")
		}
		return controlplane.MachineRequestClaims{UserID: "account_01", MachineID: "machine_01", InstallationGeneration: 3, OperationID: "operation_status_01"}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/machine-peer-identity/status", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("proof")))
	response := httptest.NewRecorder()
	machineEndpointStatus(reader, verifier).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct {
			State         string                      `json:"state"`
			RootPublicKey string                      `json:"root_public_key"`
			Certificate   endpointCertificateDocument `json:"certificate"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Data.State != "approved" || envelope.Data.RootPublicKey != base64.RawURLEncoding.EncodeToString(rootPublic) || envelope.Data.Certificate.Certificate != base64.RawURLEncoding.EncodeToString(raw) {
		t.Fatalf("envelope=%+v err=%v", envelope, err)
	}
}

func TestMachineEndpointStatusReportsPendingWithoutCertificate(t *testing.T) {
	body := []byte(`{"operation_id":"operation_status_01","generation":3}`)
	verifier := machineProofVerifierFunc(func(context.Context, string, []byte, string, string, []byte) (controlplane.MachineRequestClaims, error) {
		return controlplane.MachineRequestClaims{UserID: "account_01", MachineID: "machine_01", InstallationGeneration: 3, OperationID: "operation_status_01"}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/machine-peer-identity/status", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("proof")))
	response := httptest.NewRecorder()
	machineEndpointStatus(machineStatusReader{err: peeridentity.ErrUnavailable}, verifier).ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || strings.Contains(response.Body.String(), "certificate") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
