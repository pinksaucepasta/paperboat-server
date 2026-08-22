package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

type initialControlIssuerStub struct {
	machineID, environmentID, operationID string
	err                                   error
}

func (s *initialControlIssuerStub) IssueInitialMachineControl(_ context.Context, machineID, environmentID, operationID string) (usermachines.MachineControlCredential, error) {
	s.machineID, s.environmentID, s.operationID = machineID, environmentID, operationID
	if s.err != nil {
		return usermachines.MachineControlCredential{}, s.err
	}
	return usermachines.MachineControlCredential{Credential: "machine-control-credential-012345678901234567890", ExpiresAt: time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)}, nil
}

type helperProofVerifierStub struct {
	claims controlplane.HelperProofClaims
	err    error
	seen   bool
}

func (s *helperProofVerifierStub) VerifyHelperRequest(_ context.Context, credential string, proof []byte, method, path string, body []byte) (controlplane.HelperProofClaims, error) {
	s.seen = true
	if credential != "helper-identity" || string(proof) != "proof" || method != http.MethodPost || path != "/v1/machine-control-credentials" || !bytes.Equal(body, []byte(`{"operation_id":"machine-control-initial-test"}`)) {
		return controlplane.HelperProofClaims{}, errors.New("unexpected bootstrap proof inputs")
	}
	return s.claims, s.err
}

func TestMachineControlInitialBindsVerifiedHelperMachine(t *testing.T) {
	issuer := &initialControlIssuerStub{}
	verifier := &helperProofVerifierStub{claims: controlplane.HelperProofClaims{HelperID: "hlp_1", MachineID: "mch_1", EnvironmentID: "env_1"}}
	request := httptest.NewRequest(http.MethodPost, "/v1/machine-control-credentials", bytes.NewBufferString(`{"operation_id":"machine-control-initial-test"}`))
	request.Header.Set("Authorization", "Bearer helper-identity")
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("proof")))
	response := httptest.NewRecorder()
	machineControlInitial(issuer, verifier).ServeHTTP(response, request)
	if response.Code != http.StatusCreated || !verifier.seen || issuer.machineID != "mch_1" || issuer.environmentID != "env_1" || issuer.operationID != "machine-control-initial-test" || response.Header().Get("Cache-Control") == "" {
		t.Fatalf("status=%d verifier=%v issuer=%+v headers=%v body=%s", response.Code, verifier.seen, issuer, response.Header(), response.Body.String())
	}
}

func TestMachineControlInitialRejectsMissingHelperBearer(t *testing.T) {
	issuer := &initialControlIssuerStub{}
	verifier := &helperProofVerifierStub{}
	request := httptest.NewRequest(http.MethodPost, "/v1/machine-control-credentials", bytes.NewBufferString(`{"operation_id":"machine-control-initial-test"}`))
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("proof")))
	response := httptest.NewRecorder()
	machineControlInitial(issuer, verifier).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || verifier.seen || issuer.operationID != "" {
		t.Fatalf("status=%d verifier=%v issuer=%+v body=%s", response.Code, verifier.seen, issuer, response.Body.String())
	}
}
