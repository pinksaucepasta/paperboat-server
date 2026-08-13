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

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/peersessions"
)

type peerAttemptServiceStub struct {
	pair peersessions.Pair
	err  error
}

func (s peerAttemptServiceStub) Issue(context.Context, peersessions.Request) (peersessions.Pair, error) {
	return s.pair, s.err
}
func (s peerAttemptServiceStub) NextControlled(context.Context, string, string, int64) (peersessions.Pair, error) {
	return s.pair, s.err
}
func (s peerAttemptServiceStub) Revoke(context.Context, string, string, string, int64, string) error {
	return s.err
}

func TestControlledPeerAttemptUsesExactMachineProofAndControlledAuthority(t *testing.T) {
	t.Parallel()
	body := []byte(`{"operation_id":"operation_poll_01","generation":3}`)
	pair := controlledPairForTest()
	verifier := machineProofVerifierFunc(func(_ context.Context, credential string, proof []byte, method, path string, exactBody []byte) (controlplane.MachineRequestClaims, error) {
		if credential != "machine-token" || string(proof) != "proof" || method != http.MethodPost || path != "/v1/machine-peer-attempts/next" || !bytes.Equal(exactBody, body) {
			t.Fatalf("proof inputs credential=%q proof=%q method=%q path=%q body=%q", credential, proof, method, path, exactBody)
		}
		return controlplane.MachineRequestClaims{UserID: pair.UserID, MachineID: pair.Controlled.EndpointID, InstallationGeneration: pair.HostGeneration, OperationID: "operation_poll_01"}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/machine-peer-attempts/next", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer machine-token")
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("proof")))
	response := httptest.NewRecorder()
	controlledPeerAttemptNext(peerAttemptServiceStub{pair: pair}, verifier).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data peerAttemptDescriptor `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	value := envelope.Data
	if value.Role != "controlled" || value.Signaling.Credential != pair.Controlled.Token || value.Signaling.Credential == pair.Controlling.Token || value.HostGeneration != pair.HostGeneration || value.AuthorizationGeneration != pair.AuthorizationGeneration || value.DeviceID != pair.CLIClientSessionID || value.OperationID != pair.OperationKey || len(value.Relays) != 1 || value.Relays[0].QUICURL != "https://edge.example.test/v1/peer-relay" || value.Relays[0].WSSURL != "wss://edge.example.test/v1/peer-relay" || len(value.Policy.AllowedPaths) != 3 || value.Policy.AllowedPaths[1] != "relay_quic" {
		t.Fatalf("descriptor=%+v", value)
	}
}

func TestControlledPeerAttemptEmptyQueueReturnsNoContent(t *testing.T) {
	t.Parallel()
	body := []byte(`{"operation_id":"operation_poll_01","generation":3}`)
	verifier := machineProofVerifierFunc(func(context.Context, string, []byte, string, string, []byte) (controlplane.MachineRequestClaims, error) {
		return controlplane.MachineRequestClaims{UserID: "account_01", MachineID: "machine_01", InstallationGeneration: 3, OperationID: "operation_poll_01"}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/machine-peer-attempts/next", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer machine-token")
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("proof")))
	response := httptest.NewRecorder()
	controlledPeerAttemptNext(peerAttemptServiceStub{err: peersessions.ErrUnavailable}, verifier).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestControlledPeerAttemptRejectsProofClaimMismatch(t *testing.T) {
	t.Parallel()
	body := []byte(`{"operation_id":"operation_poll_01","generation":3}`)
	verifier := machineProofVerifierFunc(func(context.Context, string, []byte, string, string, []byte) (controlplane.MachineRequestClaims, error) {
		return controlplane.MachineRequestClaims{OperationID: "different", InstallationGeneration: 3}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/machine-peer-attempts/next", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer machine-token")
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("proof")))
	response := httptest.NewRecorder()
	controlledPeerAttemptNext(peerAttemptServiceStub{err: errors.New("must not be reached")}, verifier).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestDirectProbeDescriptorPublishesDirectOnlyPolicy(t *testing.T) {
	pair := controlledPairForTest()
	pair.Purpose = "direct_probe"
	descriptor := peerAttemptResponse(pair, "controlling")
	if descriptor.Purpose != "direct_probe" || len(descriptor.Policy.AllowedPaths) != 1 || descriptor.Policy.AllowedPaths[0] != "direct_quic" {
		t.Fatalf("descriptor=%+v", descriptor)
	}
}

func TestReusablePeerDescriptorPublishesExactStreamPolicy(t *testing.T) {
	pair := controlledPairForTest()
	pair.Purpose = "peer_transport"
	pair.Consumer = "peer_transport"
	descriptor := peerAttemptResponse(pair, "controlling")
	if descriptor.StreamPolicy == nil || descriptor.StreamPolicy.Protocol != "paperboat.peer-stream.v1" || descriptor.StreamPolicy.MaximumStreams != 64 || !equalStrings(descriptor.StreamPolicy.AllowedConsumers, []string{"terminal", "exec", "ssh", "private_preview", "codex"}) {
		t.Fatalf("stream policy=%+v", descriptor.StreamPolicy)
	}
	pair.Purpose = "interactive"
	pair.Consumer = "terminal"
	if legacy := peerAttemptResponse(pair, "controlling"); legacy.StreamPolicy != nil {
		t.Fatalf("legacy descriptor unexpectedly advertised stream policy=%+v", legacy.StreamPolicy)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestFileTransferKeyDescriptorPublishesExactBinding(t *testing.T) {
	pair := controlledPairForTest()
	pair.Purpose = "file_transfer_key"
	pair.Transfer = &peersessions.TransferBinding{TransferID: "transfer_01", Generation: 3, ExpiresAt: pair.ExpiresAt.Add(time.Hour)}
	descriptor := peerAttemptResponse(pair, "controlling")
	if descriptor.Purpose != "file_transfer_key" || descriptor.Transfer == nil || descriptor.Transfer.TransferID != pair.Transfer.TransferID || descriptor.Transfer.Generation != pair.Transfer.Generation || descriptor.Transfer.ExpiresAt != pair.Transfer.ExpiresAt.Format("2006-01-02T15:04:05Z") || len(descriptor.Policy.AllowedPaths) != 3 {
		t.Fatalf("descriptor=%+v", descriptor)
	}
}

func controlledPairForTest() peersessions.Pair {
	now := time.Now().UTC().Truncate(time.Second)
	return peersessions.Pair{UserID: "account_01", CLIClientSessionID: "cli_01", OperationKey: "operation_terminal_01", IntentID: "psi_0123456789abcdef", EnvironmentID: "env_01", Purpose: "interactive", SignalingHost: "edge.example.test", STUNHost: "stun.example.test", STUNPort: 3478, ICEUfrag: "abcdefghijklmnop", ICEPassword: "abcdefghijklmnopqrstuvwxyzABCDEF", ControllingCertificate: []byte("cli-certificate"), ControlledCertificate: []byte("machine-certificate"), AttemptGeneration: 2, NetworkGeneration: 4, HostGeneration: 3, AuthorizationGeneration: 7, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), Controlling: peersessions.Credential{EndpointID: "cli_01", Role: "controlling", Token: "controlling.token.signature", ExpiresAt: now.Add(5 * time.Minute)}, Controlled: peersessions.Credential{EndpointID: "machine_01", Role: "controlled", Token: "controlled.token.signature", ExpiresAt: now.Add(5 * time.Minute)}, Relay: peersessions.Relay{Region: "development", RouteGeneration: 1, Token: "relay.token.signature", ExpiresAt: now.Add(5 * time.Minute)}}
}
