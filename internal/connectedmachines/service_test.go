package connectedmachines

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
)

func TestProvisionApprovedMachineRequiresCanonicalHelperGrant(t *testing.T) {
	service := &Service{encryptionKey: "configured"}
	err := service.provisionApprovedMachine(context.Background(), "usr_1", "pair_1", Machine{ID: "cm_1", EnvironmentID: "env_1", Platform: "linux", Architecture: "amd64"})
	if !errors.Is(err, ErrProvisioningUnavailable) {
		t.Fatalf("provision error = %v, want ErrProvisioningUnavailable", err)
	}
}

func TestEntitlementActiveRejectsExpiredPeriod(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	if entitlementActive("active", now, now) {
		t.Fatal("expired active entitlement was accepted")
	}
	if !entitlementActive("trialing", now.Add(time.Second), now) {
		t.Fatal("current trialing entitlement was rejected")
	}
}

func TestNewDefaultsConnectedMachineOfflineTimeout(t *testing.T) {
	service := New(nil, nil, Policy{}, nil)
	if service.policy.OfflineAfter != 2*time.Minute {
		t.Fatalf("offline timeout = %s", service.policy.OfflineAfter)
	}
}

func TestConfigureHelperArtifactsVerifiesSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("helper"))
	artifact := HelperArtifact{Schema: "paperboat.helper-artifact/v1", Version: "0.0.0-development", Platform: "linux", Architecture: "amd64", URL: "https://updates.example.test/paperboat-helper", ByteLength: 6, SHA256: hex.EncodeToString(digest[:])}
	payload, err := json.Marshal(struct {
		Architecture string `json:"architecture"`
		ByteLength   int64  `json:"byte_length"`
		Platform     string `json:"platform"`
		Schema       string `json:"schema"`
		SHA256       string `json:"sha256"`
		URL          string `json:"url"`
		Version      string `json:"version"`
	}{artifact.Architecture, artifact.ByteLength, artifact.Platform, artifact.Schema, artifact.SHA256, artifact.URL, artifact.Version})
	if err != nil {
		t.Fatal(err)
	}
	artifact.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	encoded, err := json.Marshal([]HelperArtifact{artifact})
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{}
	if err := service.ConfigureHelperArtifacts(string(encoded), base64.RawURLEncoding.EncodeToString(publicKey)); err != nil {
		t.Fatal(err)
	}
	artifact.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	encoded, _ = json.Marshal([]HelperArtifact{artifact})
	if err := service.ConfigureHelperArtifacts(string(encoded), base64.RawURLEncoding.EncodeToString(publicKey)); err == nil {
		t.Fatal("invalid artifact signature was accepted")
	}
}

func TestConnectResponseSerializesCanonicalPayload(t *testing.T) {
	expires := time.Now().UTC().Add(time.Minute)
	response := ConnectResponse{
		Schema: accessdescriptor.SchemaV1, Issuer: "https://api.example", ConnectedMachineID: "cm_1", ConnectedMachineState: "online", Connectable: true, ExpiresAt: expires,
		Capabilities: []string{accessdescriptor.CapabilityTerminal, accessdescriptor.CapabilityUpload}, Status: "ready", Reason: "ready",
		Environment: map[string]any{"id": "env_1", "kind": "byod", "resource_id": "cm_1", "display_name": "Studio", "state": "ready", "root": "/Users/paperboat", "connected_machine_id": "cm_1"},
		Terminal:    map[string]any{"endpoint": "wss://edge.example/e/env_1/terminal", "session_id": "session", "thread_id": "thread", "terminal_id": "terminal", "cwd": "/Users/paperboat", "auth": map[string]any{"method": "websocket_ticket", "ticket": "t", "expires_at": expires, "scopes": []string{"terminal:operate"}}, "kind": "papercode_websocket"},
		Upload:      map[string]any{"endpoint": "https://edge.example/e/env_1/uploads", "max_bytes": int64(1024), "allowed_mime_types": []string{"image/png"}, "retention_seconds": int64(60), "auth": map[string]any{"method": "bearer", "token": "u", "expires_at": expires, "scopes": []string{"file:stage"}}, "kind": "papercode_staged_image"},
	}
	b, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"connected_machine_id", "connected_machine_state", "papercode_websocket", "papercode_staged_image", "websocket_base_url", "http_base_url"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("canonical payload contains legacy field %q: %s", forbidden, b)
		}
	}
}

func TestPairingJSONUsesConnectorFieldNames(t *testing.T) {
	encoded, err := json.Marshal(Pairing{ID: "cmp_1", UserCode: "ABCD1234", ExpiresAt: time.Unix(0, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	value := string(encoded)
	for _, field := range []string{"\"user_code\"", "\"expires_at\""} {
		if !strings.Contains(value, field) {
			t.Fatalf("pairing response missing %s: %s", field, value)
		}
	}
}

func TestMachineJSONUsesDashboardFieldNames(t *testing.T) {
	encoded, err := json.Marshal(Machine{ID: "cm_1", EnvironmentID: "env_1", DisplayName: "Test Mac", SeatState: "occupied", RuntimeVersions: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	value := string(encoded)
	for _, field := range []string{"\"id\"", "\"environment_id\"", "\"display_name\"", "\"seat_state\"", "\"runtime_versions\""} {
		if !strings.Contains(value, field) {
			t.Fatalf("machine response missing %s: %s", field, value)
		}
	}
}
