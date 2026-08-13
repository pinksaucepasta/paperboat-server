package usermachines

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
)

func TestProvisionApprovedMachineRequiresCanonicalHelperGrant(t *testing.T) {
	service := &Service{encryptionKey: "configured"}
	err := service.provisionApprovedUserMachine(context.Background(), "usr_1", "pair_1", UserMachine{ID: "um_1", EnvironmentID: "env_1", Platform: "linux", Architecture: "amd64"})
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

func TestNewDefaultsUserMachineOfflineTimeout(t *testing.T) {
	service := New(nil, nil, Policy{}, nil)
	if service.policy.OfflineAfter != 2*time.Minute {
		t.Fatalf("offline timeout = %s", service.policy.OfflineAfter)
	}
}

func TestConfigureMachineArtifactsBuildsTUFDescriptor(t *testing.T) {
	service := &Service{}
	if err := service.ConfigureMachineArtifacts("https://updates.example.test/paperboat/", "2026.08.07"); err != nil {
		t.Fatal(err)
	}
	artifact, ok := service.machineArtifact("linux", "amd64")
	if !ok || artifact.Schema != "paperboat.tuf-target/v1" || artifact.RepositoryURL != "https://updates.example.test/paperboat" || artifact.TargetPath != "pb-linux-amd64" || artifact.Version != "2026.08.07" {
		t.Fatalf("artifact=%+v ok=%v", artifact, ok)
	}
	if err := service.ConfigureMachineArtifacts("http://updates.example.test", "2026.08.07"); err == nil {
		t.Fatal("insecure artifact repository was accepted")
	}
}

func TestConnectionDescriptorSerializesCanonicalPayload(t *testing.T) {
	expires := time.Now().UTC().Add(time.Minute)
	response := ConnectionDescriptor{
		Schema: accessdescriptor.SchemaV1, Issuer: "https://api.example", UserMachineID: "um_1", UserMachineState: "online", Connectable: true, ExpiresAt: expires,
		Capabilities: []string{accessdescriptor.CapabilityTerminal, accessdescriptor.CapabilityFileTransfer}, Status: "ready", Reason: "ready",
		Environment:  map[string]any{"id": "env_1", "kind": "byod", "resource_id": "um_1", "display_name": "Studio", "state": "ready", "root": "/Users/paperboat", "user_machine_id": "um_1"},
		Terminal:     map[string]any{"endpoint": "wss://edge.example/e/env_1/terminal", "session_id": "session", "thread_id": "thread", "terminal_id": "terminal", "cwd": "/Users/paperboat", "auth": map[string]any{"method": "websocket_ticket", "ticket": "t", "expires_at": expires, "scopes": []string{"terminal:operate"}}, "kind": "paperboat_terminal_v1"},
		FileTransfer: map[string]any{"endpoint": "https://edge.example/v1/file-transfers", "policy": accessdescriptor.FileTransferPolicy{Revision: "file-transfer-v1", MaxFileBytes: 50 << 20, MaxBatchFiles: 10, MaxBatchBytes: 500 << 20, MaxConcurrentTransfers: 2, RetentionSeconds: 604800, DeliveryTimeoutSeconds: 600, MaxPendingSpoolBytes: 1 << 30}, "auth": map[string]any{"method": "bearer", "token": "u", "expires_at": expires, "scopes": []string{"file:transfer"}}},
	}
	b, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"user_machine_id", "user_machine_state", "paperboat_terminal_v1", "paperboat_staged_image_v1", "websocket_base_url", "http_base_url", `"upload"`} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("canonical payload contains legacy field %q: %s", forbidden, b)
		}
	}
}

func TestPairingJSONUsesConnectorFieldNames(t *testing.T) {
	encoded, err := json.Marshal(Pairing{ID: "ump_1", UserCode: "ABCD1234", ExpiresAt: time.Unix(0, 0).UTC()})
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
	encoded, err := json.Marshal(UserMachine{ID: "um_1", EnvironmentID: "env_1", DisplayName: "Test Mac", SeatState: "occupied", RuntimeVersions: json.RawMessage(`{}`)})
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
