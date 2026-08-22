package usermachines

import (
	"context"
	"encoding/base64"
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

func TestEnrollmentStartJSONIncludesBootstrapTokenForOneShotSetup(t *testing.T) {
	value := EnrollmentStart{
		Enrollment:        Enrollment{ID: "ume_1"},
		BootstrapToken:    "super-secret-bootstrap-token",
		BootstrapCommand:  "install-paperboat",
		TokenDownloadPath: "/v1/machine-enrollments/ume_1/bootstrap-token",
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, value.BootstrapToken) {
		t.Fatalf("enrollment response omitted one-shot bootstrap token: %s", text)
	}
	if !strings.Contains(text, value.TokenDownloadPath) {
		t.Fatalf("enrollment response omitted token download path: %s", text)
	}
}

func TestRandomEnrollmentTokenMatchesInstallerContract(t *testing.T) {
	token, err := randomEnrollmentToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != enrollmentTokenLength {
		t.Fatalf("token length = %d, want %d", len(token), enrollmentTokenLength)
	}
}

func TestEnrollmentTokenMetadataParityAndLength(t *testing.T) {
	tests := []struct {
		role, shell         string
		roleEven, shellEven bool
	}{
		{role: "host", shell: "posix", roleEven: true, shellEven: true},
		{role: "host", shell: "powershell", roleEven: true, shellEven: false},
		{role: "client", shell: "posix", roleEven: false, shellEven: true},
		{role: "client", shell: "powershell", roleEven: false, shellEven: false},
	}
	for _, test := range tests {
		token, err := randomEnrollmentTokenFor(test.role, test.shell)
		if err != nil {
			t.Fatal(err)
		}
		if len(token) != 26 {
			t.Fatalf("%s/%s token length = %d, want 26", test.role, test.shell, len(token))
		}
		if enrollmentCharacterEven(token[0]) != test.roleEven || enrollmentCharacterEven(token[1]) != test.shellEven {
			t.Fatalf("%s/%s token metadata = %q, wrong parity", test.role, test.shell, token[:2])
		}
	}
}

func TestEnrollmentTokenMetadataDoesNotChangeCredential(t *testing.T) {
	token, err := randomEnrollmentTokenFor("host", "posix")
	if err != nil {
		t.Fatal(err)
	}
	variant := "11" + token[2:]
	if enrollmentTokenHash(token) != enrollmentTokenHash(variant) {
		t.Fatal("metadata-only token variant changed the credential hash")
	}
	changedSecret := variant[:2] + variant[2:len(variant)-1] + "0"
	if changedSecret == variant {
		changedSecret = variant[:len(variant)-1] + "1"
	}
	if enrollmentTokenHash(token) == enrollmentTokenHash(changedSecret) {
		t.Fatal("secret change did not change the credential hash")
	}
}

func enrollmentCharacterEven(character byte) bool {
	if character >= '0' && character <= '9' {
		return (character-'0')%2 == 0
	}
	return (character-'A'+1)%2 == 0
}

func TestCanonicalWorkspaceRootIsPlatformAware(t *testing.T) {
	tests := []struct {
		platform string
		root     string
		want     string
		valid    bool
	}{
		{platform: "linux", root: "/home/sailor", want: "/home/sailor", valid: true},
		{platform: "windows", root: `C:\Users\pujan`, want: `C:\Users\pujan`, valid: true},
		{platform: "windows", root: `\\server\share\workspace`, want: `\\server\share\workspace`, valid: true},
		{platform: "windows", root: `C:\Users\..\Windows`, valid: false},
		{platform: "windows", root: `\Users\pujan`, valid: false},
	}
	for _, test := range tests {
		got, valid := canonicalWorkspaceRoot(test.platform, test.root)
		if got != test.want || valid != test.valid {
			t.Errorf("canonicalWorkspaceRoot(%q, %q) = %q, %v; want %q, %v", test.platform, test.root, got, valid, test.want, test.valid)
		}
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

func TestMachineArchitectureIsExactAndPortable(t *testing.T) {
	for _, value := range []string{"amd64", "AMD64", " arm64 "} {
		if !validMachineArchitecture(value) {
			t.Fatalf("architecture %q was rejected", value)
		}
	}
	for _, value := range []string{"", "x86", "aarch64", "armv7", "amd64/x"} {
		if validMachineArchitecture(value) {
			t.Fatalf("architecture %q was accepted", value)
		}
	}
}

func TestSetupAndPairingRejectDarwinAMD64BeforePersistence(t *testing.T) {
	publicIdentityKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	service := New(nil, nil, Policy{AllowedPlatforms: []string{"darwin"}, PairingLifetime: time.Minute}, nil)
	setup := SetupInput{SetupMode: "host", DisplayName: "Intel Mac", Platform: "darwin", Architecture: "amd64", WorkspaceRoot: "/Users/paperboat", PublicIdentityKey: publicIdentityKey}
	if _, err := service.Setup(t.Context(), "usr_1", setup); !errors.Is(err, ErrInvalidSetup) {
		t.Fatalf("darwin amd64 setup error = %v", err)
	}
	pairing := PairingInput{Verifier: "verifier", DisplayName: "Intel Mac", Platform: "darwin", Architecture: "amd64", WorkspaceRoot: "/Users/paperboat", PublicIdentityKey: publicIdentityKey}
	if err := service.validatePairing(pairing); !errors.Is(err, ErrInvalidPairing) {
		t.Fatalf("darwin amd64 pairing error = %v", err)
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
	for _, target := range []struct {
		platform     string
		architecture string
	}{
		{platform: "darwin", architecture: "arm64"},
		{platform: "linux", architecture: "amd64"},
		{platform: "linux", architecture: "arm64"},
		{platform: "windows", architecture: "amd64"},
		{platform: "windows", architecture: "arm64"},
	} {
		if _, ok := service.machineArtifact(target.platform, target.architecture); !ok {
			t.Fatalf("supported artifact %s/%s was rejected", target.platform, target.architecture)
		}
	}
	if artifact, ok := service.machineArtifact("darwin", "amd64"); ok || artifact != (MachineArtifact{}) {
		t.Fatalf("darwin amd64 artifact = %+v, ok=%v", artifact, ok)
	}
}

func TestMachineArtifactUsesCurrentReleaseResolver(t *testing.T) {
	service := New(nil, nil, Policy{}, nil)
	if err := service.ConfigureMachineArtifacts("https://pprbt.dev/tuf", "bootstrap"); err != nil {
		t.Fatal(err)
	}
	service.ConfigureMachineArtifactVersionResolver(func() string { return "2026.08.17.1" })
	artifact, ok := service.machineArtifact("linux", "arm64")
	if !ok || artifact.Version != "2026.08.17.1" || artifact.RepositoryURL != "https://pprbt.dev/tuf" {
		t.Fatalf("artifact = %#v, %v", artifact, ok)
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
