package environment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is a structural guardrail for the control plane trust boundary. The
// server may validate and route opaque documents, but must not grow a secret
// decryption or plaintext snapshot path.
func TestServerEnvironmentSourcesContainNoPlaintextOrDecryptPath(t *testing.T) {
	files := []string{"protocol.go", "repository.go", "service.go", "../httpapi/environment_variable_handlers.go", "../httpapi/runtime_observation_handlers.go", "../httpapi/router.go"}
	forbidden := []string{"environment_snapshot", "content_hash", "value_bytes", "EncryptionKey", "Decrypt(", ".Open(", `PUT /v1/environment-variables`, `DELETE /v1/environment-variables`, `PUT /v1/machines/{machine_id}/environment-variables`, `DELETE /v1/machines/{machine_id}/environment-variables`}
	for _, name := range files {
		raw, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range forbidden {
			if strings.Contains(string(raw), token) {
				t.Fatalf("server ENV trust boundary violation: %s contains %q", name, token)
			}
		}
	}
}

func TestCanonicalBase64URLRejectsPaddedAndOversizeInputs(t *testing.T) {
	for _, value := range []string{"YQ==", strings.Repeat("a", 100)} {
		if _, err := DecodeCanonicalBase64URL(value, 32); err == nil {
			t.Fatalf("accepted noncanonical or oversized input %q", value)
		}
	}
}
