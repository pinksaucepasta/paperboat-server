package accessdescriptor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDescriptorUsesCanonicalNames(t *testing.T) {
	expires := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d := Descriptor{
		Schema: SchemaV1, Issuer: "https://api.paperboat.test", Connectable: true, ExpiresAt: expires,
		Environment:  Environment{ID: "env_1", Kind: EnvironmentHosted, ResourceID: "prj_1", DisplayName: "demo", State: "ready", Root: "/workspace"},
		Capabilities: []string{CapabilityTerminal, CapabilityUpload},
		Terminal:     &Terminal{Endpoint: "wss://edge.paperboat.test/e/env_1/terminal", SessionID: "session_1", ThreadID: "thread_1", TerminalID: "term_1", CWD: "/workspace"},
		Upload:       &Upload{Endpoint: "https://edge.paperboat.test/e/env_1/uploads", MaxBytes: 1024, AllowedMIMETypes: []string{"image/png"}, RetentionSeconds: 60},
		Status:       "ready", Reason: "ready",
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, forbidden := range []string{"papercode", "agentunnel", "websocket_base_url", "http_base_url", "project_id", "connected_machine_id"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("descriptor contains legacy name %q: %s", forbidden, got)
		}
	}
}
