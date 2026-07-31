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
		Capabilities: []string{CapabilityTerminal, CapabilityFileTransfer},
		Terminal:     &Terminal{Protocol: "paperboat.terminal.v1", Endpoints: TerminalEndpoints{QUIC: "quic://edge.paperboat.test:443", WSS: "wss://edge.paperboat.test/v1/runtime"}, SessionID: "session_1", ThreadID: "thread_1", TerminalID: "term_1", CWD: "/workspace"},
		FileTransfer: &FileTransfer{Endpoint: "https://edge.paperboat.test/v1/file-transfers", Auth: Auth{Method: "bearer", Token: "token", ExpiresAt: expires, Scopes: []string{"file:transfer"}}, Policy: FileTransferPolicy{Revision: "file-transfer-v1", MaxFileBytes: 50 << 20, MaxBatchFiles: 10, MaxBatchBytes: 500 << 20, MaxConcurrentTransfers: 2, RetentionSeconds: 604800, DeliveryTimeoutSeconds: 600, MaxPendingSpoolBytes: 1 << 30}},
		Status:       "ready", Reason: "ready",
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, `"file_transfer"`) || !strings.Contains(got, `"max_pending_spool_bytes":1073741824`) {
		t.Fatalf("descriptor omits file transfer policy: %s", got)
	}
	for _, forbidden := range []string{"helper", "provider_route", "websocket_base_url", "http_base_url", "project_id", "user_machine_id"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("descriptor contains legacy name %q: %s", forbidden, got)
		}
	}
}
