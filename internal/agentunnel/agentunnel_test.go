package agentunnel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPClientStatusUsesConnectInfoEnvelope(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		if r.URL.Path != "/api/tcp-tunnels/tun_123/connect-info" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"data": map[string]any{
				"type":              "tcp_tunnel_connect_info",
				"protocol":          "ssh",
				"host":              "ssh.agentunnel.example",
				"port":              25432,
				"tunnel_id":         "tun_123",
				"status":            "active",
				"lifecycle":         "persistent",
				"forwarding_status": "online",
				"can_connect":       true,
			},
		})
	}))
	defer server.Close()

	status, err := (HTTPClient{BaseURL: server.URL, APIKey: "agentunnel-api-key"}).Status(context.Background(), ResourceDescriptor{TunnelID: "tun_123"})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.Status != "online" {
		t.Fatalf("status = %#v", status)
	}
	if status.SSHHost != "ssh.agentunnel.example" || status.SSHPort != 25432 {
		t.Fatalf("resolved ssh routing = %q:%d", status.SSHHost, status.SSHPort)
	}
	if authHeader != "Bearer agentunnel-api-key" {
		t.Fatalf("authorization header = %q", authHeader)
	}
}

func TestHTTPClientStatusMapsNotReady(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"data": map[string]any{
				"tunnel_id":         "tun_123",
				"status":            "active",
				"forwarding_status": "offline",
				"can_connect":       false,
				"reason_code":       "CLIENT_OFFLINE",
				"message":           "Machine client is offline.",
			},
		})
	}))
	defer server.Close()

	status, err := (HTTPClient{BaseURL: server.URL}).Status(context.Background(), ResourceDescriptor{TunnelID: "tun_123"})
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.Status != "offline" || status.Reason != "CLIENT_OFFLINE" {
		t.Fatalf("status = %#v", status)
	}
}
