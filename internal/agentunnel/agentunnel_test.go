package agentunnel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/projects"
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

func TestHTTPClientEnsureProjectResourcesCreatesClientAndHTTPTunnel(t *testing.T) {
	var paths []string
	var authHeaders []string
	var createBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/api/clients":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"client_id":    "cli_prj_1",
					"client_token": "clt_project_machine_token",
					"token_prefix": "clt_project",
					"status":       "active",
				},
			})
		case "/api/http-tunnels":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":   "tun_http_1",
					"preview_url": "https://pb-prj-1.agentunnel.example",
					"status":      "active",
				},
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	resource, err := (HTTPClient{
		BaseURL:              server.URL,
		APIKey:               "agentunnel-api-key",
		PapercodeLocalURL:    "http://127.0.0.1:4099",
		RouteExpiresIn:       time.Hour,
		RouteSubdomainPrefix: "pb",
	}).EnsureProjectResources(context.Background(), ProjectRef{ID: "prj_1", Name: "Demo"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, ",") != "POST /api/clients,POST /api/http-tunnels" {
		t.Fatalf("paths = %#v", paths)
	}
	for _, got := range authHeaders {
		if got != "Bearer agentunnel-api-key" {
			t.Fatalf("authorization header = %q", got)
		}
	}
	if createBody["client_id"] != "cli_prj_1" || createBody["local_url"] != "http://127.0.0.1:4099" || createBody["subdomain"] != "pb-prj-1" {
		t.Fatalf("create body = %#v", createBody)
	}
	if resource.TunnelID != "tun_http_1" || resource.ClientID != "cli_prj_1" {
		t.Fatalf("resource ids = %#v", resource)
	}
	if resource.MachineToken != "clt_project_machine_token" {
		t.Fatalf("machine token was not captured")
	}
	if resource.HTTPBaseURL != "https://pb-prj-1.agentunnel.example" || resource.WebSocketBaseURL != "wss://pb-prj-1.agentunnel.example" {
		t.Fatalf("route urls = %q %q", resource.HTTPBaseURL, resource.WebSocketBaseURL)
	}
	resourceJSON := strings.ToLower(mustJSONForTest(resource))
	if strings.Contains(resourceJSON, "api-key") || strings.Contains(resourceJSON, "project_machine_token") {
		t.Fatalf("resource leaked secret: %#v", resource)
	}
}

func TestHTTPClientStatusUsesHTTPTunnelRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/http-tunnels/tun_http_1" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"data": map[string]any{
				"tunnel_id":   "tun_http_1",
				"preview_url": "https://pb-prj-1.agentunnel.example",
				"status":      "active",
			},
		})
	}))
	defer server.Close()

	status, err := (HTTPClient{BaseURL: server.URL}).Status(context.Background(), ResourceDescriptor{
		TunnelID: "tun_http_1",
		Metadata: map[string]any{
			"resource_kind": "http_tunnel",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.HTTPBaseURL != "https://pb-prj-1.agentunnel.example" || status.WebSocketBaseURL != "wss://pb-prj-1.agentunnel.example" {
		t.Fatalf("status = %#v", status)
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

func TestBuildCLIResponseDoesNotInventUnvalidatedAuth(t *testing.T) {
	resp := buildResponse(ConnectCLI, projects.Project{ID: "prj_1", Name: "Demo"}, ResourceDescriptor{
		HTTPBaseURL:      "https://agentunnel.example/projects/prj_1",
		WebSocketBaseURL: "wss://agentunnel.example/projects/prj_1",
	}, time.Now().UTC().Add(time.Minute))

	if _, ok := resp.Terminal["auth"]; ok {
		t.Fatalf("terminal descriptor should not include unvalidated auth: %#v", resp.Terminal)
	}
	if _, ok := resp.PapercodeUpload["auth"]; ok {
		t.Fatalf("upload descriptor should not include unvalidated auth: %#v", resp.PapercodeUpload)
	}
}

func mustJSONForTest(value any) string {
	b, _ := json.Marshal(value)
	return string(b)
}
