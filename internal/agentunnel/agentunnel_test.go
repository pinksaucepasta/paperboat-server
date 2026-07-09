package agentunnel

import (
	"context"
	"encoding/json"
	"errors"
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
	var clientCreateBody map[string]any
	var httpCreateBody map[string]any
	var tcpCreateBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/api/clients":
			if err := json.NewDecoder(r.Body).Decode(&clientCreateBody); err != nil {
				t.Fatal(err)
			}
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
			if err := json.NewDecoder(r.Body).Decode(&httpCreateBody); err != nil {
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
		case "/api/tcp-tunnels":
			if err := json.NewDecoder(r.Body).Decode(&tcpCreateBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":         "tun_tcp_1",
					"remote_port":       25432,
					"local_port":        22,
					"status":            "active",
					"lifecycle":         "persistent",
					"forwarding_status": "online",
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
		SSHLocalHost:         "127.0.0.1",
		SSHLocalPort:         22,
		SSHRemotePortStart:   25000,
		SSHRemotePortEnd:     25999,
	}).EnsureProjectResources(context.Background(), ProjectRef{ID: "prj_1", Name: "Demo"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, ",") != "POST /api/clients,POST /api/http-tunnels,POST /api/tcp-tunnels" {
		t.Fatalf("paths = %#v", paths)
	}
	if name, _ := clientCreateBody["name"].(string); !strings.HasPrefix(name, "paperboat-demo-") || strings.Contains(name, "_") {
		t.Fatalf("client name = %q, want sanitized demo client name", name)
	}
	for _, got := range authHeaders {
		if got != "Bearer agentunnel-api-key" {
			t.Fatalf("authorization header = %q", got)
		}
	}
	if httpCreateBody["client_id"] != "cli_prj_1" || httpCreateBody["local_url"] != "http://127.0.0.1:4099" || httpCreateBody["subdomain"] != "pb-prj-1" {
		t.Fatalf("http create body = %#v", httpCreateBody)
	}
	if tcpCreateBody["client_id"] != "cli_prj_1" || tcpCreateBody["local_host"] != "127.0.0.1" || tcpCreateBody["local_port"].(float64) != 22 || tcpCreateBody["expires_in"] != "never" {
		t.Fatalf("tcp create body = %#v", tcpCreateBody)
	}
	if resource.TunnelID != "tun_http_1" || resource.ClientID != "cli_prj_1" || resource.ResourceID != "tun_http_1" {
		t.Fatalf("resource ids = %#v", resource)
	}
	if resource.MachineToken != "clt_project_machine_token" {
		t.Fatalf("machine token was not captured")
	}
	if resource.HTTPBaseURL != "https://pb-prj-1.agentunnel.example" || resource.WebSocketBaseURL != "wss://pb-prj-1.agentunnel.example" {
		t.Fatalf("route urls = %q %q", resource.HTTPBaseURL, resource.WebSocketBaseURL)
	}
	if resource.SSHPort != 25432 || resource.Metadata["tcp_tunnel_id"] != "tun_tcp_1" {
		t.Fatalf("ssh/tcp metadata = port %d metadata %#v", resource.SSHPort, resource.Metadata)
	}
	resourceJSON := strings.ToLower(mustJSONForTest(resource))
	if strings.Contains(resourceJSON, "api-key") || strings.Contains(resourceJSON, "project_machine_token") {
		t.Fatalf("resource leaked secret: %#v", resource)
	}
}

func TestHTTPClientEnsureProjectResourcesAllowsHTTPOnlyWhenTCPDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/clients":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"client_id":    "cli_prj_http_only",
					"client_token": "clt_http_only_machine_token",
				},
			})
		case "/api/http-tunnels":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":   "tun_http_only",
					"preview_url": "https://pb-prj-http-only.agentunnel.example",
					"status":      "active",
				},
			})
		case "/api/tcp-tunnels":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": false,
				"error": map[string]any{
					"code":    "TCP_TUNNELS_DISABLED",
					"message": "TCP tunnels are disabled on this server.",
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
		SSHRemotePortStart:   25000,
		SSHRemotePortEnd:     25000,
	}).EnsureProjectResources(context.Background(), ProjectRef{ID: "prj_http_only"})
	if err != nil {
		t.Fatal(err)
	}
	if resource.TunnelID != "tun_http_only" || resource.MachineToken != "clt_http_only_machine_token" {
		t.Fatalf("resource = %#v", resource)
	}
	if resource.Metadata["tcp_status"] != "disabled" || resource.Metadata["tcp_error_code"] != "TCP_TUNNELS_DISABLED" {
		t.Fatalf("tcp disabled metadata = %#v", resource.Metadata)
	}
}

func TestHTTPClientEnsureProjectResourcesRetriesSubdomainConflict(t *testing.T) {
	var httpCreateBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/clients":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"client_id":    "cli_prj_conflict",
					"client_token": "clt_conflict_machine_token",
				},
			})
		case "/api/http-tunnels":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			httpCreateBodies = append(httpCreateBodies, body)
			if len(httpCreateBodies) == 1 {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"ok": false,
					"error": map[string]any{
						"code":    "SUBDOMAIN_IN_USE",
						"message": "This tunnel hostname is already in use.",
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":   "tun_http_conflict_retry",
					"preview_url": "https://pb-prj-conflict-alt.agentunnel.example",
					"status":      "active",
				},
			})
		case "/api/tcp-tunnels":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": false,
				"error": map[string]any{
					"code": "TCP_TUNNELS_DISABLED",
				},
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	resource, err := (HTTPClient{
		BaseURL:              server.URL,
		PapercodeLocalURL:    "http://127.0.0.1:4099",
		RouteExpiresIn:       time.Hour,
		RouteSubdomainPrefix: "pb",
		SSHRemotePortStart:   25000,
		SSHRemotePortEnd:     25000,
	}).EnsureProjectResources(context.Background(), ProjectRef{ID: "prj_conflict"})
	if err != nil {
		t.Fatal(err)
	}
	if len(httpCreateBodies) != 2 {
		t.Fatalf("http create attempts = %d, want 2", len(httpCreateBodies))
	}
	if httpCreateBodies[0]["subdomain"] == httpCreateBodies[1]["subdomain"] {
		t.Fatalf("retry reused conflicting subdomain: %#v", httpCreateBodies)
	}
	if resource.TunnelID != "tun_http_conflict_retry" {
		t.Fatalf("resource = %#v", resource)
	}
}

func TestHTTPClientEnsureProjectResourcesRetriesTCPPortConflict(t *testing.T) {
	var tcpPorts []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/clients":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"client_id":    "cli_prj_retry",
					"client_token": "clt_project_machine_token",
				},
			})
		case "/api/http-tunnels":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":   "tun_http_retry",
					"preview_url": "https://pb-prj-retry.agentunnel.example",
					"status":      "active",
				},
			})
		case "/api/tcp-tunnels":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			tcpPorts = append(tcpPorts, int(body["remote_port"].(float64)))
			if len(tcpPorts) < 10 {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"ok": false,
					"error": map[string]any{
						"code":    "REMOTE_PORT_IN_USE",
						"message": "remote port is already reserved",
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":   "tun_tcp_retry",
					"remote_port": tcpPorts[len(tcpPorts)-1],
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
		PapercodeLocalURL:    "http://127.0.0.1:4099",
		RouteExpiresIn:       time.Hour,
		RouteSubdomainPrefix: "pb",
		SSHRemotePortStart:   25000,
		SSHRemotePortEnd:     25011,
	}).EnsureProjectResources(context.Background(), ProjectRef{ID: "prj_retry"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tcpPorts) != 10 {
		t.Fatalf("tcp ports = %#v, want retry through the tenth candidate", tcpPorts)
	}
	seen := map[int]bool{}
	for _, port := range tcpPorts {
		if seen[port] {
			t.Fatalf("tcp ports = %#v, want unique candidates", tcpPorts)
		}
		seen[port] = true
	}
	if resource.Metadata["tcp_tunnel_id"] != "tun_tcp_retry" || resource.SSHPort != tcpPorts[9] {
		t.Fatalf("resource = %#v", resource)
	}
}

func TestHTTPClientEnsureProjectResourcesDoesNotRetryNonConflictProviderError(t *testing.T) {
	var tcpAttempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/clients":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"client_id":    "cli_prj_non_retry",
					"client_token": "clt_project_machine_token",
				},
			})
		case "/api/http-tunnels":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":   "tun_http_non_retry",
					"preview_url": "https://pb-prj-non-retry.agentunnel.example",
					"status":      "active",
				},
			})
		case "/api/tcp-tunnels":
			tcpAttempts++
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": false,
				"error": map[string]any{
					"code":    "UNAUTHORIZED",
					"message": "invalid api key",
				},
			})
		case "/api/clients/cli_prj_non_retry/machine-cleanup":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{"client_status": "revoked"}})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := (HTTPClient{
		BaseURL:              server.URL,
		PapercodeLocalURL:    "http://127.0.0.1:4099",
		RouteExpiresIn:       time.Hour,
		RouteSubdomainPrefix: "pb",
		SSHRemotePortStart:   25000,
		SSHRemotePortEnd:     25011,
	}).EnsureProjectResources(context.Background(), ProjectRef{ID: "prj_non_retry"})
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("EnsureProjectResources error = %v, want ErrProvider", err)
	}
	if tcpAttempts != 1 {
		t.Fatalf("tcp attempts = %d, want 1", tcpAttempts)
	}
}

func TestHTTPClientEnsureProjectResourcesCleansUpAfterTCPFailure(t *testing.T) {
	var cleanupBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/clients":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"client_id":    "cli_prj_cleanup",
					"client_token": "clt_project_machine_token",
				},
			})
		case "/api/http-tunnels":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":   "tun_http_cleanup",
					"preview_url": "https://pb-prj-cleanup.agentunnel.example",
					"status":      "active",
				},
			})
		case "/api/tcp-tunnels":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": false,
				"error": map[string]any{
					"code":    "REMOTE_PORT_IN_USE",
					"message": "remote port is already reserved",
				},
			})
		case "/api/clients/cli_prj_cleanup/machine-cleanup":
			if err := json.NewDecoder(r.Body).Decode(&cleanupBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{"client_status": "revoked"}})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := (HTTPClient{
		BaseURL:              server.URL,
		PapercodeLocalURL:    "http://127.0.0.1:4099",
		RouteExpiresIn:       time.Hour,
		RouteSubdomainPrefix: "pb",
		SSHRemotePortStart:   25000,
		SSHRemotePortEnd:     25000,
	}).EnsureProjectResources(context.Background(), ProjectRef{ID: "prj_cleanup"})
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("EnsureProjectResources error = %v, want ErrProvider", err)
	}
	if cleanupBody["action"] != "close" || cleanupBody["reason"] != "provision_failed" {
		t.Fatalf("cleanup body = %#v", cleanupBody)
	}
}

func TestHTTPClientCleanupProjectResourcesCallsMachineCleanup(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/clients/cli_prj_1/machine-cleanup" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer agentunnel-api-key" {
			t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{"client_status": "revoked"}})
	}))
	defer server.Close()

	err := (HTTPClient{BaseURL: server.URL, APIKey: "agentunnel-api-key"}).CleanupProjectResources(context.Background(), ResourceDescriptor{ClientID: "cli_prj_1"}, "close", "project_delete")
	if err != nil {
		t.Fatal(err)
	}
	if body["action"] != "close" || body["reason"] != "project_delete" {
		t.Fatalf("cleanup body = %#v", body)
	}
}

func TestHTTPClientStatusUsesHTTPTunnelRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/http-tunnels/tun_http_1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":   "tun_http_1",
					"preview_url": "https://pb-prj-1.agentunnel.example",
					"status":      "active",
				},
			})
		case "/api/tcp-tunnels/tun_tcp_1/connect-info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":         "tun_tcp_1",
					"host":              "ssh.agentunnel.example",
					"port":              25432,
					"status":            "active",
					"forwarding_status": "online",
					"can_connect":       true,
				},
			})
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	status, err := (HTTPClient{BaseURL: server.URL}).Status(context.Background(), ResourceDescriptor{
		TunnelID: "tun_http_1",
		Metadata: map[string]any{
			"resource_kind": "http_tunnel",
			"tcp_tunnel_id": "tun_tcp_1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.HTTPBaseURL != "https://pb-prj-1.agentunnel.example" || status.WebSocketBaseURL != "wss://pb-prj-1.agentunnel.example" {
		t.Fatalf("status = %#v", status)
	}
	if status.SSHHost != "ssh.agentunnel.example" || status.SSHPort != 25432 {
		t.Fatalf("status = %#v", status)
	}
}

func TestHTTPClientStatusRequiresCombinedTCPTunnelReadiness(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/http-tunnels/tun_http_1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":   "tun_http_1",
					"preview_url": "https://pb-prj-1.agentunnel.example",
					"status":      "active",
				},
			})
		case "/api/tcp-tunnels/tun_tcp_1/connect-info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"tunnel_id":         "tun_tcp_1",
					"status":            "active",
					"forwarding_status": "offline",
					"can_connect":       false,
					"reason_code":       "CLIENT_OFFLINE",
				},
			})
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	status, err := (HTTPClient{BaseURL: server.URL}).Status(context.Background(), ResourceDescriptor{
		TunnelID: "tun_http_1",
		Metadata: map[string]any{
			"resource_kind": "http_tunnel",
			"tcp_tunnel_id": "tun_tcp_1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.Status != "offline" || status.Reason != "CLIENT_OFFLINE" {
		t.Fatalf("status = %#v", status)
	}
	if status.HTTPBaseURL != "https://pb-prj-1.agentunnel.example" || status.WebSocketBaseURL != "wss://pb-prj-1.agentunnel.example" {
		t.Fatalf("status = %#v", status)
	}
}

func TestHTTPClientStatusRejectsCombinedResourceWithoutTCPTunnelID(t *testing.T) {
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
	if status.Ready || status.Reason != "TCP_TUNNEL_MISSING" {
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

func TestHTTPClientStatusMapsSuspendedTunnel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"data": map[string]any{
				"tunnel_id":         "tun_123",
				"status":            "suspended",
				"forwarding_status": "suspended",
				"can_connect":       false,
				"reason_code":       "TUNNEL_SUSPENDED",
			},
		})
	}))
	defer server.Close()

	status, err := (HTTPClient{BaseURL: server.URL}).Status(context.Background(), ResourceDescriptor{TunnelID: "tun_123"})
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.Status != "suspended" || status.Reason != "TUNNEL_SUSPENDED" {
		t.Fatalf("status = %#v", status)
	}
}

func TestHTTPClientStatusMapsProviderEnvelopeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false,
			"error": map[string]any{
				"code":    "REMOTE_PORT_IN_USE",
				"message": "remote port is already reserved",
			},
		})
	}))
	defer server.Close()

	_, err := (HTTPClient{BaseURL: server.URL}).Status(context.Background(), ResourceDescriptor{TunnelID: "tun_123"})
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("status error = %v, want ErrProvider", err)
	}
}

func TestHTTPClientStatusMapsExpiredProviderToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false,
			"error": map[string]any{
				"code":    "TOKEN_REVOKED",
				"message": "client token was revoked",
			},
		})
	}))
	defer server.Close()

	_, err := (HTTPClient{BaseURL: server.URL}).Status(context.Background(), ResourceDescriptor{TunnelID: "tun_123"})
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("status error = %v, want ErrProvider", err)
	}
}

func TestBuildCLIResponseDoesNotInventUnvalidatedAuth(t *testing.T) {
	resp := buildResponse(ConnectCLI, projects.Project{ID: "prj_1", Name: "Demo"}, ResourceDescriptor{
		HTTPBaseURL:      "https://agentunnel.example/projects/prj_1",
		WebSocketBaseURL: "wss://agentunnel.example/projects/prj_1",
	}, time.Now().UTC().Add(time.Minute), CLICredentials{})

	if _, ok := resp.Terminal["auth"]; ok {
		t.Fatalf("terminal descriptor should not include unvalidated auth: %#v", resp.Terminal)
	}
	if _, ok := resp.PapercodeUpload["auth"]; ok {
		t.Fatalf("upload descriptor should not include unvalidated auth: %#v", resp.PapercodeUpload)
	}
}

func TestWaitForReadyPollsUntilTunnelReady(t *testing.T) {
	client := &sequenceStatusClient{statuses: []TunnelStatus{
		{Ready: false, Status: "starting", Reason: "CLIENT_STARTING"},
		{Ready: true, Status: "online"},
	}}
	service := &Service{
		client:              client,
		connectReadyTimeout: 50 * time.Millisecond,
		connectPollInterval: time.Millisecond,
	}
	status, err := service.waitForReady(context.Background(), ResourceDescriptor{TunnelID: "tun_wait"})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.Status != "online" {
		t.Fatalf("status = %#v", status)
	}
	if client.calls != 2 {
		t.Fatalf("status calls = %d, want 2", client.calls)
	}
}

func TestWaitForReadyReturnsLastNotReadyStatusOnTimeout(t *testing.T) {
	client := &sequenceStatusClient{statuses: []TunnelStatus{{Ready: false, Status: "offline", Reason: "CLIENT_OFFLINE"}}}
	service := &Service{
		client:              client,
		connectReadyTimeout: 3 * time.Millisecond,
		connectPollInterval: time.Millisecond,
	}
	status, err := service.waitForReady(context.Background(), ResourceDescriptor{TunnelID: "tun_wait"})
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.Status != "offline" || status.Reason != "CLIENT_OFFLINE" {
		t.Fatalf("status = %#v", status)
	}
	if client.calls < 2 {
		t.Fatalf("status calls = %d, want repeated polling", client.calls)
	}
}

func TestRecordActivityRejectsUnapprovedSource(t *testing.T) {
	repo := &Repository{}
	err := repo.RecordActivity(context.Background(), "prj_activity", "browser_ping", nil)
	if err == nil || !strings.Contains(err.Error(), "not accepted") {
		t.Fatalf("RecordActivity error = %v, want source rejection", err)
	}
}

type sequenceStatusClient struct {
	statuses []TunnelStatus
	calls    int
}

func (c *sequenceStatusClient) EnsureProjectResources(context.Context, ProjectRef) (ResourceDescriptor, error) {
	return ResourceDescriptor{}, ErrTunnelUnavailable
}

func (c *sequenceStatusClient) Status(context.Context, ResourceDescriptor) (TunnelStatus, error) {
	c.calls++
	if c.calls <= len(c.statuses) {
		return c.statuses[c.calls-1], nil
	}
	return c.statuses[len(c.statuses)-1], nil
}

func (c *sequenceStatusClient) CleanupProjectResources(context.Context, ResourceDescriptor, string, string) error {
	return nil
}

func mustJSONForTest(value any) string {
	b, _ := json.Marshal(value)
	return string(b)
}
