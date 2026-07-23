package agentunnel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/projects"
)

func TestHTTPClientEnsureProjectResourcesCreatesClientAndHTTPTunnel(t *testing.T) {
	var paths []string
	var authHeaders []string
	var clientCreateBody map[string]any
	var httpCreateBody map[string]any
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
					"tunnel_id": "tun_http_1", "preview_url": "https://pb-prj-1.agentunnel.example",
					"status": "active", "forwarding_status": "online", "client_connected": true,
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
	if resource.TunnelID != "tun_http_1" || resource.ClientID != "cli_prj_1" || resource.ResourceID != "tun_http_1" {
		t.Fatalf("resource ids = %#v", resource)
	}
	if resource.MachineToken != "clt_project_machine_token" {
		t.Fatalf("machine token was not captured")
	}
	if resource.HTTPBaseURL != "https://pb-prj-1.agentunnel.example" || resource.WebSocketBaseURL != "wss://pb-prj-1.agentunnel.example" {
		t.Fatalf("route urls = %q %q", resource.HTTPBaseURL, resource.WebSocketBaseURL)
	}
	if _, ok := resource.Metadata["tcp_tunnel_id"]; ok {
		t.Fatalf("resource retained stale TCP metadata: %#v", resource.Metadata)
	}
	resourceJSON := strings.ToLower(mustJSONForTest(resource))
	if strings.Contains(resourceJSON, "api-key") || strings.Contains(resourceJSON, "project_machine_token") {
		t.Fatalf("resource leaked secret: %#v", resource)
	}
}

func TestHTTPClientReattachProjectResourcesPreservesHTTPRoute(t *testing.T) {
	var reassignedClientID string
	var reassignedExpiresIn string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/clients":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{
				"client_id": "cli_replacement", "client_token": "clt_replacement_token",
			}})
		case "/api/http-tunnels/tun_stable/reassign":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			reassignedClientID = body["client_id"]
			reassignedExpiresIn = body["expires_in"]
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{
				"tunnel_id": "tun_stable", "client_id": "cli_replacement",
				"preview_url": "https://pb-stable.agentunnel.example", "status": "active",
			}})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	resource, err := (HTTPClient{BaseURL: server.URL, RouteExpiresIn: 30 * 24 * time.Hour}).ReattachProjectResources(context.Background(), ProjectRef{ID: "prj_1"}, ResourceDescriptor{
		TunnelID: "tun_stable", ResourceID: "tun_stable", ClientID: "cli_old",
		HTTPBaseURL: "https://pb-stable.agentunnel.example", WebSocketBaseURL: "wss://pb-stable.agentunnel.example",
		Metadata: map[string]any{"resource_kind": "http_tunnel", "tcp_tunnel_id": "tun_tcp_old"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if reassignedClientID != "cli_replacement" || resource.ClientID != "cli_replacement" || resource.MachineToken != "clt_replacement_token" {
		t.Fatalf("reattached resource = %#v, requested client = %q", resource, reassignedClientID)
	}
	if reassignedExpiresIn != "never" {
		t.Fatalf("reassignment expires_in = %q, want persistent lifetime", reassignedExpiresIn)
	}
	if resource.Metadata["superseded_client_id"] != "cli_old" {
		t.Fatalf("superseded client cleanup was not persisted: %#v", resource.Metadata)
	}
	if resource.TunnelID != "tun_stable" || resource.HTTPBaseURL != "https://pb-stable.agentunnel.example" || resource.WebSocketBaseURL != "wss://pb-stable.agentunnel.example" {
		t.Fatalf("stable route changed: %#v", resource)
	}
	if _, ok := resource.Metadata["tcp_tunnel_id"]; ok {
		t.Fatalf("stale legacy TCP assignment retained: %#v", resource.Metadata)
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
					"tunnel_id": "tun_http_1", "preview_url": "https://pb-prj-1.agentunnel.example",
					"status": "active", "forwarding_status": "online", "client_connected": true,
				},
			})
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	status, err := (HTTPClient{BaseURL: server.URL}).Status(context.Background(), ResourceDescriptor{
		TunnelID: "tun_http_1",
		Metadata: map[string]any{"resource_kind": "http_tunnel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.HTTPBaseURL != "https://pb-prj-1.agentunnel.example" || status.WebSocketBaseURL != "wss://pb-prj-1.agentunnel.example" {
		t.Fatalf("status = %#v", status)
	}
}

func TestHTTPClientStatusAllowsHTTPWebSocketResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/http-tunnels/tun_http_1" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"data": map[string]any{
				"tunnel_id": "tun_http_1", "preview_url": "https://pb-prj-1.agentunnel.example",
				"status": "active", "forwarding_status": "online", "client_connected": true,
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
	if !status.Ready || status.Reason != "" {
		t.Fatalf("status = %#v", status)
	}
}

func TestHTTPClientStatusMapsOfflineHTTPRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{
			"tunnel_id": "tun_http_1", "preview_url": "https://pb-prj-1.agentunnel.example",
			"status": "active", "forwarding_status": "offline", "client_connected": false,
		}})
	}))
	defer server.Close()

	status, err := (HTTPClient{BaseURL: server.URL}).Status(context.Background(), ResourceDescriptor{
		TunnelID: "tun_http_1", Metadata: map[string]any{"resource_kind": "http_tunnel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.Status != "offline" || status.Reason != "CLIENT_OFFLINE" {
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
	if status.Ready || status.Status != "suspended" || status.Reason != "HTTP_ROUTE_NOT_ACTIVE" {
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
	}, time.Now().UTC().Add(time.Minute), CLICredentials{}, 7<<20, []string{"image/png"}, 604800, "", "", "")
	if resp.Schema != "paperboat.environment-connection/v1" || resp.Environment["kind"] != "hosted" || resp.Environment["resource_id"] != "prj_1" {
		t.Fatalf("canonical descriptor identity is incomplete: %#v", resp)
	}
	if resp.Terminal["endpoint"] != "wss://agentunnel.example/projects/prj_1" || resp.PapercodeUpload["endpoint"] != "https://agentunnel.example/projects/prj_1/api/files/staged-images" {
		t.Fatalf("canonical endpoints are incomplete: terminal=%#v upload=%#v", resp.Terminal, resp.PapercodeUpload)
	}

	if _, ok := resp.Terminal["auth"]; ok {
		t.Fatalf("terminal descriptor should not include unvalidated auth: %#v", resp.Terminal)
	}
	if _, ok := resp.PapercodeUpload["auth"]; ok {
		t.Fatalf("upload descriptor should not include unvalidated auth: %#v", resp.PapercodeUpload)
	}
	if resp.PapercodeUpload["max_bytes"] != int64(7<<20) || !slices.Equal(resp.PapercodeUpload["allowed_mime_types"].([]string), []string{"image/png"}) {
		t.Fatalf("upload policy was not sourced from config: %#v", resp.PapercodeUpload)
	}
	if resp.PapercodeUpload["path"] != "/projects/prj_1/api/files/staged-images" {
		t.Fatalf("upload path was not derived from route base: %#v", resp.PapercodeUpload)
	}
	if resp.PapercodeUpload["kind"] != "papercode_staged_image" || resp.PapercodeUpload["retention_seconds"] != int64(604800) {
		t.Fatalf("upload contract metadata is incomplete: %#v", resp.PapercodeUpload)
	}
}

func TestBuildCLIResponseSerializesCanonicalPayload(t *testing.T) {
	expires := time.Now().UTC().Add(time.Minute)
	resp := buildResponse(ConnectCLI, projects.Project{ID: "prj_1", Name: "Demo"}, ResourceDescriptor{
		HTTPBaseURL: "https://edge.example/projects/prj_1", WebSocketBaseURL: "wss://edge.example/projects/prj_1",
	}, expires, CLICredentials{
		TerminalAuth: map[string]any{"method": "websocket_ticket", "ticket": "t", "expires_at": expires, "scopes": []string{"terminal:operate"}},
		UploadAuth:   map[string]any{"method": "bearer", "token": "u", "expires_at": expires, "scopes": []string{"file:stage"}},
	}, 1024, []string{"image/png"}, 60, "thread", "terminal", "/workspace")
	resp.Issuer = "https://api.example"
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"project_id", "project_state", "papercode_websocket", "papercode_staged_image", "websocket_base_url", "http_base_url", "connected_machine_id"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("canonical payload contains legacy field %q: %s", forbidden, b)
		}
	}
	if payload["schema"] != "paperboat.environment-connection/v1" {
		t.Fatalf("schema = %v", payload["schema"])
	}
}

func TestHTTPClientStatusRejectsProxyBelowUploadLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{
			"tunnel_id": "tun_http_1", "preview_url": "https://pb-prj-1.agentunnel.example",
			"status": "active", "forwarding_status": "online", "client_connected": true,
			"max_request_body_bytes": 4 << 20,
		}})
	}))
	defer server.Close()
	status, err := (HTTPClient{BaseURL: server.URL, UploadMaxBytes: 8 << 20}).Status(context.Background(), ResourceDescriptor{
		TunnelID: "tun_http_1", Metadata: map[string]any{"resource_kind": "http_tunnel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.Status != "proxy_limit_incompatible" || status.Reason != "PROXY_BODY_LIMIT_TOO_LOW" {
		t.Fatalf("status = %#v", status)
	}
}

func TestHTTPClientStatusRejectsUnknownProxyUploadLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{
			"tunnel_id": "tun_http_1", "preview_url": "https://pb-prj-1.agentunnel.example",
			"status": "active", "forwarding_status": "online", "client_connected": true,
		}})
	}))
	defer server.Close()
	status, err := (HTTPClient{BaseURL: server.URL, UploadMaxBytes: 8 << 20}).Status(context.Background(), ResourceDescriptor{
		TunnelID: "tun_http_1", Metadata: map[string]any{"resource_kind": "http_tunnel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.Status != "proxy_limit_incompatible" || status.Reason != "PROXY_BODY_LIMIT_UNKNOWN" {
		t.Fatalf("status = %#v", status)
	}
}

func TestHTTPClientStatusRequiresMultipartHeadroom(t *testing.T) {
	const uploadLimit int64 = 8 << 20
	for _, tc := range []struct {
		name       string
		proxyLimit int64
		wantReady  bool
	}{
		{name: "one byte short", proxyLimit: uploadLimit + (64 << 10) - 1},
		{name: "exact headroom", proxyLimit: uploadLimit + (64 << 10), wantReady: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{
					"tunnel_id": "tun_http_1", "preview_url": "https://pb-prj-1.agentunnel.example",
					"status": "active", "forwarding_status": "online", "client_connected": true,
					"max_request_body_bytes": tc.proxyLimit,
				}})
			}))
			defer server.Close()
			status, err := (HTTPClient{BaseURL: server.URL, UploadMaxBytes: uploadLimit}).Status(context.Background(), ResourceDescriptor{
				TunnelID: "tun_http_1", Metadata: map[string]any{"resource_kind": "http_tunnel"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if status.Ready != tc.wantReady {
				t.Fatalf("status = %#v", status)
			}
		})
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

func TestStaleHTTPStatusPreservesOfflineClientRoute(t *testing.T) {
	resource := ResourceDescriptor{
		HTTPBaseURL:      "https://project.example",
		WebSocketBaseURL: "wss://project.example",
		Metadata:         map[string]any{"resource_kind": "http_tunnel"},
	}
	status := TunnelStatus{Status: "offline", Reason: "CLIENT_OFFLINE"}
	if staleHTTPStatus(resource, status) {
		t.Fatal("offline client route must not be reprovisioned")
	}
}

func TestRetryAfterSecondsUsesConfiguredPollInterval(t *testing.T) {
	service := &Service{connectPollInterval: 1250 * time.Millisecond}
	if got := service.retryAfterSeconds(); got != 2 {
		t.Fatalf("retry_after_seconds = %d, want 2", got)
	}
	service.connectPollInterval = 0
	if got := service.retryAfterSeconds(); got != 1 {
		t.Fatalf("default retry_after_seconds = %d, want 1", got)
	}
}

func TestRecordActivityRejectsUnapprovedSource(t *testing.T) {
	repo := &Repository{}
	err := repo.RecordActivity(context.Background(), "prj_activity", "browser_ping", nil)
	if err == nil || !strings.Contains(err.Error(), "not accepted") {
		t.Fatalf("RecordActivity error = %v, want source rejection", err)
	}
}

func TestRevokePapercodeSessionsContinuesAfterIndependentFailure(t *testing.T) {
	issuer := &selectiveRevocationIssuer{failProjectID: "prj_unavailable"}
	service := &Service{credentials: issuer}
	err := service.revokePapercodeSessions(context.Background(), []PapercodeSessionLink{
		{ProjectID: "prj_unavailable", UserID: "usr_1", ClientSessionID: "cls_1", TerminalSessionID: "session-1", HTTPBaseURL: "https://unavailable.example"},
		{ProjectID: "prj_reachable", UserID: "usr_1", ClientSessionID: "cls_1", TerminalSessionID: "session-2", HTTPBaseURL: "https://reachable.example"},
	}, "logout")
	if err == nil || !strings.Contains(err.Error(), "prj_unavailable") {
		t.Fatalf("revocation error=%v, want unavailable project failure", err)
	}
	if strings.Join(issuer.attemptedProjects, ",") != "prj_unavailable,prj_reachable" {
		t.Fatalf("attempted projects=%v", issuer.attemptedProjects)
	}
}

type selectiveRevocationIssuer struct {
	failProjectID     string
	attemptedProjects []string
}

func (*selectiveRevocationIssuer) CheckCLI(context.Context, CredentialInput) error {
	return nil
}

func (*selectiveRevocationIssuer) IssueCLI(context.Context, CredentialInput) (CLICredentials, error) {
	return CLICredentials{}, nil
}

func (i *selectiveRevocationIssuer) RevokeCLI(_ context.Context, input CredentialRevocationInput) error {
	i.attemptedProjects = append(i.attemptedProjects, input.ProjectID)
	if input.ProjectID == i.failProjectID {
		return errors.New("environment unavailable")
	}
	return nil
}

type sequenceStatusClient struct {
	statuses []TunnelStatus
	calls    int
}

func (c *sequenceStatusClient) EnsureProjectResources(context.Context, ProjectRef) (ResourceDescriptor, error) {
	return ResourceDescriptor{}, ErrTunnelUnavailable
}

func (c *sequenceStatusClient) ReattachProjectResources(context.Context, ProjectRef, ResourceDescriptor) (ResourceDescriptor, error) {
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

func TestPreserveMachineCredentialKeepsExistingCiphertext(t *testing.T) {
	existing := ResourceDescriptor{
		Metadata: map[string]any{"machine_token_ciphertext": "encrypted-current-token"},
	}
	reconciled := ResourceDescriptor{
		MachineToken: "new-token-from-provider",
		Metadata:     map[string]any{"resource_kind": "http_tunnel"},
	}

	preserveMachineCredential(existing, &reconciled)

	if reconciled.MachineToken != "" {
		t.Fatalf("machine token was not cleared")
	}
	if got, _ := reconciled.Metadata["machine_token_ciphertext"].(string); got != "encrypted-current-token" {
		t.Fatalf("machine_token_ciphertext = %q", got)
	}
}

func mustJSONForTest(value any) string {
	b, _ := json.Marshal(value)
	return string(b)
}

func TestFakeCredentialIssuerUsesSeparatedScopes(t *testing.T) {
	credentials, err := (FakeCredentialIssuer{}).IssueCLI(context.Background(), CredentialInput{ProjectID: "prj_1", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if got := credentials.TerminalAuth["scopes"].([]string); len(got) != 1 || got[0] != "terminal:operate" {
		t.Fatalf("terminal scopes = %#v", got)
	}
	if got := credentials.UploadAuth["scopes"].([]string); len(got) != 1 || got[0] != "file:stage" {
		t.Fatalf("upload scopes = %#v", got)
	}
}
