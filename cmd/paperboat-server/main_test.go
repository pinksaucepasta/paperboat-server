package main

import (
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

func TestCommandAgentunnelClientUsesHTTPAdapterOutsideFakeMode(t *testing.T) {
	cfg := config.Default()
	cfg.Providers.FakeMode = false
	cfg.Providers.Agentunnel.BaseURL = "https://agentunnel.example"
	cfg.Providers.Agentunnel.PapercodeLocalURL = "http://127.0.0.1:4099"
	cfg.Providers.Agentunnel.RouteExpiresIn = time.Hour
	cfg.Providers.Agentunnel.RouteSubdomainPrefix = "pb"
	cfg.Secrets.AgentunnelAPIKey = "agentunnel-api-key"

	client, ok := commandAgentunnelClient(cfg).(agentunnel.HTTPClient)
	if !ok {
		t.Fatalf("client type = %T, want agentunnel.HTTPClient", commandAgentunnelClient(cfg))
	}
	if client.BaseURL != cfg.Providers.Agentunnel.BaseURL ||
		client.APIKey != cfg.Secrets.AgentunnelAPIKey ||
		client.PapercodeLocalURL != cfg.Providers.Agentunnel.PapercodeLocalURL ||
		client.RouteExpiresIn != cfg.Providers.Agentunnel.RouteExpiresIn ||
		client.RouteSubdomainPrefix != cfg.Providers.Agentunnel.RouteSubdomainPrefix {
		t.Fatalf("client config = %#v", client)
	}
}
