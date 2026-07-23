package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

var ErrHostedHelperNotReady = errors.New("hosted helper is not ready")

type HostedReadinessError struct {
	Stage  string
	Reason string
}

func (e *HostedReadinessError) Error() string {
	return fmt.Sprintf("%s: %s", e.Stage, e.Reason)
}

func (e *HostedReadinessError) Unwrap() error { return ErrHostedHelperNotReady }

func HostedHelperHealthURL(cfg config.Config, projectID string) string {
	host := providerName(cfg.Providers.Agentunnel.RouteSubdomainPrefix, projectID) + "." + strings.Trim(strings.ToLower(cfg.HelperBaseDomain), ".")
	if base := strings.TrimRight(strings.TrimSpace(cfg.Fly.HostedReadinessBaseURL), "/"); base != "" {
		return base + "/healthz"
	}
	return "https://" + host + "/healthz"
}

func HostedHelperHealthHost(cfg config.Config, projectID string) string {
	return providerName(cfg.Providers.Agentunnel.RouteSubdomainPrefix, projectID) + "." + strings.Trim(strings.ToLower(cfg.HelperBaseDomain), ".")
}

type helperHealth struct {
	Live         bool                        `json:"live"`
	Version      string                      `json:"version"`
	Capabilities map[string]helperCapability `json:"capabilities"`
	CheckedAt    time.Time                   `json:"checked_at"`
}

type helperCapability struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

func NewHTTPReadinessVerifier(client *http.Client, endpoint func(string) string) func(context.Context, string) error {
	return NewHTTPReadinessVerifierWithHost(client, endpoint, nil)
}

func NewHTTPReadinessVerifierWithHost(client *http.Client, endpoint func(string) string, host func(string) string) func(context.Context, string) error {
	return func(ctx context.Context, projectID string) error {
		if client == nil || endpoint == nil {
			return &HostedReadinessError{Stage: "helper_health", Reason: "verifier is not configured"}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint(projectID), nil)
		if err != nil {
			return &HostedReadinessError{Stage: "helper_health", Reason: "construct request failed"}
		}
		request.Header.Set("Accept", "application/json")
		if host != nil {
			request.Host = host(projectID)
		}
		response, err := client.Do(request)
		if err != nil {
			return &HostedReadinessError{Stage: "helper_health", Reason: "request failed"}
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			return &HostedReadinessError{Stage: "helper_health", Reason: fmt.Sprintf("status %d", response.StatusCode)}
		}
		decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
		decoder.DisallowUnknownFields()
		var health helperHealth
		if err := decoder.Decode(&health); err != nil {
			return &HostedReadinessError{Stage: "helper_health", Reason: "invalid health response"}
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return &HostedReadinessError{Stage: "helper_health", Reason: "invalid trailing health response"}
		}
		if !health.Live {
			return &HostedReadinessError{Stage: "helper_health", Reason: "helper is not live"}
		}
		for _, name := range []string{"hosted_lifecycle", "edge", "control_plane"} {
			capability, ok := health.Capabilities[name]
			if !ok || capability.State != "ready" {
				reason := strings.TrimSpace(capability.Reason)
				if reason == "" {
					reason = "unavailable"
				}
				stage := map[string]string{"hosted_lifecycle": "workspace", "edge": "connector_admission", "control_plane": "runtime_dependencies"}[name]
				return &HostedReadinessError{Stage: stage, Reason: "capability " + name + " is " + reason}
			}
		}
		return nil
	}
}
