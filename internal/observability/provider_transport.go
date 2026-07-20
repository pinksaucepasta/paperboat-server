package observability

import (
	"net/http"
	"sync"
	"time"
)

type providerMetric struct {
	requests       int64
	errors         int64
	latencyMSTotal int64
	latencyMSMax   int64
}

var providerMetrics = struct {
	sync.Mutex
	values map[string]providerMetric
}{values: make(map[string]providerMetric)}

type providerTransport struct {
	provider string
	next     http.RoundTripper
}

func DefaultProviderClient(provider string) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: InstrumentProviderTransport(provider, http.DefaultTransport)}
}

func InstrumentProviderTransport(provider string, next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return providerTransport{provider: normalizeProvider(provider), next: next}
}

func (t providerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	started := time.Now()
	response, err := t.next.RoundTrip(request)
	latency := max(0, time.Since(started).Milliseconds())
	failed := err != nil || response == nil || response.StatusCode >= http.StatusInternalServerError

	providerMetrics.Lock()
	metric := providerMetrics.values[t.provider]
	metric.requests++
	metric.latencyMSTotal += latency
	if latency > metric.latencyMSMax {
		metric.latencyMSMax = latency
	}
	if failed {
		metric.errors++
	}
	providerMetrics.values[t.provider] = metric
	providerMetrics.Unlock()
	return response, err
}

func normalizeProvider(provider string) string {
	switch provider {
	case "workos", "polar", "github", "agentunnel", "papercode":
		return provider
	default:
		return "unknown"
	}
}

func providerMetricsSnapshot() map[string]int64 {
	providerMetrics.Lock()
	defer providerMetrics.Unlock()
	providers := [...]string{"workos", "polar", "github", "agentunnel", "papercode", "unknown"}
	result := make(map[string]int64, len(providers)*4)
	for _, provider := range providers {
		metric := providerMetrics.values[provider]
		prefix := "provider_" + provider
		result[prefix+"_requests_total"] = metric.requests
		result[prefix+"_errors_total"] = metric.errors
		result[prefix+"_latency_ms_total"] = metric.latencyMSTotal
		result[prefix+"_latency_ms_max"] = metric.latencyMSMax
	}
	return result
}
