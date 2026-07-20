package observability

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestProviderTransportRecordsBoundedLatencyAndErrors(t *testing.T) {
	providerMetrics.Lock()
	providerMetrics.values = make(map[string]providerMetric)
	providerMetrics.Unlock()

	transport := InstrumentProviderTransport("polar", roundTripFunc(func(*http.Request) (*http.Response, error) {
		time.Sleep(2 * time.Millisecond)
		return &http.Response{StatusCode: http.StatusServiceUnavailable}, nil
	}))
	request, err := http.NewRequest(http.MethodGet, "https://polar.example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatal(err)
	}
	metrics := MetricsSnapshot()
	if metrics["provider_polar_requests_total"] != 1 || metrics["provider_polar_errors_total"] != 1 {
		t.Fatalf("provider metrics = %#v", metrics)
	}
	if metrics["provider_polar_latency_ms_total"] < 1 || metrics["provider_polar_latency_ms_max"] < 1 {
		t.Fatalf("provider latency metrics = %#v", metrics)
	}
}

func TestProviderTransportCountsNetworkFailureAndBoundsUnknownProvider(t *testing.T) {
	providerMetrics.Lock()
	providerMetrics.values = make(map[string]providerMetric)
	providerMetrics.Unlock()

	transport := InstrumentProviderTransport("user-controlled-value", roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network unavailable")
	}))
	request, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("expected transport error")
	}
	metrics := MetricsSnapshot()
	if metrics["provider_unknown_requests_total"] != 1 || metrics["provider_unknown_errors_total"] != 1 {
		t.Fatalf("unknown provider metrics = %#v", metrics)
	}
}

func TestDefaultProviderClientHasFiniteTimeoutAndInstrumentation(t *testing.T) {
	client := DefaultProviderClient("github")
	if client.Timeout <= 0 {
		t.Fatalf("timeout = %s, want finite timeout", client.Timeout)
	}
	transport, ok := client.Transport.(providerTransport)
	if !ok || transport.provider != "github" || transport.next == nil {
		t.Fatalf("transport = %#v, want instrumented github transport", client.Transport)
	}
}
