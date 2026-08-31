package telemetry

import (
	"math"
	"strings"
	"sync"
	"testing"
)

func TestMetricsAreFixedCardinalityDeterministicAndExactJSON(t *testing.T) {
	metrics := NewMetrics()
	if err := metrics.AddCounter(MetricEdgeRequests, MetricLabels{"protocol": "https", "outcome": "success"}, 3); err != nil {
		t.Fatal(err)
	}
	if err := metrics.AddCounter(MetricAccessDecisions, MetricLabels{"decision": "denied"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := metrics.SetGauge(MetricHealthDimension, MetricLabels{"dimension": "route", "status": "degraded"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := metrics.ObserveHistogram(MetricOperationLatency, MetricLabels{"operation": "reconcile"}, 0.2); err != nil {
		t.Fatal(err)
	}
	body, err := metrics.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"kind":"histogram"`) || !strings.Contains(string(body), `"upper_bound":0.25`) {
		t.Fatalf("histogram missing: %s", body)
	}
	second, _ := metrics.JSON()
	if string(second) != string(body) {
		t.Fatalf("non-deterministic JSON = %s", second)
	}

	descriptors := MetricDescriptors()
	descriptors[0].Labels[0].AllowedValues[0] = "customer.example.com"
	if MetricDescriptors()[0].Labels[0].AllowedValues[0] == "customer.example.com" {
		t.Fatal("descriptor mutation escaped")
	}
}

func TestMetricsRejectUnknownAndHighCardinalityLabels(t *testing.T) {
	metrics := NewMetricsWithLimit(1)
	base := MetricLabels{"protocol": "https", "outcome": "success"}
	tests := []struct {
		name   string
		labels MetricLabels
		code   ErrorCode
	}{
		{"hostname", MetricLabels{"protocol": "customer.example.com", "outcome": "success"}, ErrorLabelValueRejected},
		{"url", MetricLabels{"protocol": "https://customer.example.com", "outcome": "success"}, ErrorLabelValueRejected},
		{"arbitrary id", MetricLabels{"protocol": "route_customer123", "outcome": "success"}, ErrorLabelValueRejected},
		{"token", MetricLabels{"protocol": "Bearer-secret", "outcome": "success"}, ErrorLabelValueRejected},
		{"unknown", MetricLabels{"protocol": "https", "outcome": "success", "hostname": "customer.example.com"}, ErrorUnknownLabel},
		{"missing", MetricLabels{"protocol": "https"}, ErrorMissingLabel},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := metrics.AddCounter(MetricEdgeRequests, test.labels, 1); errorCode(err) != test.code {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if err := metrics.SetGauge(MetricEdgeRequests, base, 1); errorCode(err) != ErrorMetricKindMismatch {
		t.Fatalf("kind mismatch = %v", err)
	}
	if err := metrics.AddCounter("paperboat_edge_unknown_total", base, 1); errorCode(err) != ErrorUnknownMetric {
		t.Fatalf("unknown metric = %v", err)
	}
	if err := metrics.AddCounter(MetricEdgeRequests, base, math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	if err := metrics.AddCounter(MetricEdgeRequests, base, 1); errorCode(err) != ErrorMetricOverflow {
		t.Fatalf("overflow = %v", err)
	}
	if err := metrics.AddCounter(MetricAccessDecisions, MetricLabels{"decision": "allowed"}, 1); errorCode(err) != ErrorMetricCardinality {
		t.Fatalf("cardinality = %v", err)
	}
	if err := metrics.ObserveHistogram(MetricOperationLatency, MetricLabels{"operation": "reconcile"}, math.NaN()); errorCode(err) != ErrorInvalidObservation {
		t.Fatalf("nan = %v", err)
	}
}

func TestMetricsConcurrentUse(t *testing.T) {
	metrics := NewMetrics()
	labels := MetricLabels{"protocol": "https", "outcome": "success"}
	var group sync.WaitGroup
	for worker := 0; worker < 64; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for iteration := 0; iteration < 100; iteration++ {
				if err := metrics.AddCounter(MetricEdgeRequests, labels, 1); err != nil {
					t.Errorf("AddCounter: %v", err)
					return
				}
				_ = metrics.Snapshot()
			}
		}()
	}
	group.Wait()
	samples := metrics.Snapshot()
	if len(samples) != 1 || samples[0].Value != 6400 {
		t.Fatalf("samples = %#v", samples)
	}
}

func TestServerMetricsCoverRequiredFailureDomainsWithFiniteLabels(t *testing.T) {
	descriptors := MetricDescriptors()
	wanted := map[string]bool{
		MetricDNSVerificationDuration:  false,
		MetricDNSVerificationFailures:  false,
		MetricCertificateExpiryHorizon: false,
		MetricPreviewAllocation:        false,
		MetricPreviewLeaseCleanup:      false,
		MetricOperationIdempotency:     false,
		MetricServiceUptime:            false,
		MetricServiceWatchdog:          false,
		MetricServiceCrashLoop:         false,
	}
	for _, descriptor := range descriptors {
		if _, ok := wanted[descriptor.Name]; !ok {
			continue
		}
		wanted[descriptor.Name] = true
		for _, label := range descriptor.Labels {
			if len(label.AllowedValues) == 0 || len(label.AllowedValues) > 16 {
				t.Fatalf("unbounded label %q on %s", label.Name, descriptor.Name)
			}
			for _, value := range label.AllowedValues {
				if strings.ContainsAny(value, "/:@") || strings.Contains(value, ".") {
					t.Fatalf("unsafe/dynamic label value %q on %s", value, descriptor.Name)
				}
			}
		}
	}
	for name, found := range wanted {
		if !found {
			t.Fatalf("required server metric %s missing", name)
		}
	}
}
