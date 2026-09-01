package telemetry

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPObserverRecordsFiniteLabelsAndSafeEvent(t *testing.T) {
	metrics := NewMetrics()
	events, err := NewEventLog(4)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	observer := HTTPObserver{
		Metrics: metrics, Events: events, Now: func() time.Time { return now },
		Identity: func(context.Context) (string, string) { return "req_http_1", "cor_http_1" },
	}
	handler := observer.Wrap("public_api", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/private/customer.example/token-secret" {
			t.Fatalf("path changed: %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/private/customer.example/token-secret", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d", recorder.Code)
	}
	samples := metrics.Snapshot()
	found := false
	for _, sample := range samples {
		if sample.Name == MetricHTTPRequests {
			found = true
			if labels := metricLabelMap(sample.Labels); labels["method"] != "post" || labels["route_family"] != "public_api" || labels["status_class"] != "4xx" {
				t.Fatalf("labels=%v", labels)
			}
		}
	}
	if !found {
		t.Fatal("request metric missing")
	}
	recorded := events.Snapshot()
	if len(recorded) != 1 || recorded[0].Code != "http_request_rejected" || recorded[0].RequestID != "req_http_1" || recorded[0].CorrelationID != "cor_http_1" {
		t.Fatalf("events=%#v", recorded)
	}
	body, err := recorded[0].JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"customer.example", "token-secret", "authorization", "cookie"} {
		if strings.Contains(strings.ToLower(string(body)), forbidden) {
			t.Fatalf("event leaked %q: %s", forbidden, body)
		}
	}
}

func TestHTTPObserverPreservesStreamingInterfaces(t *testing.T) {
	observer := HTTPObserver{Metrics: NewMetrics()}
	underlying := &interfaceWriter{header: make(http.Header)}
	handler := observer.Wrap("edge_control", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, ok := w.(http.Flusher); !ok {
			t.Fatal("flusher was not preserved")
		}
		if _, ok := w.(http.Hijacker); !ok {
			t.Fatal("hijacker was not preserved")
		}
		w.(http.Flusher).Flush()
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(underlying, httptest.NewRequest(http.MethodGet, "/v1/edge/private", nil))
	if !underlying.flushed {
		t.Fatal("flush was not forwarded")
	}
}

func TestHTTPObserverWrapFuncNormalizesDynamicFamily(t *testing.T) {
	metrics := NewMetrics()
	handler := (HTTPObserver{Metrics: metrics}).WrapFunc(func(r *http.Request) string {
		if strings.HasPrefix(r.URL.Path, "/v1/edge/") {
			return "edge_control"
		}
		return r.URL.Query().Get("family")
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, target := range []string{"/v1/edge/routes", "/unsafe?family=customer.example"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))
	}
	seen := map[string]bool{}
	for _, sample := range metrics.Snapshot() {
		if sample.Name == MetricHTTPRequests {
			seen[metricLabelMap(sample.Labels)["route_family"]] = true
		}
	}
	if !seen["edge_control"] || !seen["other"] || seen["customer.example"] {
		t.Fatalf("route families=%v", seen)
	}
}

type interfaceWriter struct {
	header  http.Header
	status  int
	flushed bool
}

func (w *interfaceWriter) Header() http.Header { return w.header }
func (w *interfaceWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return len(body), nil
}
func (w *interfaceWriter) WriteHeader(status int) { w.status = status }
func (w *interfaceWriter) Flush()                 { w.flushed = true }
func (w *interfaceWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	left, right := net.Pipe()
	_ = right.Close()
	return left, bufio.NewReadWriter(bufio.NewReader(left), bufio.NewWriter(left)), nil
}

func metricLabelMap(labels []MetricLabel) map[string]string {
	result := make(map[string]string, len(labels))
	for _, label := range labels {
		result[label.Name] = label.Value
	}
	return result
}
