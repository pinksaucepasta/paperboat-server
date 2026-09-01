package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/telemetry"
)

func TestTelemetryDiagnosticsIsLoopbackBoundedAndCorrelated(t *testing.T) {
	at := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	health, err := telemetry.NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	if err := health.Update(telemetry.HealthUpdate{
		Dimension: telemetry.DimensionOrigin, Status: telemetry.StatusDegraded, Code: "origin_retrying",
		Summary:      "The origin is retrying after a connection failure.",
		RepairAction: "Retry when the origin is available.", CorrelationID: "corr_diag",
		Retry: telemetry.RetryScheduled, NextRetryAt: at.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	metrics := telemetry.NewMetrics()
	if err := metrics.IncCounter(telemetry.MetricHTTPRequests, telemetry.MetricLabels{"method": "get", "route_family": "health", "status_class": "2xx"}); err != nil {
		t.Fatal(err)
	}
	events, err := telemetry.NewEventLog(4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	if _, err := events.Record(telemetry.EventInput{
		At: at, Severity: telemetry.SeverityInfo, Component: telemetry.DimensionOrigin,
		Name: "origin_retry", Code: "origin_retrying", Outcome: telemetry.OutcomeStateChange,
		Message: "Origin is retrying.", CorrelationID: "corr_diag", Retry: telemetry.RetryScheduled,
		NextRetryAt: at.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	diagnostics, err := telemetry.NewDiagnostics(telemetry.DiagnosticsConfig{Metrics: metrics, Health: health, Events: events, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/diagnostics", nil)
	request.RemoteAddr = "127.0.0.1:43210"
	request = request.WithContext(observability.WithCorrelationID(observability.WithRequestID(request.Context(), "req_diag"), "corr_diag"))
	first := httptest.NewRecorder()
	telemetryDiagnostics(diagnostics).ServeHTTP(first, request)
	if first.Code != http.StatusOK || first.Header().Get("Content-Type") != "application/json" || first.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("code=%d headers=%v body=%q", first.Code, first.Header(), first.Body.String())
	}
	var snapshot telemetry.DiagnosticsSnapshot
	if err := json.Unmarshal(first.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
	if snapshot.RequestID != "req_diag" || snapshot.CorrelationID != "corr_diag" || snapshot.Retry != telemetry.RetryScheduled || snapshot.NextRetryAt == nil || len(snapshot.Metrics) != 1 || len(snapshot.Events) != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if len(first.Body.Bytes()) > telemetry.MaximumDiagnosticsBytes {
		t.Fatalf("diagnostics body=%d bytes", first.Body.Len())
	}
	second := httptest.NewRecorder()
	telemetryDiagnostics(diagnostics).ServeHTTP(second, request)
	if !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatalf("snapshot is not deterministic:\nfirst=%s\nsecond=%s", first.Body.Bytes(), second.Body.Bytes())
	}
	if strings.Contains(first.Body.String(), "https://") || strings.Contains(first.Body.String(), "127.0.0.1") || strings.Contains(first.Body.String(), "Bearer ") {
		t.Fatalf("diagnostics contains unsafe transport data: %s", first.Body.String())
	}
}

func TestTelemetryDiagnosticsRejectsRemoteQueryAndMethods(t *testing.T) {
	at := time.Unix(10, 0).UTC()
	health, err := telemetry.NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	diagnostics, err := telemetry.NewDiagnostics(telemetry.DiagnosticsConfig{Health: health, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		remote string
		method string
		target string
		want   int
	}{
		{name: "remote", remote: "192.0.2.1:43210", method: http.MethodGet, target: "http://127.0.0.1/diagnostics", want: http.StatusForbidden},
		{name: "forwarded remote", remote: "192.0.2.1:43210", method: http.MethodGet, target: "http://127.0.0.1/diagnostics", want: http.StatusForbidden},
		{name: "query", remote: "127.0.0.1:43210", method: http.MethodGet, target: "http://127.0.0.1/diagnostics?verbose=true", want: http.StatusNotFound},
		{name: "method", remote: "127.0.0.1:43210", method: http.MethodPost, target: "http://127.0.0.1/diagnostics", want: http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, nil)
			request.RemoteAddr = test.remote
			request.Header.Set("X-Forwarded-For", "127.0.0.1")
			response := httptest.NewRecorder()
			telemetryDiagnostics(diagnostics).ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

func TestRouterTelemetryDiagnosticsUsesLiveEventLog(t *testing.T) {
	at := time.Unix(11, 0).UTC()
	health, err := telemetry.NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	events, err := telemetry.NewEventLog(4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	diagnostics, err := telemetry.NewDiagnostics(telemetry.DiagnosticsConfig{Health: health, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	diagnostics.SetEventLog(events)
	if _, err := events.Record(telemetry.EventInput{At: at, Severity: telemetry.SeverityInfo, Component: telemetry.DimensionService, Name: "service_ready", Code: "ready", Outcome: telemetry.OutcomeSuccess, Message: "Service is ready.", CorrelationID: "corr_diag", Retry: telemetry.RetryNone}); err != nil {
		t.Fatal(err)
	}
	router := NewRouter(Options{Config: config.Default(), TelemetryDiagnostics: diagnostics})
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/diagnostics", nil)
	request.RemoteAddr = "127.0.0.1:43210"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"events":[`) || !strings.Contains(response.Body.String(), `"name":"service_ready"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestTelemetryDiagnosticsUnavailableWithoutHealth(t *testing.T) {
	diagnostics, err := telemetry.NewDiagnostics(telemetry.DiagnosticsConfig{Now: func() time.Time { return time.Unix(12, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/diagnostics", nil)
	request.RemoteAddr = "127.0.0.1:43210"
	response := httptest.NewRecorder()
	telemetryDiagnostics(diagnostics).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"diagnostics_unavailable"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
