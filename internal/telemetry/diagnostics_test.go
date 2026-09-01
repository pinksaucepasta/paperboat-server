package telemetry

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticsSnapshotIsBoundedDeterministicAndSecretSafe(t *testing.T) {
	at := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	health, err := NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	if err := health.Update(HealthUpdate{
		Dimension: DimensionRoute, Status: StatusDegraded, Code: "route_retrying",
		Summary:      "The route is retrying after an origin failure at https://private.example.test.",
		RepairAction: "Retry after 2026-08-31T12:01:00Z.", CorrelationID: "corr_diag",
		Retry: RetryScheduled, NextRetryAt: at.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	metrics := NewMetrics()
	if err := metrics.IncCounter(MetricHTTPRequests, MetricLabels{"method": "get", "route_family": "health", "status_class": "2xx"}); err != nil {
		t.Fatal(err)
	}
	events, err := NewEventLog(8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	for index := 0; index < 3; index++ {
		if _, err := events.Record(EventInput{
			At: at.Add(time.Duration(index) * time.Second), Severity: SeverityInfo,
			Component: DimensionRoute, Name: "route_retry", Code: "route_retrying",
			Outcome: OutcomeStateChange, Message: "Bearer route-secret at https://private.example.test.",
			CorrelationID: "corr_diag", IDs: SafeIDs{RouteID: "route_diag"}, Retry: RetryScheduled,
			NextRetryAt: at.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	diagnostics, err := NewDiagnostics(DiagnosticsConfig{
		Metrics: metrics, Health: health, Events: events, Now: func() time.Time { return at }, MaximumEvents: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := diagnostics.JSONWithIdentity("req_diag", "corr_diag")
	if err != nil {
		t.Fatal(err)
	}
	second, err := diagnostics.JSONWithIdentity("req_diag", "corr_diag")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("snapshot changed without telemetry changes:\nfirst=%s\nsecond=%s", first, second)
	}
	if len(first) > MaximumDiagnosticsBytes {
		t.Fatalf("snapshot size=%d, limit=%d", len(first), MaximumDiagnosticsBytes)
	}
	var snapshot DiagnosticsSnapshot
	if err := json.Unmarshal(first, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Schema != DiagnosticsSchemaV1 || snapshot.RequestID != "req_diag" || snapshot.CorrelationID != "corr_diag" || snapshot.Retry != RetryScheduled || snapshot.NextRetryAt == nil || len(snapshot.Metrics) != 1 || len(snapshot.Events) != 2 || snapshot.DroppedEvents != 0 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	encoded := string(first)
	for _, secret := range []string{"private.example.test", "Bearer route-secret", "https://"} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("snapshot leaked %q: %s", secret, encoded)
		}
	}
	if !strings.Contains(encoded, RedactedValue) {
		t.Fatalf("snapshot did not retain redaction marker: %s", encoded)
	}
}

func TestDiagnosticsEventLogCanBeAttachedAfterConstruction(t *testing.T) {
	at := time.Unix(10, 0).UTC()
	health, err := NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	diagnostics, err := NewDiagnostics(DiagnosticsConfig{Health: health, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(diagnostics.Snapshot().Events); got != 0 {
		t.Fatalf("events before attach=%d", got)
	}
	events, err := NewEventLog(2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	diagnostics.SetEventLog(events)
	if _, err := events.Record(EventInput{
		At: at, Severity: SeverityInfo, Component: DimensionService, Name: "service_ready", Code: "ready",
		Outcome: OutcomeSuccess, Message: "Service is ready.", CorrelationID: "corr_diag", Retry: RetryNone,
	}); err != nil {
		t.Fatal(err)
	}
	if got := len(diagnostics.Snapshot().Events); got != 1 {
		t.Fatalf("events after attach=%d", got)
	}
}

func TestDiagnosticsRejectsUnsafeIdentityAndOversizedConfiguration(t *testing.T) {
	at := time.Unix(11, 0).UTC()
	health, err := NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiagnostics(DiagnosticsConfig{Health: health, MaximumBytes: 17 << 20}); ErrorCodeOf(err) != ErrorInvalidCapacity {
		t.Fatalf("oversized config error=%v code=%v", err, ErrorCodeOf(err))
	}
	diagnostics, err := NewDiagnostics(DiagnosticsConfig{Health: health, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := diagnostics.SnapshotWithIdentity("req_diag", "corr_diag")
	snapshot.RequestID = "request/unsafe"
	if _, err := snapshot.JSON(); ErrorCodeOf(err) != ErrorInvalidObservation {
		t.Fatalf("unsafe identity error=%v code=%v", err, ErrorCodeOf(err))
	}
	if _, err := diagnostics.JSONWithIdentity("req_diag", "corr_diag"); err != nil {
		t.Fatal(err)
	}
}
