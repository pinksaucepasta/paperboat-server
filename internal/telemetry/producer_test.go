package telemetry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProducerRecordsTypedSignalsWithSafeIdentity(t *testing.T) {
	at := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	events, err := NewEventLogWithQueue(128, 128)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	lifecycle, err := NewLifecycleEventLog(32)
	if err != nil {
		t.Fatal(err)
	}
	defer lifecycle.Close()
	health, err := NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	producer := NewProducer(ProducerOptions{
		Metrics:         NewMetrics(),
		Events:          events,
		Health:          health,
		LifecycleEvents: lifecycle,
		Now:             func() time.Time { return at },
	})

	identity := ProducerIdentity{
		RequestID: "req_01", CorrelationID: "cor_01", ResourceKind: "route", ResourceID: "route_01",
		OperationKind: "verify", OperationID: "op_01", ActorType: "system", ActorID: "actor_01",
		IDs: SafeIDs{DomainID: "domain_01", RouteID: "route_01"},
	}
	if err := producer.RecordDNSVerification(DNSVerificationInput{
		Outcome: DNSVerificationSucceeded, Duration: 2 * time.Second, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordCertificateLifecycle(CertificateLifecycleInput{
		Operation: CertificateRenew, Outcome: CertificateSucceeded, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordCertificateExpiry(CertificateExpiryInput{
		Horizon: CertificateUnder7D, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordPreviewAllocation(PreviewAllocationInput{
		Outcome: PreviewAllocationSucceeded, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordPreviewCleanup(PreviewCleanupInput{
		Outcome: PreviewCleanupAlreadyClean, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordConnectorSession(ConnectorSessionInput{
		State: ConnectorSessionActive, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordConnectorReconnect(ConnectorReconnectInput{
		Outcome: ConnectorReconnectSucceeded, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordConnectorBackoff(ConnectorBackoffInput{
		State: ConnectorBackoffScheduled, Duration: 3 * time.Second, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordConnectorHandshake(ConnectorHandshakeInput{
		Outcome: ConnectorHandshakeSucceeded, Duration: 50 * time.Millisecond, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordConnectorDisconnect(ConnectorDisconnectInput{
		Reason: ConnectorDisconnectNetwork, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordConfigApply(ConfigApplyInput{
		State: ConfigGenerationApplied, Generation: 4, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordRouteError(RouteErrorInput{
		Class: RouteErrorOrigin, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordRouteLatency(RouteLatencyInput{
		Protocol: RouteProtocolHTTPS, Duration: 25 * time.Millisecond, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordServiceLifecycle(ServiceLifecycleInput{
		State: ServiceRunning, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordServiceRestart(ServiceRestartInput{
		Outcome: ServiceRestartSucceeded, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordWatchdog(WatchdogInput{
		Outcome: WatchdogHealthy, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordCrashLoop(CrashLoopInput{
		State: CrashLoopClear, Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}
	if err := events.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := len(events.Snapshot()); got != 17 {
		t.Fatalf("event count = %d, want 17", got)
	}
	if got := len(lifecycle.Snapshot()); got != 17 {
		t.Fatalf("lifecycle count = %d, want 17", got)
	}
	for _, event := range events.Snapshot() {
		if event.RequestID != "req_01" || event.CorrelationID != "cor_01" {
			t.Fatalf("identity was not preserved: %#v", event)
		}
		if err := event.Validate(); err != nil {
			t.Fatalf("invalid event: %v", err)
		}
	}
	for _, event := range lifecycle.Snapshot() {
		if event.RequestID != "req_01" || event.CorrelationID != "cor_01" || event.Operation.ID != "op_01" {
			t.Fatalf("lifecycle identity was not preserved: %#v", event)
		}
		if err := event.Validate(); err != nil {
			t.Fatalf("invalid lifecycle event: %v", err)
		}
	}

	if got := health.Snapshot().Dimensions.Route.Status; got != StatusReady {
		t.Fatalf("route status after recovery = %s, want %s", got, StatusReady)
	}
	if got := health.Snapshot().Dimensions.Service.Status; got != StatusReady {
		t.Fatalf("service status = %s, want %s", got, StatusReady)
	}
	body, err := producer.Metrics.JSON()
	if err != nil || !json.Valid(body) {
		t.Fatalf("metrics JSON = %s, err=%v", body, err)
	}
	second, _ := producer.Metrics.JSON()
	if string(second) != string(body) {
		t.Fatalf("metrics JSON is not deterministic: %s vs %s", body, second)
	}
}

func TestProducerFailuresRecoverAndNeverRecordRawInput(t *testing.T) {
	at := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	events, err := NewEventLogWithQueue(32, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	health, err := NewHealthTracker(func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	producer := &Producer{Metrics: NewMetrics(), Events: events, Health: health, Now: func() time.Time { return at }}
	unsafe := ProducerIdentity{
		RequestID: "https://alice:password@example.test/path", CorrelationID: "customer.example.test",
		ResourceKind: "route", ResourceID: "customer.example.test", OperationID: "Bearer-secret",
		IDs: SafeIDs{RouteID: "customer.example.test", RequestID: "token=never"},
	}
	if err := producer.RecordDNSVerification(DNSVerificationInput{
		Outcome: DNSVerificationFailed, FailureClass: DNSFailureTimeout, Duration: time.Second,
		Identity: unsafe,
	}); err != nil {
		t.Fatal(err)
	}
	if err := producer.RecordRouteError(RouteErrorInput{Class: RouteErrorInternal, Identity: unsafe}); err != nil {
		t.Fatal(err)
	}
	if err := events.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, event := range events.Snapshot() {
		body, err := event.JSON()
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"alice", "password", "example.test", "Bearer", "token=never", "customer.example"} {
			if strings.Contains(string(body), forbidden) {
				t.Fatalf("raw input %q leaked in %s", forbidden, body)
			}
		}
		if event.RequestID != "" || event.CorrelationID == "customer.example.test" {
			t.Fatalf("unsafe identity was retained: %#v", event)
		}
	}
	if got := health.Snapshot().Dimensions.Route.Status; got != StatusDegraded {
		t.Fatalf("route failure status = %s, want %s", got, StatusDegraded)
	}
	if got := health.Snapshot().Dimensions.DNS.Status; got != StatusDegraded {
		t.Fatalf("dns failure status = %s, want %s", got, StatusDegraded)
	}
}

func TestProducerUsesOnlyFiniteMetricLabels(t *testing.T) {
	metrics := NewMetricsWithLimit(1)
	producer := &Producer{Metrics: metrics, Now: func() time.Time { return time.Unix(1, 0).UTC() }}
	if err := producer.RecordDNSVerification(DNSVerificationInput{
		Outcome: DNSVerificationSucceeded, Duration: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	// A second descriptor series is rejected by the core cardinality guard. No
	// caller value is ever used as a label, even when the safe enum is invalid.
	if err := producer.RecordDNSVerification(DNSVerificationInput{
		Outcome: DNSVerificationFailed, FailureClass: DNSFailureProvider, Duration: time.Second,
	}); ErrorCodeOf(err) != ErrorMetricCardinality {
		t.Fatalf("cardinality error = %v, want %s", err, ErrorMetricCardinality)
	}
	for _, descriptor := range MetricDescriptors() {
		for _, label := range descriptor.Labels {
			for _, value := range label.AllowedValues {
				if strings.ContainsAny(value, "/:@") || strings.Contains(value, ".") {
					t.Fatalf("unsafe finite label %q on %s", value, descriptor.Name)
				}
			}
		}
	}
}

func TestProducerServiceUptimeIsDurationNotBoolean(t *testing.T) {
	producer := &Producer{Metrics: NewMetrics(), Now: func() time.Time { return time.Unix(1, 0).UTC() }}
	if err := producer.RecordServiceLifecycle(ServiceLifecycleInput{State: ServiceRunning, Uptime: 90 * time.Second}); err != nil {
		t.Fatal(err)
	}
	values := map[string]uint64{}
	for _, sample := range producer.Metrics.Snapshot() {
		if sample.Name != MetricServiceUptime {
			continue
		}
		state := ""
		for _, label := range sample.Labels {
			if label.Name == "state" {
				state = label.Value
			}
		}
		values[state] = sample.Value
	}
	if values["running"] != 90 || values["degraded"] != 0 || values["stopped"] != 0 {
		t.Fatalf("uptime values=%v", values)
	}
	if err := producer.RecordServiceLifecycle(ServiceLifecycleInput{State: ServiceStopped, Uptime: -time.Second}); ErrorCodeOf(err) != ErrorInvalidObservation {
		t.Fatalf("negative uptime error=%v", err)
	}
}

func TestProducerRejectsUnboundedDurationsWithoutRecording(t *testing.T) {
	metrics := NewMetrics()
	producer := &Producer{Metrics: metrics, Now: time.Now}
	if err := producer.RecordConnectorHandshake(ConnectorHandshakeInput{
		Outcome: ConnectorHandshakeSucceeded, Duration: 25 * time.Hour,
	}); ErrorCodeOf(err) != ErrorInvalidObservation {
		t.Fatalf("duration error = %v, want %s", err, ErrorInvalidObservation)
	}
	if len(metrics.Snapshot()) != 0 {
		t.Fatal("invalid duration recorded a metric")
	}
}
