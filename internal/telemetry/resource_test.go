package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHealthResourceMatchesCanonicalProjection(t *testing.T) {
	at := time.Date(2026, 8, 30, 11, 2, 0, 0, time.UTC)
	tracker := newTestHealthTracker(t, func() time.Time { return at })
	setAllReady(t, tracker)
	at = at.Add(time.Minute)
	updateHealth(t, tracker, HealthUpdate{Dimension: DimensionOrigin, Status: StatusDegraded, Code: "origin_connection_refused", Summary: "Edge connected; origin refused connection.", RepairAction: "Start the origin.", CorrelationID: "cor_01", Retry: RetryScheduled, NextRetryAt: at.Add(time.Minute)})
	resource, err := tracker.Snapshot().AsResource("tunnel", "tun_01", "cor_01")
	if err != nil {
		t.Fatal(err)
	}
	if err := resource.Validate(); err != nil {
		t.Fatal(err)
	}
	body, err := resource.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{"schema": ContractSchemaV1, "kind": KindHealth, "resource_kind": "tunnel", "resource_id": "tun_01", "overall_code": "origin_connection_refused", "retrying": true, "correlation_id": "cor_01"} {
		if decoded[key] != want {
			t.Fatalf("%s = %#v, want %#v", key, decoded[key], want)
		}
	}
	dimensions, ok := decoded["dimensions"].(map[string]any)
	if !ok || len(dimensions) != len(dimensionOrder) {
		t.Fatalf("dimensions = %#v", decoded["dimensions"])
	}
	if origin := dimensions["origin"].(map[string]any); origin["status"] != string(StatusDegraded) || origin["code"] != "origin_connection_refused" {
		t.Fatalf("origin = %#v", origin)
	}
	if strings.Contains(string(body), "broken_since") || strings.Contains(string(body), "suppressed_by") || strings.Contains(string(body), "etag") {
		t.Fatalf("rich internal fields leaked into canonical resource: %s", body)
	}
}

func TestHealthResourceRejectsFabricatedIdentityAndOmitsUnscheduledRetry(t *testing.T) {
	at := time.Date(2026, 8, 30, 11, 2, 0, 0, time.UTC)
	tracker := newTestHealthTracker(t, func() time.Time { return at })
	setAllReady(t, tracker)
	snapshot := tracker.Snapshot()

	resource, err := snapshot.AsResource("tunnel", "tun_01", "cor_ready")
	if err != nil {
		t.Fatal(err)
	}
	if resource.NextRetryAt != nil || resource.Retrying {
		t.Fatalf("unscheduled retry = retrying:%t next:%v", resource.Retrying, resource.NextRetryAt)
	}
	body, err := resource.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "next_retry_at") {
		t.Fatalf("unscheduled retry was emitted: %s", body)
	}

	snapshot.Overall.CorrelationID = ""
	if _, err := snapshot.AsResource("tunnel", "tun_01", ""); err == nil {
		t.Fatal("missing durable correlation ID was accepted")
	}
	snapshot.Overall.CorrelationID = "cor_original"
	if _, err := snapshot.AsResource("tunnel", "tun_01", "cor_relabel"); err == nil {
		t.Fatal("relabeled correlation ID was accepted")
	}
	if _, err := snapshot.AsResource("operation", "op_01", "cor_original"); err == nil {
		t.Fatal("operation was accepted as a health resource kind")
	}
}

func TestCanonicalEventAndLogRejectSecretsAndKeepCopies(t *testing.T) {
	metadata := map[string]any{"generation": int64(3), "nested": map[string]any{"note": "safe"}}
	event, err := NewEventResource(CanonicalEventInput{ID: "evt_01", Cursor: "cur_00000001", EventType: "connector.attached", ResourceKind: "connector", ResourceID: "con_01", OccurredAt: time.Date(2026, 8, 30, 11, 2, 0, 0, time.UTC), ActorType: "host", ActorID: "host_01", CorrelationID: "cor_01", SafeMetadata: metadata})
	if err != nil {
		t.Fatal(err)
	}
	metadata["generation"] = "changed"
	if event.SafeMetadata["generation"] != int64(3) {
		t.Fatalf("metadata was not copied: %#v", event.SafeMetadata)
	}
	body, err := event.JSON()
	if err != nil || !json.Valid(body) {
		t.Fatalf("event json: %s, %v", body, err)
	}
	if _, err := NewEventResource(CanonicalEventInput{ID: "evt_01", Cursor: "cur_00000001", EventType: "access.denied", ResourceKind: "connector", ResourceID: "con_01", OccurredAt: time.Now(), ActorType: "host", ActorID: "host_01", CorrelationID: "cor_01", SafeMetadata: map[string]any{"access_token": "secret"}}); errorCode(err) != ErrorInvalidString {
		t.Fatalf("secret metadata error = %v", err)
	}
	if _, err := NewEventResource(CanonicalEventInput{ID: "evt_02", Cursor: "cur_00000002", EventType: "operation.completed", ResourceKind: "operation", ResourceID: "op_01", OccurredAt: time.Now(), ActorType: "system", ActorID: "system_01", CorrelationID: "cor_01"}); err != nil {
		t.Fatalf("operation event rejected: %v", err)
	}
	if _, err := NewEventResource(CanonicalEventInput{ID: "evt_03", Cursor: "cur_00000003", EventType: "operation-completed", ResourceKind: "operation", ResourceID: "op_01", OccurredAt: time.Now(), ActorType: "system", ActorID: "system_01", CorrelationID: "cor_01"}); err == nil {
		t.Fatal("hyphenated canonical event type was accepted")
	}

	entry, err := NewLogEntry(LogEntryInput{ID: "log_01", TunnelID: "tun_01", ConnectorID: "con_01", Level: SeverityWarn, Component: "connector", Code: "heartbeat_late", Message: "Connector heartbeat is late.", Metadata: map[string]any{"generation": 3}, CorrelationID: "cor_01", OccurredAt: time.Now(), Cursor: "log_00000001"})
	if err != nil {
		t.Fatal(err)
	}
	if err := entry.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLogEntry(LogEntryInput{ID: "log_01", Level: SeverityError, Component: "origin", Code: "origin_error", Message: "origin failed: https://user:pass@example.test", CorrelationID: "cor_01", OccurredAt: time.Now(), Cursor: "log_bad"}); err != nil {
		t.Fatal("safe URL should be redacted, not rejected", err)
	}
	badMetadata := map[string]any{"Authorization": "secret"}
	if _, err := NewLogEntry(LogEntryInput{ID: "log_01", Level: SeverityError, Component: "access", Code: "access_denied", Message: "denied", Metadata: badMetadata, CorrelationID: "cor_01", OccurredAt: time.Now(), Cursor: "log_bad"}); errorCode(err) != ErrorInvalidString {
		t.Fatalf("secret log metadata error = %v", err)
	}
}

func TestErrorResourceIsTypedAndSecretSafe(t *testing.T) {
	errorResource, err := NewErrorResource(ErrorResourceInput{Code: "generation_conflict", Component: DimensionConfig, Message: "The tunnel changed before this update was applied.", Outcome: "unchanged", Retryable: false, RepairAction: "Fetch the current tunnel and retry with its ETag.", RequestID: "req_01", CorrelationID: "cor_01"})
	if err != nil {
		t.Fatal(err)
	}
	if err := errorResource.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewErrorResource(ErrorResourceInput{Code: "access_denied", Component: DimensionAccess, Message: "Authorization: Bearer secret", Outcome: "unchanged", RepairAction: "Retry.", RequestID: "req_01", CorrelationID: "cor_01"}); err != nil {
		t.Fatal("secret should be redacted", err)
	}
}
