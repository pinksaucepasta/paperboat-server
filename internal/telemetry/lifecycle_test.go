package telemetry

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLifecycleEventAndLogAreTypedRedactedAndDeterministic(t *testing.T) {
	at := time.Date(2026, 8, 31, 4, 5, 6, 123000000, time.FixedZone("IST", 19800))
	metadata := map[string]any{
		"request_id": "request_01",
		"generation": int64(4),
		"nested":     map[string]any{"note": "safe"},
	}
	event, err := NewLifecycleEvent(LifecycleEventInput{
		ID: "evt_01", Cursor: "cur_0001", At: at, Severity: SeverityInfo,
		Component: DimensionRoute, EventType: "route.activated", Code: "route_ready",
		Outcome: OutcomeStateChange, Message: "Route activated for https://user:password@example.test.",
		RequestID: "request_01", CorrelationID: "corr_01",
		ResourceKind: "route", ResourceID: "route_01", OperationID: "operation_01",
		Metadata: metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata["generation"] = int64(99)
	if event.Metadata["generation"] != int64(4) || event.Metadata["request_id"] != "request_01" {
		t.Fatalf("metadata was not copied safely: %#v", event.Metadata)
	}
	body, err := event.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(mustJSON(t, event)) {
		t.Fatal("event JSON is not deterministic")
	}
	for _, unsafe := range []string{"password@example.test", "https://user", "user:password"} {
		if strings.Contains(string(body), unsafe) {
			t.Fatalf("unsafe lifecycle value %q in %s", unsafe, body)
		}
	}
	if !strings.Contains(string(body), "request_01") || !strings.Contains(string(body), "operation_01") {
		t.Fatalf("required identity was lost: %s", body)
	}

	log, err := NewLogRecord(LogRecordInput{
		OccurredAt: at, Level: SeverityWarn, Component: DimensionAccess, Code: "access_denied",
		Message: "Authorization: Bearer secret", RequestID: "req_01", CorrelationID: "cor_01",
		Resource: ResourceIdentity{Kind: "tunnel", ID: "tun_01"}, Operation: OperationIdentity{Kind: "delete", ID: "op_01"},
	})
	if err != nil {
		t.Fatal(err)
	}
	logBody, err := log.JSON()
	if err != nil || !strings.Contains(string(logBody), RedactedValue) || strings.Contains(string(logBody), "secret") {
		t.Fatalf("redacted log = %s, err=%v", logBody, err)
	}
}

func TestLifecycleRejectsMissingIdentitySecretKeysAndUnsafeControl(t *testing.T) {
	base := LifecycleEventInput{
		At: time.Unix(1, 0), Severity: SeverityInfo, Component: DimensionService,
		EventType: "service.started", Code: "ready", Outcome: OutcomeSuccess, Message: "Ready.",
		RequestID: "req_01", CorrelationID: "cor_01", ResourceKind: "tunnel", ResourceID: "tun_01", OperationID: "op_01",
	}
	tests := []struct {
		name string
		edit func(*LifecycleEventInput)
		code ErrorCode
	}{
		{"missing request", func(input *LifecycleEventInput) { input.RequestID = "" }, ErrorIdentityRequired},
		{"missing operation", func(input *LifecycleEventInput) { input.OperationID = "" }, ErrorIdentityRequired},
		{"hostname resource", func(input *LifecycleEventInput) { input.ResourceID = "customer.example.com" }, ErrorIdentityRequired},
		{"secret metadata key", func(input *LifecycleEventInput) { input.Metadata = map[string]any{"access_token": "never"} }, ErrorInvalidString},
		{"mismatched resource aliases", func(input *LifecycleEventInput) { input.Resource = ResourceIdentity{Kind: "route", ID: "route_01"} }, ErrorIdentityMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.edit(&input)
			if _, err := NewLifecycleEvent(input); errorCode(err) != test.code {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
		})
	}
	if _, err := NewLogRecord(LogRecordInput{
		OccurredAt: time.Unix(1, 0), Level: SeverityInfo, Component: DimensionService, Code: "ready", Message: "bad\x00line",
		RequestID: "req_01", CorrelationID: "cor_01", ResourceKind: "tunnel", ResourceID: "tun_01", OperationID: "op_01",
	}); err != nil {
		t.Fatalf("control characters should be normalized safely: %v", err)
	}
}

func TestLifecycleEventAndLogBuffersAreBoundedAndRaceSafe(t *testing.T) {
	at := time.Unix(1, 0)
	eventInput := LifecycleEventInput{
		At: at, Severity: SeverityInfo, Component: DimensionService, EventType: "service.started", Code: "ready", Outcome: OutcomeSuccess, Message: "Ready.",
		RequestID: "req_01", CorrelationID: "cor_01", ResourceKind: "tunnel", ResourceID: "tun_01", OperationID: "op_01",
	}
	events, err := NewLifecycleEventLog(8)
	if err != nil {
		t.Fatal(err)
	}
	logs, err := NewLifecycleLog(8)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for count := 0; count < 50; count++ {
				_, _ = events.Record(eventInput)
				_, _ = logs.Record(LogRecordInput{OccurredAt: at, Level: SeverityInfo, Component: DimensionService, Code: "ready", Message: "Ready.", RequestID: "req_01", CorrelationID: "cor_01", ResourceKind: "tunnel", ResourceID: "tun_01", OperationID: "op_01"})
				_ = events.Snapshot()
				_ = logs.Snapshot()
			}
		}()
	}
	group.Wait()
	if len(events.Snapshot()) > 8 || len(logs.Snapshot()) > 8 {
		t.Fatalf("buffers exceeded bounds: events=%d logs=%d", len(events.Snapshot()), len(logs.Snapshot()))
	}
	if events.Dropped()+logs.Dropped() == 0 {
		t.Fatal("contention/eviction was not observable")
	}
	_ = events.Close()
	_ = logs.Close()
}

func mustJSON(t *testing.T, value interface{ JSON() ([]byte, error) }) []byte {
	t.Helper()
	body, err := value.JSON()
	if err != nil {
		t.Fatal(err)
	}
	return body
}
