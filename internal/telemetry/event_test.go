package telemetry

import (
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func TestEventExactJSONAndTypedFields(t *testing.T) {
	at := time.Date(2026, 8, 31, 1, 2, 3, 456000000, time.FixedZone("offset", 19800))
	nextRetry := at.Add(time.Minute)
	event, err := NewEvent(EventInput{At: at, Severity: SeverityWarn, Component: DimensionRoute, Name: "route_transition", Code: "route_stale", Outcome: OutcomeStateChange, Message: "Route assignment is stale.", CorrelationID: "corr_event_1", IDs: SafeIDs{AccountID: "account_01", TunnelID: "tunnel_01", RouteID: "route_02", ConnectorID: "connector_03"}, Generations: Generations{Config: 4, Route: 5, Assignment: 6}, Retry: RetryScheduled, NextRetryAt: nextRetry})
	if err != nil {
		t.Fatal(err)
	}
	body, err := event.JSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"paperboat.edge_event.v1","at":"2026-08-30T19:32:03.456Z","severity":"warn","component":"route","name":"route_transition","code":"route_stale","outcome":"state_change","message":"Route assignment is stale.","correlation_id":"corr_event_1","ids":{"account_id":"account_01","tunnel_id":"tunnel_01","route_id":"route_02","connector_id":"connector_03"},"generations":{"config":4,"route":5,"assignment":6},"retry":"scheduled","next_retry_at":"2026-08-30T19:33:03.456Z"}`
	if string(body) != want {
		t.Fatalf("JSON = %s\nwant = %s", body, want)
	}
}

func TestEventRedactsSecretsPersonalDataAndArbitraryIDs(t *testing.T) {
	secret := "Authorization: Bearer abcdef Cookie=session-secret token=xoxb-123456789012 customer.example.com https://alice:password@example.com/x alice@example.com /Users/alice/private route_customer123 -----BEGIN PRIVATE KEY----- key -----END PRIVATE KEY-----"
	event, err := NewEvent(EventInput{At: time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC), Severity: SeverityError, Component: DimensionAccess, Name: "access_decision", Code: "access_denied", Outcome: OutcomeRejected, Message: secret, CorrelationID: "corr_safe_1", IDs: SafeIDs{TunnelID: "tunnel_01", RequestID: "request_02"}, Retry: RetryNotRetryable})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := event.JSON()
	for _, unsafe := range []string{"abcdef", "session-secret", "xoxb-", "customer.example.com", "alice", "route_customer123", "PRIVATE KEY"} {
		if strings.Contains(string(body), unsafe) {
			t.Fatalf("unsafe value %q in %s", unsafe, body)
		}
	}
	if !strings.Contains(string(body), RedactedValue) || !strings.Contains(string(body), "tunnel_01") || !strings.Contains(string(body), "request_02") {
		t.Fatalf("safe identifiers/redaction missing: %s", body)
	}
}

func TestEventValidationBoundsAndLogIsolation(t *testing.T) {
	base := EventInput{At: time.Now(), Severity: SeverityInfo, Component: DimensionService, Name: "service_started", Code: "ready", Outcome: OutcomeSuccess, Message: strings.Repeat("界", 300), CorrelationID: "corr_event_1", Retry: RetryNone}
	event, err := NewEvent(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(event.Message) > maximumMessageBytes || !utf8.ValidString(event.Message) {
		t.Fatalf("message not safely bounded: %d", len(event.Message))
	}
	base.Message = string([]byte{0xff})
	if _, err := NewEvent(base); errorCode(err) != ErrorInvalidString {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
	base.Message = "ok"
	base.IDs.RouteID = "customer.example.com"
	if _, err := NewEvent(base); errorCode(err) != ErrorInvalidID {
		t.Fatalf("invalid id error = %v", err)
	}
	base.IDs = SafeIDs{}
	base.Retry = RetryScheduled
	if _, err := NewEvent(base); errorCode(err) != ErrorInvalidRetry {
		t.Fatalf("invalid retry error = %v", err)
	}

	log, err := NewEventLog(2)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	base.Retry = RetryNone
	base.NextRetryAt = time.Time{}
	first, _ := log.Record(base)
	base.Code = "degraded"
	_, _ = log.Record(base)
	base.Code = "down"
	last, _ := log.Record(base)
	got := log.Snapshot()
	if len(got) != 2 || got[0].Code != "degraded" || got[1].Code != last.Code || got[0].Code == first.Code {
		t.Fatalf("bounded log = %#v", got)
	}
	if log.DroppedEvents() != 1 {
		t.Fatalf("retention drops = %d, want 1", log.DroppedEvents())
	}
}

func TestEventLogIsNonblockingBoundedAndCountsDrops(t *testing.T) {
	log, err := NewEventLogWithQueue(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	input := EventInput{At: time.Now(), Severity: SeverityWarn, Component: DimensionService, Name: "service_event", Code: "busy", Outcome: OutcomeFailed, Message: "busy", CorrelationID: "corr_drop_1", Retry: RetryWaitForChange}
	if _, err := log.Record(input); err != nil {
		t.Fatal(err)
	}
	if log.DroppedEvents() != 1 {
		t.Fatalf("drops = %d", log.DroppedEvents())
	}
	for range 100 {
		_, _ = log.Record(input)
	}
	if log.DroppedEvents() != 101 {
		t.Fatalf("drops = %d", log.DroppedEvents())
	}
}

func TestEventLogConcurrentUse(t *testing.T) {
	log, err := NewEventLog(128)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	input := EventInput{At: time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC), Severity: SeverityInfo, Component: DimensionEdge, Name: "edge_request", Code: "ready", Outcome: OutcomeSuccess, Message: "Request completed.", CorrelationID: "corr_concurrent_1", Retry: RetryNone}
	var group sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for iteration := 0; iteration < 100; iteration++ {
				if _, err := log.Record(input); err != nil {
					t.Errorf("Record: %v", err)
					return
				}
				_ = log.Snapshot()
			}
		}()
	}
	group.Wait()
	if got := len(log.Snapshot()); got != 128 {
		t.Fatalf("event count = %d", got)
	}
}

func TestEventLogCloseDrainsEveryAcceptedEvent(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		log, err := NewEventLogWithQueue(64, 64)
		if err != nil {
			t.Fatal(err)
		}
		input := EventInput{At: time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC), Severity: SeverityInfo, Component: DimensionService, Name: "service_event", Code: "ready", Outcome: OutcomeSuccess, Message: "Ready.", CorrelationID: "corr_close_1", Retry: RetryNone}
		var group sync.WaitGroup
		for producer := 0; producer < 8; producer++ {
			group.Add(1)
			go func() {
				defer group.Done()
				for count := 0; count < 32; count++ {
					_, _ = log.Record(input)
				}
			}()
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		group.Wait()
		if queued := len(log.queue); queued != 0 {
			t.Fatalf("iteration %d left %d accepted events after close", iteration, queued)
		}
	}
}
