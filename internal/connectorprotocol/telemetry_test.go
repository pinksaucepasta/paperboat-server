package connectorprotocol

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	servertelemetry "github.com/pinksaucepasta/paperboat-server/internal/telemetry"
)

func newConnectorTelemetryProducer(t *testing.T, now time.Time) (*servertelemetry.Producer, *servertelemetry.EventLog) {
	t.Helper()
	events, err := servertelemetry.NewEventLog(64)
	if err != nil {
		t.Fatal(err)
	}
	health, err := servertelemetry.NewHealthTracker(func() time.Time { return now })
	if err != nil {
		events.Close()
		t.Fatal(err)
	}
	return &servertelemetry.Producer{Metrics: servertelemetry.NewMetrics(), Events: events, Health: health, Now: func() time.Time { return now }}, events
}

func TestBoundedTelemetryDurationClampsClockAnomaliesAndCapsLongHandshakes(t *testing.T) {
	if got := boundedTelemetryDuration(-time.Second); got != 0 {
		t.Fatalf("negative duration = %s, want 0", got)
	}
	if got := boundedTelemetryDuration(25 * time.Hour); got != 24*time.Hour {
		t.Fatalf("long duration = %s, want 24h", got)
	}
	if got := boundedTelemetryDuration(250 * time.Millisecond); got != 250*time.Millisecond {
		t.Fatalf("ordinary duration = %s, want 250ms", got)
	}
}

func TestConnectorTelemetryCarriesSafeIdentityAndGenerations(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	producer, events := newConnectorTelemetryProducer(t, now)
	defer events.Close()
	observer := NewConnectorTelemetry(producer)
	value := connectorTelemetryIdentity{
		AccountID:            "account_1",
		Reference:            SessionRef{TunnelID: "tunnel_1", ConnectorID: "connector_1", SessionID: "session_1", ProcessGeneration: 7},
		CredentialGeneration: 4,
		ConfigGeneration:     12,
	}
	observer.handshake(value, "host_1", servertelemetry.ConnectorHandshakeSucceeded, 20*time.Millisecond)
	observer.connection(value, "host_1", servertelemetry.ConnectorConnectionOpened)
	observer.reconnect(value, "host_1", servertelemetry.ConnectorReconnectSucceeded)
	observer.backoff(value, "host_1", servertelemetry.ConnectorBackoffScheduled, 3*time.Second)
	observer.session(value, "host_1", servertelemetry.ConnectorSessionActive, 12)
	observer.config(value, "host_1", servertelemetry.ConfigGenerationApplied, 12, servertelemetry.RetryNone, time.Time{})
	observer.disconnect(value, "host_1", ReasonSessionReplaced)
	if err := events.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	recorded := events.Snapshot()
	if len(recorded) != 7 {
		t.Fatalf("event count = %d, want 7: %+v", len(recorded), recorded)
	}
	for _, event := range recorded {
		if event.IDs.AccountID != "account_1" || event.IDs.TunnelID != "tunnel_1" || event.IDs.ConnectorID != "connector_1" || event.IDs.HostID != "host_1" || event.IDs.SessionID != "session_1" {
			t.Fatalf("unsafe or incomplete identity: %+v", event)
		}
		if event.Generations.Process != 7 || event.Generations.Credential != 4 {
			t.Fatalf("generation identity missing: %+v", event)
		}
		body, err := event.JSON()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "token") || strings.Contains(string(body), "public_key") {
			t.Fatalf("secret-like field leaked: %s", body)
		}
	}
	var configEvents int
	for _, event := range recorded {
		if event.Name == "config_apply" {
			configEvents++
			if event.Generations.Config != 12 {
				t.Fatalf("config generation = %d, want 12", event.Generations.Config)
			}
		}
	}
	if configEvents != 1 {
		t.Fatalf("config event count = %d, want 1", configEvents)
	}
}

func TestConnectorTelemetryDropsUnboundHandshakeIdentity(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC)
	producer, events := newConnectorTelemetryProducer(t, now)
	defer events.Close()
	observer := NewConnectorTelemetry(producer)
	observer.handshake(connectorTelemetryIdentity{Reference: SessionRef{TunnelID: "tunnel_1", ConnectorID: "connector_1"}}, "host_1", servertelemetry.ConnectorHandshakeFailed, time.Second)
	observer.connection(connectorTelemetryIdentity{Reference: SessionRef{TunnelID: "tunnel_1", ConnectorID: "connector_1"}}, "host_1", servertelemetry.ConnectorConnectionFailed)
	observer.disconnect(connectorTelemetryIdentity{Reference: SessionRef{TunnelID: "tunnel_1", ConnectorID: "connector_1"}}, "host_1", ReasonAuthentication)
	if err := events.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if recorded := events.Snapshot(); len(recorded) != 0 {
		t.Fatalf("unbound telemetry events = %+v, want none", recorded)
	}
}

func TestPersistentConnectorTelemetryTracksLifecycleAndIgnoresFailures(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	auth, private := testAuth(t, now, 1)
	snapshot, err := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	store := &persistenceStoreStub{
		authResult: AuthResult{
			AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID,
			IdentityKeyID: auth.IdentityKeyID, IdentityKeyThumbprint: auth.IdentityKeyThumbprint,
			ProcessGeneration: 1, CredentialGeneration: auth.CredentialGeneration,
			CredentialExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Hour),
		},
		snapshot: snapshot,
	}
	server, err := NewPersistentServer(store, IdentityProofVerifierFuncs{
		AuthFunc: func(_ context.Context, _ AuthRequest, payload, signature []byte) error {
			if !ed25519.Verify(private.Public().(ed25519.PublicKey), payload, signature) {
				return ErrAuthenticationFailed
			}
			return nil
		},
		RenewalFunc: func(context.Context, RenewalRequest, []byte, []byte) error { return nil },
	}, ServerConfig{
		Capabilities: requiredCapabilityList(), Clock: &testClock{now: now}, LeaseDuration: time.Minute,
		HeartbeatInterval: 10 * time.Second, SessionIDs: func() (string, error) { return "session_telemetry_1", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	producer, events := newConnectorTelemetryProducer(t, now)
	defer events.Close()
	server.SetTelemetryProducer(producer)
	hello := Hello{Protocol: ProtocolName, MinVersion: ProtocolVersion, MaxVersion: ProtocolVersion, AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: 1, Capabilities: requiredCapabilityList(), Auth: auth}
	session, welcome, first, err := server.Accept(context.Background(), hello)
	if err != nil {
		t.Fatal(err)
	}
	apply := Ack{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, Kind: AckSnapshot, Status: AckApplied, Generation: first.Generation, ContentHash: first.ContentHash}
	if err := session.HandleAck(context.Background(), apply); err != nil {
		t.Fatal(err)
	}
	readiness := Readiness{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, Generation: first.Generation, ContentHash: first.ContentHash, EdgeReady: true, RouteReady: true, OriginReady: true}
	if _, err := session.HandleReadiness(context.Background(), readiness); err != nil {
		t.Fatal(err)
	}
	if _, err := session.BeginDrain(context.Background(), "drain_telemetry_1", now.Add(20*time.Second), true); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(context.Background(), ReasonProtocolClosed); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(context.Background(), ReasonProtocolClosed); err != nil {
		t.Fatal(err)
	}
	if err := events.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	recorded := events.Snapshot()
	if countTelemetryEvents(recorded, "connector_handshake", "connector_ready") != 1 || countTelemetryEvents(recorded, "connector_connection", "") != 2 || countTelemetryEvents(recorded, "config_apply", "config_pending") != 1 || countTelemetryEvents(recorded, "config_apply", "config_applied") != 1 || countTelemetryEvents(recorded, "connector_session", "connector_ready") != 1 || countTelemetryEvents(recorded, "connector_session", "connector_draining") != 1 || countTelemetryEvents(recorded, "connector_session", "connector_closed") != 1 || countTelemetryEvents(recorded, "connector_disconnect", "") != 1 {
		t.Fatalf("lifecycle events = %+v", recorded)
	}
	for _, event := range recorded {
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), auth.IdentityKeyID) || strings.Contains(string(body), auth.IdentityKeyThumbprint) {
			t.Fatalf("credential identity leaked into event: %s", body)
		}
	}
}

func TestPersistentConnectorTelemetryFencesReplacementStaleAndReadiness(t *testing.T) {
	now := time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)
	auth, private := testAuth(t, now, 1)
	snapshot, err := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	store := &persistenceStoreStub{
		authResult: AuthResult{
			AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID,
			IdentityKeyID: auth.IdentityKeyID, IdentityKeyThumbprint: auth.IdentityKeyThumbprint,
			ProcessGeneration: 1, CredentialGeneration: auth.CredentialGeneration,
			CredentialExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Hour),
		},
		snapshot: snapshot,
	}
	sessionIDs := []string{"session_replacement_1", "session_replacement_2", "session_stale_3"}
	nextSessionID := 0
	server, err := NewPersistentServer(store, IdentityProofVerifierFuncs{
		AuthFunc: func(_ context.Context, _ AuthRequest, payload, signature []byte) error {
			if !ed25519.Verify(private.Public().(ed25519.PublicKey), payload, signature) {
				return ErrAuthenticationFailed
			}
			return nil
		},
		RenewalFunc: func(context.Context, RenewalRequest, []byte, []byte) error { return nil },
	}, ServerConfig{
		Capabilities: requiredCapabilityList(), Clock: &testClock{now: now}, LeaseDuration: time.Minute,
		HeartbeatInterval: 10 * time.Second,
		SessionIDs: func() (string, error) {
			id := sessionIDs[nextSessionID]
			nextSessionID++
			return id, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	producer, events := newConnectorTelemetryProducer(t, now)
	defer events.Close()
	server.SetTelemetryProducer(producer)
	hello := func(request AuthRequest) Hello {
		return Hello{
			Protocol: ProtocolName, MinVersion: ProtocolVersion, MaxVersion: ProtocolVersion,
			AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID,
			HostID: request.HostID, ProcessGeneration: request.ProcessGeneration,
			Capabilities: requiredCapabilityList(), Auth: request,
		}
	}
	firstSession, firstWelcome, firstSnapshot, err := server.Accept(context.Background(), hello(auth))
	if err != nil {
		t.Fatal(err)
	}
	staleReadiness := Readiness{
		AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: firstWelcome.SessionID,
		ProcessGeneration: 1, Generation: firstSnapshot.Generation + 1, ContentHash: firstSnapshot.ContentHash,
		EdgeReady: true, RouteReady: true, OriginReady: true,
	}
	if _, err := firstSession.HandleReadiness(context.Background(), staleReadiness); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale readiness error=%v", err)
	}
	firstAck := Ack{
		AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: firstWelcome.SessionID,
		ProcessGeneration: 1, Kind: AckSnapshot, Status: AckApplied, Generation: firstSnapshot.Generation, ContentHash: firstSnapshot.ContentHash,
	}
	if err := firstSession.HandleAck(context.Background(), firstAck); err != nil {
		t.Fatal(err)
	}
	firstReady := staleReadiness
	firstReady.Generation = firstSnapshot.Generation
	if _, err := firstSession.HandleReadiness(context.Background(), firstReady); err != nil {
		t.Fatal(err)
	}

	secondAuth := auth
	secondAuth.ProcessGeneration = 2
	secondAuth.Nonce = "nonce-replacement-0002"
	secondAuth.SignedProof = ""
	secondAuth, err = SignAuthProof(secondAuth, func(payload []byte) []byte { return ed25519.Sign(private, payload) })
	if err != nil {
		t.Fatal(err)
	}
	store.authResult.ProcessGeneration = 2
	secondSession, secondWelcome, secondSnapshot, err := server.Accept(context.Background(), hello(secondAuth))
	if err != nil {
		t.Fatal(err)
	}

	staleAuth := auth
	staleAuth.Nonce = "nonce-stale-replacement-0003"
	staleAuth.SignedProof = ""
	staleAuth, err = SignAuthProof(staleAuth, func(payload []byte) []byte { return ed25519.Sign(private, payload) })
	if err != nil {
		t.Fatal(err)
	}
	store.authResult.ProcessGeneration = 1
	if _, _, _, err := server.Accept(context.Background(), hello(staleAuth)); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("stale replacement accept error=%v", err)
	}
	if err := firstSession.HandleAck(context.Background(), firstAck); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale old-session ack error=%v", err)
	}
	if err := firstSession.Close(context.Background(), ReasonSessionReplaced); err != nil {
		t.Fatal(err)
	}

	secondAck := firstAck
	secondAck.SessionID = secondWelcome.SessionID
	secondAck.ProcessGeneration = 2
	secondAck.Generation = secondSnapshot.Generation
	secondAck.ContentHash = secondSnapshot.ContentHash
	if err := secondSession.HandleAck(context.Background(), secondAck); err != nil {
		t.Fatal(err)
	}
	secondReady := firstReady
	secondReady.SessionID = secondWelcome.SessionID
	secondReady.ProcessGeneration = 2
	secondReady.Generation = secondSnapshot.Generation
	secondReady.ContentHash = secondSnapshot.ContentHash
	if _, err := secondSession.HandleReadiness(context.Background(), secondReady); err != nil {
		t.Fatal(err)
	}
	if err := secondSession.Close(context.Background(), ReasonProtocolClosed); err != nil {
		t.Fatal(err)
	}
	if err := secondSession.Close(context.Background(), ReasonProtocolClosed); err != nil {
		t.Fatal(err)
	}
	if err := events.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	recorded := events.Snapshot()
	checks := []struct {
		name string
		want int
		got  int
	}{
		{"handshake success", 2, countTelemetryEvents(recorded, "connector_handshake", "connector_ready")},
		{"handshake failure", 1, countTelemetryEvents(recorded, "connector_handshake", "connector_connection_failed")},
		{"connection opened", 2, countTelemetryEvents(recorded, "connector_connection", "connector_ready")},
		{"connection failure", 1, countTelemetryEventsWithOutcome(recorded, "connector_connection", servertelemetry.OutcomeFailed)},
		{"connection closed", 2, countTelemetryEventsWithOutcome(recorded, "connector_connection", servertelemetry.OutcomeStateChange)},
		{"reconnect success", 1, countTelemetryEvents(recorded, "connector_reconnect", "connector_ready")},
		{"reconnect failure", 1, countTelemetryEventsWithOutcome(recorded, "connector_reconnect", servertelemetry.OutcomeFailed)},
		{"session active", 2, countTelemetryEvents(recorded, "connector_session", "connector_ready")},
		{"session closed", 2, countTelemetryEvents(recorded, "connector_session", "connector_closed")},
		{"disconnect", 2, countTelemetryEvents(recorded, "connector_disconnect", "")},
		{"desired config", 2, countTelemetryEvents(recorded, "config_apply", "config_pending")},
		{"applied config", 2, countTelemetryEvents(recorded, "config_apply", "config_applied")},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %d, want %d; events=%+v", check.name, check.got, check.want, recorded)
		}
	}
}

func countTelemetryEvents(events []servertelemetry.Event, name, code string) int {
	count := 0
	for _, event := range events {
		if event.Name == name && (code == "" || event.Code == code) {
			count++
		}
	}
	return count
}

func countTelemetryEventsWithOutcome(events []servertelemetry.Event, name string, outcome servertelemetry.EventOutcome) int {
	count := 0
	for _, event := range events {
		if event.Name == name && event.Outcome == outcome {
			count++
		}
	}
	return count
}
