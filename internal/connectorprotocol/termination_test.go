package connectorprotocol

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"
)

type terminationHarness struct {
	transport *ControlTransport
	auth      AuthRequest
	clock     *testClock
	snapshot  Snapshot
}

func newTerminationHarness(t *testing.T) terminationHarness {
	t.Helper()
	now := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	auth, private := testAuth(t, now, 1)
	snapshot, err := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "control.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	store := &persistenceStoreStub{authResult: AuthResult{
		AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID,
		HostID: auth.HostID, IdentityKeyID: auth.IdentityKeyID, IdentityKeyThumbprint: auth.IdentityKeyThumbprint,
		ProcessGeneration: 1, CredentialGeneration: auth.CredentialGeneration,
		CredentialExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Hour),
	}, snapshot: snapshot}
	server, err := NewPersistentServer(store, IdentityProofVerifierFuncs{
		AuthFunc: func(_ context.Context, _ AuthRequest, payload, signature []byte) error {
			if !ed25519.Verify(private.Public().(ed25519.PublicKey), payload, signature) {
				return ErrAuthenticationFailed
			}
			return nil
		},
		RenewalFunc: func(context.Context, RenewalRequest, []byte, []byte) error { return nil },
	}, ServerConfig{
		Capabilities: requiredCapabilityList(), Clock: clock,
		LeaseDuration: time.Minute, HeartbeatInterval: 10 * time.Second,
		SessionIDs: func() (string, error) { return "session_termination_01", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewControlTransport(server, nil)
	if err != nil {
		t.Fatal(err)
	}
	return terminationHarness{transport: transport, auth: auth, clock: clock, snapshot: snapshot}
}

func (h terminationHarness) hello() Frame {
	return mustTerminationFrame(Hello{
		Protocol: ProtocolName, MinVersion: ProtocolVersion, MaxVersion: ProtocolVersion,
		AccountID: h.auth.AccountID, TunnelID: h.auth.TunnelID, ConnectorID: h.auth.ConnectorID,
		HostID: h.auth.HostID, ProcessGeneration: 1, Capabilities: requiredCapabilityList(), Auth: h.auth,
	}, MessageHello, "hello_termination_01")
}

func mustTerminationFrame(value any, kind MessageType, requestID string) Frame {
	frame, err := NewFrame(kind, requestID, value)
	if err != nil {
		panic(err)
	}
	return frame
}

func readTerminationHandshake(t *testing.T, client net.Conn, auth AuthRequest) Welcome {
	t.Helper()
	frame, err := ReadFrame(client)
	if err != nil || frame.Type != MessageWelcome {
		t.Fatalf("welcome frame=%+v err=%v", frame, err)
	}
	var welcome Welcome
	if err := frame.DecodePayload(&welcome); err != nil {
		t.Fatal(err)
	}
	frame, err = ReadFrame(client)
	if err != nil || frame.Type != MessageSnapshot {
		t.Fatalf("snapshot frame=%+v err=%v", frame, err)
	}
	var snapshot Snapshot
	if err := frame.DecodePayload(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.TunnelID != auth.TunnelID || snapshot.ConnectorID != auth.ConnectorID || snapshot.SessionID != welcome.SessionID || snapshot.ProcessGeneration != 1 {
		t.Fatalf("bound snapshot=%+v welcome=%+v", snapshot, welcome)
	}
	return welcome
}

func waitTermination(t *testing.T, done <-chan error, events <-chan ControlTerminationEvent) (ControlTerminationEvent, error) {
	t.Helper()
	var event ControlTerminationEvent
	select {
	case err := <-done:
		select {
		case event = <-events:
		case <-time.After(time.Second):
			t.Fatal("termination observer did not run")
		}
		return event, err
	case <-time.After(time.Second):
		t.Fatal("control transport did not terminate")
		return event, nil
	}
}

func TestControlTransportReportsPeerEOF(t *testing.T) {
	harness := newTerminationHarness(t)
	events := make(chan ControlTerminationEvent, 1)
	harness.transport.SetTerminationObserver(func(event ControlTerminationEvent) { events <- event })
	serverSide, clientSide := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- harness.transport.Serve(context.Background(), serverSide, harness.auth.TunnelID, harness.auth.ConnectorID)
	}()
	if err := WriteFrame(clientSide, harness.hello()); err != nil {
		t.Fatal(err)
	}
	welcome := readTerminationHandshake(t, clientSide, harness.auth)
	if err := clientSide.Close(); err != nil {
		t.Fatal(err)
	}
	event, serveErr := waitTermination(t, done, events)
	if serveErr != nil {
		t.Fatalf("peer EOF serve error=%v", serveErr)
	}
	if event.Kind != ControlTerminationPeerEOF || event.SessionID != welcome.SessionID || event.ProcessGeneration != 1 || event.ProtocolReason != "" {
		t.Fatalf("peer EOF event=%+v", event)
	}
}

func TestControlTransportReportsExplicitDisconnect(t *testing.T) {
	harness := newTerminationHarness(t)
	events := make(chan ControlTerminationEvent, 1)
	harness.transport.SetTerminationObserver(func(event ControlTerminationEvent) { events <- event })
	serverSide, clientSide := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- harness.transport.Serve(context.Background(), serverSide, harness.auth.TunnelID, harness.auth.ConnectorID)
	}()
	if err := WriteFrame(clientSide, harness.hello()); err != nil {
		t.Fatal(err)
	}
	welcome := readTerminationHandshake(t, clientSide, harness.auth)
	disconnect := Disconnect{AccountID: harness.auth.AccountID, TunnelID: harness.auth.TunnelID, ConnectorID: harness.auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, Reason: ReasonProtocolClosed}
	if err := WriteFrame(clientSide, mustTerminationFrame(disconnect, MessageDisconnect, "disconnect_termination_01")); err != nil {
		t.Fatal(err)
	}
	if err := clientSide.Close(); err != nil {
		t.Fatal(err)
	}
	event, serveErr := waitTermination(t, done, events)
	if serveErr != nil {
		t.Fatalf("explicit disconnect serve error=%v", serveErr)
	}
	if event.Kind != ControlTerminationPeerDisconnect || event.SessionID != welcome.SessionID || event.ProtocolReason != ReasonProtocolClosed {
		t.Fatalf("explicit disconnect event=%+v", event)
	}
}

func TestControlTransportContextCancellationInterruptsBlockedRead(t *testing.T) {
	harness := newTerminationHarness(t)
	events := make(chan ControlTerminationEvent, 1)
	harness.transport.SetTerminationObserver(func(event ControlTerminationEvent) { events <- event })
	serverSide, clientSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- harness.transport.Serve(ctx, serverSide, harness.auth.TunnelID, harness.auth.ConnectorID)
	}()
	if err := WriteFrame(clientSide, harness.hello()); err != nil {
		t.Fatal(err)
	}
	readTerminationHandshake(t, clientSide, harness.auth)
	cancel()
	event, serveErr := waitTermination(t, done, events)
	if serveErr != nil {
		t.Fatalf("context cancellation serve error=%v", serveErr)
	}
	if event.Kind != ControlTerminationServerShutdown || event.ProtocolReason != "" {
		t.Fatalf("context cancellation event=%+v", event)
	}
	_ = clientSide.Close()
}

func TestControlTransportReportsProtocolError(t *testing.T) {
	harness := newTerminationHarness(t)
	events := make(chan ControlTerminationEvent, 1)
	harness.transport.SetTerminationObserver(func(event ControlTerminationEvent) { events <- event })
	serverSide, clientSide := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- harness.transport.Serve(context.Background(), serverSide, harness.auth.TunnelID, harness.auth.ConnectorID)
	}()
	if err := WriteFrame(clientSide, harness.hello()); err != nil {
		t.Fatal(err)
	}
	readTerminationHandshake(t, clientSide, harness.auth)
	if err := WriteFrame(clientSide, harness.hello()); err != nil {
		t.Fatal(err)
	}
	if frame, err := ReadFrame(clientSide); err != nil || frame.Type != MessageReject {
		t.Fatalf("reject frame=%+v err=%v", frame, err)
	}
	_ = clientSide.Close()
	event, serveErr := waitTermination(t, done, events)
	if serveErr == nil || CodeOf(serveErr) != CodeUnsupportedMessage {
		t.Fatalf("protocol serve error=%v", serveErr)
	}
	if event.Kind != ControlTerminationProtocolError || event.ProtocolReason != ReasonProtocolMismatch || event.Code != CodeUnsupportedMessage {
		t.Fatalf("protocol error event=%+v", event)
	}
}

func TestControlTransportReportsLeaseExpiry(t *testing.T) {
	harness := newTerminationHarness(t)
	events := make(chan ControlTerminationEvent, 1)
	harness.transport.SetTerminationObserver(func(event ControlTerminationEvent) { events <- event })
	serverSide, clientSide := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- harness.transport.Serve(context.Background(), serverSide, harness.auth.TunnelID, harness.auth.ConnectorID)
	}()
	if err := WriteFrame(clientSide, harness.hello()); err != nil {
		t.Fatal(err)
	}
	readTerminationHandshake(t, clientSide, harness.auth)
	harness.clock.Advance(2 * time.Minute)
	heartbeat := Heartbeat{
		AccountID: harness.auth.AccountID, TunnelID: harness.auth.TunnelID, ConnectorID: harness.auth.ConnectorID,
		SessionID: "session_termination_01", ProcessGeneration: 1,
		LastAppliedGeneration: harness.snapshot.Generation, LastAppliedHash: harness.snapshot.ContentHash,
		SentAt: harness.clock.Now(),
	}
	if err := WriteFrame(clientSide, mustTerminationFrame(heartbeat, MessageHeartbeat, "heartbeat_termination_01")); err != nil {
		t.Fatal(err)
	}
	if frame, err := ReadFrame(clientSide); err != nil || frame.Type != MessageReject {
		t.Fatalf("reject frame=%+v err=%v", frame, err)
	}
	_ = clientSide.Close()
	event, serveErr := waitTermination(t, done, events)
	if serveErr == nil || CodeOf(serveErr) != CodeLeaseExpired {
		t.Fatalf("lease serve error=%v", serveErr)
	}
	if event.Kind != ControlTerminationSessionExpired || event.ProtocolReason != ReasonLeaseExpired || event.Code != CodeLeaseExpired || !event.Retryable {
		t.Fatalf("lease expiry event=%+v", event)
	}
}
