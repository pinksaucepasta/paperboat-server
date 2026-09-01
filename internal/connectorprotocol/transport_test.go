package connectorprotocol

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"
)

func TestControlTransportPersistsReadyHeartbeatAndGenerationSafeDisconnect(t *testing.T) {
	now := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
	auth, private := testAuth(t, now, 1)
	snapshot, err := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "app.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	store := &persistenceStoreStub{authResult: AuthResult{
		AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID,
		HostID: auth.HostID, IdentityKeyID: auth.IdentityKeyID, IdentityKeyThumbprint: auth.IdentityKeyThumbprint,
		ProcessGeneration: 1, CredentialGeneration: auth.CredentialGeneration, CredentialExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Hour),
	}, snapshot: snapshot}
	server, err := NewPersistentServer(store, IdentityProofVerifierFuncs{
		AuthFunc: func(_ context.Context, _ AuthRequest, payload, signature []byte) error {
			if !ed25519.Verify(private.Public().(ed25519.PublicKey), payload, signature) {
				return ErrAuthenticationFailed
			}
			return nil
		},
		RenewalFunc: func(context.Context, RenewalRequest, []byte, []byte) error { return nil },
	}, ServerConfig{Capabilities: ProductionCapabilities(), Clock: &testClock{now: now}, LeaseDuration: time.Minute, HeartbeatInterval: 10 * time.Second, SessionIDs: func() (string, error) { return "session_transport_01", nil }})
	if err != nil {
		t.Fatal(err)
	}
	sessions := NewActiveControlSessions()
	rotationStore := &dispatcherStore{MemoryRotationPersistence: &MemoryRotationPersistence{}}
	dispatcher, err := NewRotationDispatcher(RotationDispatcherConfig{Store: rotationStore, VerifyOldProof: rotationVerifier(nil), Clock: &testClock{now: now}, ReportError: func(error) {}})
	if err != nil {
		t.Fatal(err)
	}
	drainDispatcher, err := NewDrainDispatcher(DrainDispatcherConfig{Store: &drainOperationSourceStub{}, Clock: &testClock{now: now}, ReportError: func(error) {}})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewControlTransportWithDispatchers(server, sessions, dispatcher, drainDispatcher)
	if err != nil {
		t.Fatal(err)
	}
	serverSide, clientSide := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- transport.Serve(context.Background(), serverSide, auth.TunnelID, auth.ConnectorID) }()

	hello := Hello{Protocol: ProtocolName, MinVersion: ProtocolVersion, MaxVersion: ProtocolVersion, AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: 1, Capabilities: ProductionCapabilities(), Auth: auth}
	helloFrame, err := NewFrame(MessageHello, "hello_transport_01", hello)
	if err != nil || WriteFrame(clientSide, helloFrame) != nil {
		t.Fatalf("write hello: %v", err)
	}
	welcomeFrame, err := ReadFrame(clientSide)
	if err != nil || welcomeFrame.Type != MessageWelcome {
		select {
		case serveErr := <-done:
			t.Fatalf("welcome frame=%+v err=%v serve_err=%v", welcomeFrame, err, serveErr)
		default:
			t.Fatalf("welcome frame=%+v err=%v", welcomeFrame, err)
		}
	}
	var welcome Welcome
	if err = welcomeFrame.DecodePayload(&welcome); err != nil {
		t.Fatal(err)
	}
	snapshotFrame, err := ReadFrame(clientSide)
	if err != nil || snapshotFrame.Type != MessageSnapshot {
		t.Fatalf("snapshot frame=%+v err=%v", snapshotFrame, err)
	}
	var bound Snapshot
	if err = snapshotFrame.DecodePayload(&bound); err != nil {
		t.Fatal(err)
	}
	var live RotationLiveSession
	var registered bool
	registrationDeadline := time.Now().Add(time.Second)
	for !registered && time.Now().Before(registrationDeadline) {
		live, registered = dispatcher.session(auth.ConnectorID)
		if !registered {
			time.Sleep(time.Millisecond)
		}
	}
	if !registered || live.Reference.SessionID != welcome.SessionID || live.CredentialGeneration != auth.CredentialGeneration {
		t.Fatalf("rotation live session = %+v registered=%t", live, registered)
	}
	drainOperation := DrainOperation{
		OperationID: "operation_transport_drain_01", OperationType: "connector.drain",
		AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID,
		SessionID: welcome.SessionID, ProcessGeneration: 1, ConfigGeneration: bound.Generation, ConfigContentHash: bound.ContentHash,
	}
	drainLive, drainRegistered := drainDispatcher.session(drainOperation)
	if !drainRegistered || drainLive.Session.Reference() != live.Reference {
		t.Fatalf("drain live session = %+v registered=%t", drainLive.Projection, drainRegistered)
	}
	drain := Drain{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, DrainID: "drain_transport_01", Generation: bound.Generation, ContentHash: bound.ContentHash, Deadline: now.Add(20 * time.Second), StopNewStreams: true, ForceAfterDeadline: true}
	drainFrame, err := NewFrame(MessageDrain, "drain_transport_01", drain)
	if err != nil {
		t.Fatal(err)
	}
	sendDone := make(chan error, 1)
	go func() { sendDone <- live.Send(context.Background(), drainFrame) }()
	receivedDrain, err := ReadFrame(clientSide)
	if err != nil || receivedDrain.Type != MessageDrain {
		t.Fatalf("outbound drain=%+v err=%v", receivedDrain, err)
	}
	if err = <-sendDone; err != nil {
		t.Fatal(err)
	}
	active, ok := sessions.Lookup(auth.TunnelID, auth.ConnectorID, welcome.SessionID, 1)
	if !ok || active.HostID != auth.HostID || active.ConfigGeneration != 1 || active.ConfigContentHash != bound.ContentHash {
		t.Fatalf("active session = %+v ok=%t", active, ok)
	}
	ack := Ack{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, Kind: AckSnapshot, Status: AckApplied, Generation: bound.Generation, ContentHash: bound.ContentHash}
	frame, _ := NewFrame(MessageAck, snapshotFrame.RequestID, ack)
	if err = WriteFrame(clientSide, frame); err != nil {
		t.Fatal(err)
	}
	ready := Readiness{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, Generation: bound.Generation, ContentHash: bound.ContentHash, EdgeReady: true, RouteReady: true, OriginReady: true}
	frame, _ = NewFrame(MessageReady, "ready_transport_01", ready)
	if err = WriteFrame(clientSide, frame); err != nil {
		t.Fatal(err)
	}
	readyAck, err := ReadFrame(clientSide)
	if err != nil || readyAck.Type != MessageAck {
		t.Fatalf("ready ack=%+v err=%v", readyAck, err)
	}
	heartbeat := Heartbeat{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, LastAppliedGeneration: bound.Generation, LastAppliedHash: bound.ContentHash, SentAt: now}
	frame, _ = NewFrame(MessageHeartbeat, "heartbeat_transport_01", heartbeat)
	if err = WriteFrame(clientSide, frame); err != nil {
		t.Fatal(err)
	}
	heartbeatAck, err := ReadFrame(clientSide)
	if err != nil || heartbeatAck.Type != MessageHeartbeatAck {
		t.Fatalf("heartbeat ack=%+v err=%v", heartbeatAck, err)
	}
	disconnect := Disconnect{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, Reason: ReasonProtocolClosed}
	frame, _ = NewFrame(MessageDisconnect, "disconnect_transport_01", disconnect)
	if err = WriteFrame(clientSide, frame); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok = sessions.Lookup(auth.TunnelID, auth.ConnectorID, welcome.SessionID, 1); ok || len(store.applied) != 1 || len(store.ready) != 1 || len(store.heartbeats) != 1 || len(store.disconnect) != 1 {
		t.Fatalf("active=%t applied=%d ready=%d heartbeats=%d disconnects=%d", ok, len(store.applied), len(store.ready), len(store.heartbeats), len(store.disconnect))
	}
	if _, ok = dispatcher.session(auth.ConnectorID); ok {
		t.Fatal("rotation delivery route remained after control disconnect")
	}
	if _, ok = drainDispatcher.session(drainOperation); ok {
		t.Fatal("drain delivery route remained after control disconnect")
	}
}

func TestControlTransportRejectsPathIdentityBeforeSessionCreation(t *testing.T) {
	now := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
	auth, _ := testAuth(t, now, 1)
	snapshot, _ := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "app.example.test"))
	store := &persistenceStoreStub{snapshot: snapshot}
	server, err := NewPersistentServer(store, IdentityProofVerifierFuncs{
		AuthFunc: func(context.Context, AuthRequest, []byte, []byte) error { return nil }, RenewalFunc: func(context.Context, RenewalRequest, []byte, []byte) error { return nil },
	}, ServerConfig{Capabilities: requiredCapabilityList(), Clock: &testClock{now: now}})
	if err != nil {
		t.Fatal(err)
	}
	transport, _ := NewControlTransport(server, nil)
	serverSide, clientSide := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- transport.Serve(context.Background(), serverSide, "wrong_tunnel", auth.ConnectorID) }()
	hello := Hello{Protocol: ProtocolName, MinVersion: ProtocolVersion, MaxVersion: ProtocolVersion, AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: 1, Capabilities: requiredCapabilityList(), Auth: auth}
	frame, _ := NewFrame(MessageHello, "hello_wrong_path_01", hello)
	if err = WriteFrame(clientSide, frame); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, ErrIdentityMismatch) || len(store.created) != 0 {
		t.Fatalf("err=%v created=%d", err, len(store.created))
	}
}

func TestActiveControlSessionsOldDetachCannotRemoveReplacement(t *testing.T) {
	registry := NewActiveControlSessions()
	base := ActiveControlSession{AccountID: "account_01", TunnelID: "tunnel_01", ConnectorID: "connector_01", HostID: "host_01", SessionID: "session_old_01", IdentityKeyID: "ed25519:" + testThumbprint, IdentityKeyThumbprint: testThumbprint, ProcessGeneration: 1, CredentialGeneration: 1, ConfigGeneration: 1, ConfigContentHash: "sha256:" + string(make([]byte, 64))}
	// Use a syntactically valid hash; content is not interpreted by the registry.
	base.ConfigContentHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	oldSession := &PersistentSession{}
	if err := registry.attach(base, oldSession); err != nil {
		t.Fatal(err)
	}
	replacement := base
	replacement.SessionID, replacement.ProcessGeneration = "session_new_01", 2
	if err := registry.attach(replacement, &PersistentSession{}); err != nil {
		t.Fatal(err)
	}
	registry.detach(base)
	if got, ok := registry.Lookup(replacement.TunnelID, replacement.ConnectorID, replacement.SessionID, replacement.ProcessGeneration); !ok || got.SessionID != replacement.SessionID {
		t.Fatalf("replacement removed: %+v ok=%t", got, ok)
	}
}

const testThumbprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
