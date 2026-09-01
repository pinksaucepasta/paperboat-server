package connectorprotocol

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type drainOperationSourceStub struct {
	mu         sync.Mutex
	operations []DrainOperation
	err        error
	limits     []int
	started    chan struct{}
	startOnce  sync.Once
}

func (s *drainOperationSourceStub) ListConnectorDrainOperations(_ context.Context, limit int) ([]DrainOperation, error) {
	if s.started != nil {
		s.startOnce.Do(func() { close(s.started) })
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limits = append(s.limits, limit)
	return append([]DrainOperation(nil), s.operations...), s.err
}

type drainFrameSender struct {
	mu       sync.Mutex
	frames   []Frame
	failures int
	err      error
}

func (s *drainFrameSender) send(_ context.Context, frame Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures > 0 {
		s.failures--
		return s.err
	}
	s.frames = append(s.frames, frame)
	return nil
}

func (s *drainFrameSender) snapshot() []Frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Frame(nil), s.frames...)
}

func newDrainDispatcherTestSession(t *testing.T, now time.Time, processGeneration uint64, sessionID string, capabilities []string) DrainLiveSession {
	t.Helper()
	auth, _ := testAuth(t, now, processGeneration)
	snapshot, err := NewSnapshot(auth.TunnelID, 7, testConfigPayload(7, "app.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	store := &persistenceStoreStub{authResult: AuthResult{
		AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID,
		HostID: auth.HostID, IdentityKeyID: auth.IdentityKeyID, IdentityKeyThumbprint: auth.IdentityKeyThumbprint,
		ProcessGeneration: processGeneration, CredentialGeneration: auth.CredentialGeneration,
		CredentialExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Hour),
	}, snapshot: snapshot}
	server, err := NewPersistentServer(store, IdentityProofVerifierFuncs{
		AuthFunc:    func(context.Context, AuthRequest, []byte, []byte) error { return nil },
		RenewalFunc: func(context.Context, RenewalRequest, []byte, []byte) error { return nil },
	}, ServerConfig{
		Capabilities: capabilities, Clock: &testClock{now: now}, LeaseDuration: time.Minute,
		HeartbeatInterval: 10 * time.Second, SessionIDs: func() (string, error) { return sessionID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	hello := Hello{Protocol: ProtocolName, MinVersion: ProtocolVersion, MaxVersion: ProtocolVersion, AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: processGeneration, Capabilities: capabilities, Auth: auth}
	session, welcome, candidate, err := server.Accept(context.Background(), hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.HandleAck(context.Background(), Ack{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: processGeneration, Kind: AckSnapshot, Status: AckApplied, Generation: candidate.Generation, ContentHash: candidate.ContentHash}); err != nil {
		t.Fatal(err)
	}
	if _, err := session.HandleReadiness(context.Background(), Readiness{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: processGeneration, Generation: candidate.Generation, ContentHash: candidate.ContentHash, EdgeReady: true, RouteReady: true, OriginReady: true}); err != nil {
		t.Fatal(err)
	}
	return DrainLiveSession{
		Projection: ActiveControlSession{
			AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID,
			HostID: auth.HostID, SessionID: welcome.SessionID, IdentityKeyID: auth.IdentityKeyID,
			IdentityKeyThumbprint: auth.IdentityKeyThumbprint, ProcessGeneration: processGeneration,
			CredentialGeneration: auth.CredentialGeneration, ConfigGeneration: candidate.Generation,
			ConfigContentHash: candidate.ContentHash,
		},
		Session: session, NegotiatedCapabilities: append([]string(nil), capabilities...),
	}
}

func operationForDrainSession(session DrainLiveSession, operationID, operationType string) DrainOperation {
	projection := session.Projection
	return DrainOperation{
		OperationID: operationID, OperationType: operationType, AccountID: projection.AccountID,
		TunnelID: projection.TunnelID, ConnectorID: projection.ConnectorID, HostID: projection.HostID,
		SessionID: projection.SessionID, ProcessGeneration: projection.ProcessGeneration,
		ConfigGeneration: projection.ConfigGeneration, ConfigContentHash: projection.ConfigContentHash,
	}
}

func newDrainDispatcherForTest(t *testing.T, now time.Time, source *drainOperationSourceStub) *DrainDispatcher {
	t.Helper()
	dispatcher, err := NewDrainDispatcher(DrainDispatcherConfig{
		Store: source, Clock: &testClock{now: now}, ReconcileInterval: time.Millisecond,
		DrainDeadline: 40 * time.Second, RevokeDeadline: 12 * time.Second,
		SendTimeout: time.Second, OperationLimit: 8, ReportError: func(error) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}

func TestDrainDispatcherDeliversExactDrainAndReplaysSameOperation(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	live := newDrainDispatcherTestSession(t, now, 1, "session_drain_01", ProductionCapabilities())
	operation := operationForDrainSession(live, "operation_drain_01", "connector.drain")
	source := &drainOperationSourceStub{operations: []DrainOperation{operation}}
	dispatcher := newDrainDispatcherForTest(t, now, source)
	frames := &drainFrameSender{}
	live.Send = frames.send
	if err := dispatcher.RegisterSession(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	delivered := frames.snapshot()
	if len(delivered) != 2 {
		t.Fatalf("delivered frames = %d, want 2", len(delivered))
	}
	var first, replay Drain
	if delivered[0].Type != MessageDrain || delivered[0].RequestID != operation.OperationID || delivered[0].DecodePayload(&first) != nil || delivered[1].DecodePayload(&replay) != nil {
		t.Fatalf("frames = %+v", delivered)
	}
	if first != replay || first.DrainID != operation.OperationID || first.AccountID != operation.AccountID || first.TunnelID != operation.TunnelID || first.ConnectorID != operation.ConnectorID || first.SessionID != operation.SessionID || first.ProcessGeneration != operation.ProcessGeneration || first.Generation != operation.ConfigGeneration || first.ContentHash != operation.ConfigContentHash || first.ForceAfterDeadline || !first.Deadline.Equal(now.Add(40*time.Second)) {
		t.Fatalf("first=%+v replay=%+v operation=%+v", first, replay, operation)
	}
}

func TestDrainDispatcherRevokeForcesAtBoundedDeadline(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 10, 0, 0, time.UTC)
	live := newDrainDispatcherTestSession(t, now, 1, "session_revoke_01", ProductionCapabilities())
	operation := operationForDrainSession(live, "operation_revoke_01", "connector.revoke")
	dispatcher := newDrainDispatcherForTest(t, now, &drainOperationSourceStub{operations: []DrainOperation{operation}})
	frames := &drainFrameSender{}
	live.Send = frames.send
	if err := dispatcher.RegisterSession(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	var drain Drain
	if delivered := frames.snapshot(); len(delivered) != 1 || delivered[0].DecodePayload(&drain) != nil {
		t.Fatalf("frames=%+v", delivered)
	}
	if !drain.ForceAfterDeadline || !drain.Deadline.Equal(now.Add(12*time.Second)) || drain.DrainID != operation.OperationID {
		t.Fatalf("revoke drain = %+v", drain)
	}
}

func TestDrainDispatcherReplacementAndDetachAreGenerationSafe(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 20, 0, 0, time.UTC)
	old := newDrainDispatcherTestSession(t, now, 1, "session_old_drain_01", ProductionCapabilities())
	replacement := newDrainDispatcherTestSession(t, now, 2, "session_new_drain_01", ProductionCapabilities())
	operation := operationForDrainSession(replacement, "operation_replacement_01", "connector.drain")
	dispatcher := newDrainDispatcherForTest(t, now, &drainOperationSourceStub{operations: []DrainOperation{operation}})
	oldFrames, newFrames := &drainFrameSender{}, &drainFrameSender{}
	old.Send, replacement.Send = oldFrames.send, newFrames.send
	if err := dispatcher.RegisterSession(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.RegisterSession(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	dispatcher.DetachSession(old.Session.Reference())
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(oldFrames.snapshot()) != 0 || len(newFrames.snapshot()) != 1 {
		t.Fatalf("old=%d replacement=%d", len(oldFrames.snapshot()), len(newFrames.snapshot()))
	}
	dispatcher.DetachSession(replacement.Session.Reference())
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(newFrames.snapshot()) != 1 {
		t.Fatal("detached replacement received another drain")
	}
}

func TestDrainDispatcherNoSessionOrCapabilityPreservesReadySession(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 30, 0, 0, time.UTC)
	withoutDrain := []string{CapabilitySnapshot, CapabilityDelta, CapabilityAck, CapabilityHeartbeat, CapabilityRenewal}
	live := newDrainDispatcherTestSession(t, now, 1, "session_no_capability_01", withoutDrain)
	operation := operationForDrainSession(live, "operation_no_capability_01", "connector.drain")
	dispatcher := newDrainDispatcherForTest(t, now, &drainOperationSourceStub{operations: []DrainOperation{operation}})
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	frames := &drainFrameSender{}
	live.Send = frames.send
	if err := dispatcher.RegisterSession(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(frames.snapshot()) != 0 {
		t.Fatal("drain was delivered without negotiated capability")
	}
	if _, ready, generation := live.Session.Current(); !ready || generation != operation.ConfigGeneration {
		t.Fatalf("session readiness changed ready=%t generation=%d", ready, generation)
	}
}

func TestDrainDispatcherSendFailureRetriesSameDrain(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 40, 0, 0, time.UTC)
	live := newDrainDispatcherTestSession(t, now, 1, "session_send_retry_01", ProductionCapabilities())
	operation := operationForDrainSession(live, "operation_send_retry_01", "connector.drain")
	dispatcher := newDrainDispatcherForTest(t, now, &drainOperationSourceStub{operations: []DrainOperation{operation}})
	frames := &drainFrameSender{failures: 1, err: errors.New("bounded send failed")}
	live.Send = frames.send
	if err := dispatcher.RegisterSession(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.ReconcileOnce(context.Background()); !errors.Is(err, frames.err) {
		t.Fatalf("first reconcile err = %v", err)
	}
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	delivered := frames.snapshot()
	if len(delivered) != 1 {
		t.Fatalf("frames = %d, want 1", len(delivered))
	}
	var drain Drain
	if err := delivered[0].DecodePayload(&drain); err != nil || drain.DrainID != operation.OperationID || !drain.Deadline.Equal(now.Add(40*time.Second)) {
		t.Fatalf("retried drain=%+v err=%v", drain, err)
	}
}

func TestDrainDispatcherRejectsStaleRegistrationAndBoundsRun(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 50, 0, 0, time.UTC)
	current := newDrainDispatcherTestSession(t, now, 2, "session_current_run_01", ProductionCapabilities())
	stale := newDrainDispatcherTestSession(t, now, 1, "session_stale_run_01", ProductionCapabilities())
	source := &drainOperationSourceStub{started: make(chan struct{})}
	dispatcher := newDrainDispatcherForTest(t, now, source)
	current.Send, stale.Send = (&drainFrameSender{}).send, (&drainFrameSender{}).send
	if err := dispatcher.RegisterSession(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.RegisterSession(context.Background(), stale); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("stale registration err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dispatcher.Run(ctx) }()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("drain dispatcher did not begin reconciliation")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run err = %v", err)
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if len(source.limits) == 0 || source.limits[0] != 8 {
		t.Fatalf("source limits = %+v", source.limits)
	}
}
