package connectorprotocol

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type dispatcherPlanSource struct {
	plans []RotationPlan
	err   error
}

type dispatcherStore struct {
	*MemoryRotationPersistence
	dispatcherPlanSource
	resetCalls  int
	rebindCalls int
}

func (s *dispatcherStore) RecordDisconnected(context.Context, SessionRef, Disconnect) error {
	return nil
}

func (s *dispatcherStore) ResetCredentialRotationInstall(context.Context, RotationPlan, RotationTarget, SessionRef) error {
	s.resetCalls++
	return nil
}

func (s *dispatcherStore) RebindCredentialRotationRevoke(_ context.Context, plan RotationPlan, target RotationTarget, ref SessionRef, nonce string, issuedAt, deadline time.Time) (CredentialRotationRevoke, error) {
	s.rebindCalls++
	return CredentialRotationRevoke{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: target.ConnectorID, HostID: target.HostID, SessionID: ref.SessionID, ProcessGeneration: ref.ProcessGeneration, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: target.OldCredentialGeneration, NewCredentialGeneration: target.NewCredentialGeneration, RevokeNonce: nonce, IssuedAt: issuedAt, Deadline: deadline}, nil
}

func (s *dispatcherStore) FailCredentialRotationTarget(context.Context, RotationPlan, RotationTarget, Code) error {
	return nil
}

func (s dispatcherPlanSource) ListCredentialRotationPlans(context.Context, int) ([]RotationPlan, error) {
	return append([]RotationPlan(nil), s.plans...), s.err
}

func (s dispatcherPlanSource) LoadCredentialRotationPlan(_ context.Context, operationID string) (RotationPlan, error) {
	if s.err != nil {
		return RotationPlan{}, s.err
	}
	for _, plan := range s.plans {
		if plan.OperationID == operationID {
			return plan, nil
		}
	}
	return RotationPlan{}, ErrOperationNotFound
}

type dispatcherFrames struct {
	mu     sync.Mutex
	frames []Frame
}

func (s *dispatcherFrames) send(_ context.Context, frame Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frames = append(s.frames, frame)
	return nil
}

func (s *dispatcherFrames) snapshot() []Frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Frame(nil), s.frames...)
}

func newDispatcherForTest(t *testing.T, now time.Time, memory *MemoryRotationPersistence, plans []RotationPlan, keys map[string]ed25519.PrivateKey) (*RotationDispatcher, *dispatcherStore) {
	t.Helper()
	store := &dispatcherStore{MemoryRotationPersistence: memory, dispatcherPlanSource: dispatcherPlanSource{plans: plans}}
	dispatcher, err := NewRotationDispatcher(RotationDispatcherConfig{
		Store:          store,
		VerifyOldProof: rotationVerifier(keys), Clock: &testClock{now: now},
		ChallengeTTL: time.Minute, Overlap: 10 * time.Minute, CredentialLifetime: 24 * time.Hour,
		ReportError: func(error) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher, store
}

func registerDispatcherSession(t *testing.T, dispatcher *RotationDispatcher, frames *dispatcherFrames, accountID, tunnelID, connectorID, hostID, sessionID string, processGeneration, credentialGeneration uint64, keyID, thumbprint string) {
	t.Helper()
	if err := dispatcher.RegisterSession(context.Background(), RotationLiveSession{
		AccountID: accountID, HostID: hostID,
		Reference:            SessionRef{TunnelID: tunnelID, ConnectorID: connectorID, SessionID: sessionID, ProcessGeneration: processGeneration},
		CredentialGeneration: credentialGeneration, IdentityKeyID: keyID, IdentityKeyThumbprint: thumbprint,
		NegotiatedCapabilities: []string{CapabilityCredentialRotation}, Send: frames.send,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRotationDispatcherReconcilesPrivateImmutableTargets(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	oldOne, oldOneID, oldOneThumbprint := rotationKey(71)
	oldTwo, oldTwoID, oldTwoThumbprint := rotationKey(72)
	plan, err := NewRotationPlan("acct_dispatch", "tunnel_dispatch", "op_dispatch_two", []RotationTarget{
		{ConnectorID: "connector_one", HostID: "host_one", OldCredentialGeneration: 2, NewCredentialGeneration: 3},
		{ConnectorID: "connector_two", HostID: "host_two", OldCredentialGeneration: 5, NewCredentialGeneration: 6},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &MemoryRotationPersistence{}
	if err := store.BeginCredentialRotation(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	dispatcher, _ := newDispatcherForTest(t, now, store, []RotationPlan{plan}, map[string]ed25519.PrivateKey{oldOneID: oldOne, oldTwoID: oldTwo})
	oneFrames, twoFrames := &dispatcherFrames{}, &dispatcherFrames{}
	registerDispatcherSession(t, dispatcher, oneFrames, plan.AccountID, plan.TunnelID, "connector_one", "host_one", "session_one", 7, 2, oldOneID, oldOneThumbprint)
	registerDispatcherSession(t, dispatcher, twoFrames, plan.AccountID, plan.TunnelID, "connector_two", "host_two", "session_two", 9, 5, oldTwoID, oldTwoThumbprint)

	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for connectorID, frames := range map[string][]Frame{"connector_one": oneFrames.snapshot(), "connector_two": twoFrames.snapshot()} {
		if len(frames) != 1 || frames[0].Type != MessageCredentialRotationChallenge {
			t.Fatalf("%s frames=%+v", connectorID, frames)
		}
		var challenge CredentialRotationChallenge
		if err := frames[0].DecodePayload(&challenge); err != nil {
			t.Fatal(err)
		}
		if challenge.ConnectorID != connectorID || challenge.Target.ConnectorID != connectorID || challenge.TargetSetHash != plan.TargetSetHash {
			t.Fatalf("target privacy/binding failed: %+v", challenge)
		}
		encoded := string(frames[0].Payload)
		other := "connector_two"
		if connectorID == other {
			other = "connector_one"
		}
		if strings.Contains(encoded, other) {
			t.Fatalf("%s challenge disclosed %s: %s", connectorID, other, encoded)
		}
	}
	if len(store.Challenges) != 2 {
		t.Fatalf("durable challenges=%d", len(store.Challenges))
	}
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(oneFrames.snapshot()) != 1 || len(twoFrames.snapshot()) != 1 {
		t.Fatalf("unexpired challenges were retransmitted: one=%d two=%d", len(oneFrames.snapshot()), len(twoFrames.snapshot()))
	}
}

func TestRotationDispatcherRoutesProofReplacementReadinessAndRevoke(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)
	oldPrivate, oldID, oldThumbprint := rotationKey(73)
	newPrivate, newID, newThumbprint := rotationKey(74)
	plan, err := NewRotationPlan("acct_dispatch", "tunnel_dispatch", "op_dispatch_flow", []RotationTarget{{ConnectorID: "connector_one", HostID: "host_one", OldCredentialGeneration: 4, NewCredentialGeneration: 5}})
	if err != nil {
		t.Fatal(err)
	}
	store := &MemoryRotationPersistence{}
	if err := store.BeginCredentialRotation(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	dispatcher, _ := newDispatcherForTest(t, now, store, []RotationPlan{plan}, map[string]ed25519.PrivateKey{oldID: oldPrivate})
	oldFrames := &dispatcherFrames{}
	oldRef := SessionRef{TunnelID: plan.TunnelID, ConnectorID: "connector_one", SessionID: "session_old", ProcessGeneration: 11}
	registerDispatcherSession(t, dispatcher, oldFrames, plan.AccountID, plan.TunnelID, oldRef.ConnectorID, "host_one", oldRef.SessionID, oldRef.ProcessGeneration, 4, oldID, oldThumbprint)
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	var challenge CredentialRotationChallenge
	if err := oldFrames.snapshot()[0].DecodePayload(&challenge); err != nil {
		t.Fatal(err)
	}
	proof := rotationProofFor(t, challenge, oldPrivate, newPrivate, "keychain://paperboat/rotation/connector_one", now)
	_, wrongOldID, wrongOldThumbprint := rotationKey(80)
	wrongProof := proof
	wrongProof.OldIdentityKeyID = wrongOldID
	wrongProof.OldIdentityKeyThumbprint = wrongOldThumbprint
	wrongProofFrame, err := NewFrame(MessageCredentialRotationProof, "req_wrong_old_identity", wrongProof)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.HandleFrame(context.Background(), oldRef, wrongProofFrame); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("proof from mismatched authenticated credential error=%v", err)
	}
	proofFrame, err := NewFrame(MessageCredentialRotationProof, "req_proof_dispatch", proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.HandleFrame(context.Background(), oldRef, proofFrame); err != nil {
		t.Fatal(err)
	}
	frames := oldFrames.snapshot()
	if len(frames) != 2 || frames[1].Type != MessageCredentialRotationInstall {
		t.Fatalf("install frames=%+v", frames)
	}
	var install CredentialRotationInstall
	if err := frames[1].DecodePayload(&install); err != nil {
		t.Fatal(err)
	}

	newFrames := &dispatcherFrames{}
	newRef := SessionRef{TunnelID: plan.TunnelID, ConnectorID: "connector_one", SessionID: "session_new", ProcessGeneration: install.ReplacementProcessGeneration}
	registerDispatcherSession(t, dispatcher, newFrames, plan.AccountID, plan.TunnelID, newRef.ConnectorID, "host_one", newRef.SessionID, newRef.ProcessGeneration, 5, newID, newThumbprint)
	if err := dispatcher.UnregisterSession(context.Background(), oldRef, ReasonSessionReplaced); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("late old unregister error=%v", err)
	}
	ready := CredentialRotationReady{
		AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: "connector_one", HostID: "host_one",
		SessionID: newRef.SessionID, PreviousSessionID: oldRef.SessionID, ProcessGeneration: newRef.ProcessGeneration, TargetSetHash: plan.TargetSetHash,
		OldCredentialGeneration: 4, NewCredentialGeneration: 5, NewIdentityKeyID: install.NewIdentityKeyID, NewIdentityKeyThumbprint: install.NewIdentityKeyThumbprint,
		NewPublicKey: install.NewPublicKey, NewCredentialReference: install.NewCredentialReference, NewCredentialValidUntil: install.NewCredentialValidUntil,
		ConfigGeneration: 2, ConfigContentHash: "sha256:" + strings.Repeat("c", 64), EdgeReady: true, RouteReady: true, OriginReady: true, ReadyAt: now,
	}
	readyFrame, err := NewFrame(MessageCredentialRotationReady, "req_ready_dispatch", ready)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.HandleFrame(context.Background(), newRef, readyFrame); err != nil {
		t.Fatal(err)
	}
	newSent := newFrames.snapshot()
	if len(newSent) != 1 || newSent[0].Type != MessageCredentialRotationRevoke {
		t.Fatalf("revoke frames=%+v", newSent)
	}
	var revoke CredentialRotationRevoke
	if err := newSent[0].DecodePayload(&revoke); err != nil {
		t.Fatal(err)
	}
	revoked := CredentialRotationAck{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: "connector_one", HostID: "host_one", SessionID: newRef.SessionID, ProcessGeneration: newRef.ProcessGeneration, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: 4, NewCredentialGeneration: 5, Status: RotationAckRevoked}
	revokedFrame, err := NewFrame(MessageCredentialRotationAck, "req_revoked_dispatch", revoked)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.HandleFrame(context.Background(), newRef, revokedFrame); err != nil {
		t.Fatal(err)
	}
	if len(store.Results) != 1 || store.Results[0].Status != RotationAggregateSucceeded {
		t.Fatalf("results=%+v", store.Results)
	}
	if err := dispatcher.HandleFrame(context.Background(), oldRef, revokedFrame); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale carrier accepted: %v", err)
	}
}

func TestRotationDispatcherRestartResendsDurableChallenge(t *testing.T) {
	now := time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC)
	oldPrivate, oldID, oldThumbprint := rotationKey(75)
	plan, err := NewRotationPlan("acct_dispatch", "tunnel_dispatch", "op_dispatch_restart", []RotationTarget{{ConnectorID: "connector_one", HostID: "host_one", OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	store := &MemoryRotationPersistence{}
	if err := store.BeginCredentialRotation(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	first, _ := newDispatcherForTest(t, now, store, []RotationPlan{plan}, map[string]ed25519.PrivateKey{oldID: oldPrivate})
	firstFrames := &dispatcherFrames{}
	registerDispatcherSession(t, first, firstFrames, plan.AccountID, plan.TunnelID, "connector_one", "host_one", "session_old", 3, 1, oldID, oldThumbprint)
	if err := first.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	restarted, _ := newDispatcherForTest(t, now, store, []RotationPlan{plan}, map[string]ed25519.PrivateKey{oldID: oldPrivate})
	restartFrames := &dispatcherFrames{}
	registerDispatcherSession(t, restarted, restartFrames, plan.AccountID, plan.TunnelID, "connector_one", "host_one", "session_old", 3, 1, oldID, oldThumbprint)
	if err := restarted.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(restartFrames.snapshot()) != 1 || len(store.Challenges) != 1 {
		t.Fatalf("restart frames=%d durable challenges=%d", len(restartFrames.snapshot()), len(store.Challenges))
	}
}

func TestRotationDispatcherRejectsIncompleteOrStaleSessions(t *testing.T) {
	store := &MemoryRotationPersistence{}
	_, oldID, oldThumbprint := rotationKey(76)
	config := RotationDispatcherConfig{Store: &dispatcherStore{MemoryRotationPersistence: store}, VerifyOldProof: rotationVerifier(nil), ReportError: func(error) {}}
	dispatcher, err := NewRotationDispatcher(config)
	if err != nil {
		t.Fatal(err)
	}
	base := RotationLiveSession{AccountID: "acct_dispatch", HostID: "host_one", Reference: SessionRef{TunnelID: "tunnel_dispatch", ConnectorID: "connector_one", SessionID: "session_one", ProcessGeneration: 2}, CredentialGeneration: 1, IdentityKeyID: oldID, IdentityKeyThumbprint: oldThumbprint, Send: (&dispatcherFrames{}).send}
	if err := dispatcher.RegisterSession(context.Background(), base); !errors.Is(err, ErrCapabilityMissing) {
		t.Fatalf("missing capability error=%v", err)
	}
	base.NegotiatedCapabilities = []string{CapabilityCredentialRotation}
	if err := dispatcher.RegisterSession(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	stale := base
	stale.Reference.SessionID = "session_stale"
	if err := dispatcher.RegisterSession(context.Background(), stale); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("stale replacement error=%v", err)
	}
}

func TestRotationDispatcherInboundLookupIsNotLimitedByReconcilePage(t *testing.T) {
	now := time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)
	memory := &MemoryRotationPersistence{}
	plans := make([]RotationPlan, 0, 65)
	for index := 0; index < 65; index++ {
		plan, err := NewRotationPlan("acct_dispatch", "tunnel_dispatch", "op_dispatch_page_"+fmt.Sprint(index), []RotationTarget{{ConnectorID: "connector_page_" + fmt.Sprint(index), HostID: "host_page_" + fmt.Sprint(index), OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
		if err != nil {
			t.Fatal(err)
		}
		if err := memory.BeginCredentialRotation(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		plans = append(plans, plan)
	}
	dispatcher, _ := newDispatcherForTest(t, now, memory, plans, nil)
	coordinator, loaded, err := dispatcher.findCoordinator(context.Background(), plans[64].OperationID)
	if err != nil || coordinator == nil || loaded.OperationID != plans[64].OperationID {
		t.Fatalf("operation-specific lookup coordinator=%v plan=%+v err=%v", coordinator, loaded, err)
	}
}

func TestRotationDispatcherUsesPersistedCredentialPolicy(t *testing.T) {
	now := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	dispatcher, _ := newDispatcherForTest(t, now, &MemoryRotationPersistence{}, nil, nil)
	overlapUntil := now.Add(7 * time.Minute)
	validUntil := now.Add(90 * time.Minute)
	expiresAt, gotOverlap, gotValidUntil, err := dispatcher.rotationPolicy(now, RotationResumeTarget{
		OverlapUntil: overlapUntil, NewCredentialValidUntil: validUntil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !gotOverlap.Equal(overlapUntil) || !gotValidUntil.Equal(validUntil) {
		t.Fatalf("persisted policy changed: overlap=%s valid_until=%s", gotOverlap, gotValidUntil)
	}
	if want := now.Add(time.Minute); !expiresAt.Equal(want) {
		t.Fatalf("challenge expiry=%s want=%s", expiresAt, want)
	}
	if _, _, _, err := dispatcher.rotationPolicy(overlapUntil, RotationResumeTarget{
		OverlapUntil: overlapUntil, NewCredentialValidUntil: validUntil,
	}); !errors.Is(err, ErrCredentialExpired) {
		t.Fatalf("expired persisted overlap error=%v", err)
	}
}

func TestRotationDispatcherRunReportsAndRetriesTransientFailure(t *testing.T) {
	reports := make(chan error, 4)
	store := &dispatcherStore{
		MemoryRotationPersistence: &MemoryRotationPersistence{},
		dispatcherPlanSource:      dispatcherPlanSource{err: errors.New("temporary database failure")},
	}
	dispatcher, err := NewRotationDispatcher(RotationDispatcherConfig{
		Store: store, VerifyOldProof: rotationVerifier(nil), ReconcileInterval: time.Millisecond,
		ChallengeTTL: time.Minute, Overlap: 10 * time.Minute, CredentialLifetime: time.Hour,
		ReportError: func(err error) { reports <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dispatcher.Run(ctx) }()
	for index := 0; index < 2; index++ {
		select {
		case reported := <-reports:
			if reported == nil || !strings.Contains(reported.Error(), "temporary database failure") {
				t.Fatalf("reported error=%v", reported)
			}
		case <-time.After(time.Second):
			t.Fatal("dispatcher did not retry and report the transient failure")
		}
	}
	cancel()
	select {
	case runErr := <-done:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("run error=%v", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not stop after cancellation")
	}
}

func TestRotationDispatcherSendIsBoundedByTimeout(t *testing.T) {
	now := time.Date(2026, 8, 30, 17, 0, 0, 0, time.UTC)
	oldPrivate, oldID, oldThumbprint := rotationKey(77)
	plan, err := NewRotationPlan("acct_dispatch", "tunnel_dispatch", "op_dispatch_timeout", []RotationTarget{{ConnectorID: "connector_one", HostID: "host_one", OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	memory := &MemoryRotationPersistence{}
	if err := memory.BeginCredentialRotation(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	store := &dispatcherStore{MemoryRotationPersistence: memory, dispatcherPlanSource: dispatcherPlanSource{plans: []RotationPlan{plan}}}
	dispatcher, err := NewRotationDispatcher(RotationDispatcherConfig{
		Store: store, VerifyOldProof: rotationVerifier(map[string]ed25519.PrivateKey{oldID: oldPrivate}), Clock: &testClock{now: now},
		ChallengeTTL: time.Minute, Overlap: 10 * time.Minute, CredentialLifetime: time.Hour, SendTimeout: 10 * time.Millisecond,
		ReportError: func(error) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := SessionRef{TunnelID: plan.TunnelID, ConnectorID: "connector_one", SessionID: "session_blocked", ProcessGeneration: 1}
	if err := dispatcher.RegisterSession(context.Background(), RotationLiveSession{
		AccountID: plan.AccountID, HostID: "host_one", Reference: ref, CredentialGeneration: 1,
		IdentityKeyID: oldID, IdentityKeyThumbprint: oldThumbprint, NegotiatedCapabilities: []string{CapabilityCredentialRotation},
		Send: func(ctx context.Context, _ Frame) error { <-ctx.Done(); return ctx.Err() },
	}); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := dispatcher.ReconcileOnce(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded send error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded send took %s", elapsed)
	}
}

func TestRotationDispatcherRecoversInstalledAndRevokingSessions(t *testing.T) {
	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	oldPrivate, oldID, oldThumbprint := rotationKey(78)
	newPrivate, newID, newThumbprint := rotationKey(79)
	plan, err := NewRotationPlan("acct_dispatch", "tunnel_dispatch", "op_dispatch_recovery", []RotationTarget{{ConnectorID: "connector_one", HostID: "host_one", OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	memory := &MemoryRotationPersistence{}
	if err := memory.BeginCredentialRotation(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewRotationCoordinator(plan, RotationConfig{Store: memory, VerifyOldProof: rotationVerifier(map[string]ed25519.PrivateKey{oldID: oldPrivate}), Clock: &testClock{now: now}})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	challenge, err := coordinator.ChallengeWithCredentialExpiry(context.Background(), "connector_one", "session_old", 1, oldID, oldThumbprint, "rotation-recovery-nonce-value", now, now.Add(time.Minute), now.Add(10*time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	proof := rotationProofFor(t, challenge, oldPrivate, newPrivate, "keychain://paperboat/rotation/connector_one", now)
	install, _, err := coordinator.AcceptProof(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, tracked := newDispatcherForTest(t, now, memory, []RotationPlan{plan}, map[string]ed25519.PrivateKey{oldID: oldPrivate})
	oldRecoveryFrames := &dispatcherFrames{}
	registerDispatcherSession(t, dispatcher, oldRecoveryFrames, plan.AccountID, plan.TunnelID, "connector_one", "host_one", "session_old_reconnect", 3, 1, oldID, oldThumbprint)
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tracked.resetCalls != 1 {
		t.Fatalf("install reset calls=%d", tracked.resetCalls)
	}

	ready := CredentialRotationReady{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: "connector_one", HostID: "host_one", SessionID: "session_new", PreviousSessionID: install.SessionID, ProcessGeneration: install.ReplacementProcessGeneration, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: 1, NewCredentialGeneration: 2, NewIdentityKeyID: newID, NewIdentityKeyThumbprint: newThumbprint, NewPublicKey: install.NewPublicKey, NewCredentialReference: install.NewCredentialReference, NewCredentialValidUntil: install.NewCredentialValidUntil, ConfigGeneration: 1, ConfigContentHash: "sha256:" + strings.Repeat("a", 64), EdgeReady: true, RouteReady: true, OriginReady: true, ReadyAt: now}
	if _, err := coordinator.MarkReady(context.Background(), ready); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Revoke(context.Background(), "connector_one"); err != nil {
		t.Fatal(err)
	}
	newRecoveryFrames := &dispatcherFrames{}
	registerDispatcherSession(t, dispatcher, newRecoveryFrames, plan.AccountID, plan.TunnelID, "connector_one", "host_one", "session_new_reconnect", 4, 2, newID, newThumbprint)
	if err := dispatcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tracked.rebindCalls != 1 {
		t.Fatalf("revoke rebind calls=%d", tracked.rebindCalls)
	}
	frames := newRecoveryFrames.snapshot()
	if len(frames) != 1 || frames[0].Type != MessageCredentialRotationRevoke {
		t.Fatalf("rebound revoke frames=%+v", frames)
	}
}
