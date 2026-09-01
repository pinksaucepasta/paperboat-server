package connectorprotocol

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestTRK35ReconnectStormKeepsHighestSessionAndFencesLateDisconnects(t *testing.T) {
	registry := NewSessionRegistry()
	const stormSize = 128
	refs := make([]SessionRef, stormSize)
	for index := range refs {
		generation := uint64(index + 1)
		refs[index] = SessionRef{
			TunnelID:          "tunnel_trk35",
			ConnectorID:       "connector_trk35",
			SessionID:         fmt.Sprintf("session_trk35_%03d", generation),
			ProcessGeneration: generation,
		}
	}

	start := make(chan struct{})
	var workers sync.WaitGroup
	errorsByWorker := make(chan error, len(refs))
	for _, ref := range refs {
		ref := ref
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			if _, err := registry.Attach(ref); err != nil && !errors.Is(err, ErrSessionConflict) {
				errorsByWorker <- err
			}
		}()
	}
	close(start)
	workers.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		t.Fatalf("reconnect storm returned unexpected error: %v", err)
	}

	active, ok := registry.Active(refs[0].ConnectorID)
	if !ok || active != refs[len(refs)-1] {
		t.Fatalf("storm active session = %+v, want highest generation %+v", active, refs[len(refs)-1])
	}
	if got := registry.Count(); got != 1 {
		t.Fatalf("storm registry count = %d, want one live session", got)
	}

	// Every old process can close in any order after the replacement wins. A
	// stale close must report the typed fence and leave the replacement live.
	for index := len(refs) - 2; index >= 0; index-- {
		if err := registry.Disconnect(refs[index], ReasonSessionReplaced); !errors.Is(err, ErrStaleSession) {
			t.Fatalf("late disconnect generation %d = %v, want ErrStaleSession", refs[index].ProcessGeneration, err)
		}
		if current, ok := registry.Active(refs[0].ConnectorID); !ok || current != refs[len(refs)-1] {
			t.Fatalf("late disconnect removed replacement: current=%+v ok=%t", current, ok)
		}
	}
	if err := registry.Disconnect(refs[len(refs)-1], ReasonProtocolClosed); err != nil {
		t.Fatalf("replacement disconnect = %v", err)
	}
	if err := registry.Disconnect(refs[len(refs)-1], ReasonProtocolClosed); err != nil {
		t.Fatalf("duplicate replacement disconnect = %v", err)
	}
	if registry.Count() != 0 {
		t.Fatalf("registry count after terminal disconnect = %d, want zero", registry.Count())
	}
}

func TestTRK35NewerSnapshotAndDeltaFenceStaleAcknowledgements(t *testing.T) {
	serverSession, _, _, _, first := testSessionPair(t)
	ctx := context.Background()
	identity := func(snapshot Snapshot) Ack {
		return Ack{
			AccountID:         "acct_1",
			TunnelID:          "tunnel_1",
			ConnectorID:       "connector_1",
			SessionID:         "sess_1",
			ProcessGeneration: 1,
			Kind:              AckSnapshot,
			Status:            AckApplied,
			Generation:        snapshot.Generation,
			ContentHash:       snapshot.ContentHash,
		}
	}
	readiness := func(snapshot Snapshot) Readiness {
		return Readiness{
			AccountID:         "acct_1",
			TunnelID:          "tunnel_1",
			ConnectorID:       "connector_1",
			SessionID:         "sess_1",
			ProcessGeneration: 1,
			Generation:        snapshot.Generation,
			ContentHash:       snapshot.ContentHash,
			EdgeReady:         true,
			RouteReady:        true,
			OriginReady:       true,
		}
	}

	second, err := NewSnapshot("tunnel_1", 2, testConfigPayload(2, "second.preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	third, err := NewSnapshot("tunnel_1", 3, testConfigPayload(3, "third.preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []*Snapshot{&second, &third} {
		snapshot.AccountID = "acct_1"
		snapshot.ConnectorID = "connector_1"
		snapshot.SessionID = "sess_1"
		snapshot.ProcessGeneration = 1
	}
	if err := serverSession.OfferSnapshot(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := serverSession.HandleAck(ctx, identity(second)); err != nil {
		t.Fatal(err)
	}
	if err := serverSession.OfferSnapshot(ctx, third); err != nil {
		t.Fatal(err)
	}
	if err := serverSession.HandleAck(ctx, identity(third)); err != nil {
		t.Fatal(err)
	}

	staleAck := identity(second)
	staleAck.Status = AckDuplicate
	if err := serverSession.HandleAck(ctx, staleAck); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale snapshot ACK = %v, want ErrStaleGeneration", err)
	}
	if _, err := serverSession.HandleReadiness(ctx, readiness(second)); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale snapshot readiness = %v, want ErrStaleGeneration", err)
	}
	current, ready, generation := serverSession.Current()
	if !ready || generation != first.Generation || current.ContentHash != first.ContentHash {
		t.Fatalf("stale candidate changed LKG: current=%+v ready=%t generation=%d", current, ready, generation)
	}
	if _, err := serverSession.HandleReadiness(ctx, readiness(third)); err != nil {
		t.Fatal(err)
	}
	current, ready, generation = serverSession.Current()
	if !ready || generation != third.Generation || current.ContentHash != third.ContentHash {
		t.Fatalf("newer snapshot was not promoted: current=%+v ready=%t generation=%d", current, ready, generation)
	}
	if err := serverSession.HandleAck(ctx, func() Ack {
		ack := identity(third)
		ack.Status = AckDuplicate
		return ack
	}()); err != nil {
		t.Fatalf("duplicate current snapshot ACK = %v", err)
	}

	// A delta built from the previous generation is an out-of-order event after
	// generation three became active. The valid generation-four delta then wins,
	// while an ACK for generation three cannot consume its pending state.
	staleDelta, err := NewDelta("tunnel_1", second, 3, testConfigPayload(3, "stale-third.preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	staleDelta.AccountID, staleDelta.ConnectorID, staleDelta.SessionID, staleDelta.ProcessGeneration = "acct_1", "connector_1", "sess_1", 1
	if err := serverSession.OfferDelta(ctx, staleDelta); !errors.Is(err, ErrGenerationGap) {
		t.Fatalf("out-of-order delta = %v, want ErrGenerationGap", err)
	}
	fourth, err := NewDelta("tunnel_1", third, 4, testConfigPayload(4, "fourth.preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	fourth.AccountID, fourth.ConnectorID, fourth.SessionID, fourth.ProcessGeneration = "acct_1", "connector_1", "sess_1", 1
	if err := serverSession.OfferDelta(ctx, fourth); err != nil {
		t.Fatal(err)
	}
	staleDeltaAck := identity(third)
	staleDeltaAck.Kind = AckDelta
	staleDeltaAck.Status = AckDuplicate
	if err := serverSession.HandleAck(ctx, staleDeltaAck); !errors.Is(err, ErrDeltaRejected) {
		t.Fatalf("stale delta ACK = %v, want ErrDeltaRejected", err)
	}
	current, ready, generation = serverSession.Current()
	if !ready || generation != third.Generation || current.ContentHash != third.ContentHash {
		t.Fatalf("stale delta ACK changed active state: current=%+v ready=%t generation=%d", current, ready, generation)
	}
	fourthAck := identity(fourthToSnapshot(fourth))
	fourthAck.Kind = AckDelta
	if err := serverSession.HandleAck(ctx, fourthAck); err != nil {
		t.Fatal(err)
	}
	if _, err := serverSession.HandleReadiness(ctx, readiness(fourthToSnapshot(fourth))); err != nil {
		t.Fatal(err)
	}
	current, ready, generation = serverSession.Current()
	if !ready || generation != 4 || current.ContentHash != fourth.ContentHash {
		t.Fatalf("valid delta was not promoted: current=%+v ready=%t generation=%d", current, ready, generation)
	}
}

func fourthToSnapshot(delta Delta) Snapshot {
	return Snapshot{
		AccountID: delta.AccountID, TunnelID: delta.TunnelID, ConnectorID: delta.ConnectorID,
		SessionID: delta.SessionID, ProcessGeneration: delta.ProcessGeneration,
		Generation: delta.Generation, ContentHash: delta.ContentHash, Payload: append([]byte(nil), delta.Payload...),
	}
}
