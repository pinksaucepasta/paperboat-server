package previewattachment

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServiceEdgeProcessReplacementKeepsConfigGenerationAndFencesOldBinding(t *testing.T) {
	now := testNow()
	authority := &testAuthority{resolution: testResolution(now)}
	repository := &serviceRepositoryFake{}
	service, err := NewService(repository, authority, &testPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetClock(func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	proof, req := testProof(), testRequest()
	allocated, err := service.Allocate(ctx, proof, req)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := service.Admit(ctx, proof, req, allocated.Binding, allocated.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	edgeReady, err := service.ObserveEdge(ctx, req, admitted.Binding, admitted.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := service.ObserveOrigin(ctx, proof, req, edgeReady.Binding, edgeReady.AttachmentGeneration, true)
	if err != nil {
		t.Fatal(err)
	}

	authority.setResolution(func(resolution *Resolution) {
		resolution.Carrier.EdgeProcessEpoch = "edge-process-2"
	})
	rebound, err := service.Renew(ctx, proof, req, ready.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if rebound.EdgeProcessEpoch != "edge-process-2" {
		t.Fatalf("edge process epoch = %q, want replacement epoch", rebound.EdgeProcessEpoch)
	}
	if rebound.ConfigGeneration != ready.ConfigGeneration || rebound.ConfigContentHash != ready.ConfigContentHash {
		t.Fatalf("epoch-only replacement changed config identity: before=(%d,%q) after=(%d,%q)", ready.ConfigGeneration, ready.ConfigContentHash, rebound.ConfigGeneration, rebound.ConfigContentHash)
	}
	if rebound.State != StatePending || rebound.EdgeReady || rebound.OriginReady || rebound.ReadyAt != nil {
		t.Fatalf("replacement attachment = %#v, want pending with readiness reset", rebound)
	}
	if rebound.AttachmentGeneration != ready.AttachmentGeneration+1 {
		t.Fatalf("attachment generation = %d, want %d", rebound.AttachmentGeneration, ready.AttachmentGeneration+1)
	}

	if _, err := service.ObserveEdge(ctx, req, ready.Binding, ready.AttachmentGeneration); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("old edge binding error = %v, want ErrStaleBinding", err)
	}
	if _, err := service.ObserveOrigin(ctx, proof, req, ready.Binding, ready.AttachmentGeneration, true); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("old origin binding error = %v, want ErrStaleBinding", err)
	}
}
