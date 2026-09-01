package previewattachment

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestTRK35PreviewReconnectStormRejectsLateEdgeAndOriginCallbacks(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	authority := &testAuthority{resolution: testResolution(now)}
	manager := testManager(t, authority, now)
	ctx := context.Background()
	proof, req := testProof(), testRequest()

	attachment, err := manager.Allocate(ctx, proof, req)
	if err != nil {
		t.Fatal(err)
	}
	attachment, err = manager.Admit(ctx, proof, req, attachment.Binding, attachment.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	attachment, err = manager.ObserveEdge(ctx, req, attachment.Binding, attachment.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	attachment, err = manager.ObserveOrigin(ctx, proof, req, attachment.Binding, attachment.AttachmentGeneration, true)
	if err != nil {
		t.Fatal(err)
	}

	type callback struct {
		binding    Binding
		generation uint64
	}
	late := make([]callback, 0, 32)
	for processGeneration := uint64(2); processGeneration <= 32; processGeneration++ {
		late = append(late, callback{binding: attachment.Binding, generation: attachment.AttachmentGeneration})
		processID := fmt.Sprintf("connector-session-trk35-%03d", processGeneration)
		epoch := fmt.Sprintf("edge-process-trk35-%03d", processGeneration)
		authority.setResolution(func(resolution *Resolution) {
			resolution.Carrier.SessionID = processID
			resolution.Carrier.ProcessGeneration = processGeneration
			resolution.Carrier.EdgeProcessEpoch = epoch
		})
		attachment, err = manager.Renew(ctx, proof, req, attachment.AttachmentGeneration)
		if err != nil {
			t.Fatalf("reconnect %d: %v", processGeneration, err)
		}
		if attachment.State != StatePending || attachment.EdgeReady || attachment.OriginReady {
			t.Fatalf("reconnect %d state = %#v, want pending with readiness reset", processGeneration, attachment)
		}
	}

	// Callbacks from every previous carrier arrive after the storm. The live
	// authority binding is the newest process, so neither edge nor origin
	// observations may advance or roll back its attachment generation.
	for index := len(late) - 1; index >= 0; index-- {
		old := late[index]
		if _, err := manager.ObserveEdge(ctx, req, old.binding, old.generation); !errors.Is(err, ErrStaleBinding) {
			t.Fatalf("late edge callback %d = %v, want ErrStaleBinding", index, err)
		}
		if _, err := manager.ObserveOrigin(ctx, proof, req, old.binding, old.generation, true); !errors.Is(err, ErrStaleBinding) {
			t.Fatalf("late origin callback %d = %v, want ErrStaleBinding", index, err)
		}
	}
	latest, err := manager.Get(attachment.AccountID, attachment.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Binding != attachment.Binding || latest.AttachmentGeneration != attachment.AttachmentGeneration || latest.State != StatePending || latest.EdgeReady || latest.OriginReady {
		t.Fatalf("late callbacks changed current attachment: latest=%#v before=%#v", latest, attachment)
	}

	// The current process can still complete the exact pending generation after
	// all stale callbacks have been rejected.
	admitted, err := manager.Admit(ctx, proof, req, attachment.Binding, attachment.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	edgeReady, err := manager.ObserveEdge(ctx, req, admitted.Binding, admitted.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := manager.ObserveOrigin(ctx, proof, req, edgeReady.Binding, edgeReady.AttachmentGeneration, true)
	if err != nil {
		t.Fatal(err)
	}
	if ready.State != StateReady || !ready.EdgeReady || !ready.OriginReady {
		t.Fatalf("current process did not recover attachment: %#v", ready)
	}
}
