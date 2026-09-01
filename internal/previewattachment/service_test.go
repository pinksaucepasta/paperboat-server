package previewattachment

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type serviceRepositoryFake struct {
	mu      sync.Mutex
	current Attachment
	calls   []string
}

func (r *serviceRepositoryFake) Get(_ context.Context, accountID, operationID string) (Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current.OperationID == "" || r.current.AccountID != accountID || r.current.OperationID != operationID {
		return Attachment{}, ErrNotFound
	}
	return cloneAttachment(r.current), nil
}

func (r *serviceRepositoryFake) CreatePending(_ context.Context, attachment Attachment) (Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "create")
	if r.current.OperationID == "" {
		r.current = attachment
	}
	if r.current.RequestHash != attachment.RequestHash {
		return Attachment{}, ErrIdempotencyConflict
	}
	return cloneAttachment(r.current), nil
}

func (r *serviceRepositoryFake) Admit(_ context.Context, attachment Attachment, _ time.Time) (Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "admit")
	if r.current.AttachmentGeneration != attachment.AttachmentGeneration || r.current.Binding != attachment.Binding || r.current.State != StatePending {
		return Attachment{}, ErrStaleBinding
	}
	r.current.State = StateAdmitted
	r.current.AttachmentGeneration++
	return cloneAttachment(r.current), nil
}

func (r *serviceRepositoryFake) ObserveEdge(_ context.Context, attachment Attachment, _ time.Time) (Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "edge")
	if r.current.AttachmentGeneration != attachment.AttachmentGeneration || r.current.Binding != attachment.Binding {
		return Attachment{}, ErrStaleBinding
	}
	if r.current.State == StateEdgeReady && r.current.EdgeReady {
		return cloneAttachment(r.current), nil
	}
	if r.current.State != StateAdmitted {
		return Attachment{}, ErrAdmissionUnavailable
	}
	r.current.State = StateEdgeReady
	r.current.EdgeReady = true
	r.current.AttachmentGeneration++
	return cloneAttachment(r.current), nil
}

func (r *serviceRepositoryFake) ObserveOrigin(_ context.Context, attachment Attachment, originReady bool, now time.Time) (Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "origin")
	if r.current.AttachmentGeneration != attachment.AttachmentGeneration || r.current.Binding != attachment.Binding {
		return Attachment{}, ErrStaleBinding
	}
	if !r.current.EdgeReady || (r.current.State != StateEdgeReady && r.current.State != StateReady) {
		return Attachment{}, ErrAdmissionUnavailable
	}
	if r.current.OriginReady == originReady {
		return cloneAttachment(r.current), nil
	}
	r.current.OriginReady = originReady
	r.current.AttachmentGeneration++
	if originReady {
		r.current.State = StateReady
		r.current.ReadyAt = timePtr(now)
	} else {
		r.current.State = StateEdgeReady
		r.current.ReadyAt = nil
	}
	return cloneAttachment(r.current), nil
}

func (r *serviceRepositoryFake) Renew(_ context.Context, current, next Attachment, _ time.Time) (Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "renew")
	if r.current.AttachmentGeneration != current.AttachmentGeneration || r.current.Binding != current.Binding {
		return Attachment{}, ErrStaleBinding
	}
	if !logicalBindingEqual(current.Binding, next.Binding) || next.LeaseGeneration < current.LeaseGeneration || next.ProcessGeneration < current.ProcessGeneration || next.ConfigGeneration < current.ConfigGeneration || next.RouteGeneration != current.RouteGeneration {
		return Attachment{}, ErrConflict
	}
	carrierChanged := !dataCarrierBindingEqual(current.Binding, next.Binding) || current.ConfigContentHash != next.ConfigContentHash
	r.current.Binding = next.Binding
	r.current.ConfigContentHash = next.ConfigContentHash
	r.current.EdgeEndpoints = append([]string(nil), next.EdgeEndpoints...)
	r.current.ExpiresAt = next.ExpiresAt
	r.current.AttachmentGeneration++
	if carrierChanged {
		r.current.State = StatePending
		r.current.EdgeReady = false
		r.current.OriginReady = false
		r.current.ReadyAt = nil
	}
	return cloneAttachment(r.current), nil
}

func (r *serviceRepositoryFake) Release(_ context.Context, attachment Attachment, now time.Time) (Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "release")
	if r.current.AttachmentGeneration != attachment.AttachmentGeneration || r.current.Binding != attachment.Binding {
		return Attachment{}, ErrStaleBinding
	}
	if r.current.State == StateReleased || r.current.State == StateFailed {
		return cloneAttachment(r.current), nil
	}
	r.current.State = StateReleased
	r.current.EdgeReady = false
	r.current.OriginReady = false
	r.current.ReadyAt = nil
	r.current.ReleasedAt = timePtr(now)
	r.current.AttachmentGeneration++
	if now.After(r.current.IssuedAt) {
		r.current.ExpiresAt = now
	}
	return cloneAttachment(r.current), nil
}

func timePtr(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}

func TestServiceUsesSQLRepositoryBoundaryAndKeepsEdgeAuthoritySeparate(t *testing.T) {
	now := testNow()
	authority := &testAuthority{resolution: testResolution(now)}
	repository := &serviceRepositoryFake{}
	publisher := &testPublisher{}
	service, err := NewService(repository, authority, publisher)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetClock(func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	proof, req := testProof(), testRequest()
	allocated, err := service.Allocate(context.Background(), proof, req)
	if err != nil {
		t.Fatal(err)
	}
	if allocated.State != StatePending || len(repository.calls) != 1 || repository.calls[0] != "create" {
		t.Fatalf("allocate = %#v, repository calls = %#v", allocated, repository.calls)
	}
	if _, err := service.ObserveEdge(context.Background(), req, allocated.Binding, allocated.AttachmentGeneration); !errors.Is(err, ErrAdmissionUnavailable) {
		t.Fatalf("edge before admit error = %v, want ErrAdmissionUnavailable", err)
	}
	admitted, err := service.Admit(context.Background(), proof, req, allocated.Binding, allocated.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if admitted.State != StateAdmitted || admitted.EdgeReady || admitted.AttachmentGeneration != 2 {
		t.Fatalf("admitted = %#v", admitted)
	}
	edge, err := service.ObserveEdge(context.Background(), req, admitted.Binding, admitted.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	// The host can start its origin probe from the admitted projection while
	// the edge independently commits readiness. Its callback must consume that
	// exact one-generation advance rather than fail a valid race.
	ready, err := service.ObserveOrigin(context.Background(), proof, req, edge.Binding, admitted.AttachmentGeneration, true)
	if err != nil {
		t.Fatal(err)
	}
	if ready.State != StateReady || !ready.EdgeReady || !ready.OriginReady || ready.AttachmentGeneration != edge.AttachmentGeneration+1 {
		t.Fatalf("ready = %#v", ready)
	}
	if _, err := service.ObserveEdge(context.Background(), req, edge.Binding, edge.AttachmentGeneration); err != nil {
		t.Fatalf("lost-response edge replay error = %v", err)
	}
	if len(publisher.calls) != 1 {
		t.Fatalf("publisher calls = %d, want one exact admission", len(publisher.calls))
	}
}

func TestServiceAllowsReleaseRetryAfterLeaseWasStopped(t *testing.T) {
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
	proof, req := testProof(), testRequest()
	allocated, err := service.Allocate(context.Background(), proof, req)
	if err != nil {
		t.Fatal(err)
	}
	released, err := service.Release(context.Background(), proof, req, allocated, allocated.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a network loss: the caller only has the pre-release generation,
	// while SQL already contains the terminal row and the lease may be stopped.
	retry, err := service.Release(context.Background(), proof, req, allocated, allocated.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if retry.State != StateReleased || retry.AttachmentGeneration != released.AttachmentGeneration {
		t.Fatalf("release retry = %#v, first release = %#v", retry, released)
	}
}

func TestEphemeralCarrierAllocatorRejectsMalformedIssuerOutput(t *testing.T) {
	now := testNow()
	issuer := previewIssuerFake{allocation: PreviewCarrierAllocation{
		Carrier: CarrierSnapshot{AccountID: "account-1", HostID: "machine-1", Ephemeral: false},
	}}
	allocator, err := NewEphemeralCarrierAllocator(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err := allocator.SetClock(func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	resolution := testResolution(now)
	hash, err := testRequest().Hash(resolution.Lease.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = allocator.AllocatePreviewCarrier(context.Background(), PreviewCarrierAllocationRequest{Proof: testProof(), Request: testRequest(), Lease: resolution.Lease, RequestHash: hash, EdgeNodeID: resolution.Carrier.EdgeNodeID})
	if !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("malformed issuer error = %v, want ErrStaleBinding", err)
	}
}

type previewIssuerFake struct {
	allocation PreviewCarrierAllocation
}

func (f previewIssuerFake) IssuePreviewCarrier(context.Context, PreviewCarrierAllocationRequest) (PreviewCarrierAllocation, error) {
	return f.allocation, nil
}

func (r *serviceRepositoryFake) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return fmt.Sprintf("%s/%d", r.current.State, r.current.AttachmentGeneration)
}
