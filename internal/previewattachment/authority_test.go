package previewattachment

import (
	"context"
	"errors"
	"testing"
	"time"
)

type authorityLeaseResolver struct {
	lease LeaseSnapshot
	last  LeaseLookupRequest
}

func (r *authorityLeaseResolver) ResolvePreviewLease(_ context.Context, request LeaseLookupRequest) (LeaseSnapshot, error) {
	r.last = request
	return r.lease, nil
}

type authorityCarrierAllocator struct {
	allocation PreviewCarrierAllocation
	last       PreviewCarrierAllocationRequest
}

func (a *authorityCarrierAllocator) AllocatePreviewCarrier(_ context.Context, request PreviewCarrierAllocationRequest) (PreviewCarrierAllocation, error) {
	a.last = request
	return a.allocation, nil
}

func TestServerAuthorityBindsProofToDurableLeaseAndPreviewEphemeralAllocator(t *testing.T) {
	resolution := testResolution(testNow())
	lease := &authorityLeaseResolver{lease: resolution.Lease}
	allocator := &authorityCarrierAllocator{allocation: PreviewCarrierAllocation{Carrier: resolution.Carrier, Route: resolution.Route}}
	authority := ServerAuthority{Leases: lease, Carriers: allocator}

	result, err := authority.ResolvePreviewAttachment(context.Background(), ResolveRequest{Proof: testProof(), Request: testRequest()})
	if err != nil {
		t.Fatal(err)
	}
	if result.Lease.AccountID != "account-1" || !result.Carrier.Ephemeral || result.Route.RouteID != "route-1" {
		t.Fatalf("resolution = %#v, want account-scoped preview-ephemeral carrier", result)
	}
	if lease.last.UserID != "user-1" || lease.last.MachineID != "machine-1" || lease.last.OwnerSessionID != "owner-session-1" || lease.last.OperationID != "operation-1" {
		t.Fatalf("lease lookup = %#v, want proof/body binding", lease.last)
	}
	if allocator.last.RequestHash == "" || allocator.last.Lease.PreviewID != "preview-1" {
		t.Fatalf("carrier allocation request = %#v", allocator.last)
	}
}

func TestServerAuthorityRejectsOwnerSessionOrOperationMismatchBeforeAllocation(t *testing.T) {
	resolution := testResolution(testNow())
	lease := &authorityLeaseResolver{lease: resolution.Lease}
	allocator := &authorityCarrierAllocator{allocation: PreviewCarrierAllocation{Carrier: resolution.Carrier, Route: resolution.Route}}
	authority := ServerAuthority{Leases: lease, Carriers: allocator}
	req := testRequest()
	req.OwnerSessionID = "owner-session-other"
	if _, err := authority.ResolvePreviewAttachment(context.Background(), ResolveRequest{Proof: testProof(), Request: req}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("owner session mismatch error = %v, want ErrUnauthorized", err)
	}
	if allocator.last.RequestHash != "" {
		t.Fatal("allocator was called before authoritative lease rejected owner session")
	}
}

func TestPreviewCarrierIDsShareMachineIdentityButIsolateRoutes(t *testing.T) {
	now := testNow()
	firstRequest := testRequest()
	firstResolution := testResolution(now)
	firstHash, err := firstRequest.Hash(firstResolution.Lease.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	first := previewCarrierIDs(PreviewCarrierAllocationRequest{
		Proof: testProof(), Request: firstRequest, Lease: firstResolution.Lease,
		RequestHash: firstHash,
	}, firstResolution.Carrier.EdgeNodeID)

	secondRequest := firstRequest
	secondRequest.PreviewID = "preview-2"
	secondRequest.OperationID = "operation-2"
	secondRequest.IdempotencyKey = "operation-2"
	secondRequest.RequestID = "request-2"
	secondRequest.CorrelationID = "correlation-2"
	secondResolution := firstResolution
	secondResolution.Lease.PreviewID = secondRequest.PreviewID
	secondResolution.Lease.OperationID = secondRequest.OperationID
	secondResolution.Route.RouteID = "route-2"
	secondProof := testProof()
	secondProof.OperationID = secondRequest.OperationID
	secondHash, err := secondRequest.Hash(secondResolution.Lease.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	second := previewCarrierIDs(PreviewCarrierAllocationRequest{
		Proof: secondProof, Request: secondRequest, Lease: secondResolution.Lease,
		RequestHash: secondHash,
	}, secondResolution.Carrier.EdgeNodeID)
	if first.tunnelID != second.tunnelID || first.connectorID != second.connectorID || first.sessionID != second.sessionID {
		t.Fatalf("machine carrier identity changed across previews: first=%+v second=%+v", first, second)
	}
	if first.routeID == second.routeID {
		t.Fatalf("preview routes were not isolated: first=%q second=%q", first.routeID, second.routeID)
	}

	third := previewCarrierIDs(PreviewCarrierAllocationRequest{
		Proof: testProof(), Request: firstRequest, Lease: firstResolution.Lease,
		RequestHash: firstHash,
	}, firstResolution.Carrier.EdgeNodeID, 2)
	fourth := previewCarrierIDs(PreviewCarrierAllocationRequest{
		Proof: testProof(), Request: firstRequest, Lease: firstResolution.Lease,
		RequestHash: firstHash,
	}, firstResolution.Carrier.EdgeNodeID, 3)
	if third.tunnelID != fourth.tunnelID || third.connectorID != fourth.connectorID {
		t.Fatalf("worker restart changed stable carrier identity: before=%+v after=%+v", third, fourth)
	}
	if third.sessionID == fourth.sessionID {
		t.Fatalf("worker restart reused carrier session: before=%q after=%q", third.sessionID, fourth.sessionID)
	}
}

func testNow() time.Time {
	return time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
}
