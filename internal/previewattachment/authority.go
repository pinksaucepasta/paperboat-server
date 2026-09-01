package previewattachment

import (
	"context"
	"fmt"
)

// LeaseLookupRequest is derived from the verified machine proof and the
// signed request body. Implementations must resolve the durable preview row
// and its create operation in one account-scoped transaction.
type LeaseLookupRequest struct {
	UserID                 string
	MachineID              string
	InstallationGeneration uint64
	PreviewID              string
	OperationID            string
	OwnerSessionID         string
}

type PreviewLeaseResolver interface {
	ResolvePreviewLease(context.Context, LeaseLookupRequest) (LeaseSnapshot, error)
}

// PreviewCarrierAllocationRequest is the only allocation seam needed by the
// control plane. The allocator mints preview-ephemeral canonical IDs and
// installs the edge admission route keyed by operation/hash. It must not
// require a durable tunnel row or return credential bytes.
type PreviewCarrierAllocationRequest struct {
	Proof       MachineProof
	Request     Request
	Lease       LeaseSnapshot
	RequestHash string
	// EdgeNodeID is selected from the authoritative control_tunnel_nodes
	// registry before the external carrier issuer runs. The issuer must return
	// the same node in CarrierSnapshot; it may not substitute an endpoint.
	EdgeNodeID string
}

// PreviewEdgeNodeSelectionRequest scopes a deterministic ready-edge lookup.
// No endpoint is accepted from the caller: the selected node identity is the
// authority used by the publisher and peer verifier.
type PreviewEdgeNodeSelectionRequest struct {
	AccountID              string
	PreviewID              string
	OperationID            string
	OwnerDeviceID          string
	InstallationGeneration uint64
}

type PreviewEdgeNodeSelector interface {
	SelectPreviewEdgeNode(context.Context, PreviewEdgeNodeSelectionRequest) (string, error)
}

type PreviewCarrierAllocator interface {
	AllocatePreviewCarrier(context.Context, PreviewCarrierAllocationRequest) (PreviewCarrierAllocation, error)
}

type PreviewCarrierAllocation struct {
	Carrier CarrierSnapshot
	Route   RouteSnapshot
}

// ServerAuthority composes durable lease/create-operation validation with the
// preview-specific ephemeral carrier allocator. It is the production adapter
// for Manager.Authority.
type ServerAuthority struct {
	Leases   PreviewLeaseResolver
	Carriers PreviewCarrierAllocator
}

func (a ServerAuthority) ResolvePreviewAttachment(ctx context.Context, in ResolveRequest) (Resolution, error) {
	if ctx == nil || a.Leases == nil || a.Carriers == nil {
		return Resolution{}, fmt.Errorf("%w: incomplete server attachment authority", ErrInvalid)
	}
	if err := in.Proof.Validate(); err != nil {
		return Resolution{}, err
	}
	if err := in.Request.Validate(); err != nil {
		return Resolution{}, err
	}
	if in.Proof.OperationID != in.Request.OperationID || in.Proof.OperationID != in.Request.IdempotencyKey || in.Proof.MachineID != in.Request.OwnerDeviceID {
		return Resolution{}, ErrUnauthorized
	}
	lease, err := a.Leases.ResolvePreviewLease(ctx, LeaseLookupRequest{
		UserID: in.Proof.UserID, MachineID: in.Proof.MachineID, InstallationGeneration: in.Proof.InstallationGeneration,
		PreviewID: in.Request.PreviewID, OperationID: in.Request.OperationID, OwnerSessionID: in.Request.OwnerSessionID,
	})
	if err != nil {
		return Resolution{}, err
	}
	if lease.ActorID != in.Proof.UserID || lease.OwnerDeviceID != in.Proof.MachineID || lease.OwnerSessionID != in.Request.OwnerSessionID || lease.PreviewID != in.Request.PreviewID || lease.OperationID != in.Proof.OperationID {
		return Resolution{}, ErrUnauthorized
	}
	hash, err := in.Request.Hash(lease.AccountID)
	if err != nil {
		return Resolution{}, err
	}
	allocation, err := a.Carriers.AllocatePreviewCarrier(ctx, PreviewCarrierAllocationRequest{
		Proof: in.Proof, Request: in.Request, Lease: lease, RequestHash: hash,
	})
	if err != nil {
		return Resolution{}, err
	}
	return Resolution{Lease: lease, Carrier: allocation.Carrier, Route: allocation.Route}, nil
}
