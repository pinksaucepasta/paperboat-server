package previewattachment

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// DBPreviewLeaseResolver is the concrete durable authority for attachment
// allocation. It locks the lease, its create operation, and the owning
// machine in one transaction. The account is selected from the machine/user
// relationship, never from the request body.
//
// The resolver intentionally accepts only an active host machine. A preview
// attachment is therefore not a way to revive a stopped lease or to use a
// different machine's signed proof.
type DBPreviewLeaseResolver struct {
	db  *db.DB
	now func() time.Time
}

func NewDBPreviewLeaseResolver(database *db.DB) (*DBPreviewLeaseResolver, error) {
	if database == nil || database.Pool() == nil {
		return nil, fmt.Errorf("%w: database is not open", ErrInvalid)
	}
	return &DBPreviewLeaseResolver{db: database, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (r *DBPreviewLeaseResolver) SetClock(now func() time.Time) error {
	if r == nil || now == nil {
		return fmt.Errorf("%w: nil lease resolver clock", ErrInvalid)
	}
	r.now = now
	return nil
}

func (r *DBPreviewLeaseResolver) ResolvePreviewLease(ctx context.Context, in LeaseLookupRequest) (LeaseSnapshot, error) {
	if r == nil || r.db == nil || r.db.Pool() == nil || ctx == nil {
		return LeaseSnapshot{}, fmt.Errorf("%w: lease resolver is not available", ErrInvalid)
	}
	if !validID(in.UserID) || !validID(in.MachineID) || !validID(in.PreviewID) || !validID(in.OperationID) || !validID(in.OwnerSessionID) || in.InstallationGeneration == 0 {
		return LeaseSnapshot{}, fmt.Errorf("%w: incomplete lease lookup", ErrInvalid)
	}
	now := r.clock()
	var lease LeaseSnapshot
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row := tx.QueryRow(ctx, resolvePreviewLeaseSQL,
			in.UserID, in.MachineID, in.InstallationGeneration, in.PreviewID,
			in.OwnerSessionID, in.OperationID, now,
		)
		var publicKey string
		err := row.Scan(
			&lease.AccountID, &lease.ActorID, &lease.PreviewID, &lease.OperationID,
			&lease.OwnerDeviceID, &lease.OwnerSessionID, &lease.Endpoint,
			&lease.Target.Scheme, &lease.Target.Address, &lease.AccessMode,
			&lease.Generation, &lease.LeaseDeadline, &lease.State, &publicKey,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnauthorized
		}
		if err != nil {
			return err
		}
		thumbprint, ok := machineIdentityThumbprint(publicKey)
		if !ok {
			return ErrUnauthorized
		}
		lease.MachineIdentityPublicKey = publicKey
		lease.MachineIdentityThumbprint = thumbprint
		return nil
	})
	if err != nil {
		return LeaseSnapshot{}, err
	}
	if lease.AccountID != in.UserID || lease.ActorID != in.UserID || lease.OwnerDeviceID != in.MachineID || lease.OwnerSessionID != in.OwnerSessionID || lease.PreviewID != in.PreviewID || lease.OperationID != in.OperationID {
		return LeaseSnapshot{}, ErrUnauthorized
	}
	return lease, nil
}

func (r *DBPreviewLeaseResolver) clock() time.Time {
	if r == nil || r.now == nil {
		return time.Now().UTC()
	}
	return r.now().UTC()
}

const resolvePreviewLeaseSQL = `
SELECT p.account_id, p.actor_id, p.id, o.id,
       p.owner_device_id, p.owner_session_id, p.endpoint,
	p.target_scheme, p.target_address, p.access_mode,
	       p.generation, p.lease_deadline, p.terminal_state,
	       m.public_identity_key
FROM preview_leases AS p
JOIN user_machines AS m
  ON m.id = p.owner_device_id
 AND m.user_id = p.account_id
JOIN preview_lease_create_operations AS create_operation
  ON create_operation.account_id = p.account_id
 AND create_operation.preview_id = p.id
 AND create_operation.operation_id = $6
JOIN operations AS o
  ON o.id = create_operation.operation_id
 AND o.account_id = create_operation.account_id
WHERE p.account_id = $1
  AND p.actor_id = $1
  AND p.owner_device_id = $2
  AND m.installation_generation = $3
  AND m.state = 'online'
  AND m.online
  AND m.deleted_at IS NULL
 AND m.revoked_at IS NULL
	AND m.public_identity_key IS NOT NULL
  AND p.id = $4
  AND p.owner_session_id = $5
  AND p.terminal_state = 'active'
  AND p.lease_deadline > $7
  AND o.state IN ('pending','running','uncertain','succeeded')
FOR UPDATE OF p, m, o`

// PreviewCarrierIssuer is the narrow production seam owned by the canonical
// host/edge carrier implementation. It must mint or recover one
// preview-ephemeral identity for the exact operation/hash, without creating
// a durable tunnel row and without returning credential bytes.
//
// The issuer must be deterministic for an exact operation replay and must
// return a newer process/session generation when the host reconnects. The
// server validates the returned binding before it is persisted.
type PreviewCarrierIssuer interface {
	IssuePreviewCarrier(context.Context, PreviewCarrierAllocationRequest) (PreviewCarrierAllocation, error)
}

// EphemeralCarrierAllocator validates the host/edge implementation's result
// before exposing it through ServerAuthority. Keeping this check in the
// control plane prevents a future issuer from accidentally attaching a
// durable tunnel or crossing an account/owner/route boundary.
type EphemeralCarrierAllocator struct {
	issuer   PreviewCarrierIssuer
	selector PreviewEdgeNodeSelector
	now      func() time.Time
}

func NewEphemeralCarrierAllocator(issuer PreviewCarrierIssuer, selectors ...PreviewEdgeNodeSelector) (*EphemeralCarrierAllocator, error) {
	if issuer == nil {
		return nil, fmt.Errorf("%w: nil preview carrier issuer", ErrInvalid)
	}
	if len(selectors) > 1 {
		return nil, fmt.Errorf("%w: multiple preview edge-node selectors", ErrInvalid)
	}
	var selector PreviewEdgeNodeSelector
	if len(selectors) == 1 {
		selector = selectors[0]
		if selector == nil {
			return nil, fmt.Errorf("%w: nil preview edge-node selector", ErrInvalid)
		}
	}
	return &EphemeralCarrierAllocator{issuer: issuer, selector: selector, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (a *EphemeralCarrierAllocator) SetClock(now func() time.Time) error {
	if a == nil || now == nil {
		return fmt.Errorf("%w: nil carrier allocator clock", ErrInvalid)
	}
	a.now = now
	return nil
}

func (a *EphemeralCarrierAllocator) AllocatePreviewCarrier(ctx context.Context, in PreviewCarrierAllocationRequest) (PreviewCarrierAllocation, error) {
	if a == nil || a.issuer == nil || ctx == nil {
		return PreviewCarrierAllocation{}, fmt.Errorf("%w: carrier allocator is not available", ErrInvalid)
	}
	if err := in.Proof.Validate(); err != nil {
		return PreviewCarrierAllocation{}, err
	}
	if err := in.Request.Validate(); err != nil {
		return PreviewCarrierAllocation{}, err
	}
	if err := validateResolution(a.clock(), Resolution{Lease: in.Lease}); err != nil {
		// The carrier and route are not available yet, so validate the lease
		// portion directly. The complete result is checked below.
		if !validID(in.Lease.AccountID) || !validID(in.Lease.ActorID) || !validID(in.Lease.PreviewID) || !validID(in.Lease.OperationID) || !validID(in.Lease.OwnerDeviceID) || !validID(in.Lease.OwnerSessionID) || in.Lease.Generation == 0 || in.Lease.LeaseDeadline.IsZero() || !in.Lease.LeaseDeadline.After(a.clock()) || in.Lease.State != "active" {
			return PreviewCarrierAllocation{}, err
		}
	}
	if in.Lease.ActorID != in.Proof.UserID || in.Lease.OwnerDeviceID != in.Proof.MachineID || in.Lease.OwnerSessionID != in.Request.OwnerSessionID || in.Lease.OperationID != in.Request.OperationID {
		return PreviewCarrierAllocation{}, ErrUnauthorized
	}
	if len(in.RequestHash) != 64 {
		return PreviewCarrierAllocation{}, fmt.Errorf("%w: request hash is required", ErrInvalid)
	}
	if _, err := hex.DecodeString(in.RequestHash); err != nil {
		return PreviewCarrierAllocation{}, fmt.Errorf("%w: request hash is invalid", ErrInvalid)
	}
	if a.selector != nil {
		selectedEdgeNodeID, err := a.selector.SelectPreviewEdgeNode(ctx, PreviewEdgeNodeSelectionRequest{
			AccountID: in.Lease.AccountID, PreviewID: in.Lease.PreviewID,
			OperationID: in.Lease.OperationID, OwnerDeviceID: in.Lease.OwnerDeviceID,
			InstallationGeneration: in.Proof.InstallationGeneration,
		})
		if err != nil {
			return PreviewCarrierAllocation{}, err
		}
		in.EdgeNodeID = selectedEdgeNodeID
	}
	if !validID(in.EdgeNodeID) {
		return PreviewCarrierAllocation{}, fmt.Errorf("%w: preview edge-node identity is required", ErrConflict)
	}
	allocation, err := a.issuer.IssuePreviewCarrier(ctx, in)
	if err != nil {
		return PreviewCarrierAllocation{}, err
	}
	if allocation.Carrier.EdgeNodeID != in.EdgeNodeID {
		return PreviewCarrierAllocation{}, fmt.Errorf("%w: carrier issuer changed selected edge node", ErrStaleBinding)
	}
	if err := validateResolution(a.clock(), Resolution{Lease: in.Lease, Carrier: allocation.Carrier, Route: allocation.Route}); err != nil {
		return PreviewCarrierAllocation{}, err
	}
	return allocation, nil
}

func (a *EphemeralCarrierAllocator) clock() time.Time {
	if a == nil || a.now == nil {
		return time.Now().UTC()
	}
	return a.now().UTC()
}
