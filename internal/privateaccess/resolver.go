package privateaccess

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/previewattachment"
)

// AttachmentStore is the narrow read-only view needed to bind a private
// preview. The SQL previewattachment repository is the production
// implementation; no private credential material is read here.
type AttachmentStore interface {
	Get(context.Context, string, string) (previewattachment.Attachment, error)
}

type PreviewAttachmentResolver struct {
	store AttachmentStore
	now   func() time.Time
}

func NewPreviewAttachmentResolver(store AttachmentStore) (*PreviewAttachmentResolver, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: preview attachment store is required", ErrInvalid)
	}
	return &PreviewAttachmentResolver{store: store, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (r *PreviewAttachmentResolver) SetClock(now func() time.Time) error {
	if r == nil || now == nil {
		return fmt.Errorf("%w: preview resolver clock is required", ErrInvalid)
	}
	r.now = now
	return nil
}

func (r *PreviewAttachmentResolver) ResolvePrivate(ctx context.Context, lookup Lookup) (Binding, error) {
	if r == nil || r.store == nil || ctx == nil {
		return Binding{}, ErrIdentityUnavailable
	}
	if lookup.Request.ResourceKind != ResourcePreview || lookup.Request.OperationID == "" {
		return Binding{}, ErrResourceNotFound
	}
	attachment, err := r.store.Get(ctx, lookup.AccountID, lookup.Request.OperationID)
	if errors.Is(err, previewattachment.ErrNotFound) {
		return Binding{}, ErrResourceNotFound
	}
	if err != nil {
		return Binding{}, ErrRouteUnavailable
	}
	if attachment.AccountID != lookup.AccountID || attachment.PreviewID != lookup.Request.ResourceID || attachment.OperationID != lookup.Request.OperationID {
		return Binding{}, ErrResourceNotFound
	}
	state := "paused"
	switch attachment.State {
	case previewattachment.StateEdgeReady:
		state = "edge_ready"
	case previewattachment.StateReady:
		state = "ready"
	case previewattachment.StatePending, previewattachment.StateAdmitted:
		state = "paused"
	case previewattachment.StateFailed, previewattachment.StateReleased:
		return Binding{}, newDenied(ReasonExpired)
	}
	now := lookup.Now
	if now.IsZero() {
		now = r.clock()
	}
	if !attachment.ExpiresAt.After(now) {
		return Binding{}, newDenied(ReasonExpired)
	}
	return Binding{
		AccountID: attachment.AccountID, ResourceKind: ResourcePreview, ResourceID: attachment.PreviewID,
		RouteID: attachment.RouteID, OperationID: attachment.OperationID, ConnectorID: attachment.ConnectorID,
		CarrierSessionID: attachment.SessionID, OwnerDeviceID: attachment.OwnerDeviceID, OwnerSessionID: attachment.OwnerSessionID,
		RouteGeneration: attachment.RouteGeneration, SessionGeneration: attachment.LeaseGeneration, ProcessGeneration: attachment.ProcessGeneration, ConfigGeneration: attachment.ConfigGeneration, AssignmentGeneration: attachment.LeaseGeneration,
		Protocol: ProtocolHTTP, AccessMode: attachment.AccessMode, State: state, ExpiresAt: attachment.ExpiresAt,
		Hostname: hostFromEndpoint(attachment.Endpoint), EdgeNodeID: attachment.EdgeNodeID,
		EdgeProcessEpoch: attachment.EdgeProcessEpoch,
	}, nil
}

func (r *PreviewAttachmentResolver) clock() time.Time {
	if r == nil || r.now == nil {
		return time.Now().UTC()
	}
	return r.now().UTC()
}
