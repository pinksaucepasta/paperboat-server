package privateaccess

import (
	"context"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
)

// AuditWriterSink projects authorization events into the existing append-only
// audit stream. Only stable identifiers and policy outcomes are retained. In
// particular, proof headers, cookies, signed grant bytes, target addresses,
// and private material never enter metadata.
type AuditWriterSink struct {
	Writer *audit.Writer
}

func (s AuditWriterSink) Record(ctx context.Context, record AuditRecord) error {
	if s.Writer == nil {
		return ErrAuditUnavailable
	}
	eventType := record.EventType
	if eventType == "" {
		eventType = "private_access.denied"
		if record.Allowed {
			eventType = "private_access.allowed"
		}
	}
	resourceType := record.ResourceKind
	if resourceType == "" {
		resourceType = "private_access"
	}
	metadata := map[string]any{
		"reason":          string(record.Reason),
		"device_id":       record.DeviceID,
		"session_id":      record.SessionID,
		"route_id":        record.RouteID,
		"operation_id":    record.OperationID,
		"connector_id":    record.ConnectorID,
		"carrier_session": record.CarrierSessionID,
		"protocol":        record.Protocol,
		"request_id":      record.RequestID,
		"correlation_id":  record.CorrelationID,
	}
	actorType := audit.ActorSystem
	if record.UserID != "" {
		actorType = audit.ActorUser
	}
	return s.Writer.Write(ctx, audit.Event{
		ActorUserID:    record.UserID,
		ActorType:      actorType,
		EventType:      eventType,
		ResourceType:   resourceType,
		ResourceID:     record.ResourceID,
		IdempotencyKey: record.IdempotencyKey,
		Metadata:       metadata,
	})
}
