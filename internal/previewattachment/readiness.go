package previewattachment

import (
	"context"
	"fmt"
)

// RequirePreviewAttachmentReady implements previewv1.AttachmentReadiness.
// Readiness is read from the server-owned attachment row; no state supplied
// by the host readiness request can satisfy this gate.
func (s *Service) RequirePreviewAttachmentReady(ctx context.Context, accountID, previewID, operationID, ownerDeviceID, ownerSessionID string) error {
	if s == nil || s.repository == nil || ctx == nil {
		return fmt.Errorf("%w: attachment service is unavailable", ErrAdmissionUnavailable)
	}
	for _, value := range []string{accountID, previewID, operationID, ownerDeviceID, ownerSessionID} {
		if !validID(value) {
			return ErrUnauthorized
		}
	}
	attachment, err := s.repository.Get(ctx, accountID, operationID)
	if err != nil {
		return err
	}
	if attachment.AccountID != accountID || attachment.PreviewID != previewID || attachment.OperationID != operationID || attachment.OwnerDeviceID != ownerDeviceID || attachment.OwnerSessionID != ownerSessionID {
		return ErrUnauthorized
	}
	if attachment.State != StateReady || !attachment.EdgeReady || !attachment.OriginReady || attachment.ReadyAt == nil || attachment.ReleasedAt != nil || !attachment.ExpiresAt.After(s.clock()) {
		return ErrAdmissionUnavailable
	}
	return nil
}
