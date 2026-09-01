package previewattachment

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRequirePreviewAttachmentReadyUsesExactDurableBinding(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	readyAt := now.Add(-time.Second)
	repository := &serviceRepositoryFake{current: Attachment{
		Schema: Schema, Kind: Kind,
		Binding: Binding{AccountID: "acct_1", PreviewID: "preview_1", OperationID: "operation_1", OwnerDeviceID: "machine_1", OwnerSessionID: "owner_session_1"},
		State:   StateReady, EdgeReady: true, OriginReady: true, ReadyAt: &readyAt, ExpiresAt: now.Add(time.Hour),
	}}
	service := &Service{repository: repository, now: func() time.Time { return now }}
	if err := service.RequirePreviewAttachmentReady(context.Background(), "acct_1", "preview_1", "operation_1", "machine_1", "owner_session_1"); err != nil {
		t.Fatal(err)
	}
	for name, values := range map[string][]string{
		"preview":   {"acct_1", "preview_2", "operation_1", "machine_1", "owner_session_1"},
		"operation": {"acct_1", "preview_1", "operation_2", "machine_1", "owner_session_1"},
		"machine":   {"acct_1", "preview_1", "operation_1", "machine_2", "owner_session_1"},
		"session":   {"acct_1", "preview_1", "operation_1", "machine_1", "owner_session_2"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := service.RequirePreviewAttachmentReady(context.Background(), values[0], values[1], values[2], values[3], values[4]); err == nil {
				t.Fatal("mismatched binding was accepted")
			}
		})
	}
	repository.current.State = StateEdgeReady
	repository.current.OriginReady = false
	repository.current.ReadyAt = nil
	if err := service.RequirePreviewAttachmentReady(context.Background(), "acct_1", "preview_1", "operation_1", "machine_1", "owner_session_1"); !errors.Is(err, ErrAdmissionUnavailable) {
		t.Fatalf("not-ready error = %v", err)
	}
	repository.current.State = StateReady
	repository.current.OriginReady = true
	repository.current.ReadyAt = &readyAt
	repository.current.ExpiresAt = now
	if err := service.RequirePreviewAttachmentReady(context.Background(), "acct_1", "preview_1", "operation_1", "machine_1", "owner_session_1"); !errors.Is(err, ErrAdmissionUnavailable) {
		t.Fatalf("expired error = %v", err)
	}
}
