package previewattachment

import (
	"errors"
	"testing"
)

func TestDecodeRequestRejectsDuplicateUnknownAndTrailingFields(t *testing.T) {
	valid := `{"preview_id":"preview-1","operation_id":"operation-1","owner_device_id":"machine-1","owner_session_id":"owner-session-1","idempotency_key":"operation-1","request_id":"request-1","correlation_id":"correlation-1"}`
	request, err := DecodeRequest([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if request.PreviewID != "preview-1" {
		t.Fatalf("decoded request = %#v", request)
	}
	for name, body := range map[string]string{
		"duplicate": `{"preview_id":"preview-1","preview_id":"preview-2","operation_id":"operation-1","owner_device_id":"machine-1","owner_session_id":"owner-session-1","idempotency_key":"operation-1","request_id":"request-1","correlation_id":"correlation-1"}`,
		"unknown":   `{"preview_id":"preview-1","operation_id":"operation-1","owner_device_id":"machine-1","owner_session_id":"owner-session-1","idempotency_key":"operation-1","request_id":"request-1","correlation_id":"correlation-1","token":"must-not-be-accepted"}`,
		"trailing":  valid + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest([]byte(body)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("decode error = %v, want ErrInvalid", err)
			}
		})
	}
}
