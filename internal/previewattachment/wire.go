package previewattachment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/canonicaljson"
)

const (
	AttachmentPathPrefix = "/v1/previews/"
	AttachmentPathSuffix = "/carrier-attachment"
	MaxRequestBytes      = 64 << 10
)

// DecodeRequest is the strict wire decoder for
// POST /v1/previews/{preview_id}/carrier-attachment.  The handler must still
// require the path preview ID to equal Request.PreviewID and must verify the
// machine proof before calling Manager.
func DecodeRequest(data []byte) (Request, error) {
	if len(data) == 0 || len(data) > MaxRequestBytes {
		return Request{}, fmt.Errorf("%w: attachment request is empty or too large", ErrInvalid)
	}
	if err := canonicaljson.RejectDuplicateFields(data); err != nil {
		return Request{}, fmt.Errorf("%w: duplicate request field", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, fmt.Errorf("%w: decode attachment request: %v", ErrInvalid, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Request{}, fmt.Errorf("%w: multiple JSON values", ErrInvalid)
		}
		return Request{}, fmt.Errorf("%w: trailing request data: %v", ErrInvalid, err)
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	return request, nil
}

// MutationRequest is the strict machine-proof body used by renew, release,
// and origin-readiness calls. The request and binding are nested deliberately:
// it keeps the signed operation envelope distinct from the server-issued
// generation-fenced handle and makes accidental field collisions impossible.
type MutationRequest struct {
	Request              Request `json:"request"`
	Binding              Binding `json:"binding,omitempty"`
	AttachmentGeneration uint64  `json:"attachment_generation"`
	OriginReady          *bool   `json:"origin_ready,omitempty"`
}

func (m MutationRequest) Validate(requireBinding, requireOrigin bool) error {
	if err := m.Request.Validate(); err != nil {
		return err
	}
	if m.AttachmentGeneration == 0 {
		return fmt.Errorf("%w: attachment generation is required", ErrInvalid)
	}
	if requireBinding {
		if err := m.Binding.validate(); err != nil {
			return err
		}
	}
	if requireOrigin && m.OriginReady == nil {
		return fmt.Errorf("%w: origin_ready is required", ErrInvalid)
	}
	if !requireOrigin && m.OriginReady != nil {
		return fmt.Errorf("%w: origin_ready is not valid for this mutation", ErrInvalid)
	}
	return nil
}

// DecodeMutation rejects duplicate/unknown/trailing fields using the same
// canonical decoder as allocation. It intentionally does not accept a
// flattened Attachment object as input, so response-only fields cannot be
// smuggled into a mutation.
func DecodeMutation(data []byte, requireBinding, requireOrigin bool) (MutationRequest, error) {
	if len(data) == 0 || len(data) > MaxRequestBytes {
		return MutationRequest{}, fmt.Errorf("%w: attachment mutation is empty or too large", ErrInvalid)
	}
	if err := canonicaljson.RejectDuplicateFields(data); err != nil {
		return MutationRequest{}, fmt.Errorf("%w: duplicate mutation field", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var mutation MutationRequest
	if err := decoder.Decode(&mutation); err != nil {
		return MutationRequest{}, fmt.Errorf("%w: decode attachment mutation: %v", ErrInvalid, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return MutationRequest{}, fmt.Errorf("%w: multiple JSON values", ErrInvalid)
		}
		return MutationRequest{}, fmt.Errorf("%w: trailing mutation data: %v", ErrInvalid, err)
	}
	if err := mutation.Validate(requireBinding, requireOrigin); err != nil {
		return MutationRequest{}, err
	}
	return mutation, nil
}

func MarshalAttachment(attachment Attachment) ([]byte, error) {
	if err := attachment.Validate(attachment.IssuedAt); err != nil && attachment.State != StateReleased && attachment.State != StateFailed {
		return nil, err
	}
	return json.Marshal(attachment)
}

func MarshalAdmission(admission CarrierAdmission) ([]byte, error) {
	if err := admission.Validate(time.Time{}); err != nil {
		return nil, err
	}
	return json.Marshal(admission)
}
