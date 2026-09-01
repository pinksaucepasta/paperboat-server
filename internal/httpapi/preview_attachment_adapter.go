package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/previewattachment"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
)

// PreviewAttachmentMachineProofVerifier adapts the existing enrollment proof
// verifier to the canonical preview-attachment HTTP boundary. Account and
// machine identity come only from VerifyMachineRequest; neither is accepted
// from the request body.
type PreviewAttachmentMachineProofVerifier struct {
	identities machineRequestVerifier
}

func NewPreviewAttachmentMachineProofVerifier(identities machineRequestVerifier) (*PreviewAttachmentMachineProofVerifier, error) {
	if identities == nil {
		return nil, fmt.Errorf("preview attachment machine verifier is unavailable")
	}
	return &PreviewAttachmentMachineProofVerifier{identities: identities}, nil
}

func (v *PreviewAttachmentMachineProofVerifier) VerifyMachineRequest(ctx context.Context, r *http.Request, body []byte) (previewattachment.MachineProof, error) {
	if v == nil || v.identities == nil || r == nil || ctx == nil {
		return previewattachment.MachineProof{}, previewattachment.ErrUnauthorized
	}
	authorization := r.Header.Values("Authorization")
	identityValues := r.Header.Values("X-Paperboat-Machine-Identity")
	proofValues := r.Header.Values("X-Paperboat-Machine-Proof")
	if len(authorization) != 1 || len(identityValues) != 1 || len(proofValues) != 1 {
		return previewattachment.MachineProof{}, previewattachment.ErrUnauthorized
	}
	parts := strings.Fields(authorization[0])
	identity := identityValues[0]
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" || identity == "" || subtle.ConstantTimeCompare([]byte(parts[1]), []byte(identity)) != 1 {
		return previewattachment.MachineProof{}, previewattachment.ErrUnauthorized
	}
	proof, err := base64.RawURLEncoding.Strict().DecodeString(proofValues[0])
	if err != nil || len(proof) == 0 {
		return previewattachment.MachineProof{}, previewattachment.ErrUnauthorized
	}
	claims, err := v.identities.VerifyMachineRequest(ctx, identity, proof, r.Method, r.URL.Path, body)
	if err != nil || claims.UserID == "" || claims.MachineID == "" || claims.OperationID == "" || claims.InstallationGeneration <= 0 {
		return previewattachment.MachineProof{}, previewattachment.ErrUnauthorized
	}
	return previewattachment.MachineProof{
		UserID: claims.UserID, MachineID: claims.MachineID,
		OperationID: claims.OperationID, InstallationGeneration: uint64(claims.InstallationGeneration),
	}, nil
}

// PreviewAttachmentLeasePreconditionChecker binds If-Match to the account
// derived from the verified machine proof and to the current durable lease
// generation. This prevents an attacker from checking a lease in another
// account or replaying a stale lease ETag.
type PreviewAttachmentLeasePreconditionChecker struct {
	store *previewtunnelstore.Store
}

func NewPreviewAttachmentLeasePreconditionChecker(store *previewtunnelstore.Store) (*PreviewAttachmentLeasePreconditionChecker, error) {
	if store == nil {
		return nil, fmt.Errorf("preview attachment lease precondition store is unavailable")
	}
	return &PreviewAttachmentLeasePreconditionChecker{store: store}, nil
}

func (c *PreviewAttachmentLeasePreconditionChecker) CheckPreviewLeaseIfMatch(ctx context.Context, proof previewattachment.MachineProof, previewID, etag string) error {
	if c == nil || c.store == nil || ctx == nil || proof.UserID == "" || previewID == "" || strings.TrimSpace(etag) == "" {
		return previewattachment.ErrInvalid
	}
	lease, err := c.store.GetPreviewLeaseV1(ctx, proof.UserID, previewID)
	if err != nil {
		return previewattachment.ErrNotFound
	}
	want := previewtunnelapi.ETag("preview_lease", previewID, lease.Generation)
	if subtle.ConstantTimeCompare([]byte(etag), []byte(want)) != 1 {
		return previewattachment.ErrStaleBinding
	}
	return nil
}
