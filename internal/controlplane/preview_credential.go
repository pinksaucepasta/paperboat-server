package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

const previewCredentialTTL = 5 * time.Minute

type PreviewCredential struct {
	Credential string    `json:"credential"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (s *EnrollmentService) IssuePreviewCredential(ctx context.Context, identityToken string, proof, body []byte, method, path string) (PreviewCredential, error) {
	claims, err := s.VerifyMachineRequest(ctx, identityToken, proof, method, path, body)
	if err != nil {
		return PreviewCredential{}, err
	}
	now := s.clock().UTC()
	expiresAt := now.Add(previewCredentialTTL)
	jti, err := randomHex("jti_", 24)
	if err != nil {
		return PreviewCredential{}, err
	}
	token, err := s.signer.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-control", Subject: claims.MachineID,
		JTI: jti, IssuedAt: now, ExpiresAt: expiresAt,
		CredentialClass: "preview_registration", Scopes: []string{"preview:register"},
		EnvironmentID: claims.EnvironmentID, MachineID: claims.MachineID, InstallationGeneration: claims.InstallationGeneration,
	})
	if err != nil {
		return PreviewCredential{}, err
	}
	return PreviewCredential{Credential: token, ExpiresAt: expiresAt}, nil
}

func (s *EnrollmentService) VerifyPreviewRequest(ctx context.Context, identityToken, previewToken string, proof, body []byte, method, path string) (MachineRequestClaims, error) {
	claims, err := s.VerifyMachineRequest(ctx, identityToken, proof, method, path, body)
	if err != nil {
		return MachineRequestClaims{}, err
	}
	credential, err := s.signer.VerifyCredential(previewToken, s.issuer, "preview_registration", s.clock().UTC())
	if err != nil || credential.MachineID != claims.MachineID || credential.InstallationGeneration != claims.InstallationGeneration || credential.EnvironmentID != claims.EnvironmentID || credential.Subject != claims.MachineID {
		return MachineRequestClaims{}, errors.New("preview credential is invalid")
	}
	return claims, nil
}
