package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

type MachineRequestClaims struct {
	MachineID              string
	EnvironmentID          string
	UserID                 string
	InstallationGeneration int64
	OperationID            string
	CredentialJTI          string
	SessionGeneration      int64
}

type canonicalMachineProofClaims struct {
	MachineID              string    `json:"machine_id"`
	EnvironmentID          string    `json:"environment_id"`
	InstallationGeneration int64     `json:"installation_generation"`
	OperationID            string    `json:"operation_id"`
	Method                 string    `json:"method"`
	Path                   string    `json:"path"`
	BodySHA256             string    `json:"body_sha256"`
	IssuedAt               time.Time `json:"issued_at"`
	ExpiresAt              time.Time `json:"expires_at"`
}

func (s *EnrollmentService) VerifyMachineRequest(ctx context.Context, identityToken string, proof []byte, method, path string, body []byte) (MachineRequestClaims, error) {
	claims, err := s.VerifyMachineControlRequest(ctx, identityToken, proof, method, path, body)
	if err == nil {
		return claims, nil
	}
	helper, err := s.VerifyHelperRequest(ctx, identityToken, proof, method, path, body)
	if err != nil {
		return MachineRequestClaims{}, err
	}
	machine, err := s.store.Queries().GetActiveUserMachineForControl(ctx, helper.MachineID)
	if err != nil || machine.EnvironmentID != helper.EnvironmentID {
		return MachineRequestClaims{}, ErrHelperProof
	}
	return MachineRequestClaims{MachineID: machine.ID, EnvironmentID: machine.EnvironmentID, UserID: machine.UserID, InstallationGeneration: machine.InstallationGeneration, OperationID: helper.OperationID}, nil
}

// VerifyMachineControlRequest accepts only the current renewable machine-control
// session. It deliberately has no helper-identity fallback and is the verifier
// for private-access authority.
func (s *EnrollmentService) VerifyMachineControlRequest(ctx context.Context, identityToken string, proof []byte, method, path string, body []byte) (MachineRequestClaims, error) {
	now := s.clock().UTC()
	identity, err := s.signer.VerifyCredential(identityToken, s.issuer, "machine_control", now)
	if err != nil {
		return MachineRequestClaims{}, ErrHelperProof
	}
	machine, err := s.store.Queries().GetActiveUserMachineForControl(ctx, identity.MachineID)
	if err != nil || machine.UserID != identity.UserID || machine.EnvironmentID != identity.EnvironmentID || machine.InstallationGeneration != identity.InstallationGeneration || machineControlThumbprint(machine) != identity.KeyThumbprint {
		return MachineRequestClaims{}, ErrHelperProof
	}
	current, err := s.store.Queries().GetCurrentMachineControlSession(ctx, dbsqlc.GetCurrentMachineControlSessionParams{
		MachineID: machine.ID, InstallationGeneration: machine.InstallationGeneration,
		CredentialJti: identity.JTI, Now: now,
	})
	if err != nil || current.SessionGeneration != identity.SessionGeneration || current.OperationID == "" {
		return MachineRequestClaims{}, ErrHelperProof
	}
	claims, err := verifyCanonicalMachineProof(machine, proof, method, path, body, now)
	if err != nil {
		return MachineRequestClaims{}, err
	}
	return MachineRequestClaims{
		MachineID: machine.ID, EnvironmentID: machine.EnvironmentID, UserID: machine.UserID,
		InstallationGeneration: machine.InstallationGeneration, OperationID: claims.OperationID,
		CredentialJTI: current.CredentialJti, SessionGeneration: current.SessionGeneration,
	}, nil
}

func verifyCanonicalMachineProof(machine dbsqlc.UserMachine, encoded []byte, method, path string, body []byte, now time.Time) (canonicalMachineProofClaims, error) {
	if len(encoded) == 0 || len(encoded) > 16<<10 || !machine.PublicIdentityKey.Valid {
		return canonicalMachineProofClaims{}, ErrHelperProof
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(machine.PublicIdentityKey.String)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return canonicalMachineProofClaims{}, ErrHelperProof
	}
	var envelope helperProofEnvelope
	if strictProofJSON(encoded, &envelope) != nil || envelope.Algorithm != "EdDSA" {
		return canonicalMachineProofClaims{}, ErrHelperProof
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) > 16<<10 {
		return canonicalMachineProofClaims{}, ErrHelperProof
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return canonicalMachineProofClaims{}, ErrHelperProof
	}
	var claims canonicalMachineProofClaims
	if strictCanonicalMachineJSON(payload, &claims) != nil {
		return canonicalMachineProofClaims{}, ErrHelperProof
	}
	digest := sha256.Sum256(body)
	if claims.MachineID != machine.ID || claims.EnvironmentID != machine.EnvironmentID || claims.InstallationGeneration != machine.InstallationGeneration || len(claims.OperationID) < 8 || len(claims.OperationID) > 128 || claims.Method != strings.ToUpper(method) || claims.Path != path || claims.BodySHA256 != base64.RawURLEncoding.EncodeToString(digest[:]) || claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(claims.IssuedAt) || claims.ExpiresAt.Sub(claims.IssuedAt) > time.Minute || claims.IssuedAt.After(now.Add(time.Minute)) || !claims.ExpiresAt.After(now) {
		return canonicalMachineProofClaims{}, ErrHelperProof
	}
	return claims, nil
}

func machineControlThumbprint(machine dbsqlc.UserMachine) string {
	publicKey, err := base64.RawURLEncoding.DecodeString(machine.PublicIdentityKey.String)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return ""
	}
	digest := sha256.Sum256(publicKey)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func strictCanonicalMachineJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrHelperProof
	}
	return nil
}
