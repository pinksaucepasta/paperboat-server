package usermachines

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/canonicaljson"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

var ErrMachineControlInvalid = errors.New("machine control credential request is invalid")

const machineControlTTL = time.Hour

type MachineControlCredential struct {
	Credential string    `json:"credential"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type machineProofEnvelope struct {
	Algorithm string `json:"alg"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type MachineProofClaims struct {
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

func (s *Service) ConfigureMachineControl(signer *mint.Provider, issuer string) {
	s.controlSigner = signer
	s.issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
}

func (s *Service) IssueMachineControl(ctx context.Context, userID, machineID string, proof, body []byte, method, path string) (MachineControlCredential, error) {
	if s.controlSigner == nil || strings.TrimSpace(userID) == "" {
		return MachineControlCredential{}, ErrMachineControlInvalid
	}
	machine, err := s.db.Queries().GetOwnedActiveUserMachineForControl(ctx, dbsqlc.GetOwnedActiveUserMachineForControlParams{ID: machineID, UserID: userID})
	if err != nil {
		return MachineControlCredential{}, ErrMachineControlInvalid
	}
	claims, err := verifyMachineProof(machine, proof, method, path, body, s.now().UTC())
	if err != nil {
		return MachineControlCredential{}, err
	}
	connector, err := s.db.Queries().EnsureControlConnectorMachine(ctx, dbsqlc.EnsureControlConnectorMachineParams{EnvironmentID: machine.EnvironmentID, ConnectorID: "runtime", MachineID: machine.ID, EdgePool: "default"})
	if err != nil || connector.MachineID != machine.ID {
		return MachineControlCredential{}, ErrMachineControlInvalid
	}
	return s.mintMachineControl(ctx, machine, claims.OperationID)
}

// IssueInitialMachineControl exchanges an already verified helper identity for
// the first machine-control credential. The HTTP boundary verifies that the
// helper credential and proof are bound to this exact machine key; this method
// then repeats the durable machine and connector binding checks before minting.
// It intentionally does not accept a user session because one-shot bootstrap
// may install the runtime before a local CLI session is usable.
func (s *Service) IssueInitialMachineControl(ctx context.Context, machineID, environmentID, operationID string) (MachineControlCredential, error) {
	if s.controlSigner == nil || strings.TrimSpace(machineID) == "" || strings.TrimSpace(environmentID) == "" || len(operationID) < 8 || len(operationID) > 128 {
		return MachineControlCredential{}, ErrMachineControlInvalid
	}
	machine, err := s.db.Queries().GetActiveUserMachineForControl(ctx, machineID)
	// Initial machine-control credentials are for managed hosts. Client
	// enrollments never run a host runtime and must not mint this credential.
	if err != nil || machine.EnvironmentID != environmentID || machine.SetupMode != "host" {
		return MachineControlCredential{}, ErrMachineControlInvalid
	}
	connector, err := s.db.Queries().EnsureControlConnectorMachine(ctx, dbsqlc.EnsureControlConnectorMachineParams{EnvironmentID: machine.EnvironmentID, ConnectorID: "runtime", MachineID: machine.ID, EdgePool: "default"})
	if err != nil || connector.MachineID != machine.ID {
		return MachineControlCredential{}, ErrMachineControlInvalid
	}
	return s.mintMachineControl(ctx, machine, operationID)
}

func (s *Service) RenewMachineControl(ctx context.Context, credential string, proof, body []byte, method, path string) (MachineControlCredential, error) {
	if s.controlSigner == nil {
		return MachineControlCredential{}, ErrMachineControlInvalid
	}
	now := s.now().UTC()
	identity, err := s.controlSigner.VerifyCredentialWithExpiryGrace(credential, s.issuer, "machine_control", now, time.Hour)
	if err != nil {
		return MachineControlCredential{}, ErrMachineControlInvalid
	}
	machine, err := s.db.Queries().GetActiveUserMachineForControl(ctx, identity.MachineID)
	if err != nil || machine.UserID != identity.UserID || machine.EnvironmentID != identity.EnvironmentID || machine.InstallationGeneration != identity.InstallationGeneration || machineKeyThumbprint(machine) != identity.KeyThumbprint {
		return MachineControlCredential{}, ErrMachineControlInvalid
	}
	claims, err := verifyMachineProof(machine, proof, method, path, body, now)
	if err != nil {
		return MachineControlCredential{}, err
	}
	return s.mintMachineControl(ctx, machine, claims.OperationID)
}

func (s *Service) mintMachineControl(ctx context.Context, machine dbsqlc.UserMachine, operationID string) (MachineControlCredential, error) {
	issuedAt := s.now().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(machineControlTTL)
	var row dbsqlc.MachineControlRenewal
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Queries().DeleteExpiredMachineControlRenewals(ctx, issuedAt.Add(-time.Hour)); err != nil {
			return err
		}
		current, err := tx.Queries().GetMachineControlRenewalForUpdate(ctx, operationID)
		if err == nil {
			return s.resolveMachineControlRenewal(ctx, tx, current, machine, operationID, issuedAt, expiresAt, &row)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// The insert is an idempotent reservation. If another request inserted
		// the operation after the lookup, PostgreSQL returns that committed row
		// through the conflict update; resolve it using the same binding and
		// expiry rules below.
		created, err := tx.Queries().CreateMachineControlRenewal(ctx, dbsqlc.CreateMachineControlRenewalParams{
			OperationID: operationID, MachineID: machine.ID, InstallationGeneration: machine.InstallationGeneration,
			CredentialJti: newID("mcc"), IssuedAt: issuedAt, ExpiresAt: expiresAt,
		})
		if err != nil {
			return err
		}
		return s.resolveMachineControlRenewal(ctx, tx, created, machine, operationID, issuedAt, expiresAt, &row)
	})
	if err != nil || row.MachineID != machine.ID || row.InstallationGeneration != machine.InstallationGeneration {
		return MachineControlCredential{}, ErrMachineControlInvalid
	}
	token, err := s.controlSigner.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-control", Subject: machine.ID, JTI: row.CredentialJti,
		IssuedAt: row.IssuedAt, ExpiresAt: row.ExpiresAt, CredentialClass: "machine_control",
		Scopes: []string{"machine:connect", "machine:renew"}, EnvironmentID: machine.EnvironmentID,
		MachineID: machine.ID, UserID: machine.UserID, KeyThumbprint: machineKeyThumbprint(machine),
		InstallationGeneration: machine.InstallationGeneration,
	})
	if err != nil {
		return MachineControlCredential{}, err
	}
	return MachineControlCredential{Credential: token, ExpiresAt: row.ExpiresAt}, nil
}

func (s *Service) resolveMachineControlRenewal(ctx context.Context, tx *db.Tx, row dbsqlc.MachineControlRenewal, machine dbsqlc.UserMachine, operationID string, issuedAt, expiresAt time.Time, result *dbsqlc.MachineControlRenewal) error {
	if row.OperationID != operationID || row.MachineID != machine.ID || row.InstallationGeneration != machine.InstallationGeneration {
		return ErrMachineControlInvalid
	}
	if row.ExpiresAt.After(issuedAt) {
		*result = row
		return nil
	}
	rotated, err := tx.Queries().RotateMachineControlRenewal(ctx, dbsqlc.RotateMachineControlRenewalParams{
		OperationID: operationID, MachineID: machine.ID, InstallationGeneration: machine.InstallationGeneration,
		CredentialJti: newID("mcc"), IssuedAt: issuedAt, ExpiresAt: expiresAt,
	})
	if err != nil {
		return err
	}
	*result = rotated
	return nil
}

func verifyMachineProof(machine dbsqlc.UserMachine, encoded []byte, method, path string, body []byte, now time.Time) (MachineProofClaims, error) {
	if len(encoded) == 0 || len(encoded) > 16<<10 || len(body) > 1<<20 || !machine.PublicIdentityKey.Valid {
		return MachineProofClaims{}, ErrMachineControlInvalid
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(machine.PublicIdentityKey.String)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return MachineProofClaims{}, ErrMachineControlInvalid
	}
	var envelope machineProofEnvelope
	if strictMachineJSON(encoded, &envelope) != nil || envelope.Algorithm != "EdDSA" {
		return MachineProofClaims{}, ErrMachineControlInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) > 16<<10 {
		return MachineProofClaims{}, ErrMachineControlInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return MachineProofClaims{}, ErrMachineControlInvalid
	}
	var claims MachineProofClaims
	bodyHash := sha256.Sum256(body)
	if strictMachineJSON(payload, &claims) != nil || claims.MachineID != machine.ID || claims.EnvironmentID != machine.EnvironmentID || claims.InstallationGeneration != machine.InstallationGeneration || len(claims.OperationID) < 8 || len(claims.OperationID) > 128 || claims.Method != method || claims.Path != path || claims.BodySHA256 != base64.RawURLEncoding.EncodeToString(bodyHash[:]) || claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(claims.IssuedAt) || claims.ExpiresAt.Sub(claims.IssuedAt) > time.Minute || claims.IssuedAt.After(now.Add(time.Minute)) || !claims.ExpiresAt.After(now) {
		return MachineProofClaims{}, ErrMachineControlInvalid
	}
	return claims, nil
}

func machineKeyThumbprint(machine dbsqlc.UserMachine) string {
	publicKey, err := base64.RawURLEncoding.DecodeString(machine.PublicIdentityKey.String)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return ""
	}
	digest := sha256.Sum256(publicKey)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func strictMachineJSON(data []byte, target any) error {
	if canonicaljson.RejectDuplicateFields(data) != nil {
		return ErrMachineControlInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrMachineControlInvalid
	}
	return nil
}
