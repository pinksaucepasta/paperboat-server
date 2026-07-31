package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

var (
	ErrConfigCredentialInvalid = errors.New("config credential request is invalid")
	ErrConfigCredentialReplay  = errors.New("config credential request conflicts with an existing operation")
)

type ConfigCredentialService struct {
	store           *db.DB
	signer          *mint.Provider
	issuer          string
	encryptionKey   string
	clock           func() time.Time
	audit           *audit.Writer
	warningRevision string
	mode            string
	byodEnabled     bool
	allowlist       map[string]bool
}

func NewConfigCredentialService(store *db.DB, signer *mint.Provider, issuer, encryptionKey string) *ConfigCredentialService {
	return &ConfigCredentialService{store: store, signer: signer, issuer: strings.TrimRight(issuer, "/"), encryptionKey: encryptionKey, clock: func() time.Time { return time.Now().UTC() }}
}

func (s *ConfigCredentialService) SetAuditWriter(writer *audit.Writer) { s.audit = writer }
func (s *ConfigCredentialService) SetWarningRevision(revision string) {
	s.warningRevision = strings.TrimSpace(revision)
}
func (s *ConfigCredentialService) SetRollout(mode string, byodEnabled bool, environmentAllowlist []string) {
	s.mode, s.byodEnabled = strings.TrimSpace(mode), byodEnabled
	s.allowlist = make(map[string]bool, len(environmentAllowlist))
	for _, environmentID := range environmentAllowlist {
		s.allowlist[strings.TrimSpace(environmentID)] = true
	}
}

type ConfigCredential struct {
	Credential      string    `json:"credential"`
	EnvironmentID   string    `json:"environment_id"`
	MachineID       string    `json:"machine_id"`
	AssignmentID    string    `json:"assignment_id"`
	WarningRevision string    `json:"warning_revision"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func (s *ConfigCredentialService) Issue(ctx context.Context, identityToken string, proof, body []byte, method, path string) (ConfigCredential, error) {
	if s == nil || s.signer == nil || s.store == nil || s.issuer == "" || s.encryptionKey == "" {
		return ConfigCredential{}, ErrConfigCredentialInvalid
	}
	claims, err := (&EnrollmentService{store: s.store, signer: s.signer, issuer: s.issuer, clock: s.clock}).VerifyMachineRequest(ctx, identityToken, proof, method, path, body)
	if err != nil {
		return ConfigCredential{}, err
	}
	byod, err := s.store.Queries().IsControlEnvironmentBYOD(ctx, claims.EnvironmentID)
	if err != nil || s.mode == "" || s.mode == "disabled" ||
		(len(s.allowlist) > 0 && !s.allowlist[claims.EnvironmentID]) ||
		(byod && !s.byodEnabled) {
		return ConfigCredential{}, ErrConfigCredentialInvalid
	}
	requestHash := sha256.Sum256(append([]byte(claims.MachineID+"\x00"+claims.EnvironmentID+"\x00"), body...))
	operationKey := "config-credential:" + claims.MachineID + ":" + claims.OperationID
	now := s.clock().UTC()
	var result ConfigCredential
	issuedNew := false
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		existing, getErr := tx.Queries().GetControlConfigCredentialByOperation(ctx, operationKey)
		if getErr == nil {
			if !bytes.Equal(existing.RequestHash, requestHash[:]) || existing.RevokedAt.Valid || !existing.ExpiresAt.After(now) {
				return ErrConfigCredentialReplay
			}
			plaintext, decryptErr := secrets.Decrypt(s.encryptionKey, existing.CredentialCiphertext)
			if decryptErr != nil || json.Unmarshal([]byte(plaintext), &result) != nil {
				return ErrConfigCredentialInvalid
			}
			return nil
		}
		if !errors.Is(getErr, sql.ErrNoRows) {
			return getErr
		}
		assignment, err := tx.Queries().GetEligibleMachineConfigAssignment(ctx, dbsqlc.GetEligibleMachineConfigAssignmentParams{MachineID: claims.MachineID, EnvironmentID: claims.EnvironmentID, InstallationGeneration: claims.InstallationGeneration})
		if err != nil || !assignment.WarningRevision.Valid || assignment.WarningRevision.String == "" {
			return ErrConfigCredentialInvalid
		}
		byod, err := tx.Queries().IsControlEnvironmentBYOD(ctx, claims.EnvironmentID)
		if err != nil || (byod && (s.warningRevision == "" || assignment.WarningRevision.String != s.warningRevision)) {
			return ErrConfigCredentialInvalid
		}
		jti, err := randomHex("jti_", 24)
		if err != nil {
			return err
		}
		machineID := claims.MachineID
		if strings.TrimSpace(machineID) == "" || assignment.MachineID != machineID {
			return ErrConfigCredentialInvalid
		}
		expiresAt := now.Add(5 * time.Minute)
		token, err := s.signer.SignCredential(mint.CredentialInput{Issuer: s.issuer, Audience: "paperboat-machine", Subject: claims.MachineID, JTI: jti, IssuedAt: now, ExpiresAt: expiresAt, CredentialClass: "config_sync", Scopes: []string{"config:pull", "config:apply", "config:report"}, EnvironmentID: claims.EnvironmentID, MachineID: machineID, InstallationGeneration: claims.InstallationGeneration, AssignmentID: assignment.ID, WarningRevision: assignment.WarningRevision.String})
		if err != nil {
			return err
		}
		result = ConfigCredential{Credential: token, EnvironmentID: claims.EnvironmentID, MachineID: claims.MachineID, AssignmentID: assignment.ID, WarningRevision: assignment.WarningRevision.String, ExpiresAt: expiresAt}
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		ciphertext, err := secrets.Encrypt(s.encryptionKey, string(encoded))
		if err != nil {
			return err
		}
		jtiHash := sha256.Sum256([]byte(jti))
		if _, err = tx.Queries().CreateControlConfigCredential(ctx, dbsqlc.CreateControlConfigCredentialParams{JtiHash: jtiHash[:], Jti: jti, OperationKey: operationKey, RequestHash: requestHash[:], EnvironmentID: claims.EnvironmentID, MachineID: claims.MachineID, AssignmentID: assignment.ID, WarningRevision: assignment.WarningRevision, CredentialCiphertext: ciphertext, ExpiresAt: expiresAt}); err != nil {
			return err
		}
		issuedNew = true
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorType: audit.ActorSystem, EventType: "config.credential_issued", ResourceType: "config_assignment", ResourceID: assignment.ID, IdempotencyKey: operationKey, Metadata: map[string]any{"environment_id": claims.EnvironmentID, "machine_id": claims.MachineID, "warning_revision": assignment.WarningRevision.String, "expires_at": expiresAt}})
	})
	if err == nil && issuedNew {
		observability.ControlCredentialIssued()
	}
	return result, err
}
