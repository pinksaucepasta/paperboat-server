package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

var (
	ErrConfigRepositoryAccessInvalid   = errors.New("config repository access request is invalid")
	ErrConfigRepositoryAccessReplay    = errors.New("config repository access operation conflicts with an earlier request")
	ErrConfigRepositoryAccessUncertain = errors.New("config repository access issuance outcome is uncertain")
)

type ScopedRepositoryCredential struct {
	Token     string
	ExpiresAt time.Time
}

type ConfigRepositoryAccessIssuer interface {
	IssueRepositoryAccess(context.Context, string, string, string) (ScopedRepositoryCredential, error)
	RevokeRepositoryAccess(context.Context, string) error
}

type ConfigRepositoryAccessIssuerFuncs struct {
	Issue  func(context.Context, string, string, string) (ScopedRepositoryCredential, error)
	Revoke func(context.Context, string) error
}

func (f ConfigRepositoryAccessIssuerFuncs) IssueRepositoryAccess(ctx context.Context, authorizationRef, repositoryID, contentsPermission string) (ScopedRepositoryCredential, error) {
	return f.Issue(ctx, authorizationRef, repositoryID, contentsPermission)
}
func (f ConfigRepositoryAccessIssuerFuncs) RevokeRepositoryAccess(ctx context.Context, token string) error {
	return f.Revoke(ctx, token)
}

type ConfigRepositoryAccess struct {
	RepositoryID  string    `json:"repository_id"`
	AssignmentID  string    `json:"assignment_id"`
	EnvironmentID string    `json:"environment_id"`
	HelperID      string    `json:"helper_id"`
	CloneURL      string    `json:"clone_url"`
	PublishURL    string    `json:"publish_url"`
	Branch        string    `json:"branch"`
	Username      string    `json:"username"`
	Password      string    `json:"password"`
	Capability    string    `json:"capability"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type ConfigRepositoryAccessService struct {
	store         *db.DB
	leases        *ConfigLeaseService
	issuer        ConfigRepositoryAccessIssuer
	encryptionKey string
	audit         *audit.Writer
	clock         func() time.Time
}

func NewConfigRepositoryAccessService(store *db.DB, leases *ConfigLeaseService, issuer ConfigRepositoryAccessIssuer, encryptionKey string, writer *audit.Writer) *ConfigRepositoryAccessService {
	return &ConfigRepositoryAccessService{
		store: store, leases: leases, issuer: issuer, encryptionKey: encryptionKey,
		audit: writer, clock: func() time.Time { return time.Now().UTC() },
	}
}

func (s *ConfigRepositoryAccessService) Issue(ctx context.Context, identityToken, configCredential string, proof, body []byte, method, path, operationID string) (ConfigRepositoryAccess, error) {
	if s == nil || s.store == nil || s.leases == nil || s.issuer == nil || s.encryptionKey == "" ||
		strings.TrimSpace(operationID) == "" || len(operationID) > 256 {
		return ConfigRepositoryAccess{}, ErrConfigRepositoryAccessInvalid
	}
	holder, err := s.leases.Authenticate(ctx, identityToken, configCredential, proof, body, method, path)
	if err != nil {
		return ConfigRepositoryAccess{}, ErrConfigRepositoryAccessInvalid
	}
	contentsPermission := "write"
	capability := "repository_contents_write"
	if s.leases.mode == "read_only" {
		contentsPermission, capability = "read", "repository_contents_read"
	}
	requestHash := repositoryAccessRequestHash(operationID, holder, capability)
	now := s.clock().UTC()
	existing, err := s.store.Queries().GetControlConfigRepositoryAccessOperation(ctx, operationID)
	if err == nil {
		return s.replay(existing, requestHash, capability, now)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ConfigRepositoryAccess{}, err
	}
	repository, err := s.store.Queries().GetActiveControlConfigRepository(ctx, holder.RepositoryID)
	if err != nil || !repository.AuthorizationRef.Valid || !repository.ExternalRepositoryID.Valid ||
		!repository.CloneUrl.Valid || !repository.PublishUrl.Valid || !repository.DefaultBranch.Valid ||
		repository.CredentialCapability.String != "github_app_installation_repository_contents_rw" ||
		!safeRepositoryCoordinate(repository.CloneUrl.String) || !safeRepositoryCoordinate(repository.PublishUrl.String) {
		return ConfigRepositoryAccess{}, ErrConfigRepositoryAccessInvalid
	}
	_, err = s.store.Queries().ReserveControlConfigRepositoryAccess(ctx, dbsqlc.ReserveControlConfigRepositoryAccessParams{
		OperationID: operationID, RequestHash: requestHash, RepositoryID: holder.RepositoryID,
		AssignmentID: holder.AssignmentID, EnvironmentID: holder.EnvironmentID, HelperID: holder.HelperID,
		HelperGeneration: holder.HelperGeneration, WarningRevision: currentWarningRevision(ctx, s.store, holder.EnvironmentID),
	})
	if errors.Is(err, sql.ErrNoRows) {
		existing, getErr := s.store.Queries().GetControlConfigRepositoryAccessOperation(ctx, operationID)
		if getErr != nil {
			return ConfigRepositoryAccess{}, getErr
		}
		return s.replay(existing, requestHash, capability, now)
	}
	if err != nil {
		return ConfigRepositoryAccess{}, err
	}

	issued, issueErr := s.issuer.IssueRepositoryAccess(ctx, repository.AuthorizationRef.String, repository.ExternalRepositoryID.String, contentsPermission)
	if issueErr != nil {
		_, _ = s.store.Queries().MarkControlConfigRepositoryAccessUncertain(ctx, dbsqlc.MarkControlConfigRepositoryAccessUncertainParams{
			LastErrorCode: sql.NullString{String: "provider_outcome_uncertain", Valid: true}, Now: now, OperationID: operationID,
		})
		return ConfigRepositoryAccess{}, errors.Join(ErrConfigRepositoryAccessUncertain, issueErr)
	}
	if issued.Token == "" || len(issued.Token) > 4096 || !issued.ExpiresAt.After(now.Add(time.Minute)) ||
		issued.ExpiresAt.After(now.Add(time.Hour+time.Minute)) {
		return ConfigRepositoryAccess{}, ErrConfigRepositoryAccessInvalid
	}
	result := ConfigRepositoryAccess{
		RepositoryID: holder.RepositoryID, AssignmentID: holder.AssignmentID, EnvironmentID: holder.EnvironmentID,
		HelperID: holder.HelperID, CloneURL: repository.CloneUrl.String, PublishURL: repository.PublishUrl.String,
		Branch: repository.DefaultBranch.String, Username: "x-access-token", Password: issued.Token,
		Capability: capability, ExpiresAt: issued.ExpiresAt.UTC(),
	}
	encoded, _ := json.Marshal(result)
	ciphertext, err := secrets.Encrypt(s.encryptionKey, string(encoded))
	if err != nil {
		return ConfigRepositoryAccess{}, err
	}
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Queries().CompleteControlConfigRepositoryAccess(ctx, dbsqlc.CompleteControlConfigRepositoryAccessParams{
			AccessCiphertext: ciphertext, ExpiresAt: sql.NullTime{Time: issued.ExpiresAt.UTC(), Valid: true}, Now: now, OperationID: operationID,
		}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorType: audit.ActorSystem, EventType: "config.repository_access_issued",
			ResourceType: "config_repository", ResourceID: holder.RepositoryID,
			IdempotencyKey: "config.repository_access:" + operationID,
			Metadata:       map[string]any{"assignment_id": holder.AssignmentID, "environment_id": holder.EnvironmentID, "helper_id": holder.HelperID, "expires_at": issued.ExpiresAt.UTC()}})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ConfigRepositoryAccess{}, ErrConfigRepositoryAccessInvalid
	}
	return result, err
}

func (s *ConfigRepositoryAccessService) replay(row dbsqlc.ControlConfigRepositoryAccessOperation, requestHash []byte, capability string, now time.Time) (ConfigRepositoryAccess, error) {
	if !bytes.Equal(row.RequestHash, requestHash) {
		return ConfigRepositoryAccess{}, ErrConfigRepositoryAccessReplay
	}
	if row.State == "pending" || row.State == "uncertain" {
		return ConfigRepositoryAccess{}, ErrConfigRepositoryAccessUncertain
	}
	if row.State != "issued" || row.RevokedAt.Valid || !row.ExpiresAt.Valid || !row.ExpiresAt.Time.After(now) {
		return ConfigRepositoryAccess{}, ErrConfigRepositoryAccessInvalid
	}
	plaintext, err := secrets.Decrypt(s.encryptionKey, row.AccessCiphertext)
	if err != nil {
		return ConfigRepositoryAccess{}, ErrConfigRepositoryAccessInvalid
	}
	var result ConfigRepositoryAccess
	decoder := json.NewDecoder(strings.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || result.Password == "" || result.Capability != capability || !result.ExpiresAt.After(now) {
		return ConfigRepositoryAccess{}, ErrConfigRepositoryAccessInvalid
	}
	return result, nil
}

func repositoryAccessRequestHash(operationID string, holder ConfigLeaseHolder, capability string) []byte {
	encoded, _ := json.Marshal(struct {
		OperationID string
		Holder      ConfigLeaseHolder
		Capability  string
	}{operationID, holder, capability})
	sum := sha256.Sum256(encoded)
	return sum[:]
}

func safeRepositoryCoordinate(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.User == nil && parsed.Hostname() != "" &&
		parsed.RawQuery == "" && parsed.Fragment == "" && strings.HasSuffix(parsed.Path, ".git")
}

func currentWarningRevision(ctx context.Context, store *db.DB, environmentID string) string {
	assignment, err := store.Queries().GetControlConfigAssignment(ctx, environmentID)
	if err != nil || !assignment.WarningRevision.Valid {
		return ""
	}
	return assignment.WarningRevision.String
}

func (s *ConfigRepositoryAccessService) RevocationWorker(interval time.Duration, batchSize int32) func(context.Context) error {
	if interval <= 0 {
		interval = time.Minute
	}
	if batchSize < 1 || batchSize > 100 {
		batchSize = 25
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := s.revokeProviderAccess(ctx, batchSize); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func (s *ConfigRepositoryAccessService) revokeProviderAccess(ctx context.Context, batchSize int32) error {
	now := s.clock().UTC()
	rows, err := s.store.Queries().ListControlConfigRepositoryAccessPendingProviderRevoke(ctx, dbsqlc.ListControlConfigRepositoryAccessPendingProviderRevokeParams{Now: sql.NullTime{Time: now, Valid: true}, RowLimit: batchSize})
	if err != nil {
		return err
	}
	for _, row := range rows {
		plaintext, decryptErr := secrets.Decrypt(s.encryptionKey, row.AccessCiphertext)
		var access ConfigRepositoryAccess
		if decryptErr == nil {
			decryptErr = json.Unmarshal([]byte(plaintext), &access)
		}
		if decryptErr != nil || access.Password == "" {
			_, _ = s.store.Queries().RecordControlConfigRepositoryAccessRevokeFailure(ctx, dbsqlc.RecordControlConfigRepositoryAccessRevokeFailureParams{
				LastErrorCode: sql.NullString{String: "access_decrypt_failed", Valid: true}, Now: now, OperationID: row.OperationID,
			})
			continue
		}
		if revokeErr := s.issuer.RevokeRepositoryAccess(ctx, access.Password); revokeErr != nil {
			_, _ = s.store.Queries().RecordControlConfigRepositoryAccessRevokeFailure(ctx, dbsqlc.RecordControlConfigRepositoryAccessRevokeFailureParams{
				LastErrorCode: sql.NullString{String: "provider_revoke_failed", Valid: true}, Now: now, OperationID: row.OperationID,
			})
			continue
		}
		if _, err := s.store.Queries().MarkControlConfigRepositoryAccessProviderRevoked(ctx, dbsqlc.MarkControlConfigRepositoryAccessProviderRevokedParams{Now: sql.NullTime{Time: now, Valid: true}, OperationID: row.OperationID}); err != nil {
			return err
		}
	}
	return nil
}
