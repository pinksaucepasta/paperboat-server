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
)

var (
	ErrConfigLeaseInvalid   = errors.New("config repository lease request is invalid")
	ErrConfigLeaseBusy      = errors.New("config repository lease is held by another writer")
	ErrConfigLeaseLost      = errors.New("config repository lease is no longer valid")
	ErrConfigLeaseReplay    = errors.New("config repository lease operation conflicts with an existing operation")
	ErrConfigWritesDisabled = errors.New("config repository writes are disabled by rollout policy")
)

const (
	minConfigLeaseTTL = 15 * time.Second
	maxConfigLeaseTTL = 2 * time.Minute
)

type ConfigLeaseService struct {
	store           *db.DB
	audit           *audit.Writer
	clock           func() time.Time
	identities      *EnrollmentService
	signer          *mint.Provider
	issuer          string
	warningRevision string
	mode            string
	byodEnabled     bool
	allowlist       map[string]bool
}

func NewConfigLeaseService(store *db.DB, writer *audit.Writer) *ConfigLeaseService {
	return &ConfigLeaseService{store: store, audit: writer, clock: func() time.Time { return time.Now().UTC() }}
}

func (s *ConfigLeaseService) ConfigureAuthentication(identities *EnrollmentService, signer *mint.Provider, issuer, warningRevision string) {
	s.identities, s.signer, s.issuer = identities, signer, strings.TrimRight(strings.TrimSpace(issuer), "/")
	s.warningRevision = strings.TrimSpace(warningRevision)
}

func (s *ConfigLeaseService) ConfigureRollout(mode string, byodEnabled bool, environmentAllowlist []string) {
	s.mode, s.byodEnabled = strings.TrimSpace(mode), byodEnabled
	s.allowlist = make(map[string]bool, len(environmentAllowlist))
	for _, environmentID := range environmentAllowlist {
		s.allowlist[strings.TrimSpace(environmentID)] = true
	}
}

type ConfigLeaseHolder struct {
	RepositoryID       string
	AssignmentID       string
	EnvironmentID      string
	HelperID           string
	HelperGeneration   int64
	BaseRemoteRevision string
}

type ConfigLease struct {
	LeaseID       string    `json:"lease_id"`
	RepositoryID  string    `json:"repository_id"`
	AssignmentID  string    `json:"assignment_id"`
	EnvironmentID string    `json:"environment_id"`
	HelperID      string    `json:"helper_id"`
	FencingToken  int64     `json:"fencing_token"`
	BaseRevision  string    `json:"base_remote_revision"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (s *ConfigLeaseService) Authenticate(ctx context.Context, identityToken, credential string, proof, body []byte, method, path string) (ConfigLeaseHolder, error) {
	if s == nil || s.store == nil || s.identities == nil || s.signer == nil || s.issuer == "" {
		return ConfigLeaseHolder{}, ErrConfigLeaseInvalid
	}
	identity, err := s.identities.VerifyHelperRequest(ctx, identityToken, proof, method, path, body)
	if err != nil {
		return ConfigLeaseHolder{}, ErrConfigLeaseInvalid
	}
	claims, err := s.signer.VerifyCredential(credential, s.issuer, "config_sync", s.clock())
	if err != nil || claims.EnvironmentID != identity.EnvironmentID || claims.HelperID != identity.HelperID || claims.Subject != identity.HelperID {
		return ConfigLeaseHolder{}, ErrConfigLeaseInvalid
	}
	persistedCredential, err := s.store.Queries().GetActiveControlConfigCredentialByJTI(ctx, dbsqlc.GetActiveControlConfigCredentialByJTIParams{
		Jti: claims.JTI, EnvironmentID: claims.EnvironmentID, HelperID: claims.HelperID,
		AssignmentID: claims.AssignmentID, Now: s.clock().UTC(),
	})
	if err != nil || !persistedCredential.WarningRevision.Valid || persistedCredential.WarningRevision.String != claims.WarningRevision {
		return ConfigLeaseHolder{}, ErrConfigLeaseInvalid
	}
	assignment, err := s.store.Queries().GetEligibleControlConfigAssignment(ctx, dbsqlc.GetEligibleControlConfigAssignmentParams{
		EnvironmentID: identity.EnvironmentID, HelperID: identity.HelperID,
	})
	if err != nil || assignment.ID != claims.AssignmentID || !assignment.RepositoryID.Valid ||
		!assignment.WarningRevision.Valid || assignment.WarningRevision.String != claims.WarningRevision {
		return ConfigLeaseHolder{}, ErrConfigLeaseInvalid
	}
	byod, err := s.store.Queries().IsControlEnvironmentBYOD(ctx, identity.EnvironmentID)
	if err != nil || s.mode == "" || s.mode == "disabled" ||
		(len(s.allowlist) > 0 && !s.allowlist[identity.EnvironmentID]) ||
		(byod && (!s.byodEnabled || s.warningRevision == "" || assignment.WarningRevision.String != s.warningRevision)) {
		return ConfigLeaseHolder{}, ErrConfigLeaseInvalid
	}
	helper, err := s.store.Queries().GetActiveControlHelperForEnvironment(ctx, identity.EnvironmentID)
	if err != nil || helper.ID != identity.HelperID {
		return ConfigLeaseHolder{}, ErrConfigLeaseInvalid
	}
	return ConfigLeaseHolder{
		RepositoryID: assignment.RepositoryID.String, AssignmentID: assignment.ID, EnvironmentID: identity.EnvironmentID,
		HelperID: identity.HelperID, HelperGeneration: helper.Generation,
	}, nil
}

func (s *ConfigLeaseService) Acquire(ctx context.Context, operationID string, holder ConfigLeaseHolder, ttl time.Duration) (ConfigLease, error) {
	if err := validateConfigLeaseRequest(operationID, holder, ttl); err != nil || s == nil || s.store == nil {
		return ConfigLease{}, ErrConfigLeaseInvalid
	}
	if s.mode != "leased_writes" {
		return ConfigLease{}, ErrConfigWritesDisabled
	}
	requestHash := configLeaseRequestHash("acquire", operationID, holder, "", 0, ttl)
	now := s.clock().UTC()
	var result ConfigLease
	var resultErr error
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		replayed, replayErr := replayConfigLeaseOperation(ctx, tx, operationID, requestHash)
		if replayErr == nil {
			result, resultErr = replayed.lease, replayed.err
			return nil
		}
		if !errors.Is(replayErr, sql.ErrNoRows) {
			return replayErr
		}
		assignment, err := tx.Queries().GetEligibleControlConfigAssignment(ctx, dbsqlc.GetEligibleControlConfigAssignmentParams{
			EnvironmentID: holder.EnvironmentID, HelperID: holder.HelperID,
		})
		if err != nil || assignment.ID != holder.AssignmentID || !assignment.RepositoryID.Valid || assignment.RepositoryID.String != holder.RepositoryID {
			return ErrConfigLeaseInvalid
		}
		helper, err := tx.Queries().GetActiveControlHelperForEnvironment(ctx, holder.EnvironmentID)
		if err != nil || helper.ID != holder.HelperID || helper.Generation != holder.HelperGeneration {
			return ErrConfigLeaseInvalid
		}
		if _, err = tx.Queries().EnsureControlConfigLeaseAuthority(ctx, holder.RepositoryID); err != nil {
			return err
		}
		leaseID, err := randomHex("cfglse_", 12)
		if err != nil {
			return err
		}
		expiresAt := now.Add(ttl)
		row, err := tx.Queries().GrantControlConfigRepositoryLease(ctx, dbsqlc.GrantControlConfigRepositoryLeaseParams{
			LeaseID: sql.NullString{String: leaseID, Valid: true}, AssignmentID: sql.NullString{String: holder.AssignmentID, Valid: true},
			EnvironmentID: sql.NullString{String: holder.EnvironmentID, Valid: true}, HelperID: sql.NullString{String: holder.HelperID, Valid: true},
			HelperGeneration:   sql.NullInt64{Int64: holder.HelperGeneration, Valid: true},
			BaseRemoteRevision: nullableString(holder.BaseRemoteRevision), OperationID: sql.NullString{String: operationID, Valid: true},
			Now: sql.NullTime{Time: now, Valid: true}, ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true}, RepositoryID: holder.RepositoryID,
		})
		state := "acquired"
		if errors.Is(err, sql.ErrNoRows) {
			state, resultErr = "busy", ErrConfigLeaseBusy
		} else if err != nil {
			return err
		} else {
			result = leaseFromAuthority(row)
		}
		if _, err = tx.Queries().CreateControlConfigLeaseOperation(ctx, dbsqlc.CreateControlConfigLeaseOperationParams{
			OperationID: operationID, OperationType: "acquire", RequestHash: requestHash, RepositoryID: holder.RepositoryID,
			LeaseID: nullableString(result.LeaseID), FencingToken: nullableInt64(result.FencingToken),
			ResultState: state, ExpiresAt: nullableTime(result.ExpiresAt),
		}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorType: audit.ActorSystem, EventType: "config.lease_" + state,
			ResourceType: "config_repository", ResourceID: holder.RepositoryID, IdempotencyKey: "config.lease:" + operationID,
			Metadata: map[string]any{"assignment_id": holder.AssignmentID, "environment_id": holder.EnvironmentID, "helper_id": holder.HelperID}})
	})
	if err != nil {
		return ConfigLease{}, err
	}
	return result, resultErr
}

func (s *ConfigLeaseService) Renew(ctx context.Context, operationID string, holder ConfigLeaseHolder, leaseID string, fencingToken int64, ttl time.Duration) (ConfigLease, error) {
	if err := validateHeldConfigLeaseRequest(operationID, holder, leaseID, fencingToken, ttl); err != nil || s == nil || s.store == nil {
		return ConfigLease{}, ErrConfigLeaseInvalid
	}
	requestHash := configLeaseRequestHash("renew", operationID, holder, leaseID, fencingToken, ttl)
	now := s.clock().UTC()
	var result ConfigLease
	var resultErr error
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		replayed, replayErr := replayConfigLeaseOperation(ctx, tx, operationID, requestHash)
		if replayErr == nil {
			result, resultErr = replayed.lease, replayed.err
			return nil
		}
		if !errors.Is(replayErr, sql.ErrNoRows) {
			return replayErr
		}
		if err := validateEligibleLeaseHolder(ctx, tx, holder); err != nil {
			return err
		}
		expiresAt := now.Add(ttl)
		row, updateErr := tx.Queries().RenewControlConfigRepositoryLease(ctx, dbsqlc.RenewControlConfigRepositoryLeaseParams{
			ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true}, Now: now, RepositoryID: holder.RepositoryID,
			LeaseID: sql.NullString{String: leaseID, Valid: true}, FencingToken: fencingToken,
		})
		state := "renewed"
		if errors.Is(updateErr, sql.ErrNoRows) {
			state, resultErr = "lost", ErrConfigLeaseLost
		} else if updateErr != nil {
			return updateErr
		} else {
			result = leaseFromAuthority(row)
		}
		return s.recordLeaseOperation(ctx, tx, operationID, "renew", requestHash, holder, result, state)
	})
	if err != nil {
		return ConfigLease{}, err
	}
	return result, resultErr
}

func (s *ConfigLeaseService) Release(ctx context.Context, operationID string, holder ConfigLeaseHolder, leaseID string, fencingToken int64) error {
	if err := validateHeldConfigLeaseRequest(operationID, holder, leaseID, fencingToken, minConfigLeaseTTL); err != nil || s == nil || s.store == nil {
		return ErrConfigLeaseInvalid
	}
	requestHash := configLeaseRequestHash("release", operationID, holder, leaseID, fencingToken, 0)
	now := s.clock().UTC()
	var resultErr error
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		replayed, replayErr := replayConfigLeaseOperation(ctx, tx, operationID, requestHash)
		if replayErr == nil {
			resultErr = replayed.err
			return nil
		}
		if !errors.Is(replayErr, sql.ErrNoRows) {
			return replayErr
		}
		if err := validateEligibleLeaseHolder(ctx, tx, holder); err != nil {
			return err
		}
		row, updateErr := tx.Queries().ReleaseControlConfigRepositoryLease(ctx, dbsqlc.ReleaseControlConfigRepositoryLeaseParams{
			Now: now, RepositoryID: holder.RepositoryID, LeaseID: sql.NullString{String: leaseID, Valid: true}, FencingToken: fencingToken,
		})
		state := "released"
		if errors.Is(updateErr, sql.ErrNoRows) {
			state, resultErr = "lost", ErrConfigLeaseLost
		} else if updateErr != nil {
			return updateErr
		}
		result := leaseFromAuthority(row)
		result.LeaseID, result.FencingToken = leaseID, fencingToken
		return s.recordLeaseOperation(ctx, tx, operationID, "release", requestHash, holder, result, state)
	})
	if err != nil {
		return err
	}
	return resultErr
}

func validateEligibleLeaseHolder(ctx context.Context, tx *db.Tx, holder ConfigLeaseHolder) error {
	assignment, err := tx.Queries().GetEligibleControlConfigAssignment(ctx, dbsqlc.GetEligibleControlConfigAssignmentParams{
		EnvironmentID: holder.EnvironmentID, HelperID: holder.HelperID,
	})
	if err != nil || assignment.ID != holder.AssignmentID || !assignment.RepositoryID.Valid || assignment.RepositoryID.String != holder.RepositoryID {
		return ErrConfigLeaseLost
	}
	helper, err := tx.Queries().GetActiveControlHelperForEnvironment(ctx, holder.EnvironmentID)
	if err != nil || helper.ID != holder.HelperID || helper.Generation != holder.HelperGeneration {
		return ErrConfigLeaseLost
	}
	return nil
}

func (s *ConfigLeaseService) recordLeaseOperation(ctx context.Context, tx *db.Tx, operationID, operationType string, requestHash []byte, holder ConfigLeaseHolder, lease ConfigLease, state string) error {
	if _, err := tx.Queries().CreateControlConfigLeaseOperation(ctx, dbsqlc.CreateControlConfigLeaseOperationParams{
		OperationID: operationID, OperationType: operationType, RequestHash: requestHash, RepositoryID: holder.RepositoryID,
		LeaseID: nullableString(lease.LeaseID), FencingToken: nullableInt64(lease.FencingToken),
		ResultState: state, ExpiresAt: nullableTime(lease.ExpiresAt),
	}); err != nil {
		return err
	}
	return s.audit.WriteTx(ctx, tx, audit.Event{ActorType: audit.ActorSystem, EventType: "config.lease_" + state,
		ResourceType: "config_repository", ResourceID: holder.RepositoryID, IdempotencyKey: "config.lease:" + operationID,
		Metadata: map[string]any{"assignment_id": holder.AssignmentID, "environment_id": holder.EnvironmentID, "helper_id": holder.HelperID}})
}

func validateConfigLeaseRequest(operationID string, holder ConfigLeaseHolder, ttl time.Duration) error {
	if strings.TrimSpace(operationID) == "" || len(operationID) > 256 || holder.RepositoryID == "" ||
		holder.AssignmentID == "" || holder.EnvironmentID == "" || holder.HelperID == "" ||
		holder.HelperGeneration < 1 || ttl < minConfigLeaseTTL || ttl > maxConfigLeaseTTL ||
		len(holder.BaseRemoteRevision) > 256 {
		return ErrConfigLeaseInvalid
	}
	return nil
}

func validateHeldConfigLeaseRequest(operationID string, holder ConfigLeaseHolder, leaseID string, fencingToken int64, ttl time.Duration) error {
	if validateConfigLeaseRequest(operationID, holder, ttl) != nil || strings.TrimSpace(leaseID) == "" || fencingToken < 1 {
		return ErrConfigLeaseInvalid
	}
	return nil
}

type leaseReplay struct {
	lease ConfigLease
	err   error
}

func replayConfigLeaseOperation(ctx context.Context, tx *db.Tx, operationID string, requestHash []byte) (leaseReplay, error) {
	row, err := tx.Queries().GetControlConfigLeaseOperation(ctx, operationID)
	if err != nil {
		return leaseReplay{}, err
	}
	if !bytes.Equal(row.RequestHash, requestHash) {
		return leaseReplay{}, ErrConfigLeaseReplay
	}
	switch row.ResultState {
	case "busy":
		return leaseReplay{err: ErrConfigLeaseBusy}, nil
	case "lost":
		return leaseReplay{err: ErrConfigLeaseLost}, nil
	default:
		return leaseReplay{lease: ConfigLease{LeaseID: row.LeaseID.String, RepositoryID: row.RepositoryID, FencingToken: row.FencingToken.Int64, ExpiresAt: row.ExpiresAt.Time}}, nil
	}
}

func configLeaseRequestHash(kind, operationID string, holder ConfigLeaseHolder, leaseID string, fencingToken int64, ttl time.Duration) []byte {
	encoded, _ := json.Marshal(struct {
		Kind, OperationID string
		Holder            ConfigLeaseHolder
		LeaseID           string
		FencingToken      int64
		TTL               int64
	}{kind, operationID, holder, leaseID, fencingToken, int64(ttl)})
	sum := sha256.Sum256(encoded)
	return sum[:]
}

func leaseFromAuthority(row dbsqlc.ControlConfigRepositoryLeaseAuthority) ConfigLease {
	return ConfigLease{
		LeaseID: row.LeaseID.String, RepositoryID: row.RepositoryID, AssignmentID: row.AssignmentID.String,
		EnvironmentID: row.EnvironmentID.String, HelperID: row.HelperID.String, FencingToken: row.LastFencingToken,
		BaseRevision: row.BaseRemoteRevision.String, ExpiresAt: row.ExpiresAt.Time,
	}
}

func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func nullableInt64(value int64) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: value != 0}
}

func nullableTime(value time.Time) sql.NullTime {
	return sql.NullTime{Time: value, Valid: !value.IsZero()}
}
