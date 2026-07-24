package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var (
	ErrConfigConflictResolutionInvalid = errors.New("config conflict resolution is invalid")
	ErrConfigConflictResolutionStale   = errors.New("config conflict resolution is stale")
)

type ConfigConflictResolution struct {
	ID                     string `json:"id"`
	Path                   string `json:"path"`
	ConflictRevision       string `json:"conflict_revision"`
	ExpectedRemoteRevision string `json:"expected_remote_revision"`
	Action                 string `json:"action"`
}

type ConfigConflictService struct {
	store  *db.DB
	leases *ConfigLeaseService
	clock  func() time.Time
	audit  *audit.Writer
}

func NewConfigConflictService(store *db.DB, leases *ConfigLeaseService, writer *audit.Writer) *ConfigConflictService {
	return &ConfigConflictService{store: store, leases: leases, audit: writer, clock: func() time.Time { return time.Now().UTC() }}
}

func (s *ConfigConflictService) Request(ctx context.Context, userID, environmentID string, expectedAssignmentVersion int64, resolution ConfigConflictResolution) (ConfigConflictResolution, error) {
	if s == nil || s.store == nil || strings.TrimSpace(userID) == "" || strings.TrimSpace(environmentID) == "" ||
		expectedAssignmentVersion < 1 || !validConfigConflictResolution(resolution) {
		return ConfigConflictResolution{}, ErrConfigConflictResolutionInvalid
	}
	id, err := randomHex("cfgres_", 12)
	if err != nil {
		return ConfigConflictResolution{}, err
	}
	var result dbsqlc.ControlConfigConflictResolution
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		current, queryErr := tx.Queries().GetOwnedControlConfigConflictContext(ctx, dbsqlc.GetOwnedControlConfigConflictContextParams{
			EnvironmentID: environmentID, OwnerUserID: sql.NullString{String: userID, Valid: true},
		})
		if queryErr != nil || current.AssignmentVersion != expectedAssignmentVersion ||
			!current.RepositoryID.Valid || !current.RemoteRevision.Valid ||
			current.RemoteRevision.String != resolution.ExpectedRemoteRevision {
			return ErrConfigConflictResolutionStale
		}
		var conflicts []ConfigStatusPath
		if json.Unmarshal(current.Conflicts, &conflicts) != nil {
			return ErrConfigConflictResolutionStale
		}
		found := false
		for _, conflict := range conflicts {
			if conflict.Path == resolution.Path && conflict.Revision == resolution.ConflictRevision {
				found = true
				break
			}
		}
		if !found {
			return ErrConfigConflictResolutionStale
		}
		result, queryErr = tx.Queries().CreateControlConfigConflictResolution(ctx, dbsqlc.CreateControlConfigConflictResolutionParams{
			ID: id, EnvironmentID: environmentID, RepositoryID: current.RepositoryID.String,
			AssignmentID: current.AssignmentID, ConflictRevision: resolution.ConflictRevision,
			Path: resolution.Path, Action: resolution.Action,
			ExpectedRemoteRevision: resolution.ExpectedRemoteRevision, RequestedByUserID: userID,
		})
		if errors.Is(queryErr, sql.ErrNoRows) {
			return ErrConfigConflictResolutionStale
		}
		if queryErr != nil {
			return queryErr
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{
			ActorType: audit.ActorUser, ActorUserID: userID, EventType: "config.conflict_resolution_requested",
			ResourceType: "config_environment", ResourceID: environmentID,
			IdempotencyKey: "config.conflict_resolution:" + result.ID,
			Metadata: map[string]any{
				"assignment_id": current.AssignmentID, "repository_id": current.RepositoryID.String,
				"conflict_revision": resolution.ConflictRevision, "action": resolution.Action,
			},
		})
	})
	if err != nil {
		return ConfigConflictResolution{}, err
	}
	return conflictResolutionFromRow(result), nil
}

func (s *ConfigConflictService) Pending(ctx context.Context, identityToken, credential string, proof, body []byte, method, path string) ([]ConfigConflictResolution, error) {
	holder, err := s.authenticate(ctx, identityToken, credential, proof, body, method, path)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.Queries().ListPendingControlConfigConflictResolutions(ctx, dbsqlc.ListPendingControlConfigConflictResolutionsParams{
		EnvironmentID: holder.EnvironmentID, RepositoryID: holder.RepositoryID, AssignmentID: holder.AssignmentID,
	})
	if err != nil {
		return nil, err
	}
	result := make([]ConfigConflictResolution, 0, len(rows))
	for _, row := range rows {
		result = append(result, conflictResolutionFromRow(row))
	}
	return result, nil
}

func (s *ConfigConflictService) Acknowledge(ctx context.Context, identityToken, credential string, proof, body []byte, method, path, resolutionID, landedRevision string) error {
	holder, err := s.authenticate(ctx, identityToken, credential, proof, body, method, path)
	if err != nil || strings.TrimSpace(resolutionID) == "" || strings.TrimSpace(landedRevision) == "" {
		return ErrConfigConflictResolutionInvalid
	}
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, applyErr := tx.Queries().ApplyControlConfigConflictResolution(ctx, dbsqlc.ApplyControlConfigConflictResolutionParams{
			LandedRevision: sql.NullString{String: landedRevision, Valid: true},
			Now:            s.clock().UTC(), ID: resolutionID,
			EnvironmentID: holder.EnvironmentID, RepositoryID: holder.RepositoryID, AssignmentID: holder.AssignmentID,
		})
		if applyErr != nil {
			return applyErr
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{
			ActorType: audit.ActorSystem, EventType: "config.conflict_resolution_applied",
			ResourceType: "config_environment", ResourceID: holder.EnvironmentID,
			IdempotencyKey: "config.conflict_resolution_applied:" + resolutionID + ":" + landedRevision,
			Metadata: map[string]any{
				"assignment_id": holder.AssignmentID, "repository_id": holder.RepositoryID,
				"helper_id": holder.HelperID, "helper_generation": holder.HelperGeneration,
				"resolution_id": resolutionID, "landed_revision": landedRevision,
			},
		})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConfigConflictResolutionStale
	}
	return err
}

func (s *ConfigConflictService) authenticate(ctx context.Context, identityToken, credential string, proof, body []byte, method, path string) (ConfigLeaseHolder, error) {
	if s == nil || s.store == nil || s.leases == nil {
		return ConfigLeaseHolder{}, ErrConfigConflictResolutionInvalid
	}
	holder, err := s.leases.Authenticate(ctx, identityToken, credential, proof, body, method, path)
	if err != nil {
		return ConfigLeaseHolder{}, ErrConfigConflictResolutionInvalid
	}
	return holder, nil
}

func validConfigConflictResolution(value ConfigConflictResolution) bool {
	return safeConfigStatusPath(value.Path) && conflictRevisionPattern.MatchString(value.ConflictRevision) &&
		len(value.ExpectedRemoteRevision) > 0 && len(value.ExpectedRemoteRevision) <= 256 &&
		(value.Action == "keep_local" || value.Action == "keep_remote" || value.Action == "externally_resolved")
}

func conflictResolutionFromRow(row dbsqlc.ControlConfigConflictResolution) ConfigConflictResolution {
	return ConfigConflictResolution{
		ID: row.ID, Path: row.Path, ConflictRevision: row.ConflictRevision,
		ExpectedRemoteRevision: row.ExpectedRemoteRevision, Action: row.Action,
	}
}
