package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var (
	ErrAssignmentInvalid   = errors.New("config assignment is invalid")
	ErrAssignmentConflict  = errors.New("config assignment version conflict")
	ErrAssignmentForbidden = errors.New("config assignment is unavailable")
)

type ConfigAssignmentService struct {
	store *db.DB
	audit *audit.Writer
	clock func() time.Time
}

func NewConfigAssignmentService(store *db.DB, writer *audit.Writer) *ConfigAssignmentService {
	return &ConfigAssignmentService{store: store, audit: writer, clock: func() time.Time { return time.Now().UTC() }}
}

func (s *ConfigAssignmentService) ConnectRepository(ctx context.Context, userID, provider, externalRef, displayName string) (dbsqlc.ControlConfigRepository, error) {
	if userID == "" || strings.TrimSpace(provider) == "" || strings.TrimSpace(externalRef) == "" || strings.TrimSpace(displayName) == "" || len(displayName) > 128 {
		return dbsqlc.ControlConfigRepository{}, ErrAssignmentInvalid
	}
	id, err := randomHex("cfgrepo_", 12)
	if err != nil {
		return dbsqlc.ControlConfigRepository{}, err
	}
	return s.store.Queries().CreateControlConfigRepository(ctx, dbsqlc.CreateControlConfigRepositoryParams{ID: id, OwnerUserID: userID, Provider: strings.TrimSpace(provider), ExternalRef: strings.TrimSpace(externalRef), DisplayName: strings.TrimSpace(displayName)})
}

func (s *ConfigAssignmentService) ListRepositories(ctx context.Context, userID string, limit, offset int32) ([]dbsqlc.ControlConfigRepository, error) {
	if userID == "" || limit < 1 || limit > 100 || offset < 0 {
		return nil, ErrAssignmentInvalid
	}
	return s.store.Queries().ListControlConfigRepositories(ctx, dbsqlc.ListControlConfigRepositoriesParams{OwnerUserID: userID, RowLimit: limit, RowOffset: offset})
}

func (s *ConfigAssignmentService) Assignment(ctx context.Context, userID, environmentID string) (dbsqlc.ControlConfigAssignment, error) {
	if !s.ownsEnvironment(ctx, userID, environmentID) {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentForbidden
	}
	return s.store.Queries().GetControlConfigAssignment(ctx, environmentID)
}

func (s *ConfigAssignmentService) Assign(ctx context.Context, userID, environmentID, repositoryID, warningRevision string, expectedVersion int64) (dbsqlc.ControlConfigAssignment, error) {
	if userID == "" || environmentID == "" || repositoryID == "" || expectedVersion < 0 {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentInvalid
	}
	environment, err := s.store.Queries().GetControlEnvironment(ctx, environmentID)
	if err != nil || !environment.OwnerUserID.Valid || environment.OwnerUserID.String != userID || environment.DesiredState != "active" {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentForbidden
	}
	if _, err := s.store.Queries().GetOwnedControlConfigRepository(ctx, dbsqlc.GetOwnedControlConfigRepositoryParams{ID: repositoryID, OwnerUserID: userID}); err != nil {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentForbidden
	}
	byod, err := s.store.Queries().IsControlEnvironmentBYOD(ctx, environmentID)
	if err != nil {
		return dbsqlc.ControlConfigAssignment{}, err
	}
	consent := "not_required"
	assignmentID, err := randomHex("cfgasn_", 12)
	if err != nil {
		return dbsqlc.ControlConfigAssignment{}, err
	}
	if byod {
		warningRevision = strings.TrimSpace(warningRevision)
		if warningRevision == "" {
			return dbsqlc.ControlConfigAssignment{}, ErrAssignmentInvalid
		}
		consent = "pending"
	} else {
		warningRevision = "hosted"
	}
	var assignment dbsqlc.ControlConfigAssignment
	now := s.clock().UTC()
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		assignment, err = tx.Queries().SetControlConfigAssignment(ctx, dbsqlc.SetControlConfigAssignmentParams{AssignmentID: assignmentID, EnvironmentID: environmentID, RepositoryID: sql.NullString{String: repositoryID, Valid: true}, ConsentState: consent, WarningRevision: sql.NullString{String: warningRevision, Valid: true}, ExpectedVersion: expectedVersion, Now: now})
		if err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigCredentialsForEnvironment(ctx, dbsqlc.RevokeControlConfigCredentialsForEnvironmentParams{EnvironmentID: environmentID, RevokedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "config.assignment_set", ResourceType: "environment", ResourceID: environmentID, IdempotencyKey: "config.assignment:" + environmentID + ":" + strconv.FormatInt(assignment.Version, 10), Metadata: map[string]any{"repository_id": repositoryID, "consent_state": consent}})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentConflict
	}
	if err != nil {
		return dbsqlc.ControlConfigAssignment{}, err
	}
	return assignment, nil
}

func (s *ConfigAssignmentService) AcceptConsent(ctx context.Context, userID, environmentID, warningRevision string, expectedVersion int64) (dbsqlc.ControlConfigAssignment, error) {
	if userID == "" || environmentID == "" || warningRevision == "" || expectedVersion < 1 {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentInvalid
	}
	if !s.ownsEnvironment(ctx, userID, environmentID) {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentForbidden
	}
	assignment, err := s.store.Queries().AcceptControlConfigConsent(ctx, dbsqlc.AcceptControlConfigConsentParams{EnvironmentID: environmentID, WarningRevision: sql.NullString{String: warningRevision, Valid: true}, ExpectedVersion: expectedVersion, Now: sql.NullTime{Time: s.clock().UTC(), Valid: true}})
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentConflict
	}
	if err != nil {
		return dbsqlc.ControlConfigAssignment{}, err
	}
	return assignment, s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "config.consent_accepted", ResourceType: "environment", ResourceID: environmentID, IdempotencyKey: "config.consent:" + environmentID + ":" + strconv.FormatInt(assignment.Version, 10), Metadata: map[string]any{"warning_revision": warningRevision}})
}

func (s *ConfigAssignmentService) Clear(ctx context.Context, userID, environmentID string, expectedVersion int64) error {
	if userID == "" || environmentID == "" || expectedVersion < 1 || !s.ownsEnvironment(ctx, userID, environmentID) {
		return ErrAssignmentForbidden
	}
	var assignment dbsqlc.ControlConfigAssignment
	now := s.clock().UTC()
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		assignment, err = tx.Queries().ClearControlConfigAssignment(ctx, dbsqlc.ClearControlConfigAssignmentParams{EnvironmentID: environmentID, ExpectedVersion: expectedVersion, Now: sql.NullTime{Time: now, Valid: true}})
		if err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigCredentialsForEnvironment(ctx, dbsqlc.RevokeControlConfigCredentialsForEnvironmentParams{EnvironmentID: environmentID, RevokedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "config.assignment_cleared", ResourceType: "environment", ResourceID: environmentID, IdempotencyKey: "config.assignment.clear:" + environmentID + ":" + strconv.FormatInt(assignment.Version, 10), Metadata: map[string]any{}})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAssignmentConflict
	}
	if err != nil {
		return err
	}
	return nil
}

func (s *ConfigAssignmentService) ownsEnvironment(ctx context.Context, userID, environmentID string) bool {
	environment, err := s.store.Queries().GetControlEnvironment(ctx, environmentID)
	return err == nil && environment.OwnerUserID.Valid && environment.OwnerUserID.String == userID && environment.DesiredState == "active"
}
