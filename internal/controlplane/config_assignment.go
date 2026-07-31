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

const (
	ConfigModePullOnly      = "pull_only"
	ConfigModePushOnly      = "push_only"
	ConfigModeBidirectional = "bidirectional"
)

func validConfigMode(mode string) bool {
	return mode == ConfigModePullOnly || mode == ConfigModePushOnly || mode == ConfigModeBidirectional
}

type ConfigAssignmentService struct {
	store              *db.DB
	audit              *audit.Writer
	clock              func() time.Time
	warningRevision    string
	repositoryResolver ConfigRepositoryResolver
	repositoryCatalog  ConfigRepositoryCatalog
}

type ConfigRepositoryCandidate struct {
	Provider      string `json:"provider"`
	ExternalID    string `json:"external_id"`
	DisplayName   string `json:"display_name"`
	DefaultBranch string `json:"default_branch"`
}

type ConfigRepositoryCatalog interface {
	ListConfigRepositoryCandidates(context.Context, string) ([]ConfigRepositoryCandidate, error)
}

type ConfigRepositoryCatalogFunc func(context.Context, string) ([]ConfigRepositoryCandidate, error)

func (f ConfigRepositoryCatalogFunc) ListConfigRepositoryCandidates(ctx context.Context, userID string) ([]ConfigRepositoryCandidate, error) {
	return f(ctx, userID)
}

func (s *ConfigAssignmentService) SetRepositoryCatalog(catalog ConfigRepositoryCatalog) {
	s.repositoryCatalog = catalog
}

func (s *ConfigAssignmentService) RepositoryCandidates(ctx context.Context, userID string) ([]ConfigRepositoryCandidate, error) {
	if s == nil || s.repositoryCatalog == nil || strings.TrimSpace(userID) == "" {
		return nil, ErrAssignmentForbidden
	}
	items, err := s.repositoryCatalog.ListConfigRepositoryCandidates(ctx, userID)
	if err != nil || len(items) > 1000 {
		return nil, ErrAssignmentForbidden
	}
	return items, nil
}

func NewConfigAssignmentService(store *db.DB, writer *audit.Writer, warningRevision string) *ConfigAssignmentService {
	return &ConfigAssignmentService{store: store, audit: writer, clock: func() time.Time { return time.Now().UTC() }, warningRevision: strings.TrimSpace(warningRevision)}
}

type ConfigRepositoryConnection struct {
	ProviderAccountID    string
	ExternalRepositoryID string
	DisplayName          string
	CloneURL             string
	PublishURL           string
	DefaultBranch        string
	AuthorizationRef     string
	CredentialCapability string
	ObservedRevision     string
}

type ConfigRepositoryResolver interface {
	ResolveConfigRepository(context.Context, string, string, string) (ConfigRepositoryConnection, error)
}

type ConfigRepositoryResolverFunc func(context.Context, string, string, string) (ConfigRepositoryConnection, error)

func (f ConfigRepositoryResolverFunc) ResolveConfigRepository(ctx context.Context, userID, provider, externalID string) (ConfigRepositoryConnection, error) {
	return f(ctx, userID, provider, externalID)
}

func (s *ConfigAssignmentService) SetRepositoryResolver(resolver ConfigRepositoryResolver) {
	s.repositoryResolver = resolver
}

func (s *ConfigAssignmentService) ConnectRepository(ctx context.Context, userID, provider, externalRef, displayName string) (dbsqlc.ControlConfigRepository, error) {
	provider, externalRef = strings.ToLower(strings.TrimSpace(provider)), strings.TrimSpace(externalRef)
	if userID == "" || provider == "" || externalRef == "" || len(externalRef) > 128 || s.repositoryResolver == nil {
		return dbsqlc.ControlConfigRepository{}, ErrAssignmentInvalid
	}
	connection, err := s.repositoryResolver.ResolveConfigRepository(ctx, userID, provider, externalRef)
	if err != nil || strings.TrimSpace(connection.ExternalRepositoryID) != externalRef ||
		strings.TrimSpace(connection.ProviderAccountID) == "" || strings.TrimSpace(connection.DisplayName) == "" ||
		len(connection.DisplayName) > 128 || strings.TrimSpace(connection.CloneURL) == "" ||
		strings.TrimSpace(connection.PublishURL) == "" || strings.TrimSpace(connection.DefaultBranch) == "" ||
		strings.TrimSpace(connection.AuthorizationRef) == "" || strings.TrimSpace(connection.CredentialCapability) == "" {
		return dbsqlc.ControlConfigRepository{}, ErrAssignmentForbidden
	}
	id, err := randomHex("cfgrepo_", 12)
	if err != nil {
		return dbsqlc.ControlConfigRepository{}, err
	}
	item, err := s.store.Queries().CreateControlConfigRepository(ctx, dbsqlc.CreateControlConfigRepositoryParams{
		ID: id, OwnerUserID: userID, Provider: provider, ExternalRef: externalRef, DisplayName: strings.TrimSpace(connection.DisplayName),
		ProviderAccountID: nullableString(connection.ProviderAccountID), ExternalRepositoryID: nullableString(connection.ExternalRepositoryID),
		CloneUrl: nullableString(connection.CloneURL), PublishUrl: nullableString(connection.PublishURL),
		DefaultBranch: nullableString(connection.DefaultBranch), AuthorizationRef: nullableString(connection.AuthorizationRef),
		CredentialCapability: nullableString(connection.CredentialCapability), ObservedRevision: nullableString(connection.ObservedRevision),
	})
	if err != nil {
		return dbsqlc.ControlConfigRepository{}, err
	}
	if err := s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "config.repository_connected",
		ResourceType: "config_repository", ResourceID: item.ID, IdempotencyKey: "config.repository.connect:" + item.ID,
		Metadata: map[string]any{"provider": provider, "external_repository_id": connection.ExternalRepositoryID}}); err != nil {
		return dbsqlc.ControlConfigRepository{}, err
	}
	return item, nil
}

func (s *ConfigAssignmentService) ListRepositories(ctx context.Context, userID string, limit, offset int32) ([]dbsqlc.ControlConfigRepository, error) {
	if userID == "" || limit < 1 || limit > 100 || offset < 0 {
		return nil, ErrAssignmentInvalid
	}
	return s.store.Queries().ListControlConfigRepositories(ctx, dbsqlc.ListControlConfigRepositoriesParams{OwnerUserID: userID, RowLimit: limit, RowOffset: offset})
}

func (s *ConfigAssignmentService) DisconnectRepository(ctx context.Context, userID, repositoryID string) error {
	if userID == "" || repositoryID == "" {
		return ErrAssignmentInvalid
	}
	now := s.clock().UTC()
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		item, err := tx.Queries().DisconnectOwnedControlConfigRepository(ctx, dbsqlc.DisconnectOwnedControlConfigRepositoryParams{
			Now: sql.NullTime{Time: now, Valid: true}, ID: repositoryID, OwnerUserID: userID,
		})
		if err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigCredentialsForRepository(ctx, dbsqlc.RevokeControlConfigCredentialsForRepositoryParams{
			Now: sql.NullTime{Time: now, Valid: true}, RepositoryID: sql.NullString{String: repositoryID, Valid: true},
		}); err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigRepositoryAccessForRepository(ctx, dbsqlc.RevokeControlConfigRepositoryAccessForRepositoryParams{
			Now: now, RepositoryID: repositoryID,
		}); err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigRepositoryLease(ctx, dbsqlc.RevokeControlConfigRepositoryLeaseParams{
			Now: sql.NullTime{Time: now, Valid: true}, RepositoryID: repositoryID,
		}); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err = tx.Queries().DisableControlConfigAssignmentsForRepository(ctx, dbsqlc.DisableControlConfigAssignmentsForRepositoryParams{
			Now: sql.NullTime{Time: now, Valid: true}, RepositoryID: sql.NullString{String: repositoryID, Valid: true},
		}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "config.repository_disconnected",
			ResourceType: "config_repository", ResourceID: repositoryID, IdempotencyKey: "config.repository.disconnect:" + repositoryID + ":" + strconv.FormatInt(item.Version, 10),
			Metadata: map[string]any{"provider": item.Provider}})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAssignmentForbidden
	}
	return err
}

func (s *ConfigAssignmentService) Assignment(ctx context.Context, userID, machineID string) (dbsqlc.ControlConfigAssignment, error) {
	environmentID, ok := s.ownedMachineEnvironment(ctx, userID, machineID)
	if !ok {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentForbidden
	}
	return s.store.Queries().GetControlConfigAssignment(ctx, environmentID)
}

func (s *ConfigAssignmentService) Assign(ctx context.Context, userID, machineID, repositoryID, mode, warningRevision string, expectedVersion int64) (dbsqlc.ControlConfigAssignment, error) {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = ConfigModePullOnly
	}
	if userID == "" || machineID == "" || repositoryID == "" || !validConfigMode(mode) || expectedVersion < 0 {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentInvalid
	}
	environmentID, ok := s.ownedMachineEnvironment(ctx, userID, machineID)
	if !ok {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentForbidden
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
		if s.warningRevision == "" || (warningRevision != "" && warningRevision != s.warningRevision) {
			return dbsqlc.ControlConfigAssignment{}, ErrAssignmentConflict
		}
		warningRevision = s.warningRevision
		consent = "pending"
	} else {
		warningRevision = "hosted"
	}
	var assignment dbsqlc.ControlConfigAssignment
	now := s.clock().UTC()
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		assignment, err = tx.Queries().SetControlConfigAssignment(ctx, dbsqlc.SetControlConfigAssignmentParams{AssignmentID: assignmentID, EnvironmentID: environmentID, RepositoryID: sql.NullString{String: repositoryID, Valid: true}, Mode: mode, ConsentState: consent, WarningRevision: sql.NullString{String: warningRevision, Valid: true}, ExpectedVersion: expectedVersion, Now: now})
		if err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigCredentialsForEnvironment(ctx, dbsqlc.RevokeControlConfigCredentialsForEnvironmentParams{EnvironmentID: environmentID, RevokedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigRepositoryAccessForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryAccessForEnvironmentParams{EnvironmentID: environmentID, Now: now}); err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigRepositoryLeasesForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryLeasesForEnvironmentParams{EnvironmentID: sql.NullString{String: environmentID, Valid: true}, Now: sql.NullTime{Time: now, Valid: true}}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "config.assignment_set", ResourceType: "environment", ResourceID: environmentID, IdempotencyKey: "config.assignment:" + environmentID + ":" + strconv.FormatInt(assignment.Version, 10), Metadata: map[string]any{"repository_id": repositoryID, "mode": mode, "consent_state": consent}})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentConflict
	}
	if err != nil {
		return dbsqlc.ControlConfigAssignment{}, err
	}
	return assignment, nil
}

func (s *ConfigAssignmentService) AcceptConsent(ctx context.Context, userID, machineID, warningRevision string, expectedVersion int64) (dbsqlc.ControlConfigAssignment, error) {
	if userID == "" || machineID == "" || warningRevision == "" || expectedVersion < 1 {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentInvalid
	}
	if warningRevision != s.warningRevision {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentConflict
	}
	environmentID, ok := s.ownedMachineEnvironment(ctx, userID, machineID)
	if !ok {
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

type ConfigWarningFacts struct {
	Revision             string `json:"revision"`
	MachineName          string `json:"machine_name"`
	RepositoryName       string `json:"repository_name"`
	CanonicalScope       string `json:"canonical_scope"`
	Mode                 string `json:"mode"`
	ManifestScope        string `json:"manifest_scope"`
	RepositoryVisibility string `json:"repository_visibility"`
	HistoryRetention     string `json:"history_retention"`
	ConflictBehavior     string `json:"conflict_behavior"`
	ForceBehavior        string `json:"force_behavior"`
	DisableAction        string `json:"disable_action"`
	OfflineBehavior      string `json:"offline_behavior"`
	AccessConsequence    string `json:"access_consequence"`
}

func (s *ConfigAssignmentService) Warning(ctx context.Context, userID, machineID string) (ConfigWarningFacts, error) {
	if userID == "" || machineID == "" || s.warningRevision == "" {
		return ConfigWarningFacts{}, ErrAssignmentInvalid
	}
	environmentID, ok := s.ownedMachineEnvironment(ctx, userID, machineID)
	if !ok {
		return ConfigWarningFacts{}, ErrAssignmentForbidden
	}
	item, err := s.store.Queries().GetControlConfigWarningContext(ctx, dbsqlc.GetControlConfigWarningContextParams{
		EnvironmentID: environmentID, OwnerUserID: sql.NullString{String: userID, Valid: true},
	})
	if err != nil {
		return ConfigWarningFacts{}, ErrAssignmentForbidden
	}
	return ConfigWarningFacts{
		Revision: s.warningRevision, MachineName: item.MachineName, RepositoryName: item.RepositoryName,
		CanonicalScope: item.CanonicalScope, Mode: item.Mode,
		ManifestScope:        "Only home-relative files and directories explicitly listed in the repository .pbinclude are managed; .pbignore can narrow that scope.",
		RepositoryVisibility: "Selected configuration content is stored as ordinary plaintext in the connected private Git repository.",
		HistoryRetention:     "Git history can retain earlier and removed versions after files are changed, un-managed, or deleted.",
		ConflictBehavior:     "Only conflicting paths pause; choose this machine's version or the repository version while unrelated paths continue.",
		ForceBehavior:        "Confirmed force pull or force push can replace selected managed paths while preserving displaced versions in normal history.",
		DisableAction:        "Remove consent or unassign the repository to stop synchronization immediately.",
		OfflineBehavior:      "Offline changes remain local; synchronization requires fresh server authorization after reconnecting.",
		AccessConsequence:    "Anyone who gains repository or provider-account access may read selected configuration content and retained history.",
	}, nil
}

func (s *ConfigAssignmentService) RemoveConsent(ctx context.Context, userID, machineID string, expectedVersion int64) (dbsqlc.ControlConfigAssignment, error) {
	environmentID, ok := s.ownedMachineEnvironment(ctx, userID, machineID)
	if userID == "" || machineID == "" || expectedVersion < 1 || s.warningRevision == "" || !ok {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentForbidden
	}
	now := s.clock().UTC()
	var assignment dbsqlc.ControlConfigAssignment
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		assignment, err = tx.Queries().RemoveControlConfigConsent(ctx, dbsqlc.RemoveControlConfigConsentParams{
			WarningRevision: sql.NullString{String: s.warningRevision, Valid: true}, Now: now,
			EnvironmentID: environmentID, ExpectedVersion: expectedVersion,
		})
		if err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigCredentialsForEnvironment(ctx, dbsqlc.RevokeControlConfigCredentialsForEnvironmentParams{EnvironmentID: environmentID, RevokedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigRepositoryAccessForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryAccessForEnvironmentParams{EnvironmentID: environmentID, Now: now}); err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigRepositoryLeasesForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryLeasesForEnvironmentParams{EnvironmentID: sql.NullString{String: environmentID, Valid: true}, Now: sql.NullTime{Time: now, Valid: true}}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "config.consent_removed",
			ResourceType: "environment", ResourceID: environmentID, IdempotencyKey: "config.consent.remove:" + environmentID + ":" + strconv.FormatInt(assignment.Version, 10),
			Metadata: map[string]any{"warning_revision": s.warningRevision}})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.ControlConfigAssignment{}, ErrAssignmentConflict
	}
	return assignment, err
}

func (s *ConfigAssignmentService) ReconcileWarning(ctx context.Context) ([]string, error) {
	if s == nil || s.store == nil || s.warningRevision == "" {
		return nil, ErrAssignmentInvalid
	}
	now := s.clock().UTC()
	var environments []string
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		environments, err = tx.Queries().ReconcileStaleControlConfigWarning(ctx, dbsqlc.ReconcileStaleControlConfigWarningParams{
			WarningRevision: sql.NullString{String: s.warningRevision, Valid: true}, Now: now,
		})
		if err != nil {
			return err
		}
		for _, environmentID := range environments {
			if err := s.audit.WriteTx(ctx, tx, audit.Event{ActorType: audit.ActorSystem, EventType: "config.warning_superseded",
				ResourceType: "environment", ResourceID: environmentID,
				IdempotencyKey: "config.warning.superseded:" + environmentID + ":" + s.warningRevision,
				Metadata:       map[string]any{"warning_revision": s.warningRevision}}); err != nil {
				return err
			}
		}
		return nil
	})
	return environments, err
}

func (s *ConfigAssignmentService) WarningReconciliationWorker(interval time.Duration) func(context.Context) error {
	if interval <= 0 {
		interval = time.Minute
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if _, err := s.ReconcileWarning(ctx); err != nil {
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

func (s *ConfigAssignmentService) Clear(ctx context.Context, userID, machineID string, expectedVersion int64) error {
	environmentID, ok := s.ownedMachineEnvironment(ctx, userID, machineID)
	if userID == "" || machineID == "" || expectedVersion < 1 || !ok {
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
		if _, err = tx.Queries().RevokeControlConfigRepositoryAccessForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryAccessForEnvironmentParams{EnvironmentID: environmentID, Now: now}); err != nil {
			return err
		}
		if _, err = tx.Queries().RevokeControlConfigRepositoryLeasesForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryLeasesForEnvironmentParams{EnvironmentID: sql.NullString{String: environmentID, Valid: true}, Now: sql.NullTime{Time: now, Valid: true}}); err != nil {
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

func (s *ConfigAssignmentService) ownedMachineEnvironment(ctx context.Context, userID, machineID string) (string, bool) {
	machine, err := s.store.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: machineID, UserID: userID})
	if err != nil {
		return "", false
	}
	environment, err := s.store.Queries().GetControlEnvironment(ctx, machine.EnvironmentID)
	return machine.EnvironmentID, err == nil && environment.OwnerUserID.Valid && environment.OwnerUserID.String == userID && environment.DesiredState == "active"
}
