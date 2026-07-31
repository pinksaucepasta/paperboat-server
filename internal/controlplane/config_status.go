package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var (
	ErrConfigStatusInvalid  = errors.New("config sync status is invalid")
	ErrConfigStatusStale    = errors.New("config sync status revision is stale")
	errConfigStatusReport   = errors.New("config status report rejected")
	errConfigStatusIdentity = errors.New("config status identity rejected")
	errConfigStatusHelper   = errors.New("config status helper binding rejected")
	errConfigStatusAssign   = errors.New("config status assignment binding rejected")
	errConfigStatusPersist  = errors.New("config status persistence failed")
	statusCodePattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	conflictRevisionPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

var configStatusStates = map[string]bool{
	"disabled": true, "consent_required": true, "restoring": true, "watching": true,
	"pending": true, "syncing": true, "healthy": true, "warning": true, "conflict": true,
	"offline": true, "revoked": true, "error": true, "sync_uncertain": true,
}

type ConfigStatusPath struct {
	Path     string `json:"path"`
	Bytes    int64  `json:"bytes,omitempty"`
	Reason   string `json:"reason"`
	Revision string `json:"revision,omitempty"`
}

type ConfigStatusReport struct {
	State                  string `json:"state"`
	Mode                   string `json:"mode"`
	RepositoryID           string `json:"repository_id"`
	AssignmentID           string `json:"assignment_id"`
	EnvironmentID          string `json:"environment_id"`
	MachineID              string `json:"machine_id"`
	InstallationGeneration int64  `json:"installation_generation"`
	WarningRevision        string `json:"warning_revision"`
	PolicyRevision         string `json:"policy_revision"`
	SyncRevision           int64  `json:"sync_revision"`
	RemoteRevision         string `json:"remote_revision,omitempty"`
	ManifestHealth         string `json:"manifest_health,omitempty"`
	ManifestRevision       string `json:"manifest_revision,omitempty"`
	ManagedPathCount       int    `json:"managed_path_count"`
	PendingCleanPathCount  int    `json:"pending_clean_path_count"`
	LastAppliedRevision    string `json:"last_applied_revision,omitempty"`
	LastPublishedRevision  string `json:"last_published_revision,omitempty"`
	LeaseID                string `json:"lease_id,omitempty"`
	FencingToken           int64  `json:"fencing_token,omitempty"`

	LastAttemptAt    *time.Time         `json:"last_attempt_at,omitempty"`
	LastSuccessfulAt *time.Time         `json:"last_successful_sync_at,omitempty"`
	UpdatedAt        time.Time          `json:"updated_at"`
	Skipped          []ConfigStatusPath `json:"skipped,omitempty"`
	Conflicts        []ConfigStatusPath `json:"conflicts,omitempty"`
	ErrorCode        string             `json:"error_code,omitempty"`
	RecoveryActions  []string           `json:"recovery_actions,omitempty"`
}

type ConfigStatusService struct {
	store      *db.DB
	identities *EnrollmentService
	audit      *audit.Writer
	clock      func() time.Time
	limit      int
	policy     config.ConfigSync
}

func (s *ConfigStatusService) SetAccountPolicy(policy config.ConfigSync) {
	s.policy = policy
}

type ConfigAccountPolicy struct {
	Mode                    string `json:"mode"`
	BYODEnabled             bool   `json:"byod_enabled"`
	Format                  string `json:"format"`
	Revision                string `json:"revision"`
	ManifestContract        string `json:"manifest_contract"`
	ManifestMaxBytes        int    `json:"manifest_max_bytes"`
	ManifestMaxLines        int    `json:"manifest_max_lines"`
	ManifestMaxPatternBytes int    `json:"manifest_max_pattern_bytes"`
	MaxFileBytes            int64  `json:"max_file_bytes"`
	MaxBatchBytes           int64  `json:"max_batch_bytes"`
}

type ConfigAccountEnvironment struct {
	MachineID              string             `json:"machine_id"`
	EnvironmentID          string             `json:"environment_id"`
	DisplayName            string             `json:"display_name"`
	Profile                string             `json:"profile"`
	EnvironmentState       string             `json:"environment_state"`
	State                  string             `json:"state"`
	AssignmentID           string             `json:"assignment_id,omitempty"`
	AssignmentVersion      int64              `json:"assignment_version,omitempty"`
	RepositoryID           string             `json:"repository_id,omitempty"`
	RepositoryName         string             `json:"repository_name,omitempty"`
	Mode                   string             `json:"mode,omitempty"`
	ConsentState           string             `json:"consent_state,omitempty"`
	WarningRevision        string             `json:"warning_revision,omitempty"`
	InstallationGeneration int64              `json:"installation_generation,omitempty"`
	PolicyRevision         string             `json:"policy_revision,omitempty"`
	SyncRevision           int64              `json:"sync_revision,omitempty"`
	RemoteRevision         string             `json:"remote_revision,omitempty"`
	ManifestHealth         string             `json:"manifest_health,omitempty"`
	ManifestRevision       string             `json:"manifest_revision,omitempty"`
	ManagedPathCount       int32              `json:"managed_path_count"`
	PendingCleanPathCount  int32              `json:"pending_clean_path_count"`
	LastAppliedRevision    string             `json:"last_applied_revision,omitempty"`
	LastPublishedRevision  string             `json:"last_published_revision,omitempty"`
	Skipped                []ConfigStatusPath `json:"skipped"`
	Conflicts              []ConfigStatusPath `json:"conflicts"`
	ErrorCode              string             `json:"error_code,omitempty"`
	RecoveryActions        []string           `json:"recovery_actions"`
	LastAttemptAt          *time.Time         `json:"last_attempt_at,omitempty"`
	LastSuccessfulAt       *time.Time         `json:"last_successful_sync_at,omitempty"`
	UpdatedAt              *time.Time         `json:"updated_at,omitempty"`
}

type ConfigAccountStatus struct {
	State        string                     `json:"state"`
	Policy       ConfigAccountPolicy        `json:"policy"`
	Environments []ConfigAccountEnvironment `json:"environments"`
}

func (s *ConfigStatusService) Account(ctx context.Context, userID string) (ConfigAccountStatus, error) {
	if s == nil || s.store == nil || strings.TrimSpace(userID) == "" {
		return ConfigAccountStatus{}, ErrConfigStatusInvalid
	}
	rows, err := s.store.Queries().ListOwnedControlConfigSyncStatus(ctx, sql.NullString{String: userID, Valid: true})
	if err != nil {
		return ConfigAccountStatus{}, err
	}
	result := ConfigAccountStatus{
		State: "disabled",
		Policy: ConfigAccountPolicy{
			Mode: s.policy.Mode, BYODEnabled: s.policy.BYODEnabled,
			Format: "paperboat-config-plaintext-v1", Revision: s.policy.PolicyRevision,
			ManifestContract: s.policy.ManifestContract, ManifestMaxBytes: s.policy.ManifestMaxBytes,
			ManifestMaxLines: s.policy.ManifestMaxLines, ManifestMaxPatternBytes: s.policy.ManifestMaxPatternBytes,
			MaxFileBytes: s.policy.MaxFileBytes, MaxBatchBytes: s.policy.MaxBatchBytes,
		},
		Environments: make([]ConfigAccountEnvironment, 0, len(rows)),
	}
	for _, row := range rows {
		item := ConfigAccountEnvironment{
			MachineID: row.MachineID.String, EnvironmentID: row.EnvironmentID, DisplayName: row.DisplayName, Profile: row.Profile,
			EnvironmentState: row.EnvironmentState, State: canonicalAccountState(row, s.clock(), s.policy.StaleHeartbeatAfter),
			AssignmentID: row.AssignmentID.String, AssignmentVersion: row.AssignmentVersion.Int64,
			RepositoryID: row.RepositoryID.String, RepositoryName: row.RepositoryName.String,
			Mode:         row.Mode.String,
			ConsentState: row.ConsentState.String, WarningRevision: row.WarningRevision.String,
			InstallationGeneration: row.InstallationGeneration,
			PolicyRevision:         row.PolicyRevision.String,
			SyncRevision:           row.SyncRevision.Int64, RemoteRevision: row.RemoteRevision.String,
			ManifestHealth: row.ManifestHealth.String, ManifestRevision: row.ManifestRevision.String,
			ManagedPathCount: row.ManagedPathCount.Int32, PendingCleanPathCount: row.PendingCleanPathCount.Int32,
			LastAppliedRevision: row.LastAppliedRevision.String, LastPublishedRevision: row.LastPublishedRevision.String,
			ErrorCode: row.ErrorCode.String,
			Skipped:   []ConfigStatusPath{},
			Conflicts: []ConfigStatusPath{}, RecoveryActions: []string{},
		}
		if s.policy.Mode == "disabled" ||
			(item.Profile == "byod" && !s.policy.BYODEnabled) ||
			(len(s.policy.EnvironmentAllowlist) > 0 && !slices.Contains(s.policy.EnvironmentAllowlist, item.EnvironmentID)) {
			item.State = "disabled"
		}
		decodeAccountStatusJSON(row.Skipped, &item.Skipped, s.limit)
		decodeAccountStatusJSON(row.Conflicts, &item.Conflicts, s.limit)
		decodeAccountStatusJSON(row.RecoveryActions, &item.RecoveryActions, 8)
		item.LastAttemptAt = nullTimePointer(row.LastAttemptAt)
		item.LastSuccessfulAt = nullTimePointer(row.LastSuccessfulAt)
		item.UpdatedAt = nullTimePointer(row.MachineUpdatedAt)
		result.Environments = append(result.Environments, item)
		result.State = higherConfigAccountState(result.State, item.State)
	}
	return result, nil
}

func canonicalAccountState(row dbsqlc.ListOwnedControlConfigSyncStatusRow, now time.Time, staleAfter time.Duration) string {
	if !row.AssignmentID.Valid || !row.RepositoryID.Valid {
		return "disabled"
	}
	if row.RepositoryState.String != "active" || row.EnvironmentState != "active" {
		return "revoked"
	}
	if row.Profile == "byod" && row.ConsentState.String != "accepted" {
		return "consent_required"
	}
	if !row.MachineID.Valid || row.MachineID.String == "" || !row.SyncState.Valid ||
		row.AssignmentID.String == "" || row.PolicyRevision.String == "" ||
		row.StatusAssignmentID.String != row.AssignmentID.String ||
		row.StatusRepositoryID.String != row.RepositoryID.String ||
		row.StatusMachineID.String != row.MachineID.String ||
		row.StatusInstallationGeneration.Int64 != row.InstallationGeneration {
		return "pending"
	}
	if staleAfter > 0 && (!row.ObservedAt.Valid || now.Sub(row.ObservedAt.Time) > staleAfter) {
		return "offline"
	}
	return row.SyncState.String
}

func higherConfigAccountState(current, candidate string) string {
	priority := map[string]int{
		"disabled": 0, "healthy": 1, "watching": 2, "pending": 3, "syncing": 4,
		"restoring": 5, "consent_required": 6, "offline": 7, "warning": 8,
		"revoked": 9, "sync_uncertain": 10, "error": 11, "conflict": 12,
	}
	if priority[candidate] > priority[current] {
		return candidate
	}
	return current
}

func decodeAccountStatusJSON[T any](raw []byte, target *[]T, limit int) {
	var values []T
	if len(raw) > 0 && json.Unmarshal(raw, &values) == nil {
		if len(values) > limit {
			values = values[:limit]
		}
		*target = values
	}
}

func nullTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time.UTC()
	return &result
}

func NewConfigStatusService(store *db.DB, identities *EnrollmentService, writer *audit.Writer, summaryLimit int) *ConfigStatusService {
	return &ConfigStatusService{store: store, identities: identities, audit: writer, clock: func() time.Time { return time.Now().UTC() }, limit: summaryLimit}
}

func (s *ConfigStatusService) Record(ctx context.Context, identityToken string, proof, body []byte, method, path string, report ConfigStatusReport) error {
	if s == nil || s.store == nil || s.identities == nil || validateConfigStatus(report, s.limit, s.clock()) != nil {
		return errors.Join(ErrConfigStatusInvalid, errConfigStatusReport)
	}
	identity, err := s.identities.VerifyMachineRequest(ctx, identityToken, proof, method, path, body)
	if err != nil || identity.EnvironmentID != report.EnvironmentID || identity.MachineID != report.MachineID {
		return errors.Join(ErrConfigStatusInvalid, errConfigStatusIdentity)
	}
	if identity.InstallationGeneration != report.InstallationGeneration {
		return errors.Join(ErrConfigStatusInvalid, errConfigStatusHelper)
	}
	assignment, err := s.store.Queries().GetControlConfigAssignment(ctx, identity.EnvironmentID)
	if err != nil || assignment.ID != report.AssignmentID || !assignment.RepositoryID.Valid ||
		assignment.RepositoryID.String != report.RepositoryID || !assignment.WarningRevision.Valid ||
		assignment.WarningRevision.String != report.WarningRevision || assignment.Mode != report.Mode {
		return errors.Join(ErrConfigStatusInvalid, errConfigStatusAssign)
	}
	skipped, err := marshalConfigStatusList(report.Skipped)
	if err != nil {
		return errors.Join(ErrConfigStatusInvalid, errConfigStatusReport)
	}
	conflicts, err := marshalConfigStatusList(report.Conflicts)
	if err != nil {
		return errors.Join(ErrConfigStatusInvalid, errConfigStatusReport)
	}
	recoveryActions, err := marshalConfigStatusList(report.RecoveryActions)
	if err != nil {
		return errors.Join(ErrConfigStatusInvalid, errConfigStatusReport)
	}
	now := s.clock().UTC()
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Queries().RecordControlConfigSyncStatus(ctx, dbsqlc.RecordControlConfigSyncStatusParams{
			EnvironmentID: report.EnvironmentID, RepositoryID: report.RepositoryID, AssignmentID: report.AssignmentID,
			MachineID: report.MachineID, InstallationGeneration: report.InstallationGeneration, WarningRevision: report.WarningRevision,
			PolicyRevision: report.PolicyRevision, SyncRevision: report.SyncRevision,
			State: report.State, Mode: report.Mode, RemoteRevision: nullableString(report.RemoteRevision),
			ManifestHealth: report.ManifestHealth, ManifestRevision: nullableString(report.ManifestRevision),
			ManagedPathCount: int32(report.ManagedPathCount), PendingCleanPathCount: int32(report.PendingCleanPathCount),
			LastAppliedRevision: nullableString(report.LastAppliedRevision), LastPublishedRevision: nullableString(report.LastPublishedRevision),
			LeaseID: nullableString(report.LeaseID), FencingToken: nullableInt64(report.FencingToken),
			Skipped: skipped, Conflicts: conflicts,
			ErrorCode: nullableString(report.ErrorCode), RecoveryActions: recoveryActions,
			LastAttemptAt: nullableTimePointer(report.LastAttemptAt), LastSuccessfulAt: nullableTimePointer(report.LastSuccessfulAt),
			MachineUpdatedAt: report.UpdatedAt.UTC(), ObservedAt: now,
		})
		if err != nil {
			return err
		}
		if err = tx.Queries().InsertControlConfigSyncStatusHistory(ctx, dbsqlc.InsertControlConfigSyncStatusHistoryParams{
			EnvironmentID: report.EnvironmentID, SyncRevision: report.SyncRevision, RepositoryID: report.RepositoryID,
			AssignmentID: report.AssignmentID, MachineID: report.MachineID, InstallationGeneration: report.InstallationGeneration,
			State: report.State, ErrorCode: nullableString(report.ErrorCode), RemoteRevision: nullableString(report.RemoteRevision), ObservedAt: now,
		}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorType: audit.ActorSystem, EventType: "config.status_recorded",
			ResourceType: "environment", ResourceID: report.EnvironmentID,
			IdempotencyKey: "config.status:" + report.EnvironmentID + ":" + strings.TrimSpace(report.AssignmentID) + ":" + formatInt(report.SyncRevision),
			Metadata:       map[string]any{"repository_id": report.RepositoryID, "assignment_id": report.AssignmentID, "state": report.State, "sync_revision": report.SyncRevision}})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConfigStatusStale
	}
	if err != nil {
		return errors.Join(err, errConfigStatusPersist)
	}
	return err
}

func marshalConfigStatusList[T any](values []T) ([]byte, error) {
	if values == nil {
		values = []T{}
	}
	return json.Marshal(values)
}

// ConfigStatusRejectionClass returns a bounded, non-secret operator diagnostic.
func ConfigStatusRejectionClass(err error) string {
	switch {
	case errors.Is(err, ErrConfigStatusStale):
		return "stale"
	case errors.Is(err, errConfigStatusReport):
		return "report"
	case errors.Is(err, errConfigStatusIdentity):
		return "identity"
	case errors.Is(err, errConfigStatusHelper):
		return "helper_binding"
	case errors.Is(err, errConfigStatusAssign):
		return "assignment_binding"
	case errors.Is(err, errConfigStatusPersist):
		return "persistence"
	default:
		return "unknown"
	}
}

func validateConfigStatus(report ConfigStatusReport, limit int, now time.Time) error {
	if limit < 1 || limit > 1000 || !configStatusStates[report.State] || report.RepositoryID == "" ||
		report.AssignmentID == "" || report.EnvironmentID == "" || report.MachineID == "" ||
		report.InstallationGeneration < 1 || report.WarningRevision == "" || report.PolicyRevision == "" ||
		report.SyncRevision < 1 || !validConfigMode(report.Mode) ||
		report.ManagedPathCount < 0 || report.PendingCleanPathCount < 0 ||
		report.UpdatedAt.IsZero() || report.UpdatedAt.Before(now.Add(-5*time.Minute)) || report.UpdatedAt.After(now.Add(time.Minute)) ||
		len(report.RemoteRevision) > 256 || len(report.ManifestRevision) > 64 ||
		len(report.LastAppliedRevision) > 256 || len(report.LastPublishedRevision) > 256 ||
		len(report.LeaseID) > 128 || report.FencingToken < 0 ||
		(report.FencingToken > 0 && report.LeaseID == "") || len(report.ErrorCode) > 64 ||
		(report.ErrorCode != "" && !statusCodePattern.MatchString(report.ErrorCode)) ||
		len(report.Skipped) > limit || len(report.Conflicts) > limit ||
		len(report.RecoveryActions) > 8 || (report.State == "conflict" && len(report.Conflicts) == 0) ||
		(report.State == "sync_uncertain" && report.ErrorCode != "sync_uncertain") {
		return ErrConfigStatusInvalid
	}
	if report.ManifestHealth != "" && report.ManifestHealth != "healthy" && report.ManifestHealth != "empty" &&
		report.ManifestHealth != "missing" && report.ManifestHealth != "invalid" {
		return ErrConfigStatusInvalid
	}
	for _, group := range [][]ConfigStatusPath{report.Skipped, report.Conflicts} {
		for _, item := range group {
			if !safeConfigStatusPath(item.Path) || item.Bytes < 0 || !statusCodePattern.MatchString(item.Reason) ||
				(item.Revision != "" && !conflictRevisionPattern.MatchString(item.Revision)) {
				return ErrConfigStatusInvalid
			}
		}
	}
	for _, action := range report.RecoveryActions {
		if !statusCodePattern.MatchString(action) {
			return ErrConfigStatusInvalid
		}
	}
	return nil
}

func safeConfigStatusPath(value string) bool {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\\", "/")
	return value != "" && len(value) <= 512 && !strings.HasPrefix(value, "/") &&
		value != ".." && !strings.HasPrefix(value, "../") && !strings.Contains(value, "\x00") &&
		!strings.Contains(value, "/../") && !strings.Contains(value, "//")
}

func nullableTimePointer(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value.UTC(), Valid: true}
}

func formatInt(value int64) string {
	return strconv.FormatInt(value, 10)
}
