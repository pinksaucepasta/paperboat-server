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
	State            string `json:"state"`
	RepositoryID     string `json:"repository_id"`
	AssignmentID     string `json:"assignment_id"`
	EnvironmentID    string `json:"environment_id"`
	HelperID         string `json:"helper_id"`
	HelperGeneration int64  `json:"helper_generation"`
	WarningRevision  string `json:"warning_revision"`
	PolicyRevision   string `json:"policy_revision"`
	KeyVersion       int64  `json:"key_version"`
	SyncRevision     int64  `json:"sync_revision"`
	RemoteRevision   string `json:"remote_revision,omitempty"`
	LeaseID          string `json:"lease_id,omitempty"`
	FencingToken     int64  `json:"fencing_token,omitempty"`

	LastAttemptAt     *time.Time         `json:"last_attempt_at,omitempty"`
	LastSuccessfulAt  *time.Time         `json:"last_successful_sync_at,omitempty"`
	UpdatedAt         time.Time          `json:"updated_at"`
	PendingPathCount  int                `json:"pending_path_count"`
	ClassifierPending []ConfigStatusPath `json:"classifier_pending,omitempty"`
	Skipped           []ConfigStatusPath `json:"skipped,omitempty"`
	Conflicts         []ConfigStatusPath `json:"conflicts,omitempty"`
	ErrorCode         string             `json:"error_code,omitempty"`
	RecoveryActions   []string           `json:"recovery_actions,omitempty"`
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
	Mode                string   `json:"mode"`
	BYODEnabled         bool     `json:"byod_enabled"`
	Format              string   `json:"format"`
	Revision            string   `json:"revision"`
	MaxFileBytes        int64    `json:"max_file_bytes"`
	MaxBatchBytes       int64    `json:"max_batch_bytes"`
	MandatoryExclusions []string `json:"mandatory_exclusions"`
}

type ConfigAccountEnvironment struct {
	EnvironmentID     string             `json:"environment_id"`
	DisplayName       string             `json:"display_name"`
	Profile           string             `json:"profile"`
	EnvironmentState  string             `json:"environment_state"`
	State             string             `json:"state"`
	AssignmentID      string             `json:"assignment_id,omitempty"`
	AssignmentVersion int64              `json:"assignment_version,omitempty"`
	RepositoryID      string             `json:"repository_id,omitempty"`
	RepositoryName    string             `json:"repository_name,omitempty"`
	ConsentState      string             `json:"consent_state,omitempty"`
	WarningRevision   string             `json:"warning_revision,omitempty"`
	HelperID          string             `json:"helper_id,omitempty"`
	HelperGeneration  int64              `json:"helper_generation,omitempty"`
	PolicyRevision    string             `json:"policy_revision,omitempty"`
	KeyVersion        int64              `json:"key_version,omitempty"`
	SyncRevision      int64              `json:"sync_revision,omitempty"`
	RemoteRevision    string             `json:"remote_revision,omitempty"`
	PendingPathCount  int32              `json:"pending_path_count"`
	ClassifierPending []ConfigStatusPath `json:"classifier_pending"`
	Skipped           []ConfigStatusPath `json:"skipped"`
	Conflicts         []ConfigStatusPath `json:"conflicts"`
	ErrorCode         string             `json:"error_code,omitempty"`
	RecoveryActions   []string           `json:"recovery_actions"`
	LastAttemptAt     *time.Time         `json:"last_attempt_at,omitempty"`
	LastSuccessfulAt  *time.Time         `json:"last_successful_sync_at,omitempty"`
	UpdatedAt         *time.Time         `json:"updated_at,omitempty"`
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
			Format: "paperboat-chezmoi-age-v1", Revision: s.policy.PolicyRevision,
			MaxFileBytes: s.policy.MaxFileBytes, MaxBatchBytes: s.policy.MaxBatchBytes,
			MandatoryExclusions: append([]string(nil), s.policy.MandatoryExcludes...),
		},
		Environments: make([]ConfigAccountEnvironment, 0, len(rows)),
	}
	for _, row := range rows {
		item := ConfigAccountEnvironment{
			EnvironmentID: row.EnvironmentID, DisplayName: row.DisplayName, Profile: row.Profile,
			EnvironmentState: row.EnvironmentState, State: canonicalAccountState(row, s.clock(), s.policy.StaleHeartbeatAfter),
			AssignmentID: row.AssignmentID.String, AssignmentVersion: row.AssignmentVersion.Int64,
			RepositoryID: row.RepositoryID.String, RepositoryName: row.RepositoryName.String,
			ConsentState: row.ConsentState.String, WarningRevision: row.WarningRevision.String,
			HelperID: row.HelperID, HelperGeneration: row.HelperGeneration,
			PolicyRevision: row.PolicyRevision.String, KeyVersion: row.KeyVersion.Int64,
			SyncRevision: row.SyncRevision.Int64, RemoteRevision: row.RemoteRevision.String,
			PendingPathCount: row.PendingPathCount.Int32, ErrorCode: row.ErrorCode.String,
			ClassifierPending: []ConfigStatusPath{}, Skipped: []ConfigStatusPath{},
			Conflicts: []ConfigStatusPath{}, RecoveryActions: []string{},
		}
		if s.policy.Mode == "disabled" ||
			(item.Profile == "byod" && !s.policy.BYODEnabled) ||
			(len(s.policy.EnvironmentAllowlist) > 0 && !slices.Contains(s.policy.EnvironmentAllowlist, item.EnvironmentID)) {
			item.State = "disabled"
		}
		decodeAccountStatusJSON(row.ClassifierPending, &item.ClassifierPending, s.limit)
		decodeAccountStatusJSON(row.Skipped, &item.Skipped, s.limit)
		decodeAccountStatusJSON(row.Conflicts, &item.Conflicts, s.limit)
		decodeAccountStatusJSON(row.RecoveryActions, &item.RecoveryActions, 8)
		item.LastAttemptAt = nullTimePointer(row.LastAttemptAt)
		item.LastSuccessfulAt = nullTimePointer(row.LastSuccessfulAt)
		item.UpdatedAt = nullTimePointer(row.HelperUpdatedAt)
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
	if row.HelperID == "" || !row.SyncState.Valid ||
		row.AssignmentID.String == "" || row.PolicyRevision.String == "" ||
		row.StatusAssignmentID.String != row.AssignmentID.String ||
		row.StatusRepositoryID.String != row.RepositoryID.String ||
		row.StatusHelperID.String != row.HelperID ||
		row.StatusHelperGeneration.Int64 != row.HelperGeneration {
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
	identity, err := s.identities.VerifyHelperRequest(ctx, identityToken, proof, method, path, body)
	if err != nil || identity.EnvironmentID != report.EnvironmentID || identity.HelperID != report.HelperID {
		return errors.Join(ErrConfigStatusInvalid, errConfigStatusIdentity)
	}
	helper, err := s.store.Queries().GetActiveControlHelperForEnvironment(ctx, identity.EnvironmentID)
	if err != nil || helper.ID != identity.HelperID || helper.Generation != report.HelperGeneration {
		return errors.Join(ErrConfigStatusInvalid, errConfigStatusHelper)
	}
	assignment, err := s.store.Queries().GetControlConfigAssignment(ctx, identity.EnvironmentID)
	if err != nil || assignment.ID != report.AssignmentID || !assignment.RepositoryID.Valid ||
		assignment.RepositoryID.String != report.RepositoryID || !assignment.WarningRevision.Valid ||
		assignment.WarningRevision.String != report.WarningRevision {
		return errors.Join(ErrConfigStatusInvalid, errConfigStatusAssign)
	}
	classifierPending, err := marshalConfigStatusList(report.ClassifierPending)
	if err != nil {
		return errors.Join(ErrConfigStatusInvalid, errConfigStatusReport)
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
			HelperID: report.HelperID, HelperGeneration: report.HelperGeneration, WarningRevision: report.WarningRevision,
			PolicyRevision: report.PolicyRevision, KeyVersion: report.KeyVersion, SyncRevision: report.SyncRevision,
			State: report.State, RemoteRevision: nullableString(report.RemoteRevision), LeaseID: nullableString(report.LeaseID),
			FencingToken: nullableInt64(report.FencingToken), PendingPathCount: int32(report.PendingPathCount),
			ClassifierPending: classifierPending, Skipped: skipped, Conflicts: conflicts,
			ErrorCode: nullableString(report.ErrorCode), RecoveryActions: recoveryActions,
			LastAttemptAt: nullableTimePointer(report.LastAttemptAt), LastSuccessfulAt: nullableTimePointer(report.LastSuccessfulAt),
			HelperUpdatedAt: report.UpdatedAt.UTC(), ObservedAt: now,
		})
		if err != nil {
			return err
		}
		if err = tx.Queries().InsertControlConfigSyncStatusHistory(ctx, dbsqlc.InsertControlConfigSyncStatusHistoryParams{
			EnvironmentID: report.EnvironmentID, SyncRevision: report.SyncRevision, RepositoryID: report.RepositoryID,
			AssignmentID: report.AssignmentID, HelperID: report.HelperID, HelperGeneration: report.HelperGeneration,
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
		report.AssignmentID == "" || report.EnvironmentID == "" || report.HelperID == "" ||
		report.HelperGeneration < 1 || report.WarningRevision == "" || report.PolicyRevision == "" ||
		report.KeyVersion < 0 || report.SyncRevision < 1 || report.PendingPathCount < 0 ||
		report.UpdatedAt.IsZero() || report.UpdatedAt.Before(now.Add(-5*time.Minute)) || report.UpdatedAt.After(now.Add(time.Minute)) ||
		len(report.RemoteRevision) > 256 || len(report.LeaseID) > 128 || report.FencingToken < 0 ||
		(report.FencingToken > 0 && report.LeaseID == "") || len(report.ErrorCode) > 64 ||
		(report.ErrorCode != "" && !statusCodePattern.MatchString(report.ErrorCode)) ||
		len(report.ClassifierPending) > limit || len(report.Skipped) > limit || len(report.Conflicts) > limit ||
		len(report.RecoveryActions) > 8 || (report.State == "conflict" && len(report.Conflicts) == 0) ||
		(report.State == "sync_uncertain" && report.ErrorCode != "sync_uncertain") {
		return ErrConfigStatusInvalid
	}
	for _, group := range [][]ConfigStatusPath{report.ClassifierPending, report.Skipped, report.Conflicts} {
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
