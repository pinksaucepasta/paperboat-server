package configsync

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

type Repository struct {
	db            *db.DB
	policy        config.ConfigSync
	now           func() time.Time
	encryptionKey string
	audit         *audit.Writer
}

type AccountStatus struct {
	Repository RepositoryInfo  `json:"repository"`
	Policy     PolicyInfo      `json:"policy"`
	State      string          `json:"state"`
	Projects   []MachineStatus `json:"projects"`
}

type RepositoryInfo struct {
	Owner  string `json:"owner"`
	Name   string `json:"name"`
	Branch string `json:"branch"`
	WebURL string `json:"web_url"`
}

type PolicyInfo struct {
	Revision            string   `json:"revision"`
	MaxFileBytes        int64    `json:"max_file_bytes"`
	MaxBatchBytes       int64    `json:"max_batch_bytes"`
	Format              string   `json:"format"`
	MandatoryExclusions []string `json:"mandatory_exclusions"`
}

type MachineStatus struct {
	ProjectID                string        `json:"project_id"`
	ProjectName              string        `json:"project_name"`
	ProjectState             string        `json:"project_state"`
	MachineID                string        `json:"machine_id"`
	State                    string        `json:"state"`
	LastResultState          string        `json:"last_result_state,omitempty"`
	LastAttemptAt            *time.Time    `json:"last_attempt_at,omitempty"`
	LastSuccessfulAt         *time.Time    `json:"last_successful_sync_at,omitempty"`
	RemoteCommit             string        `json:"remote_commit,omitempty"`
	PendingPathCount         int           `json:"pending_path_count"`
	ClassifierPending        []PathSummary `json:"classifier_pending"`
	Skipped                  []PathSummary `json:"skipped"`
	Conflicts                []PathSummary `json:"conflicts"`
	ErrorCode                string        `json:"error_code,omitempty"`
	ErrorMessage             string        `json:"error_message,omitempty"`
	HeartbeatAt              *time.Time    `json:"heartbeat_at,omitempty"`
	StatusUpdatedAt          *time.Time    `json:"status_updated_at,omitempty"`
	MaxFileBytes             int64         `json:"max_file_bytes"`
	MaxBatchBytes            int64         `json:"max_batch_bytes"`
	PolicyRevision           string        `json:"policy_revision"`
	ClassifierPolicyRevision string        `json:"classifier_policy_revision,omitempty"`
	ClassifierModelRevision  string        `json:"classifier_model_revision,omitempty"`
	ClassifierHealth         string        `json:"classifier_health,omitempty"`
	EncryptionKeyVersion     int           `json:"encryption_key_version,omitempty"`
}

func NewRepository(store *db.DB, policy config.ConfigSync, encryptionKey string, auditWriter *audit.Writer) *Repository {
	return &Repository{db: store, policy: policy, encryptionKey: encryptionKey, audit: auditWriter, now: func() time.Time { return time.Now().UTC() }}
}

type AccountKey struct {
	Version   int32  `json:"version"`
	Recipient string `json:"recipient"`
	Identity  string `json:"-"`
}

type ClassificationOverride struct {
	Path      string    `json:"path"`
	Decision  string    `json:"decision"`
	Mandatory bool      `json:"mandatory"`
	UpdatedAt time.Time `json:"updated_at"`
}

var (
	ErrMandatoryExclusion = errors.New("mandatory config exclusion cannot be overridden")
	ErrRotationPending    = errors.New("account config key rotation is already pending")
)

func (r *Repository) EnsureAccountKey(ctx context.Context, userID string) (AccountKey, error) {
	if strings.TrimSpace(r.encryptionKey) == "" {
		return AccountKey{}, errors.New("config key encryption is not configured")
	}
	row, err := r.db.Queries().GetAccountConfigKey(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		identity, generateErr := age.GenerateX25519Identity()
		if generateErr != nil {
			return AccountKey{}, generateErr
		}
		ciphertext, encryptErr := secrets.Encrypt(r.encryptionKey, identity.String())
		if encryptErr != nil {
			return AccountKey{}, encryptErr
		}
		_, err = r.db.Queries().InsertAccountConfigKey(ctx, dbsqlc.InsertAccountConfigKeyParams{UserID: userID, Recipient: identity.Recipient().String(), EncryptedIdentity: ciphertext})
		if err != nil {
			return AccountKey{}, err
		}
		row, err = r.db.Queries().GetAccountConfigKey(ctx, userID)
	}
	if err != nil {
		return AccountKey{}, err
	}
	identity, err := secrets.Decrypt(r.encryptionKey, row.EncryptedIdentity)
	if err != nil {
		return AccountKey{}, fmt.Errorf("decrypt account config identity: %w", err)
	}
	if len(row.PreviousEncryptedIdentity) > 0 {
		previous, previousErr := secrets.Decrypt(r.encryptionKey, row.PreviousEncryptedIdentity)
		if previousErr != nil {
			return AccountKey{}, previousErr
		}
		identity += "\n" + previous
	}
	return AccountKey{Version: row.KeyVersion, Recipient: row.Recipient, Identity: identity}, nil
}

func (r *Repository) RotateAccountKey(ctx context.Context, userID string) (AccountKey, error) {
	row, err := r.db.Queries().GetAccountConfigKey(ctx, userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return AccountKey{}, err
	}
	if err == nil && len(row.PreviousEncryptedIdentity) > 0 {
		return AccountKey{}, ErrRotationPending
	}
	current, err := r.EnsureAccountKey(ctx, userID)
	if err != nil {
		return AccountKey{}, err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return AccountKey{}, err
	}
	ciphertext, err := secrets.Encrypt(r.encryptionKey, identity.String())
	if err != nil {
		return AccountKey{}, err
	}
	nextVersion := current.Version + 1
	if err := r.db.Queries().RotateAccountConfigKey(ctx, dbsqlc.RotateAccountConfigKeyParams{KeyVersion: nextVersion, Recipient: identity.Recipient().String(), EncryptedIdentity: ciphertext, UserID: userID}); err != nil {
		return AccountKey{}, err
	}
	if err := r.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "config_sync.key_rotated", ResourceType: "user", ResourceID: userID, IdempotencyKey: fmt.Sprintf("config-key-rotate:%s:%d", userID, nextVersion), Metadata: map[string]any{"previous_version": current.Version, "key_version": nextVersion}}); err != nil {
		return AccountKey{}, err
	}
	return AccountKey{Version: nextVersion, Recipient: identity.Recipient().String(), Identity: identity.String() + "\n" + current.Identity}, nil
}

func (r *Repository) ExportAccountKey(ctx context.Context, userID string) (AccountKey, error) {
	key, err := r.EnsureAccountKey(ctx, userID)
	if err != nil {
		return AccountKey{}, err
	}
	if err := r.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "config_sync.recovery_key_exported", ResourceType: "user", ResourceID: userID, IdempotencyKey: fmt.Sprintf("config-key-export:%s:%d:%d", userID, key.Version, r.now().UnixNano())}); err != nil {
		return AccountKey{}, err
	}
	return key, nil
}

func (r *Repository) ListOverrides(ctx context.Context, userID string) ([]ClassificationOverride, error) {
	rows, err := r.db.Queries().ListConfigClassificationOverrides(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]ClassificationOverride, 0, len(rows))
	for _, row := range rows {
		out = append(out, ClassificationOverride{Path: row.NormalizedPath, Decision: row.Decision, UpdatedAt: row.UpdatedAt})
	}
	return out, nil
}

func (r *Repository) PutOverride(ctx context.Context, userID, pathValue, decision string) error {
	pathValue = cleanRelative(pathValue)
	if pathValue == "" || validatePattern(pathValue) != nil {
		return errors.New("invalid override path")
	}
	if decision != "portable" && decision != "project_only" && decision != "exclude" {
		return errors.New("invalid override decision")
	}
	policy := Policy{MandatoryExcludes: r.policy.MandatoryExcludes}
	if policy.Excluded(pathValue) {
		return ErrMandatoryExclusion
	}
	if err := r.db.Queries().UpsertConfigClassificationOverride(ctx, dbsqlc.UpsertConfigClassificationOverrideParams{UserID: userID, NormalizedPath: pathValue, Decision: decision, CreatedBy: userID}); err != nil {
		return err
	}
	return r.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "config_sync.override_changed", ResourceType: "config_path", ResourceID: pathValue, IdempotencyKey: fmt.Sprintf("config-override:%s:%s:%d", userID, pathValue, r.now().UnixNano()), Metadata: map[string]any{"decision": decision}})
}

func (r *Repository) DeleteOverride(ctx context.Context, userID, pathValue string) error {
	pathValue = cleanRelative(pathValue)
	if pathValue == "" {
		return errors.New("invalid override path")
	}
	if _, err := r.db.Queries().DeleteConfigClassificationOverride(ctx, dbsqlc.DeleteConfigClassificationOverrideParams{UserID: userID, NormalizedPath: pathValue}); err != nil {
		return err
	}
	return r.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "config_sync.override_removed", ResourceType: "config_path", ResourceID: pathValue, IdempotencyKey: fmt.Sprintf("config-override-remove:%s:%s:%d", userID, pathValue, r.now().UnixNano())})
}

func (r *Repository) RetireCompletedRotations(ctx context.Context) error {
	rows, err := r.db.Queries().ListCompletedAccountConfigKeyRotations(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := r.db.Queries().RetirePreviousAccountConfigKey(ctx, dbsqlc.RetirePreviousAccountConfigKeyParams{UserID: row.UserID, KeyVersion: row.KeyVersion}); err != nil {
			return err
		}
		if err := r.audit.Write(ctx, audit.Event{ActorUserID: row.UserID, ActorType: audit.ActorSystem, EventType: "config_sync.previous_key_retired", ResourceType: "user", ResourceID: row.UserID, IdempotencyKey: fmt.Sprintf("config-key-retire:%s:%d", row.UserID, row.KeyVersion), Metadata: map[string]any{"key_version": row.KeyVersion}}); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) RotationWorker(interval time.Duration) func(context.Context) error {
	if interval <= 0 {
		interval = time.Minute
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := r.RetireCompletedRotations(ctx); err != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func (r *Repository) Account(ctx context.Context, userID string) (AccountStatus, error) {
	result := AccountStatus{State: "idle", Policy: PolicyInfo{Revision: r.policy.PolicyRevision, MaxFileBytes: r.policy.MaxFileBytes, MaxBatchBytes: r.policy.MaxBatchBytes, Format: "paperboat-chezmoi-age-v1", MandatoryExclusions: append([]string{}, r.policy.MandatoryExcludes...)}, Projects: []MachineStatus{}}
	repo, err := r.db.Queries().GetConfigSyncRepositoryByUser(ctx, userID)
	if err == nil {
		result.Repository = RepositoryInfo{Owner: repo.Owner, Name: repo.Name, Branch: repo.DefaultBranch, WebURL: safeWebURL(repo.HtmlUrl)}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return AccountStatus{}, err
	}
	rows, err := r.db.Queries().ListConfigSyncStatusesByUser(ctx, userID)
	if err != nil {
		return AccountStatus{}, err
	}
	for _, row := range rows {
		item := MachineStatus{ProjectID: row.ProjectID, ProjectName: row.ProjectName, ProjectState: row.ProjectState, MachineID: row.MachineID, State: row.State, RemoteCommit: row.RemoteCommit, PendingPathCount: int(row.PendingPathCount), ErrorCode: row.ErrorCode, ErrorMessage: row.ErrorMessage, MaxFileBytes: row.MaxFileBytes, MaxBatchBytes: row.MaxBatchBytes, PolicyRevision: row.PolicyRevision, ClassifierPolicyRevision: row.ClassifierPolicyRevision, ClassifierModelRevision: row.ClassifierModelRevision, ClassifierHealth: row.ClassifierHealth, EncryptionKeyVersion: int(row.EncryptionKeyVersion)}
		if row.MaxFileBytes > 0 && row.MaxFileBytes < result.Policy.MaxFileBytes {
			result.Policy.MaxFileBytes = row.MaxFileBytes
		}
		if row.MaxBatchBytes > 0 && row.MaxBatchBytes < result.Policy.MaxBatchBytes {
			result.Policy.MaxBatchBytes = row.MaxBatchBytes
		}
		if row.LastAttemptAt.Valid {
			at := row.LastAttemptAt.Time.UTC()
			item.LastAttemptAt = &at
		}
		if row.LastSuccessfulSyncAt.Valid {
			at := row.LastSuccessfulSyncAt.Time.UTC()
			item.LastSuccessfulAt = &at
		}
		_ = json.Unmarshal(row.Skipped, &item.Skipped)
		_ = json.Unmarshal(row.Conflicts, &item.Conflicts)
		_ = json.Unmarshal(row.ClassifierPending, &item.ClassifierPending)
		item.Skipped = boundSummaries(item.Skipped, r.policy.SummaryLimit)
		item.Conflicts = boundSummaries(item.Conflicts, r.policy.SummaryLimit)
		item.ClassifierPending = boundSummaries(item.ClassifierPending, r.policy.SummaryLimit)
		if item.Skipped == nil {
			item.Skipped = []PathSummary{}
		}
		if item.Conflicts == nil {
			item.Conflicts = []PathSummary{}
		}
		if item.ClassifierPending == nil {
			item.ClassifierPending = []PathSummary{}
		}
		if row.State == "" {
			item.State = stateWithoutHeartbeat(row.ProjectState)
		} else {
			heartbeat := row.HeartbeatAt.UTC()
			statusUpdated := row.StatusUpdatedAt.UTC()
			statusObserved := row.StatusObservedAt.UTC()
			received := row.ReceivedAt.UTC()
			item.HeartbeatAt = &heartbeat
			item.StatusUpdatedAt = &statusUpdated
			now := r.now()
			activityStale := now.Sub(received) > r.policy.StaleHeartbeatAfter
			statusStale := now.Sub(statusObserved) > r.policy.StaleHeartbeatAfter
			if activeProject(row.ProjectState) && (activityStale || statusStale) {
				item.LastResultState, item.State = item.State, "offline"
			} else if !activeProject(row.ProjectState) {
				item.LastResultState, item.State = item.State, "idle"
			}
		}
		result.Projects = append(result.Projects, item)
	}
	result.State = aggregate(result.Projects)
	return result, nil
}

func activeProject(state string) bool {
	switch state {
	case "creating", "provisioning_storage", "provisioning_machine", "starting", "running", "restarting", "stopping":
		return true
	}
	return false
}

func stateWithoutHeartbeat(projectState string) string {
	if activeProject(projectState) {
		return "offline"
	}
	return "idle"
}

func aggregate(items []MachineStatus) string {
	priority := map[string]int{"idle": 0, "healthy": 1, "watching": 1, "pending": 2, "syncing": 2, "restoring": 2, "warning": 3, "offline": 4, "error": 5, "conflict": 6}
	state, rank := "idle", 0
	for _, item := range items {
		candidate := item.State
		if candidate == "idle" && priority[item.LastResultState] > priority[candidate] {
			candidate = item.LastResultState
		}
		if priority[candidate] > rank {
			state, rank = candidate, priority[candidate]
		}
	}
	return state
}

func safeWebURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return ""
	}
	parsed.RawQuery, parsed.Fragment = "", ""
	return parsed.String()
}
