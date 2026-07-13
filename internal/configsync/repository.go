package configsync

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

type Repository struct {
	db     *db.DB
	policy config.ConfigSync
	now    func() time.Time
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
	Revision      string `json:"revision"`
	MaxFileBytes  int64  `json:"max_file_bytes"`
	MaxBatchBytes int64  `json:"max_batch_bytes"`
}

type MachineStatus struct {
	ProjectID        string        `json:"project_id"`
	ProjectName      string        `json:"project_name"`
	ProjectState     string        `json:"project_state"`
	MachineID        string        `json:"machine_id"`
	State            string        `json:"state"`
	LastResultState  string        `json:"last_result_state,omitempty"`
	LastAttemptAt    *time.Time    `json:"last_attempt_at,omitempty"`
	LastSuccessfulAt *time.Time    `json:"last_successful_sync_at,omitempty"`
	RemoteCommit     string        `json:"remote_commit,omitempty"`
	PendingPathCount int           `json:"pending_path_count"`
	Skipped          []PathSummary `json:"skipped"`
	Conflicts        []PathSummary `json:"conflicts"`
	ErrorCode        string        `json:"error_code,omitempty"`
	ErrorMessage     string        `json:"error_message,omitempty"`
	HeartbeatAt      *time.Time    `json:"heartbeat_at,omitempty"`
	StatusUpdatedAt  *time.Time    `json:"status_updated_at,omitempty"`
	MaxFileBytes     int64         `json:"max_file_bytes"`
	MaxBatchBytes    int64         `json:"max_batch_bytes"`
	PolicyRevision   string        `json:"policy_revision"`
}

func NewRepository(store *db.DB, policy config.ConfigSync) *Repository {
	return &Repository{db: store, policy: policy, now: func() time.Time { return time.Now().UTC() }}
}

func (r *Repository) Account(ctx context.Context, userID string) (AccountStatus, error) {
	result := AccountStatus{State: "idle", Policy: PolicyInfo{Revision: r.policy.PolicyRevision, MaxFileBytes: r.policy.MaxFileBytes, MaxBatchBytes: r.policy.MaxBatchBytes}, Projects: []MachineStatus{}}
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
		item := MachineStatus{ProjectID: row.ProjectID, ProjectName: row.ProjectName, ProjectState: row.ProjectState, MachineID: row.MachineID, State: row.State, RemoteCommit: row.RemoteCommit, PendingPathCount: int(row.PendingPathCount), ErrorCode: row.ErrorCode, ErrorMessage: row.ErrorMessage, MaxFileBytes: row.MaxFileBytes, MaxBatchBytes: row.MaxBatchBytes, PolicyRevision: row.PolicyRevision}
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
		item.Skipped = boundSummaries(item.Skipped, r.policy.SummaryLimit)
		item.Conflicts = boundSummaries(item.Conflicts, r.policy.SummaryLimit)
		if item.Skipped == nil {
			item.Skipped = []PathSummary{}
		}
		if item.Conflicts == nil {
			item.Conflicts = []PathSummary{}
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
