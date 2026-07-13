package configsync

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var validStates = map[string]struct{}{
	"restoring": {}, "watching": {}, "pending": {}, "syncing": {}, "healthy": {},
	"warning": {}, "conflict": {}, "error": {}, "offline": {},
}

type PathSummary struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes,omitempty"`
	Reason string `json:"reason"`
}

type Status struct {
	State            string        `json:"state"`
	LastAttemptAt    *time.Time    `json:"last_attempt_at,omitempty"`
	LastSuccessfulAt *time.Time    `json:"last_successful_sync_at,omitempty"`
	RemoteCommit     string        `json:"remote_commit,omitempty"`
	PendingPathCount int           `json:"pending_path_count"`
	Skipped          []PathSummary `json:"skipped,omitempty"`
	Conflicts        []PathSummary `json:"conflicts,omitempty"`
	ErrorCode        string        `json:"error_code,omitempty"`
	ErrorMessage     string        `json:"error_message,omitempty"`
	MaxFileBytes     int64         `json:"max_file_bytes"`
	MaxBatchBytes    int64         `json:"max_batch_bytes"`
	PolicyRevision   string        `json:"policy_revision"`
	UpdatedAt        time.Time     `json:"updated_at"`
}

func NormalizeStatus(status Status, limit int) (Status, error) {
	if _, ok := validStates[status.State]; !ok {
		return Status{}, fmt.Errorf("invalid config sync state")
	}
	if status.PendingPathCount < 0 || status.MaxFileBytes <= 0 || status.MaxBatchBytes < status.MaxFileBytes || strings.TrimSpace(status.PolicyRevision) == "" || status.UpdatedAt.IsZero() {
		return Status{}, fmt.Errorf("invalid config sync limits")
	}
	status.Skipped = boundSummaries(status.Skipped, limit)
	status.Conflicts = boundSummaries(status.Conflicts, limit)
	for index := range status.Skipped {
		if err := normalizeSummary(&status.Skipped[index]); err != nil {
			return Status{}, err
		}
	}
	for index := range status.Conflicts {
		if err := normalizeSummary(&status.Conflicts[index]); err != nil {
			return Status{}, err
		}
	}
	status.ErrorCode = sanitizeCode(status.ErrorCode)
	if len(status.ErrorCode) > 64 {
		status.ErrorCode = status.ErrorCode[:64]
	}
	status.ErrorMessage = sanitizeMessage(status.ErrorMessage)
	if len(status.RemoteCommit) > 128 {
		status.RemoteCommit = status.RemoteCommit[:128]
	}
	if len(status.PolicyRevision) > 64 {
		status.PolicyRevision = status.PolicyRevision[:64]
	}
	return status, nil
}

func normalizeSummary(summary *PathSummary) error {
	original := strings.TrimSpace(summary.Path)
	if len(original) > 4096 || validatePattern(original) != nil || summary.Bytes < 0 {
		return fmt.Errorf("invalid config sync path summary")
	}
	summary.Path = cleanRelative(original)
	if summary.Path == "" {
		return fmt.Errorf("invalid config sync path summary")
	}
	summary.Reason = sanitizeCode(summary.Reason)
	if len(summary.Reason) > 64 {
		summary.Reason = summary.Reason[:64]
	}
	if summary.Reason == "" {
		return fmt.Errorf("invalid config sync path summary reason")
	}
	return nil
}

type statusWriter struct {
	path  string
	limit int
	last  Status
}

func newStatusWriter(path string, policy Policy) *statusWriter {
	return &statusWriter{path: path, limit: policy.SummaryLimit, last: Status{State: "offline", MaxFileBytes: policy.MaxFileBytes, MaxBatchBytes: policy.MaxBatchBytes, PolicyRevision: policy.Revision}}
}

func (w *statusWriter) write(update func(*Status)) error {
	status := w.last
	update(&status)
	status.UpdatedAt = time.Now().UTC()
	status.Skipped = boundSummaries(status.Skipped, w.limit)
	status.Conflicts = boundSummaries(status.Conflicts, w.limit)
	status.ErrorCode = sanitizeCode(status.ErrorCode)
	status.ErrorMessage = sanitizeMessage(status.ErrorMessage)
	b, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return err
	}
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, w.path); err != nil {
		return err
	}
	w.last = status
	return nil
}

func ReadStatus(path string, limit int) (*Status, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var status Status
	if err := json.Unmarshal(b, &status); err != nil {
		return nil, err
	}
	status.Skipped = boundSummaries(status.Skipped, limit)
	status.Conflicts = boundSummaries(status.Conflicts, limit)
	status.ErrorCode = sanitizeCode(status.ErrorCode)
	status.ErrorMessage = sanitizeMessage(status.ErrorMessage)
	return &status, nil
}

func boundSummaries(values []PathSummary, limit int) []PathSummary {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return append([]PathSummary{}, values[:limit]...)
}

var codeCharacters = regexp.MustCompile(`[^a-z0-9_]+`)
var secretMessagePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:gh[pousr]_[a-z0-9_]{20,}|github_pat_[a-z0-9_]{20,})\b`),
	regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{12,}`),
	regexp.MustCompile(`(?i)\b(?:token|password|secret|api[_-]?key)\s*[=:]\s*[^\s&,;]+`),
}

func sanitizeCode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = codeCharacters.ReplaceAllString(value, "_")
	return strings.Trim(value, "_")
}

func sanitizeMessage(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	for _, pattern := range secretMessagePatterns {
		value = pattern.ReplaceAllString(value, "[redacted]")
	}
	for _, marker := range []string{"https://", "http://", "token=", "authorization:", "password="} {
		if index := strings.Index(strings.ToLower(value), marker); index >= 0 {
			value = value[:index] + "[redacted]"
		}
	}
	if len(value) > 240 {
		value = value[:240]
	}
	return value
}
