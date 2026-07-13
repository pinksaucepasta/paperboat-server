package configsync

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/pinksaucepasta/paperboat-server/internal/configsyncpolicy"
)

const manifestPath = ".paperboat/config-sync.json"

var defaultMandatoryExcludes = configsyncpolicy.MandatoryExcludes()

type Policy struct {
	Revision             string        `json:"revision"`
	HomeOverride         string        `json:"home_override,omitempty"`
	Includes             []string      `json:"includes"`
	Excludes             []string      `json:"excludes"`
	MandatoryExcludes    []string      `json:"mandatory_excludes"`
	MaxFileBytes         int64         `json:"max_file_bytes"`
	MaxBatchBytes        int64         `json:"max_batch_bytes"`
	Debounce             time.Duration `json:"-"`
	MinPushInterval      time.Duration `json:"-"`
	MaxDirtyDelay        time.Duration `json:"-"`
	RemotePollInterval   time.Duration `json:"-"`
	RetryLimit           int           `json:"retry_limit"`
	ShutdownFlushTimeout time.Duration `json:"-"`
	SummaryLimit         int           `json:"summary_limit"`
}

type manifest struct {
	SchemaVersion        int      `json:"schema_version"`
	Revision             string   `json:"revision"`
	Includes             []string `json:"includes"`
	Excludes             []string `json:"excludes"`
	MandatoryExcludes    []string `json:"mandatory_excludes"`
	MaxFileBytes         int64    `json:"max_file_bytes"`
	MaxBatchBytes        int64    `json:"max_batch_bytes"`
	DebounceSeconds      int64    `json:"debounce_seconds"`
	MinPushSeconds       int64    `json:"min_push_interval_seconds"`
	MaxDirtyDelaySeconds int64    `json:"max_dirty_delay_seconds"`
	RemotePollSeconds    int64    `json:"remote_poll_interval_seconds"`
	RetryLimit           int      `json:"retry_limit"`
	ShutdownSeconds      int64    `json:"shutdown_flush_deadline_seconds"`
	SummaryLimit         int      `json:"summary_limit"`
}

func PolicyFromEnv() Policy {
	return Policy{
		Revision:             env("PAPERBOAT_CONFIG_POLICY_REVISION", "2"),
		HomeOverride:         strings.TrimSpace(os.Getenv("PAPERBOAT_CONFIG_HOME")),
		Includes:             envList("PAPERBOAT_CONFIG_INCLUDES"),
		Excludes:             envList("PAPERBOAT_CONFIG_EXCLUDES"),
		MandatoryExcludes:    envListUnion("PAPERBOAT_CONFIG_MANDATORY_EXCLUDES", defaultMandatoryExcludes),
		MaxFileBytes:         envInt("PAPERBOAT_CONFIG_MAX_FILE_BYTES", 5<<20),
		MaxBatchBytes:        envInt("PAPERBOAT_CONFIG_MAX_BATCH_BYTES", 25<<20),
		Debounce:             envDuration("PAPERBOAT_CONFIG_DEBOUNCE_SECONDS", 10*time.Second),
		MinPushInterval:      envDuration("PAPERBOAT_CONFIG_MIN_PUSH_INTERVAL_SECONDS", time.Minute),
		MaxDirtyDelay:        envDuration("PAPERBOAT_CONFIG_MAX_DIRTY_DELAY_SECONDS", 5*time.Minute),
		RemotePollInterval:   envDuration("PAPERBOAT_CONFIG_REMOTE_POLL_SECONDS", time.Minute),
		RetryLimit:           int(envInt("PAPERBOAT_CONFIG_RETRY_LIMIT", 5)),
		ShutdownFlushTimeout: envDuration("PAPERBOAT_CONFIG_SHUTDOWN_DEADLINE_SECONDS", 30*time.Second),
		SummaryLimit:         int(envInt("PAPERBOAT_CONFIG_SUMMARY_LIMIT", 50)),
	}
}

func (p Policy) Validate(home, workspace, repo string) error {
	if p.MaxFileBytes <= 0 || p.MaxBatchBytes <= 0 || p.MaxBatchBytes < p.MaxFileBytes {
		return errors.New("config sync size limits are invalid")
	}
	if p.Debounce <= 0 || p.MinPushInterval <= 0 || p.MaxDirtyDelay <= 0 || p.RemotePollInterval <= 0 || p.ShutdownFlushTimeout <= 0 || p.RetryLimit <= 0 || p.SummaryLimit <= 0 {
		return errors.New("config sync timing and retention limits must be positive")
	}
	if strings.TrimSpace(home) == "" || !filepath.IsAbs(home) {
		return errors.New("config home must be an absolute path")
	}
	cleanHome, err := canonicalPath(home)
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	cleanWorkspace, err := canonicalPath(workspace)
	if err != nil {
		return fmt.Errorf("resolve workspace: %w", err)
	}
	cleanRepo, err := canonicalPath(repo)
	if err != nil {
		return fmt.Errorf("resolve repository: %w", err)
	}
	if cleanHome == string(filepath.Separator) || sameOrInside(cleanHome, cleanWorkspace) || sameOrInside(cleanHome, cleanRepo) || sameOrInside(cleanWorkspace, cleanHome) || sameOrInside(cleanRepo, cleanHome) {
		return errors.New("config home overlaps a protected runtime path")
	}
	patterns := append(append(append([]string{}, p.Includes...), p.Excludes...), p.MandatoryExcludes...)
	for _, pattern := range patterns {
		if err := validatePattern(pattern); err != nil {
			return err
		}
	}
	return nil
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := abs
	missing := make([]string, 0)
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func (p Policy) WithManifest(repo string) (Policy, error) {
	m, exists, err := readManifest(repo)
	if err != nil {
		return p, err
	}
	if !exists {
		return p, nil
	}
	if err := validateManifest(m); err != nil {
		return p, err
	}
	p.Includes = unique(append(p.Includes, m.Includes...))
	p.Excludes = unique(append(p.Excludes, m.Excludes...))
	p.MaxFileBytes, p.MaxBatchBytes = effectiveLimits(p.MaxFileBytes, p.MaxBatchBytes, m)
	return p, nil
}

// EnsureManifest upgrades control metadata while retaining all user patterns and
// allowing repository limits to become stricter, never looser, than server policy.
func (p Policy) EnsureManifest(repo string) (bool, error) {
	existing, exists, err := readManifest(repo)
	if err != nil {
		return false, err
	}
	if exists {
		if err := validateManifest(existing); err != nil {
			return false, err
		}
	}
	maxFile, maxBatch := p.MaxFileBytes, p.MaxBatchBytes
	if exists {
		maxFile, maxBatch = effectiveLimits(maxFile, maxBatch, existing)
	}
	next := manifest{
		SchemaVersion:        1,
		Revision:             p.Revision,
		Includes:             unique(append(append([]string{}, p.Includes...), existing.Includes...)),
		Excludes:             unique(append(append([]string{}, p.Excludes...), existing.Excludes...)),
		MandatoryExcludes:    unique(p.MandatoryExcludes),
		MaxFileBytes:         maxFile,
		MaxBatchBytes:        maxBatch,
		DebounceSeconds:      durationSeconds(p.Debounce),
		MinPushSeconds:       durationSeconds(p.MinPushInterval),
		MaxDirtyDelaySeconds: durationSeconds(p.MaxDirtyDelay),
		RemotePollSeconds:    durationSeconds(p.RemotePollInterval),
		RetryLimit:           p.RetryLimit,
		ShutdownSeconds:      durationSeconds(p.ShutdownFlushTimeout),
		SummaryLimit:         p.SummaryLimit,
	}
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return false, err
	}
	b = append(b, '\n')
	path := filepath.Join(repo, manifestPath)
	current, readErr := os.ReadFile(path)
	if readErr == nil && string(current) == string(b) {
		return false, nil
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return false, readErr
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, err
	}
	return true, nil
}

func effectiveLimits(serverFile, serverBatch int64, repository manifest) (int64, int64) {
	maxFile, maxBatch := serverFile, serverBatch
	if repository.MaxFileBytes > 0 && repository.MaxFileBytes < maxFile {
		maxFile = repository.MaxFileBytes
	}
	if repository.MaxBatchBytes > 0 && repository.MaxBatchBytes < maxBatch {
		maxBatch = repository.MaxBatchBytes
	}
	if maxFile > maxBatch {
		maxFile = maxBatch
	}
	return maxFile, maxBatch
}

func validateManifest(value manifest) error {
	if value.SchemaVersion != 0 && value.SchemaVersion != 1 {
		return fmt.Errorf("unsupported config manifest schema version %d", value.SchemaVersion)
	}
	for _, pattern := range append(append([]string{}, value.Includes...), value.Excludes...) {
		if err := validatePattern(pattern); err != nil {
			return err
		}
	}
	if value.MaxFileBytes < 0 || value.MaxBatchBytes < 0 || (value.MaxFileBytes > 0 && value.MaxBatchBytes > 0 && value.MaxBatchBytes < value.MaxFileBytes) {
		return errors.New("config manifest size limits are invalid")
	}
	return nil
}

func durationSeconds(value time.Duration) int64 {
	seconds := int64((value + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func readManifest(repo string) (manifest, bool, error) {
	path := filepath.Join(repo, manifestPath)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return manifest{}, false, nil
	}
	if err != nil {
		return manifest{}, false, err
	}
	if !info.Mode().IsRegular() {
		return manifest{}, false, errors.New("config manifest is not a regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return manifest{}, false, err
	}
	var value manifest
	if err := json.Unmarshal(b, &value); err != nil {
		return manifest{}, false, fmt.Errorf("parse config manifest: %w", err)
	}
	return value, true, nil
}

func (p Policy) Managed(rel string) bool {
	rel = cleanRelative(rel)
	if rel == "" || strings.HasPrefix(rel, ".paperboat/") || rel == ".paperboat" || p.Excluded(rel) {
		return false
	}
	first := strings.Split(rel, "/")[0]
	if strings.HasPrefix(first, ".") {
		return true
	}
	for _, pattern := range p.Includes {
		if match(pattern, rel) {
			return true
		}
	}
	return false
}

func (p Policy) Excluded(rel string) bool {
	rel = cleanRelative(rel)
	for _, pattern := range append(append([]string{}, p.MandatoryExcludes...), p.Excludes...) {
		if match(pattern, rel) {
			return true
		}
	}
	return false
}

func validatePattern(pattern string) error {
	pattern = filepath.ToSlash(strings.TrimSpace(pattern))
	if pattern == "" || filepath.IsAbs(pattern) || strings.HasPrefix(pattern, "/") {
		return fmt.Errorf("unsafe config path pattern %q", pattern)
	}
	for _, part := range strings.Split(pattern, "/") {
		if part == ".." {
			return fmt.Errorf("unsafe config path traversal in %q", pattern)
		}
	}
	if _, err := doublestar.Match(pattern, "probe"); err != nil {
		return fmt.Errorf("invalid config path pattern %q", pattern)
	}
	return nil
}

func match(pattern, rel string) bool {
	pattern = cleanRelative(pattern)
	rel = cleanRelative(rel)
	if rel == pattern || strings.HasPrefix(rel, strings.TrimSuffix(pattern, "/")+"/") {
		return true
	}
	ok, _ := doublestar.Match(pattern, rel)
	if ok {
		return true
	}
	ok, _ = doublestar.Match(strings.TrimSuffix(pattern, "/")+"/**", rel)
	return ok
}

func cleanRelative(value string) string {
	value = filepath.ToSlash(strings.TrimSpace(value))
	return strings.Trim(strings.TrimPrefix(filepath.Clean(value), "./"), "/")
}

func sameOrInside(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envDuration(name string, fallback time.Duration) time.Duration {
	return time.Duration(envInt(name, int64(fallback/time.Second))) * time.Second
}

func envList(name string) []string {
	return splitList(os.Getenv(name))
}

func envListUnion(name string, mandatory []string) []string {
	return unique(append(append([]string{}, mandatory...), splitList(os.Getenv(name))...))
}

func splitList(value string) []string {
	return unique(strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' }))
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = filepath.ToSlash(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
