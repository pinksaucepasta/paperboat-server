package activity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ProjectID            string
	MachineID            string
	RuntimeDir           string
	Workspace            string
	Endpoint             string
	Token                string
	ReporterVersion      string
	SampleInterval       time.Duration
	HeartbeatInterval    time.Duration
	OutputMinBytesPerMin int64
	FSMaxDepth           int
	ExcludePaths         []string
	HTTPClient           *http.Client
	Now                  func() time.Time
	Log                  func(Heartbeat)
}

type Heartbeat struct {
	ProjectID       string            `json:"project_id"`
	MachineID       string            `json:"machine_id"`
	LastActivityAt  time.Time         `json:"last_activity_at"`
	Signals         map[string]string `json:"signals"`
	ReporterVersion string            `json:"reporter_version"`
	SampledAt       time.Time         `json:"sampled_at"`
}

type Reporter struct {
	cfg            Config
	lastActivity   time.Time
	signals        map[string]time.Time
	lastMarkerSeen map[string]time.Time
	lastOutputSize int64
	lastFSSnapshot map[string]time.Time
}

func FromEnv() Config {
	runtimeDir := env("PAPERBOAT_RUNTIME_DIR", "/var/lib/paperboat")
	return Config{
		ProjectID:            os.Getenv("PAPERBOAT_PROJECT_ID"),
		MachineID:            env("FLY_MACHINE_ID", os.Getenv("PAPERBOAT_MACHINE_ID")),
		RuntimeDir:           runtimeDir,
		Workspace:            env("PAPERBOAT_WORKSPACE", "/workspace"),
		Endpoint:             os.Getenv("PAPERBOAT_ACTIVITY_ENDPOINT"),
		Token:                os.Getenv("PAPERBOAT_MACHINE_ACTIVITY_TOKEN"),
		ReporterVersion:      env("PAPERBOAT_ACTIVITY_REPORTER_VERSION", "dev"),
		SampleInterval:       envDurationSeconds("PAPERBOAT_ACTIVITY_SAMPLE_SECONDS", 5*time.Second),
		HeartbeatInterval:    envDurationSeconds("PAPERBOAT_ACTIVITY_INTERVAL_SECONDS", 30*time.Second),
		OutputMinBytesPerMin: envInt64("PAPERBOAT_ACTIVITY_OUTPUT_MIN_BYTES_PER_MIN", 2048),
		FSMaxDepth:           int(envInt64("PAPERBOAT_ACTIVITY_FS_MAX_DEPTH", 6)),
		ExcludePaths:         envList("PAPERBOAT_ACTIVITY_FS_EXCLUDES", ".git/objects,node_modules"),
	}
}

func NewReporter(cfg Config) (*Reporter, error) {
	if cfg.ProjectID == "" {
		return nil, errors.New("PAPERBOAT_PROJECT_ID is required")
	}
	if cfg.MachineID == "" {
		return nil, errors.New("PAPERBOAT_MACHINE_ID is required")
	}
	if cfg.RuntimeDir == "" {
		cfg.RuntimeDir = "/var/lib/paperboat"
	}
	if cfg.Workspace == "" {
		cfg.Workspace = "/workspace"
	}
	if cfg.SampleInterval <= 0 {
		cfg.SampleInterval = 5 * time.Second
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.FSMaxDepth < 0 {
		cfg.FSMaxDepth = 0
	}
	if cfg.OutputMinBytesPerMin < 0 {
		cfg.OutputMinBytesPerMin = 0
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Log == nil {
		cfg.Log = func(h Heartbeat) {
			_ = json.NewEncoder(os.Stderr).Encode(map[string]any{
				"ts":               h.SampledAt.Format(time.RFC3339Nano),
				"component":        "activity",
				"level":            "info",
				"project_id":       h.ProjectID,
				"machine_id":       h.MachineID,
				"last_activity_at": h.LastActivityAt.Format(time.RFC3339Nano),
				"signals":          h.Signals,
			})
		}
	}
	now := cfg.Now().UTC()
	return &Reporter{
		cfg:            cfg,
		lastActivity:   now,
		signals:        map[string]time.Time{},
		lastMarkerSeen: map[string]time.Time{},
		lastFSSnapshot: map[string]time.Time{},
	}, nil
}

func (r *Reporter) Run(ctx context.Context) error {
	sample := time.NewTicker(r.cfg.SampleInterval)
	defer sample.Stop()
	heartbeat := time.NewTicker(r.cfg.HeartbeatInterval)
	defer heartbeat.Stop()
	if err := r.Sample(); err != nil {
		return err
	}
	if err := r.Heartbeat(ctx); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sample.C:
			if err := r.Sample(); err != nil {
				return err
			}
		case <-heartbeat.C:
			if err := r.Heartbeat(ctx); err != nil {
				return err
			}
		}
	}
}

func (r *Reporter) Sample() error {
	now := r.cfg.Now().UTC()
	for signal, name := range map[string]string{
		"input":      "input",
		"agent_hook": "agent-busy",
	} {
		if fired, err := r.markerAdvanced(signal, filepath.Join(r.cfg.RuntimeDir, "activity", name)); err != nil {
			return err
		} else if fired {
			r.bump(signal, now)
		}
	}
	if fired, err := r.outputActive(); err != nil {
		return err
	} else if fired {
		r.bump("output", now)
	}
	if fired, err := r.fsActive(); err != nil {
		return err
	} else if fired {
		r.bump("proc_fs", now)
	}
	return nil
}

func (r *Reporter) Heartbeat(ctx context.Context) error {
	h := r.Payload()
	r.cfg.Log(h)
	if strings.TrimSpace(r.cfg.Endpoint) == "" {
		return nil
	}
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if r.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	}
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("heartbeat rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (r *Reporter) Payload() Heartbeat {
	signals := make(map[string]string, len(r.signals))
	for k, v := range r.signals {
		signals[k] = v.UTC().Format(time.RFC3339Nano)
	}
	return Heartbeat{
		ProjectID:       r.cfg.ProjectID,
		MachineID:       r.cfg.MachineID,
		LastActivityAt:  r.lastActivity.UTC(),
		Signals:         signals,
		ReporterVersion: r.cfg.ReporterVersion,
		SampledAt:       r.cfg.Now().UTC(),
	}
}

func (r *Reporter) markerAdvanced(signal, path string) (bool, error) {
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	mtime := st.ModTime()
	if prev, ok := r.lastMarkerSeen[signal]; ok && !mtime.After(prev) {
		return false, nil
	}
	r.lastMarkerSeen[signal] = mtime
	return true, nil
}

func (r *Reporter) outputActive() (bool, error) {
	path := filepath.Join(r.cfg.RuntimeDir, "activity", "output")
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	size := st.Size()
	delta := size - r.lastOutputSize
	r.lastOutputSize = size
	if delta <= 0 {
		return false, nil
	}
	threshold := r.cfg.OutputMinBytesPerMin * int64(r.cfg.SampleInterval) / int64(time.Minute)
	if threshold < 1 {
		threshold = 1
	}
	return delta >= threshold, nil
}

func (r *Reporter) fsActive() (bool, error) {
	next := map[string]time.Time{}
	active := false
	root := filepath.Clean(r.cfg.Workspace)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		if rel == "." {
			return nil
		}
		depth := strings.Count(rel, string(os.PathSeparator)) + 1
		if r.cfg.FSMaxDepth > 0 && depth > r.cfg.FSMaxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if excluded(rel, r.cfg.ExcludePaths) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil || info.IsDir() {
			return nil
		}
		mt := info.ModTime()
		next[rel] = mt
		if prev, ok := r.lastFSSnapshot[rel]; ok && mt.After(prev) {
			active = true
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		r.lastFSSnapshot = next
		return false, nil
	}
	if err != nil {
		return false, err
	}
	r.lastFSSnapshot = next
	return active, nil
}

func (r *Reporter) bump(signal string, at time.Time) {
	r.signals[signal] = at.UTC()
	if at.After(r.lastActivity) {
		r.lastActivity = at.UTC()
	}
}

func excluded(rel string, excludes []string) bool {
	rel = filepath.ToSlash(rel)
	for _, pattern := range excludes {
		pattern = strings.Trim(strings.TrimSpace(filepath.ToSlash(pattern)), "/")
		if pattern == "" {
			continue
		}
		if rel == pattern || strings.HasPrefix(rel, pattern+"/") {
			return true
		}
	}
	return false
}

func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func envDurationSeconds(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return time.Duration(n) * time.Second
}

func envInt64(name string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func envList(name, fallback string) []string {
	raw := env(name, fallback)
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
