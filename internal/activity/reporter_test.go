package activity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMarkerInputBumpsLastActivity(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	runtimeDir := t.TempDir()
	mustMkdir(t, filepath.Join(runtimeDir, "activity"))
	cfg := testConfig(runtimeDir, t.TempDir(), func() time.Time { return now })
	reporter, err := NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	mustWrite(t, filepath.Join(runtimeDir, "activity", "input"), "x")
	if err := reporter.Sample(); err != nil {
		t.Fatal(err)
	}
	if !reporter.lastActivity.Equal(now) {
		t.Fatalf("lastActivity = %s, want %s", reporter.lastActivity, now)
	}
	if reporter.signals["input"].IsZero() {
		t.Fatal("input signal was not recorded")
	}
}

func TestOutputBelowThresholdDoesNotBump(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	runtimeDir := t.TempDir()
	mustMkdir(t, filepath.Join(runtimeDir, "activity"))
	cfg := testConfig(runtimeDir, t.TempDir(), func() time.Time { return now })
	cfg.OutputMinBytesPerMin = 600
	cfg.SampleInterval = time.Second
	reporter, err := NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	initial := reporter.lastActivity
	mustWrite(t, filepath.Join(runtimeDir, "activity", "output"), "123")
	now = now.Add(time.Second)
	if err := reporter.Sample(); err != nil {
		t.Fatal(err)
	}
	if !reporter.lastActivity.Equal(initial) {
		t.Fatalf("lastActivity changed to %s for below-threshold output", reporter.lastActivity)
	}
}

func TestFilesystemChangeBumpsAfterInitialSnapshot(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "file.txt"), "one")
	cfg := testConfig(t.TempDir(), workspace, func() time.Time { return now })
	reporter, err := NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Sample(); err != nil {
		t.Fatal(err)
	}
	initial := reporter.lastActivity
	now = now.Add(time.Second)
	mustWrite(t, filepath.Join(workspace, "file.txt"), "two")
	if err := reporter.Sample(); err != nil {
		t.Fatal(err)
	}
	if !reporter.lastActivity.After(initial) {
		t.Fatalf("filesystem change did not bump activity: %s <= %s", reporter.lastActivity, initial)
	}
}

func TestHeartbeatPayloadAndPost(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	var got Heartbeat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer machine-token" {
			t.Fatalf("Authorization = %q", auth)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	cfg := testConfig(t.TempDir(), t.TempDir(), func() time.Time { return now })
	cfg.Endpoint = server.URL
	cfg.Token = "machine-token"
	reporter, err := NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reporter.bump("input", now.Add(time.Second))
	if err := reporter.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != "prj_test" || got.MachineID != "mach_test" {
		t.Fatalf("heartbeat ids = %s/%s", got.ProjectID, got.MachineID)
	}
	if got.Signals["input"] == "" {
		t.Fatal("heartbeat did not include signal timestamp")
	}
}

func TestFromEnvPrefersFlyMachineID(t *testing.T) {
	t.Setenv("PAPERBOAT_PROJECT_ID", "prj_env")
	t.Setenv("PAPERBOAT_MACHINE_ID", "configured-machine-name")
	t.Setenv("FLY_MACHINE_ID", "fly-machine-id")

	cfg := FromEnv()
	if cfg.MachineID != "fly-machine-id" {
		t.Fatalf("MachineID = %q, want fly-machine-id", cfg.MachineID)
	}
}

func testConfig(runtimeDir, workspace string, now func() time.Time) Config {
	return Config{
		ProjectID:            "prj_test",
		MachineID:            "mach_test",
		RuntimeDir:           runtimeDir,
		Workspace:            workspace,
		ReporterVersion:      "test",
		SampleInterval:       time.Second,
		HeartbeatInterval:    time.Second,
		OutputMinBytesPerMin: 1,
		FSMaxDepth:           3,
		Now:                  now,
		Log:                  func(Heartbeat) {},
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}
