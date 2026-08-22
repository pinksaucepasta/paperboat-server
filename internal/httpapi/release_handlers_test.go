package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReleaseDownloadsAreNotCutOffByAPIRequestTimeout(t *testing.T) {
	handler := timeout(time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Millisecond)
		_, _ = w.Write([]byte("complete"))
	}))

	for _, path := range []string{"/install", "/current.json", "/tuf/targets/hash.pb-linux-amd64", "/helper-releases/tuf/targets/hash.pb-linux-amd64"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || recorder.Body.String() != "complete" {
			t.Fatalf("%s response = %d %q", path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestReleaseEndpointsServeInstallAndTUF(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "install"), []byte("#!/bin/sh\necho paperboat\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "windows"), []byte("Write-Output paperboat-windows\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "current.json"), []byte(`{"schema":"paperboat.release-current/v1","version":"2026.08.18.1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(directory, "tuf", "metadata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "tuf", "metadata", "timestamp.json"), []byte(`{"signed":{"version":1}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := NewReleaseFiles(directory)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(Options{OverrideHandler: nil, ReleaseFiles: files})

	install := httptest.NewRecorder()
	router.ServeHTTP(install, httptest.NewRequest(http.MethodGet, "/install?p=4K7M9Q2V8X4N6P5R1T0W8Y2ZAB", nil))
	if install.Code != http.StatusOK || !strings.Contains(install.Body.String(), "echo paperboat") || !strings.Contains(install.Body.String(), "PAPERBOAT_ENROLLMENT_TOKEN") {
		t.Fatalf("install response = %d %q", install.Code, install.Body.String())
	}
	if got := install.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("install content type = %q", got)
	}
	windows := httptest.NewRecorder()
	windowsRequest := httptest.NewRequest(http.MethodGet, "/install?p=4K7M9Q2V8X4N6P5R1T0W8Y2ZAB", nil)
	windowsRequest.Header.Set("User-Agent", "Mozilla/5.0 PowerShell/7.5")
	router.ServeHTTP(windows, windowsRequest)
	if windows.Code != http.StatusOK || !strings.Contains(windows.Body.String(), "PAPERBOAT_ENROLLMENT_TOKEN") {
		t.Fatalf("windows response = %d %q", windows.Code, windows.Body.String())
	}
	removed := httptest.NewRecorder()
	router.ServeHTTP(removed, httptest.NewRequest(http.MethodGet, "/windows?p=4K7M9Q2V8X4N6P5R1T0W8Y2ZAB", nil))
	if removed.Code != http.StatusNotFound {
		t.Fatalf("legacy /windows endpoint status = %d", removed.Code)
	}
	current := httptest.NewRecorder()
	router.ServeHTTP(current, httptest.NewRequest(http.MethodGet, "/current.json", nil))
	if current.Code != http.StatusOK || !strings.Contains(current.Body.String(), `"version":"2026.08.18.1"`) || current.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("current response = %d %q headers=%v", current.Code, current.Body.String(), current.Header())
	}

	timestamp := httptest.NewRecorder()
	router.ServeHTTP(timestamp, httptest.NewRequest(http.MethodGet, "/tuf/metadata/timestamp.json", nil))
	if timestamp.Code != http.StatusOK || !strings.Contains(timestamp.Body.String(), `"version":1`) {
		t.Fatalf("timestamp response = %d %q", timestamp.Code, timestamp.Body.String())
	}
	if got := timestamp.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("timestamp cache control = %q", got)
	}
}

func TestWindowsReleaseTemplateUsesCanonicalModes(t *testing.T) {
	body, err := os.ReadFile("../../deploy/releases/windows")
	if err != nil {
		t.Fatal(err)
	}
	template := strings.ToLower(string(body))
	for _, required := range []string{"'host'", "'client'", "--setup-mode=$setupmode"} {
		if !strings.Contains(template, required) {
			t.Fatalf("Windows release template is missing canonical mode contract %q", required)
		}
	}
	for _, removed := range []string{"receive", "session"} {
		if strings.Contains(template, removed) {
			t.Fatalf("Windows release template contains removed mode %q", removed)
		}
	}
}

func TestNewReleaseFilesRejectsRelativeAndSymlinkDirectories(t *testing.T) {
	if _, err := NewReleaseFiles("relative"); err == nil {
		t.Fatal("expected relative directory rejection")
	}
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "release-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewReleaseFiles(link); err == nil {
		t.Fatal("expected symlink directory rejection")
	}
}

func TestTUFRepositoryDoesNotExposePrivateOrUnrelatedFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "tuf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "tuf", ".signing-state.json"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := NewReleaseFiles(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/tuf/.signing-state.json", "/tuf/unrelated.txt"} {
		recorder := httptest.NewRecorder()
		tufRepository("/tuf", files).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d", path, recorder.Code)
		}
	}
}

func TestReleaseFilesRejectNestedSymlink(t *testing.T) {
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(directory, "tuf", "metadata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "tuf", "metadata", "timestamp.json")); err != nil {
		t.Fatal(err)
	}
	files, err := NewReleaseFiles(directory)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	files.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/tuf/metadata/timestamp.json", nil))
	if recorder.Code != http.StatusNotFound || strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("symlink response = %d %q", recorder.Code, recorder.Body.String())
	}
}
