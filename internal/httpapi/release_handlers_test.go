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

	for _, path := range []string{"/install", "/tuf/targets/hash.pb-linux-amd64", "/helper-releases/tuf/targets/hash.pb-linux-amd64"} {
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
	router.ServeHTTP(install, httptest.NewRequest(http.MethodGet, "/install", nil))
	if install.Code != http.StatusOK || !strings.Contains(install.Body.String(), "echo paperboat") {
		t.Fatalf("install response = %d %q", install.Code, install.Body.String())
	}
	if got := install.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("install content type = %q", got)
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
