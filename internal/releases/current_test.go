package releases

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReadCurrent(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "current.json")
	if err := os.WriteFile(path, []byte(`{"schema":"paperboat.release-current/v1","version":"2026.08.17.1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := ReadCurrent(directory)
	if err != nil || current.Version != "2026.08.17.1" {
		t.Fatalf("current = %#v, %v", current, err)
	}
}

func TestReadCurrentRejectsUnknownFieldsAndSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte(`{"schema":"paperboat.release-current/v1","version":"1","extra":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "current.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCurrent(directory); err == nil {
		t.Fatal("expected invalid current manifest")
	}
}

func TestReadyRequiresCompletePublicBundle(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "current.json"), []byte(`{"schema":"paperboat.release-current/v1","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Ready(directory); err == nil {
		t.Fatal("expected incomplete bundle rejection")
	}
}

func TestReadyRejectsDarwinAMD64Target(t *testing.T) {
	directory := t.TempDir()
	writeReadyBundle(t, directory, false)
	if err := Ready(directory); err != nil {
		t.Fatalf("supported release bundle was rejected: %v", err)
	}
	writeReadyBundle(t, directory, true)
	if err := Ready(directory); err == nil {
		t.Fatal("release bundle containing darwin amd64 was accepted")
	}
}

func TestReadyRequiresCanonicalWindowsInstaller(t *testing.T) {
	directory := t.TempDir()
	writeReadyBundle(t, directory, false)
	if err := os.Remove(filepath.Join(directory, "windows")); err != nil {
		t.Fatal(err)
	}
	if err := Ready(directory); err == nil {
		t.Fatal("release bundle without the Windows installer was accepted")
	}
}

func writeReadyBundle(t *testing.T, directory string, includeDarwinAMD64 bool) {
	t.Helper()
	for _, relative := range []string{"install", "windows", "tuf/metadata/root.json", "tuf/metadata/timestamp.json", "tuf/metadata/snapshot.json"} {
		path := filepath.Join(directory, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("metadata"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "current.json"), []byte(`{"schema":"paperboat.release-current/v1","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	targets := map[string]any{}
	for _, target := range supportedPlatformArchitectures {
		name := "pb-" + target.platform + "-" + target.architecture
		body := []byte(name)
		digest := fmt.Sprintf("%x", sha256.Sum256(body))
		targets[name] = map[string]any{"length": len(body), "hashes": map[string]string{"sha256": digest}, "custom": map[string]string{"version": "1"}}
		path := filepath.Join(directory, "tuf", "targets", digest+"."+name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if includeDarwinAMD64 {
		targets["pb-darwin-amd64"] = map[string]any{"length": 1, "hashes": map[string]string{"sha256": "00"}, "custom": map[string]string{"version": "1"}}
	}
	metadata, err := json.Marshal(map[string]any{"signed": map[string]any{"targets": targets}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "tuf", "metadata", "targets.json"), metadata, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSupportedPlatformArchitectureMatchesReleaseMatrix(t *testing.T) {
	supported := map[string]bool{
		"darwin/arm64":  true,
		"linux/amd64":   true,
		"linux/arm64":   true,
		"windows/amd64": true,
		"windows/arm64": true,
	}
	for _, platform := range []string{"darwin", "linux", "windows", "freebsd"} {
		for _, architecture := range []string{"amd64", "arm64", "386"} {
			key := platform + "/" + architecture
			if got := SupportedPlatformArchitecture(platform, architecture); got != supported[key] {
				t.Fatalf("SupportedPlatformArchitecture(%q, %q) = %v, want %v", platform, architecture, got, supported[key])
			}
		}
	}
}
