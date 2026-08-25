package releases

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testRepository = "example/paperboat-cli"
const testVersion = "2026.08.25.1"

func testCurrent() Current {
	current := Current{Schema: CurrentSchemaV1, Version: testVersion, Repository: testRepository, Assets: map[string]Asset{}}
	for _, target := range supportedPlatformArchitectures {
		name := assetName(target.platform, target.architecture)
		body := []byte(name + " bytes")
		digest := sha256.Sum256(body)
		current.Assets[name] = Asset{Platform: target.platform, Architecture: target.architecture, Format: assetFormat(target.platform), URL: "https://github.com/" + testRepository + "/releases/download/" + testVersion + "/" + name, SHA256: hex.EncodeToString(digest[:]), Length: int64(len(body))}
	}
	return current
}

func writeCurrent(t *testing.T, directory string, current Current) {
	t.Helper()
	body, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "current.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadCurrent(t *testing.T) {
	directory := t.TempDir()
	writeCurrent(t, directory, testCurrent())
	current, err := ReadCurrent(directory)
	if err != nil || current.Version != testVersion || len(current.Assets) != 5 {
		t.Fatalf("current = %#v, %v", current, err)
	}
}

func TestCurrentRejectsNonCanonicalGitHubCoordinates(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Current)
	}{
		{name: "repository punctuation", edit: func(current *Current) {
			current.Repository = "example owner/paperboat-cli"
		}},
		{name: "repository port", edit: func(current *Current) {
			asset := current.Assets["pb-linux-amd64"]
			asset.URL = "https://github.com:443/example/paperboat-cli/releases/download/" + current.Version + "/pb-linux-amd64"
			current.Assets["pb-linux-amd64"] = asset
		}},
		{name: "escaped URL", edit: func(current *Current) {
			asset := current.Assets["pb-linux-amd64"]
			asset.URL = strings.Replace(asset.URL, "pb-linux-amd64", "pb-linux%2Dam"+"d64", 1)
			current.Assets["pb-linux-amd64"] = asset
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			current := testCurrent()
			test.edit(&current)
			if err := current.Validate(); err == nil {
				t.Fatal("non-canonical release coordinates were accepted")
			}
		})
	}
}

func TestReadCurrentRejectsUnknownFieldsAndSymlink(t *testing.T) {
	directory := t.TempDir()
	body, err := json.Marshal(testCurrent())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, append(body[:len(body)-1], []byte(`,"extra":true}`)...), 0o644); err != nil {
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
	writeCurrent(t, directory, testCurrent())
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
	current := testCurrent()
	current.Assets["pb-darwin-amd64"] = current.Assets["pb-darwin-arm64"]
	writeCurrent(t, directory, current)
	if err := Ready(directory); err == nil {
		t.Fatal("release bundle containing darwin amd64 was accepted")
	}
}

func TestReadyRejectsLocalTargetBlobs(t *testing.T) {
	directory := t.TempDir()
	writeReadyBundle(t, directory, false)
	if err := os.WriteFile(filepath.Join(directory, "tuf", "targets", "unexpected"), []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Ready(directory); err == nil {
		t.Fatal("release bundle with local target bytes was accepted")
	}
}

func TestReadyRequiresCanonicalWindowsAsset(t *testing.T) {
	directory := t.TempDir()
	writeReadyBundle(t, directory, false)
	current := testCurrent()
	delete(current.Assets, "pb-windows-arm64.exe")
	writeCurrent(t, directory, current)
	if err := Ready(directory); err == nil {
		t.Fatal("release bundle without the Windows ARM64 asset was accepted")
	}
}

func writeReadyBundle(t *testing.T, directory string, _ bool) {
	t.Helper()
	current := testCurrent()
	writeCurrent(t, directory, current)
	for _, relative := range []string{"install", "windows", "tuf/metadata/root.json", "tuf/metadata/timestamp.json", "tuf/metadata/snapshot.json", "tuf/metadata/targets.json"} {
		path := filepath.Join(directory, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("metadata"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	assets := map[string]any{}
	for name, asset := range current.Assets {
		assets[name] = map[string]any{
			"length": asset.Length,
			"hashes": map[string]string{"sha256": asset.SHA256},
			"custom": map[string]any{
				"schema": "paperboat.tuf-asset/v1", "kind": "github-release-asset", "version": current.Version,
				"platform": asset.Platform, "architecture": asset.Architecture, "format": asset.Format,
				"asset_name": name, "repository": current.Repository, "url": asset.URL, "sha256": asset.SHA256, "length": asset.Length,
				"release_index": map[string]any{"schema": "paperboat.release-index/v1"},
			},
		}
	}
	metadata, err := json.Marshal(map[string]any{"signed": map[string]any{"targets": assets}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "tuf", "metadata", "targets.json"), metadata, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(directory, "tuf", "targets"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestSupportedPlatformArchitectureMatchesReleaseMatrix(t *testing.T) {
	supported := map[string]bool{
		"darwin/arm64": true, "linux/amd64": true, "linux/arm64": true,
		"windows/amd64": true, "windows/arm64": true,
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
