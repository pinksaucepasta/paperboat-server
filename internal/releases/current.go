package releases

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CurrentSchemaV1 is the discovery document served by the release origin.
// It contains only immutable release metadata. Binary bytes are never copied
// into the release origin: every asset URL must point at the corresponding
// immutable GitHub release asset and is authenticated by the digest carried in
// TUF targets.json.
const CurrentSchemaV1 = "paperboat.release-current/v1"

const tufAssetSchemaV1 = "paperboat.tuf-asset/v1"

var (
	githubReleaseAssetPattern = regexp.MustCompile(`^/[^/]+/[^/]+/releases/download/[^/]+/[^/]+$`)
	githubRepositoryPattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

var supportedPlatformArchitectures = [...]struct {
	platform     string
	architecture string
}{
	{platform: "darwin", architecture: "arm64"},
	{platform: "linux", architecture: "amd64"},
	{platform: "linux", architecture: "arm64"},
	{platform: "windows", architecture: "amd64"},
	{platform: "windows", architecture: "arm64"},
}

type Current struct {
	Schema     string           `json:"schema"`
	Version    string           `json:"version"`
	Repository string           `json:"repository"`
	Assets     map[string]Asset `json:"assets"`
}

type Asset struct {
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
	Length       int64  `json:"length"`
}

func ReadCurrent(directory string) (Current, error) {
	path := filepath.Join(directory, "current.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 4096 {
		return Current{}, errors.New("current release manifest is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return Current{}, err
	}
	defer file.Close()
	var current Current
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&current) != nil || decoder.Decode(&extra) != io.EOF || current.Validate() != nil {
		return Current{}, errors.New("current release manifest is invalid")
	}
	return current, nil
}

func Ready(directory string) error {
	current, err := ReadCurrent(directory)
	if err != nil {
		return err
	}
	for _, relative := range []string{"install", "windows", "tuf/metadata/root.json", "tuf/metadata/timestamp.json", "tuf/metadata/snapshot.json", "tuf/metadata/targets.json"} {
		info, err := os.Lstat(filepath.Join(directory, filepath.FromSlash(relative)))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 {
			return errors.New("release bundle is incomplete")
		}
	}
	// The origin is metadata-only. A target blob here would create a second
	// binary distribution path and is rejected even if it is otherwise valid.
	if info, err := os.Lstat(filepath.Join(directory, "tuf", "targets")); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("release origin contains a non-directory TUF targets path")
		}
		entries, readErr := os.ReadDir(filepath.Join(directory, "tuf", "targets"))
		if readErr != nil || len(entries) != 0 {
			return errors.New("release origin must not contain TUF target blobs")
		}
	} else if !os.IsNotExist(err) {
		return errors.New("release origin TUF targets path is unavailable")
	}
	body, err := os.ReadFile(filepath.Join(directory, "tuf", "metadata", "targets.json"))
	if err != nil || len(body) > 512<<10 {
		return errors.New("release targets metadata is unavailable")
	}
	var metadata struct {
		Signed struct {
			Targets map[string]tufAssetTarget `json:"targets"`
		} `json:"signed"`
	}
	if json.Unmarshal(body, &metadata) != nil {
		return errors.New("release targets metadata is invalid")
	}
	if len(metadata.Signed.Targets) != len(current.Assets) {
		return errors.New("release targets metadata has an unexpected asset set")
	}
	for name, asset := range current.Assets {
		target, ok := metadata.Signed.Targets[name]
		if !ok || target.Length != asset.Length || target.Hashes["sha256"] != asset.SHA256 || !validAssetTargetCustom(target.Custom, current.Version, current.Repository, name, asset) {
			return errors.New("release target metadata is incomplete")
		}
	}
	for name := range metadata.Signed.Targets {
		if _, ok := current.Assets[name]; !ok {
			return errors.New("release targets metadata contains an unsupported target")
		}
	}
	return nil
}

type tufAssetTarget struct {
	Length int64             `json:"length"`
	Hashes map[string]string `json:"hashes"`
	Custom json.RawMessage   `json:"custom"`
}

func (c Current) Validate() error {
	if c.Schema != CurrentSchemaV1 || !validVersion(c.Version) || !validCurrentRepository(c.Repository) || len(c.Assets) != len(supportedPlatformArchitectures) {
		return errors.New("invalid current release manifest")
	}
	for _, targetPlatform := range supportedPlatformArchitectures {
		name := assetName(targetPlatform.platform, targetPlatform.architecture)
		asset, ok := c.Assets[name]
		if !ok || asset.Platform != targetPlatform.platform || asset.Architecture != targetPlatform.architecture || asset.Format != assetFormat(targetPlatform.platform) || asset.Length < 1 || asset.Length > 512<<20 || !validSHA256(asset.SHA256) || !validGitHubReleaseAssetURL(asset.URL, c.Repository, c.Version, name) {
			return errors.New("invalid current release asset")
		}
	}
	return nil
}

func validAssetTargetCustom(raw json.RawMessage, version, repository, name string, asset Asset) bool {
	var custom struct {
		Schema       string          `json:"schema"`
		Kind         string          `json:"kind"`
		Version      string          `json:"version"`
		Platform     string          `json:"platform"`
		Architecture string          `json:"architecture"`
		Format       string          `json:"format"`
		AssetName    string          `json:"asset_name"`
		Repository   string          `json:"repository"`
		URL          string          `json:"url"`
		SHA256       string          `json:"sha256"`
		Length       int64           `json:"length"`
		ReleaseIndex json.RawMessage `json:"release_index"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var extra any
	return decoder.Decode(&custom) == nil && decoder.Decode(&extra) == io.EOF && len(custom.ReleaseIndex) > 0 && custom.Schema == tufAssetSchemaV1 && custom.Kind == "github-release-asset" && custom.Version == version && custom.Platform == asset.Platform && custom.Architecture == asset.Architecture && custom.Format == asset.Format && custom.AssetName == name && custom.Repository == repository && custom.URL == asset.URL && custom.SHA256 == asset.SHA256 && custom.Length == asset.Length
}

func validCurrentRepository(value string) bool {
	return githubRepositoryPattern.MatchString(value)
}

func validGitHubReleaseAssetURL(raw, repository, version, name string) bool {
	parsed, err := url.Parse(raw)
	canonical := "https://github.com/" + repository + "/releases/download/" + version + "/" + name
	return err == nil && raw == canonical && parsed.Scheme == "https" && parsed.Hostname() == "github.com" && parsed.Port() == "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == "/"+repository+"/releases/download/"+version+"/"+name && githubReleaseAssetPattern.MatchString(parsed.Path)
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func assetName(platform, architecture string) string {
	name := "pb-" + platform + "-" + architecture
	if platform == "windows" {
		name += ".exe"
	}
	if platform == "darwin" {
		name += ".pkg"
	}
	return name
}

func assetFormat(platform string) string {
	switch platform {
	case "darwin":
		return "pkg"
	case "linux":
		return "elf"
	case "windows":
		return "pe"
	default:
		return ""
	}
}

// SupportedPlatformArchitecture reports whether the public release pipeline
// publishes native bytes for the exact platform and architecture pair.
func SupportedPlatformArchitecture(platform, architecture string) bool {
	for _, target := range supportedPlatformArchitectures {
		if platform == target.platform && architecture == target.architecture {
			return true
		}
	}
	return false
}

func validVersion(version string) bool {
	if version == "" || len(version) > 64 || strings.ContainsAny(version, "/\\\x00\r\n") {
		return false
	}
	for _, character := range version {
		if (character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && !strings.ContainsRune("._-", character) {
			return false
		}
	}
	return true
}
