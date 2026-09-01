package releases

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
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

// publishedReleaseIndex contains the current release-index envelope used by
// origin readiness. The publisher and runtime own complete policy semantics;
// this server-side gate only checks the signed identity and required policy
// fields before a bundle can be served.
type publishedReleaseIndex struct {
	Schema                 string                   `json:"schema"`
	ReleaseID              string                   `json:"release_id"`
	Version                string                   `json:"version"`
	Channel                string                   `json:"channel"`
	Severity               string                   `json:"severity"`
	CreatedAt              time.Time                `json:"created_at"`
	Platform               string                   `json:"platform"`
	Architecture           string                   `json:"architecture"`
	BinaryFormat           string                   `json:"binary_format"`
	Targets                []publishedReleaseTarget `json:"targets"`
	HostdAPIMin            uint16                   `json:"hostd_api_min"`
	HostdAPIMax            uint16                   `json:"hostd_api_max"`
	RuntimeAPIMin          uint16                   `json:"runtime_api_min"`
	RuntimeAPIMax          uint16                   `json:"runtime_api_max"`
	MinimumVersion         string                   `json:"minimum_permitted_version,omitempty"`
	RevokedVersions        []string                 `json:"revoked_versions,omitempty"`
	RolloutPolicyRevision  uint64                   `json:"rollout_policy_revision"`
	SupervisorMaintenance  bool                     `json:"supervisor_maintenance_required"`
	ManifestSHA256         string                   `json:"manifest_sha256"`
	DeploymentPlanSHA256   string                   `json:"deployment_plan_sha256"`
	DeploymentPlan         json.RawMessage          `json:"deployment_plan"`
	Revoked                bool                     `json:"revoked,omitempty"`
	Stability              string                   `json:"stability,omitempty"`
	NativeTested           bool                     `json:"native_tested,omitempty"`
	TestedWindowsBuilds    []string                 `json:"tested_windows_builds,omitempty"`
	OpenSSHPackageID       string                   `json:"openssh_package_id,omitempty"`
	OpenSSHApprovedVersion string                   `json:"openssh_approved_version,omitempty"`
}

type publishedReleaseTarget struct {
	Component    string `json:"component"`
	TargetPath   string `json:"target_path"`
	AssetName    string `json:"asset_name"`
	Repository   string `json:"repository"`
	DownloadURL  string `json:"download_url"`
	SHA256       string `json:"sha256"`
	Length       int64  `json:"length"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	BinaryFormat string `json:"binary_format"`
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
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&custom) != nil || decoder.Decode(&extra) != io.EOF || custom.Schema != tufAssetSchemaV1 || custom.Kind != "github-release-asset" || custom.Version != version || custom.Platform != asset.Platform || custom.Architecture != asset.Architecture || custom.Format != asset.Format || custom.AssetName != name || custom.Repository != repository || custom.URL != asset.URL || custom.SHA256 != asset.SHA256 || custom.Length != asset.Length {
		return false
	}
	index, ok := decodePublishedReleaseIndex(custom.ReleaseIndex, time.Now().UTC())
	if !ok || index.Version != version || index.Platform != asset.Platform || index.Architecture != asset.Architecture || index.BinaryFormat != asset.Format || len(index.Targets) != 1 {
		return false
	}
	target := index.Targets[0]
	return target.Component == "pb" && target.TargetPath == name && target.AssetName == name && target.Repository == repository && target.DownloadURL == asset.URL && target.SHA256 == asset.SHA256 && target.Length == asset.Length
}

func decodePublishedReleaseIndex(raw json.RawMessage, now time.Time) (publishedReleaseIndex, bool) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return publishedReleaseIndex{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var index publishedReleaseIndex
	var extra any
	if decoder.Decode(&index) != nil || decoder.Decode(&extra) != io.EOF || !validPublishedReleaseIndex(index, now) {
		return publishedReleaseIndex{}, false
	}
	return index, true
}

func validPublishedReleaseIndex(index publishedReleaseIndex, now time.Time) bool {
	if index.Schema != "paperboat.release-index/v1" || index.ReleaseID != "rel_"+index.Version || index.Version == "" || index.Channel != "stable" || index.CreatedAt.IsZero() || now.IsZero() || index.CreatedAt.After(now.Add(5*time.Minute)) || index.RolloutPolicyRevision == 0 || (index.Severity != "routine" && index.Severity != "security" && index.Severity != "critical") || !SupportedPlatformArchitecture(index.Platform, index.Architecture) || index.BinaryFormat != assetFormat(index.Platform) || index.HostdAPIMin == 0 || index.HostdAPIMin > index.HostdAPIMax || index.RuntimeAPIMin == 0 || index.RuntimeAPIMin > index.RuntimeAPIMax || !validSHA256(index.ManifestSHA256) || !validSHA256(index.DeploymentPlanSHA256) || len(bytes.TrimSpace(index.DeploymentPlan)) == 0 || bytes.Equal(bytes.TrimSpace(index.DeploymentPlan), []byte("null")) {
		return false
	}
	if index.Platform == "windows" {
		if index.OpenSSHPackageID != "Microsoft.OpenSSH.Preview" || !validDependencyVersion(index.OpenSSHApprovedVersion) || len(index.TestedWindowsBuilds) == 0 || index.Stability != "stable" || !index.NativeTested {
			return false
		}
	} else if index.Stability != "" || index.NativeTested || len(index.TestedWindowsBuilds) != 0 || index.OpenSSHPackageID != "" || index.OpenSSHApprovedVersion != "" {
		return false
	}
	if len(index.Targets) != 1 {
		return false
	}
	target := index.Targets[0]
	name := assetName(index.Platform, index.Architecture)
	if target.Component != "pb" || target.TargetPath != name || target.AssetName != name || !validCurrentRepository(target.Repository) || target.DownloadURL != "https://github.com/"+target.Repository+"/releases/download/"+index.Version+"/"+name || !validGitHubReleaseAssetURL(target.DownloadURL, target.Repository, index.Version, name) || target.SHA256 == "" || !validSHA256(target.SHA256) || target.Length < 1 || target.Length > 512<<20 || target.Platform != index.Platform || target.Architecture != index.Architecture || target.BinaryFormat != index.BinaryFormat {
		return false
	}
	if !validPublishedDeploymentPlanShape(index.DeploymentPlan, index.Version, index.ManifestSHA256, index.Severity, index.Platform, index.Architecture) {
		return false
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, index.DeploymentPlan); err != nil {
		return false
	}
	compact.WriteByte('\n')
	digest := sha256.Sum256(compact.Bytes())
	return hex.EncodeToString(digest[:]) == index.DeploymentPlanSHA256
}

func validPublishedDeploymentPlanShape(raw json.RawMessage, version, manifest, severity, platform, architecture string) bool {
	var plan map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&plan) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(plan) == 0 {
		return false
	}
	expected := map[string]struct{}{
		"schema": {}, "version": {}, "manifest_sha256": {}, "channel": {}, "rollout_state": {}, "severity": {},
		"policy_revision": {}, "cohort_seed": {}, "cohorts": {}, "canary": {}, "activation": {},
		"security_deferral": {}, "rollback": {},
	}
	if len(plan) != len(expected) {
		return false
	}
	for field := range expected {
		value, ok := plan[field]
		if !ok || len(bytes.TrimSpace(value)) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	var schema, planVersion, planManifest, channel, planSeverity string
	if json.Unmarshal(plan["schema"], &schema) != nil || json.Unmarshal(plan["version"], &planVersion) != nil || json.Unmarshal(plan["manifest_sha256"], &planManifest) != nil || json.Unmarshal(plan["channel"], &channel) != nil || json.Unmarshal(plan["severity"], &planSeverity) != nil {
		return false
	}
	if schema != "paperboat.release-deployment/v1" || planVersion != version || planManifest != manifest || channel != "stable" || planSeverity != severity {
		return false
	}
	var cohorts []struct {
		Platform     string `json:"platform"`
		Architecture string `json:"architecture"`
	}
	if json.Unmarshal(plan["cohorts"], &cohorts) != nil || len(cohorts) == 0 {
		return false
	}
	for _, cohort := range cohorts {
		if !SupportedPlatformArchitecture(cohort.Platform, cohort.Architecture) {
			return false
		}
	}
	for _, field := range []string{"canary", "activation", "security_deferral", "rollback"} {
		var object map[string]json.RawMessage
		if json.Unmarshal(plan[field], &object) != nil || len(object) == 0 {
			return false
		}
	}
	for _, cohort := range cohorts {
		if cohort.Platform == platform && cohort.Architecture == architecture {
			return true
		}
	}
	return false
}

func validDependencyVersion(value string) bool {
	return regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(value)
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
