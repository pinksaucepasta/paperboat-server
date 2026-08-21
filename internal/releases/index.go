package releases

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// ReleaseIndexSchemaV1 identifies the signed target that carries rollout and
// compatibility policy. The index is a TUF target; current.json is only a
// discovery hint and must never replace TUF verification.
const ReleaseIndexSchemaV1 = "paperboat.release-index/v1"

const ReleaseRolloutSchemaV1 = "paperboat.release-rollout/v1"

var (
	indexChannelPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	indexValuePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$`)
	errIndexInvalid     = errors.New("release index is invalid")
)

// ReleaseIndex is the payload signed as a TUF target. Every field that can
// affect an update decision is inside this document so the client never
// combines signed release data with mutable server state.
type ReleaseIndex struct {
	Schema                 string            `json:"schema"`
	ReleaseID              string            `json:"release_id"`
	Version                string            `json:"version"`
	Channel                string            `json:"channel"`
	Severity               string            `json:"severity"`
	CreatedAt              time.Time         `json:"created_at"`
	Platform               string            `json:"platform"`
	Architecture           string            `json:"architecture"`
	BinaryFormat           string            `json:"binary_format"`
	Targets                []ComponentTarget `json:"targets"`
	HostdAPIMin            uint16            `json:"hostd_api_min"`
	HostdAPIMax            uint16            `json:"hostd_api_max"`
	RuntimeAPIMin          uint16            `json:"runtime_api_min"`
	RuntimeAPIMax          uint16            `json:"runtime_api_max"`
	MinimumVersion         string            `json:"minimum_permitted_version,omitempty"`
	RevokedVersions        []string          `json:"revoked_versions,omitempty"`
	RolloutPolicyRevision  uint64            `json:"rollout_policy_revision"`
	SupervisorMaintenance  bool              `json:"supervisor_maintenance_required"`
	Rollout                RolloutPolicy     `json:"rollout"`
	Revoked                bool              `json:"revoked,omitempty"`
	Stability              string            `json:"stability,omitempty"`
	NativeTested           bool              `json:"native_tested,omitempty"`
	TestedWindowsBuilds    []string          `json:"tested_windows_builds,omitempty"`
	OpenSSHPackageID       string            `json:"openssh_package_id,omitempty"`
	OpenSSHApprovedVersion string            `json:"openssh_approved_version,omitempty"`
}

type ComponentTarget struct {
	Component    string `json:"component"`
	TargetPath   string `json:"target_path"`
	SHA256       string `json:"sha256"`
	Length       int64  `json:"length"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	BinaryFormat string `json:"binary_format"`
}

// RolloutPolicy is signed with the release index. CohortSeed must be stable
// for the lifetime of an index: changing it would move machines between
// cohorts without a version change.
type RolloutPolicy struct {
	Schema     string     `json:"schema"`
	CohortSeed string     `json:"cohort_seed"`
	Percentage uint8      `json:"percentage"`
	NotBefore  *time.Time `json:"not_before,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type EligibilityReason string

const (
	EligibleReasonEligible          EligibilityReason = "eligible"
	EligibleReasonInvalidIndex      EligibilityReason = "invalid_index"
	EligibleReasonEmptyMachine      EligibilityReason = "empty_machine_id"
	EligibleReasonRevoked           EligibilityReason = "revoked"
	EligibleReasonOutsideWindow     EligibilityReason = "outside_rollout_window"
	EligibleReasonUnsupportedTarget EligibilityReason = "unsupported_target"
	EligibleReasonNotInCohort       EligibilityReason = "not_in_cohort"
)

func (i ReleaseIndex) Validate(now time.Time) error {
	if i.Schema != ReleaseIndexSchemaV1 || !indexValuePattern.MatchString(i.ReleaseID) || !validVersion(i.Version) || !indexChannelPattern.MatchString(i.Channel) || i.CreatedAt.IsZero() {
		return errIndexInvalid
	}
	if i.Platform != "darwin" && i.Platform != "linux" && i.Platform != "windows" || i.Architecture != "amd64" && i.Architecture != "arm64" || !validBinaryFormat(i.Platform, i.BinaryFormat) {
		return errIndexInvalid
	}
	if i.Platform == "windows" {
		if i.OpenSSHPackageID != "Microsoft.OpenSSH.Preview" || !validVersion(i.OpenSSHApprovedVersion) || len(i.TestedWindowsBuilds) == 0 || len(i.TestedWindowsBuilds) > 16 {
			return errIndexInvalid
		}
		for _, build := range i.TestedWindowsBuilds {
			if !indexValuePattern.MatchString(build) {
				return errIndexInvalid
			}
		}
		if i.Architecture == "amd64" && (i.Stability != "stable" || !i.NativeTested) || i.Architecture == "arm64" && (i.Stability != "beta" || i.NativeTested) {
			return errIndexInvalid
		}
		if i.Architecture == "amd64" && i.Channel != "stable" || i.Architecture == "arm64" && i.Channel != "beta" {
			return errIndexInvalid
		}
	} else if i.Stability != "" || i.NativeTested || len(i.TestedWindowsBuilds) != 0 || i.OpenSSHPackageID != "" || i.OpenSSHApprovedVersion != "" {
		return errIndexInvalid
	}
	if i.Severity != "routine" && i.Severity != "security" && i.Severity != "critical" || i.HostdAPIMin == 0 || i.HostdAPIMin > i.HostdAPIMax || i.RuntimeAPIMin == 0 || i.RuntimeAPIMin > i.RuntimeAPIMax || i.RolloutPolicyRevision == 0 {
		return errIndexInvalid
	}
	if i.MinimumVersion != "" && !validVersion(i.MinimumVersion) {
		return errIndexInvalid
	}
	if err := i.validateTargets(); err != nil {
		return errIndexInvalid
	}
	seenRevoked := map[string]bool{}
	for _, version := range i.RevokedVersions {
		if !validVersion(version) || seenRevoked[version] {
			return errIndexInvalid
		}
		seenRevoked[version] = true
	}
	if err := i.Rollout.validate(now); err != nil {
		return err
	}
	return nil
}

func (i ReleaseIndex) validateTargets() error {
	required := map[string]bool{"cli": false, "runtime": false, "hostd": false, "updater": false, "launcher": false}
	if len(i.Targets) != len(required) {
		return errIndexInvalid
	}
	for _, target := range i.Targets {
		if _, ok := required[target.Component]; !ok || required[target.Component] {
			return errIndexInvalid
		}
		if target.Platform != i.Platform || target.Architecture != i.Architecture || target.BinaryFormat != i.BinaryFormat ||
			len(target.SHA256) != sha256.Size*2 || !isLowerHex(target.SHA256) || target.Length < 1 || target.Length > 512<<20 ||
			!indexValuePattern.MatchString(target.TargetPath) || strings.Contains(target.TargetPath, "..") || strings.ContainsAny(target.TargetPath, "\\?#") {
			return errIndexInvalid
		}
		want := target.Component + "-" + i.Platform + "-" + i.Architecture
		if target.TargetPath != want {
			return errIndexInvalid
		}
		required[target.Component] = true
	}
	return nil
}

func validBinaryFormat(platform, format string) bool {
	switch platform {
	case "linux":
		return format == "elf"
	case "darwin":
		return format == "mach-o"
	case "windows":
		return format == "pe"
	}
	return false
}

func (p RolloutPolicy) validate(now time.Time) error {
	if p.Schema != ReleaseRolloutSchemaV1 || p.CohortSeed == "" || len(p.CohortSeed) > 128 || strings.ContainsAny(p.CohortSeed, "\x00\r\n") || p.Percentage > 100 {
		return errIndexInvalid
	}
	if p.NotBefore != nil && p.ExpiresAt != nil && !p.ExpiresAt.After(*p.NotBefore) {
		return errIndexInvalid
	}
	if !now.IsZero() {
		// Validate timestamps even when the index is evaluated outside its
		// window. The caller receives a stable eligibility reason below.
		if p.NotBefore != nil && p.NotBefore.IsZero() || p.ExpiresAt != nil && p.ExpiresAt.IsZero() {
			return errIndexInvalid
		}
	}
	return nil
}

// Eligible evaluates a release index for one enrolled machine. The result is
// deterministic for (cohort_seed, machineID), independent of request order or
// server instance. A caller must still verify the TUF target before invoking
// this policy.
func (i ReleaseIndex) Eligible(machineID, platform, architecture string, now time.Time) (bool, EligibilityReason) {
	if err := i.Validate(now); err != nil {
		return false, EligibleReasonInvalidIndex
	}
	if strings.TrimSpace(machineID) == "" {
		return false, EligibleReasonEmptyMachine
	}
	if i.Revoked {
		return false, EligibleReasonRevoked
	}
	if platform != i.Platform || architecture != i.Architecture {
		return false, EligibleReasonUnsupportedTarget
	}
	if i.Rollout.NotBefore != nil && now.Before(i.Rollout.NotBefore.UTC()) || i.Rollout.ExpiresAt != nil && !now.Before(i.Rollout.ExpiresAt.UTC()) {
		return false, EligibleReasonOutsideWindow
	}
	if i.Rollout.Percentage == 0 {
		return false, EligibleReasonNotInCohort
	}
	digest := sha256.Sum256([]byte(i.Rollout.CohortSeed + "\x00" + machineID))
	// Ten-thousand buckets keep percentage boundaries precise to 0.01% while
	// using only a stable, non-secret hash of the enrolled machine ID.
	bucket := binary.BigEndian.Uint64(digest[:8]) % 10_000
	if bucket >= uint64(i.Rollout.Percentage)*100 {
		return false, EligibleReasonNotInCohort
	}
	return true, EligibleReasonEligible
}

// DecodeIndex strictly decodes a bounded release-index payload. TUF provides
// authenticity and this function provides schema and size validation.
func DecodeIndex(r io.Reader, now time.Time) (ReleaseIndex, error) {
	if r == nil {
		return ReleaseIndex{}, errIndexInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(r, 64<<10+1))
	decoder.DisallowUnknownFields()
	var index ReleaseIndex
	var extra any
	if err := decoder.Decode(&index); err != nil || decoder.Decode(&extra) != io.EOF {
		return ReleaseIndex{}, errIndexInvalid
	}
	if err := index.Validate(now); err != nil {
		return ReleaseIndex{}, err
	}
	return index, nil
}

func IsInvalidIndex(err error) bool { return errors.Is(err, errIndexInvalid) }

func isLowerHex(value string) bool {
	if _, err := hex.DecodeString(value); err != nil {
		return false
	}
	return value == strings.ToLower(value)
}

func (i ReleaseIndex) String() string {
	return fmt.Sprintf("%s/%s/%s/%s", i.Channel, i.Version, i.Platform, i.Architecture)
}

// ValidVersion accepts the release identifier grammar used by the static
// release bundle. It intentionally validates shape only; downgrade policy is
// a separate signed/index decision.
func ValidVersion(value string) bool { return validVersion(value) }
