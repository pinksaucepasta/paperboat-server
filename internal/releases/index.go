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
	indexErrorInvalid   = errors.New("release index is invalid")
)

// ReleaseIndex is the payload signed as a TUF target. Every field that can
// affect an update decision is inside this document so the client never
// combines signed release data with mutable server state.
type ReleaseIndex struct {
	Schema             string        `json:"schema"`
	Version            string        `json:"version"`
	Channel            string        `json:"channel"`
	PublishedAt        time.Time     `json:"published_at"`
	TargetPath         string        `json:"target_path"`
	TargetSHA256       string        `json:"target_sha256"`
	TargetLength       int64         `json:"target_length"`
	Platform           string        `json:"platform"`
	Architecture       string        `json:"architecture"`
	MinimumVersion     string        `json:"minimum_version,omitempty"`
	WorkerProtocolMin  string        `json:"worker_protocol_min"`
	WorkerProtocolMax  string        `json:"worker_protocol_max"`
	SupervisorProtoMin string        `json:"supervisor_protocol_min"`
	SupervisorProtoMax string        `json:"supervisor_protocol_max"`
	Rollout            RolloutPolicy `json:"rollout"`
	Revoked            bool          `json:"revoked,omitempty"`
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
	if i.Schema != ReleaseIndexSchemaV1 || !validVersion(i.Version) || !indexChannelPattern.MatchString(i.Channel) || i.PublishedAt.IsZero() {
		return indexErrorInvalid
	}
	if i.Platform != "darwin" && i.Platform != "linux" || i.Architecture != "amd64" && i.Architecture != "arm64" {
		return indexErrorInvalid
	}
	if i.TargetPath != "pb-"+i.Platform+"-"+i.Architecture || len(i.TargetSHA256) != sha256.Size*2 || !isLowerHex(i.TargetSHA256) || i.TargetLength < 1 || i.TargetLength > 512<<20 {
		return indexErrorInvalid
	}
	if i.MinimumVersion != "" && !validVersion(i.MinimumVersion) {
		return indexErrorInvalid
	}
	if !indexValuePattern.MatchString(i.WorkerProtocolMin) || !indexValuePattern.MatchString(i.WorkerProtocolMax) || !indexValuePattern.MatchString(i.SupervisorProtoMin) || !indexValuePattern.MatchString(i.SupervisorProtoMax) {
		return indexErrorInvalid
	}
	if err := i.Rollout.validate(now); err != nil {
		return err
	}
	return nil
}

func (p RolloutPolicy) validate(now time.Time) error {
	if p.Schema != ReleaseRolloutSchemaV1 || p.CohortSeed == "" || len(p.CohortSeed) > 128 || strings.ContainsAny(p.CohortSeed, "\x00\r\n") || p.Percentage > 100 {
		return indexErrorInvalid
	}
	if p.NotBefore != nil && p.ExpiresAt != nil && !p.ExpiresAt.After(*p.NotBefore) {
		return indexErrorInvalid
	}
	if !now.IsZero() {
		// Validate timestamps even when the index is evaluated outside its
		// window. The caller receives a stable eligibility reason below.
		if p.NotBefore != nil && p.NotBefore.IsZero() || p.ExpiresAt != nil && p.ExpiresAt.IsZero() {
			return indexErrorInvalid
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
		return ReleaseIndex{}, indexErrorInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(r, 64<<10+1))
	decoder.DisallowUnknownFields()
	var index ReleaseIndex
	var extra any
	if err := decoder.Decode(&index); err != nil || decoder.Decode(&extra) != io.EOF {
		return ReleaseIndex{}, indexErrorInvalid
	}
	if err := index.Validate(now); err != nil {
		return ReleaseIndex{}, err
	}
	return index, nil
}

func IsInvalidIndex(err error) bool { return errors.Is(err, indexErrorInvalid) }

func isLowerHex(value string) bool {
	if _, err := hex.DecodeString(value); err != nil {
		return false
	}
	return value == strings.ToLower(value)
}

func (i ReleaseIndex) String() string {
	return fmt.Sprintf("%s/%s/%s", i.Channel, i.Version, i.TargetPath)
}

// ValidVersion accepts the release identifier grammar used by the static
// release bundle. It intentionally validates shape only; downgrade policy is
// a separate signed/index decision.
func ValidVersion(value string) bool { return validVersion(value) }
