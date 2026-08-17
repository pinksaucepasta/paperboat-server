package releases

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validIndex() ReleaseIndex {
	return ReleaseIndex{
		Schema: ReleaseIndexSchemaV1, ReleaseID: "rel_2026.08.18.1", Version: "2026.08.18.1",
		Channel: "stable", Severity: "routine", CreatedAt: time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC),
		Platform: "linux", Architecture: "amd64", BinaryFormat: "elf",
		Targets:     componentTargets("linux", "amd64", "elf"),
		HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: 1,
		Rollout: RolloutPolicy{
			Schema:     ReleaseRolloutSchemaV1,
			CohortSeed: "release-seed-1",
			Percentage: 100,
		},
	}
}

func componentTargets(platform, architecture, format string) []ComponentTarget {
	result := make([]ComponentTarget, 0, 5)
	for _, component := range []string{"cli", "runtime", "hostd", "updater", "launcher"} {
		result = append(result, ComponentTarget{Component: component, TargetPath: component + "-" + platform + "-" + architecture,
			SHA256: strings.Repeat("a", 64), Length: 1024, Platform: platform, Architecture: architecture, BinaryFormat: format})
	}
	return result
}

func TestReleaseIndexDecodeStrictlyValidatesSignedPayload(t *testing.T) {
	index := validIndex()
	encoded, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	decoded, err := DecodeIndex(strings.NewReader(body), time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC))
	if err != nil || decoded.String() != index.String() {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	if _, err := DecodeIndex(strings.NewReader(body[:len(body)-1]+`,"unknown":true}`), time.Now().UTC()); err == nil {
		t.Fatal("expected unknown release-index field to be rejected")
	}
}

func TestReleaseIndexEligibilityIsStableAndBounded(t *testing.T) {
	index := validIndex()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	first, firstReason := index.Eligible("machine-1", "linux", "amd64", now)
	second, secondReason := index.Eligible("machine-1", "linux", "amd64", now)
	if !first || firstReason != EligibleReasonEligible || first != second || firstReason != secondReason {
		t.Fatalf("eligibility was not stable: %v/%s then %v/%s", first, firstReason, second, secondReason)
	}
	if ok, reason := index.Eligible("machine-1", "darwin", "arm64", now); ok || reason != EligibleReasonUnsupportedTarget {
		t.Fatalf("unsupported target = %v/%s", ok, reason)
	}
	index.Rollout.Percentage = 0
	if ok, reason := index.Eligible("machine-1", "linux", "amd64", now); ok || reason != EligibleReasonNotInCohort {
		t.Fatalf("zero-percent rollout = %v/%s", ok, reason)
	}
}

func TestReleaseIndexRejectsInvalidDigestAndWindow(t *testing.T) {
	index := validIndex()
	index.Targets[0].SHA256 = strings.Repeat("A", 64)
	if err := index.Validate(time.Now().UTC()); err == nil {
		t.Fatal("expected uppercase digest to be rejected")
	}
	index = validIndex()
	expires := index.CreatedAt
	index.Rollout.NotBefore = &expires
	index.Rollout.ExpiresAt = &expires
	if err := index.Validate(time.Now().UTC()); err == nil {
		t.Fatal("expected non-increasing rollout window to be rejected")
	}
}
