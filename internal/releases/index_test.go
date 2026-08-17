package releases

import (
	"strings"
	"testing"
	"time"
)

func validIndex() ReleaseIndex {
	return ReleaseIndex{
		Schema:             ReleaseIndexSchemaV1,
		Version:            "2026.08.18.1",
		Channel:            "stable",
		PublishedAt:        time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC),
		TargetPath:         "pb-linux-amd64",
		TargetSHA256:       strings.Repeat("a", 64),
		TargetLength:       1024,
		Platform:           "linux",
		Architecture:       "amd64",
		WorkerProtocolMin:  "1",
		WorkerProtocolMax:  "2",
		SupervisorProtoMin: "1",
		SupervisorProtoMax: "2",
		Rollout: RolloutPolicy{
			Schema:     ReleaseRolloutSchemaV1,
			CohortSeed: "release-seed-1",
			Percentage: 100,
		},
	}
}

func TestReleaseIndexDecodeStrictlyValidatesSignedPayload(t *testing.T) {
	index := validIndex()
	body := `{"schema":"paperboat.release-index/v1","version":"2026.08.18.1","channel":"stable","published_at":"2026-08-18T10:00:00Z","target_path":"pb-linux-amd64","target_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target_length":1024,"platform":"linux","architecture":"amd64","worker_protocol_min":"1","worker_protocol_max":"2","supervisor_protocol_min":"1","supervisor_protocol_max":"2","rollout":{"schema":"paperboat.release-rollout/v1","cohort_seed":"release-seed-1","percentage":100}}`
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
	index.TargetSHA256 = strings.Repeat("A", 64)
	if err := index.Validate(time.Now().UTC()); err == nil {
		t.Fatal("expected uppercase digest to be rejected")
	}
	index = validIndex()
	expires := index.PublishedAt
	index.Rollout.NotBefore = &expires
	index.Rollout.ExpiresAt = &expires
	if err := index.Validate(time.Now().UTC()); err == nil {
		t.Fatal("expected non-increasing rollout window to be rejected")
	}
}
