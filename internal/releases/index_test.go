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
	name := AssetName(platform, architecture)
	return []ComponentTarget{{Component: "pb", TargetPath: name, AssetName: name, Repository: "example/paperboat-cli", DownloadURL: "https://github.com/example/paperboat-cli/releases/download/2026.08.18.1/" + name,
		SHA256: strings.Repeat("a", 64), Length: 1024, Platform: platform, Architecture: architecture, BinaryFormat: format}}
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

func TestReleaseIndexRejectsNonCanonicalDownloadCoordinates(t *testing.T) {
	cases := []struct {
		name string
		edit func(*ReleaseIndex)
	}{
		{name: "repository punctuation", edit: func(index *ReleaseIndex) {
			index.Targets[0].Repository = "example owner/paperboat-cli"
		}},
		{name: "repository port", edit: func(index *ReleaseIndex) {
			index.Targets[0].DownloadURL = strings.Replace(index.Targets[0].DownloadURL, "https://github.com/", "https://github.com:443/", 1)
		}},
		{name: "escaped URL", edit: func(index *ReleaseIndex) {
			index.Targets[0].DownloadURL = strings.Replace(index.Targets[0].DownloadURL, "pb-linux-amd64", "pb-linux%2Dam"+"d64", 1)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			index := validIndex()
			test.edit(&index)
			if err := index.Validate(time.Now().UTC()); err == nil {
				t.Fatal("non-canonical release coordinates were accepted")
			}
		})
	}
}

func TestReleaseIndexRejectsDarwinAMD64(t *testing.T) {
	index := validIndex()
	index.Platform = "darwin"
	index.Architecture = "amd64"
	index.BinaryFormat = "pkg"
	index.Targets = componentTargets("darwin", "amd64", "pkg")
	if err := index.Validate(time.Now().UTC()); err == nil {
		t.Fatal("darwin amd64 release index was accepted")
	}

	index.Architecture = "arm64"
	index.Targets = componentTargets("darwin", "arm64", "pkg")
	if err := index.Validate(time.Now().UTC()); err != nil {
		t.Fatalf("darwin arm64 release index was rejected: %v", err)
	}
}

func TestWindowsReleaseIndexRequiresStableNativeQualificationForEveryArchitecture(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		index := validIndex()
		index.Platform = "windows"
		index.Architecture = architecture
		index.Channel = "stable"
		index.BinaryFormat = "pe"
		index.Targets = componentTargets("windows", architecture, "pe")
		index.Stability = "stable"
		index.NativeTested = true
		index.TestedWindowsBuilds = []string{"windows-11-2025"}
		index.OpenSSHPackageID = "Microsoft.OpenSSH.Preview"
		index.OpenSSHApprovedVersion = "9.8.1.0"

		if err := index.Validate(time.Now().UTC()); err != nil {
			t.Fatalf("valid Windows %s release index rejected: %v", architecture, err)
		}

		index.Channel = "beta"
		if err := index.Validate(time.Now().UTC()); err == nil {
			t.Fatalf("Windows %s beta channel was accepted", architecture)
		}
		index.Channel = "stable"
		index.Stability = "beta"
		if err := index.Validate(time.Now().UTC()); err == nil {
			t.Fatalf("Windows %s beta stability was accepted", architecture)
		}
		index.Stability = "stable"
		index.NativeTested = false
		if err := index.Validate(time.Now().UTC()); err == nil {
			t.Fatalf("Windows %s release without native qualification was accepted", architecture)
		}
	}
}
