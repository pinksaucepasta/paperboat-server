package teaminbox

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestManifestDigestBindsImmutableMetadata(t *testing.T) {
	digest := strings.Repeat("a", 64)
	files := []File{{Basename: "report.txt", Size: 7, SHA256: digest}}
	first, err := ManifestDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ManifestDigest([]File{{Basename: "other.txt", Size: 7, SHA256: digest}})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("substituted filename retained the approval digest")
	}
	third, err := ManifestDigest([]File{{Basename: "report.txt", Size: 8, SHA256: digest}})
	if err != nil {
		t.Fatal(err)
	}
	if first == third {
		t.Fatal("substituted size retained the approval digest")
	}
}

func TestManifestRejectsUnsafeOrUnboundedMetadata(t *testing.T) {
	validDigest := strings.Repeat("0", 64)
	for _, files := range [][]File{
		nil,
		{{Basename: "../secret", Size: 1, SHA256: validDigest}},
		{{Basename: "secret\nname", Size: 1, SHA256: validDigest}},
		{{Basename: "secret", Size: -1, SHA256: validDigest}},
		{{Basename: "secret", Size: 1, SHA256: "not-a-digest"}},
	} {
		if _, err := ManifestDigest(files); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ManifestDigest(%+v) error = %v", files, err)
		}
	}
	tooMany := make([]File, MaximumFiles+1)
	for i := range tooMany {
		tooMany[i] = File{Basename: "file", SHA256: validDigest}
	}
	if _, err := ManifestDigest(tooMany); !errors.Is(err, ErrInvalid) {
		t.Fatalf("too many files error = %v", err)
	}
}

func TestRequestInputRequiresBoundedExactIdentity(t *testing.T) {
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	valid := RequestInput{RequestID: "tir_1", OperationID: "op_1", SenderAccount: "usr_1", SourceMachineID: "machine_1", DestinationMachineID: "machine_2", BatchID: "batch_1", ExpiresAt: now.Add(time.Hour)}
	if !validInput(valid, now) {
		t.Fatal("valid input rejected")
	}
	valid.DestinationMachineID = valid.SourceMachineID
	if validInput(valid, now) {
		t.Fatal("same source and destination accepted")
	}
	valid.DestinationMachineID = "machine_2"
	valid.ExpiresAt = now.Add(MaximumLifetime + time.Second)
	if validInput(valid, now) {
		t.Fatal("unbounded lifetime accepted")
	}
}
