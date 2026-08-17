package releases

import (
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
