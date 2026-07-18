package configsync

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestEncryptedChezmoiRoundTripContainsNoPlaintextCredential(t *testing.T) {
	binary := os.Getenv("PAPERBOAT_TEST_CHEZMOI")
	if binary == "" {
		t.Skip("PAPERBOAT_TEST_CHEZMOI is not configured")
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	remote := encryptedRemote(t, identity.Recipient().String())
	newEngine := func(home, runtime string) *Engine {
		identityPath := filepath.Join(runtime, "identity.txt")
		if err := os.MkdirAll(runtime, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(identityPath, []byte(identity.String()+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		engine, err := New(Config{Home: home, Workspace: filepath.Join(t.TempDir(), "workspace"), RuntimeDir: runtime, RepoURL: remote, Branch: "main", ProjectID: "prj_encrypted", MachineID: "machine_encrypted", AuthorName: "Test", AuthorMail: "test@example.test", Policy: testPolicy(), ChezmoiBinary: binary, AgeIdentityPath: identityPath, AgeRecipient: identity.Recipient().String(), AgeKeyVersion: 1, RequireEncryption: true, Now: timeNow})
		if err != nil {
			t.Fatal(err)
		}
		if engine.classifier.journalPath != filepath.Join(runtime, "config-sync", "classification-pending.json") {
			t.Fatalf("classification journal path = %q", engine.classifier.journalPath)
		}
		return engine
	}
	homeA := t.TempDir()
	engineA := newEngine(homeA, t.TempDir())
	if err := engineA.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	const secret = "credential-that-must-never-enter-git-plaintext"
	writeTestFile(t, homeA, ".codex/auth.json", secret)
	if err := engineA.Sync(context.Background(), "encrypted-test"); err != nil {
		t.Fatal(err)
	}
	checkout := cloneRemote(t, remote)
	assertCompleteManifest(t, checkout, testPolicy(), "")
	output := runGitOutput(t, checkout, "grep", "-I", "-n", secret, "HEAD")
	if strings.Contains(output, secret) {
		t.Fatal("plaintext credential found in git history")
	}
	foundAge := false
	_ = filepath.WalkDir(checkout, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && strings.HasSuffix(path, ".age") {
			foundAge = true
		}
		return err
	})
	if !foundAge {
		t.Fatal("encrypted age source was not committed")
	}
	homeB := t.TempDir()
	engineB := newEngine(homeB, t.TempDir())
	if err := engineB.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(homeB, ".codex", "auth.json"))
	if err != nil || string(b) != secret {
		t.Fatalf("restored credential=%q err=%v", b, err)
	}
}

func encryptedRemote(t *testing.T, recipient string) string {
	t.Helper()
	remote := filepath.Join(t.TempDir(), "remote.git")
	runGit(t, "", "init", "--bare", "--initial-branch=main", remote)
	seed := t.TempDir()
	runGit(t, seed, "init", "--initial-branch=main")
	runGit(t, seed, "config", "user.name", "Seed")
	runGit(t, seed, "config", "user.email", "seed@example.test")
	writeTestFile(t, seed, ".paperboat/format.json", `{"format":"paperboat-chezmoi-age","version":1,"key_version":1,"recipient":"`+recipient+`"}`)
	writeTestFile(t, seed, manifestPath, `{"schema_version":2,"revision":"test"}`)
	runGit(t, seed, "add", "-A")
	runGit(t, seed, "commit", "-m", "seed")
	runGit(t, seed, "remote", "add", "origin", remote)
	runGit(t, seed, "push", "origin", "main")
	return remote
}

func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}
func timeNow() time.Time { return time.Now().UTC() }
