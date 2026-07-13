package configsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSnapshotCoversDotfilesAndRejectsSensitiveUnsafeAndOversizedFiles(t *testing.T) {
	home := t.TempDir()
	writeTestFile(t, home, ".claude/settings.json", "claude")
	writeTestFile(t, home, ".codex/config.toml", "codex")
	writeTestFile(t, home, ".cursor/preferences.json", "cursor")
	writeTestFile(t, home, ".config/tool/config", "tool")
	writeTestFile(t, home, ".zshrc", "shell")
	writeTestFile(t, home, "notes.txt", "normal")
	writeTestFile(t, home, ".ssh/id_ed25519", "secret")
	writeTestFile(t, home, ".codex/auth.json", "secret")
	writeTestFile(t, home, ".cache/cache.bin", "cache")
	writeTestFile(t, home, ".claude/large.bin", strings.Repeat("x", 33))
	outside := filepath.Join(t.TempDir(), "outside")
	writeTestFile(t, filepath.Dir(outside), filepath.Base(outside), "outside")
	if err := os.Symlink(outside, filepath.Join(home, ".escape")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(home, ".config", "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}

	policy := testPolicy()
	policy.MaxFileBytes = 32
	snapshot, err := takeSnapshot(home, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{".claude/settings.json", ".codex/config.toml", ".cursor/preferences.json", ".config/tool/config", ".zshrc"} {
		if _, ok := snapshot.Files[path]; !ok {
			t.Errorf("managed file %s missing", path)
		}
	}
	for _, path := range []string{"notes.txt", ".ssh/id_ed25519", ".codex/auth.json", ".cache/cache.bin", ".claude/large.bin", ".escape", ".config/pipe"} {
		if _, ok := snapshot.Files[path]; ok {
			t.Errorf("unsafe/unmanaged file %s included", path)
		}
	}
	if !hasReason(snapshot.Skipped, ".claude/large.bin", "max_file_bytes") || !hasReason(snapshot.Skipped, ".escape", "unsafe_symlink") || !hasReason(snapshot.Skipped, ".config/pipe", "special_file") {
		t.Fatalf("skipped = %#v", snapshot.Skipped)
	}
}

func TestAbsoluteHomeSymlinkBecomesPortableAndRestoresInsideHome(t *testing.T) {
	remote := newRemote(t)
	homeA := t.TempDir()
	engineA := newTestEngine(t, remote, homeA, t.TempDir())
	if err := engineA.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, homeA, ".config/tool/settings", "portable")
	if err := os.Symlink(filepath.Join(homeA, ".config/tool/settings"), filepath.Join(homeA, ".config-link")); err != nil {
		t.Fatal(err)
	}
	localSnapshot, err := takeSnapshot(homeA, engineA.cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if state, ok := localSnapshot.Files[".config-link"]; !ok || state.Mode&os.ModeSymlink == 0 {
		t.Fatalf("local symlink was not snapshotted: %#v skipped=%#v", state, localSnapshot.Skipped)
	}
	if err := engineA.Sync(context.Background(), "symlink"); err != nil {
		t.Fatal(err)
	}
	remoteCheckout := cloneRemote(t, remote)
	if info, err := os.Lstat(filepath.Join(remoteCheckout, ".config-link")); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("remote symlink missing or not a link: %v, %v", info, err)
	}
	homeB := t.TempDir()
	engineB := newTestEngine(t, remote, homeB, t.TempDir())
	if err := engineB.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(homeB, ".config-link"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(target) {
		t.Fatalf("restored symlink target is absolute: %q", target)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(homeB, ".config-link"))
	canonicalHome, canonicalErr := filepath.EvalSymlinks(homeB)
	if err != nil || canonicalErr != nil || !sameOrInside(resolved, canonicalHome) {
		t.Fatalf("restored symlink escaped home: %q, %v", resolved, err)
	}
	if got := readTestFile(t, homeB, ".config-link"); got != "portable" {
		t.Fatalf("restored symlink content = %q", got)
	}
}

func TestCopyStateRejectsRepositorySymlinkEscape(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()
	err := copyState(source, destination, ".config/link", fileState{Mode: os.ModeSymlink, Target: "../../outside"})
	if err == nil {
		t.Fatal("symlink escape was restored")
	}
}

func TestCopyStateRejectsSymlinkTargetEscapeThroughExistingSymlink(t *testing.T) {
	source, destination, outside := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(destination, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(destination, ".config", "redirect")); err != nil {
		t.Fatal(err)
	}
	err := copyState(source, destination, ".portable-link", fileState{Mode: os.ModeSymlink, Target: ".config/redirect/secret"})
	if err == nil {
		t.Fatal("symlink target escaped through an existing destination symlink")
	}
}

func TestCopyAndDeleteRejectDestinationParentSymlinkEscape(t *testing.T) {
	source, destination, outside := t.TempDir(), t.TempDir(), t.TempDir()
	writeTestFile(t, source, ".config/tool/file", "safe")
	value, err := takeSnapshot(source, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(destination, ".config")); err != nil {
		t.Fatal(err)
	}
	if err := copyState(source, destination, ".config/tool/file", value.Files[".config/tool/file"]); err == nil {
		t.Fatal("copy followed a destination parent symlink outside home")
	}
	writeTestFile(t, outside, "tool/file", "do-not-delete")
	if err := removeState(destination, ".config/tool/file"); err == nil {
		t.Fatal("delete followed a destination parent symlink outside home")
	}
	if got := readTestFile(t, outside, "tool/file"); got != "do-not-delete" {
		t.Fatalf("outside file changed through symlink parent: %q", got)
	}
}

func TestCopyStatePreservesPermissionMode(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()
	writeTestFile(t, source, ".config/executable", "content")
	path := filepath.Join(source, ".config/executable")
	if err := os.Chmod(path, 0o750); err != nil {
		t.Fatal(err)
	}
	value, err := takeSnapshot(source, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := copyState(source, destination, ".config/executable", value.Files[".config/executable"]); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(destination, ".config/executable"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("copied mode = %o", info.Mode().Perm())
	}
}

func TestCopyStateRejectsContentChangedAfterSnapshot(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()
	writeTestFile(t, source, ".config/file", "snapshotted")
	value, err := takeSnapshot(source, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, source, ".config/file", "changed-after-snapshot")
	writeTestFile(t, destination, ".config/file", "keep-destination")
	err = copyState(source, destination, ".config/file", value.Files[".config/file"])
	if !errors.Is(err, errSourceChanged) {
		t.Fatalf("copy error = %v, want source-changed rejection", err)
	}
	if got := readTestFile(t, destination, ".config/file"); got != "keep-destination" {
		t.Fatalf("destination changed after rejected copy: %q", got)
	}
}

func TestSnapshotFailureBlocksSyncInsteadOfDeletingRemoteState(t *testing.T) {
	remote := newRemote(t)
	work := cloneRemote(t, remote)
	writeTestFile(t, work, ".config/retained", "remote-version")
	commitAndPush(t, work, "seed retained config")
	home := t.TempDir()
	engine := newTestEngine(t, remote, home, t.TempDir())
	if err := engine.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	moved := home + ".moved"
	if err := os.Rename(home, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(home, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.Sync(context.Background(), "snapshot-failure"); err == nil {
		t.Fatal("sync accepted an unreadable config home")
	}
	if !remoteFileEquals(remote, ".config/retained", "remote-version") {
		t.Fatal("snapshot failure deleted the last remote version")
	}
}

func TestInitialRestoreDeletesManagedFilesAbsentFromRemote(t *testing.T) {
	remote := newRemote(t)
	work := cloneRemote(t, remote)
	writeTestFile(t, work, ".config/kept", "remote-version")
	commitAndPush(t, work, "seed canonical config")

	home := t.TempDir()
	writeTestFile(t, home, ".config/kept", "base-image-version")
	writeTestFile(t, home, ".config/deleted", "must-not-return")
	writeTestFile(t, home, ".zshrc", "also-deleted")
	writeTestFile(t, home, "notes.txt", "unmanaged-retained")
	writeTestFile(t, home, ".ssh/id_ed25519", "excluded-retained")
	engine := newTestEngine(t, remote, home, t.TempDir())
	if err := engine.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readTestFile(t, home, ".config/kept"); got != "remote-version" {
		t.Fatalf("restored canonical file = %q", got)
	}
	for _, rel := range []string{".config/deleted", ".zshrc"} {
		if _, err := os.Lstat(filepath.Join(home, filepath.FromSlash(rel))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("managed file absent from remote survived restore: %s, err=%v", rel, err)
		}
	}
	if got := readTestFile(t, home, "notes.txt"); got != "unmanaged-retained" {
		t.Fatalf("unmanaged file changed: %q", got)
	}
	if got := readTestFile(t, home, ".ssh/id_ed25519"); got != "excluded-retained" {
		t.Fatalf("mandatory exclusion changed: %q", got)
	}
	if err := engine.Sync(context.Background(), "post-restore"); err != nil {
		t.Fatal(err)
	}
	checkout := cloneRemote(t, remote)
	for _, rel := range []string{".config/deleted", ".zshrc"} {
		if _, err := os.Lstat(filepath.Join(checkout, filepath.FromSlash(rel))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("deleted base-image config was pushed back: %s, err=%v", rel, err)
		}
	}
}

func TestFlushWithoutRepositoryIsImmediateNoOp(t *testing.T) {
	home := t.TempDir()
	writeTestFile(t, home, ".config/local", "local-only")
	engine := newTestEngine(t, "", home, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := engine.Flush(ctx, "shutdown"); err != nil {
		t.Fatalf("no-repository flush = %v", err)
	}
	if pending, err := engine.hasFlushablePending(); err != nil || pending {
		t.Fatalf("no-repository pending = %v, err=%v", pending, err)
	}
	status, err := ReadStatus(engine.StatusPath(), 50)
	if err != nil || status == nil || status.State != "healthy" {
		t.Fatalf("no-repository status = %#v err=%v", status, err)
	}
}

func TestStableReadRejectsFileChangedAfterStat(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, ".config/file", "before")
	path := filepath.Join(root, ".config/file")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	writeTestFile(t, root, ".config/file", "after-and-larger")
	if _, stable, err := readStable(path, before); err != nil || stable {
		t.Fatalf("readStable stable=%v err=%v", stable, err)
	}
}

func TestManifestIsCreatedForEmptyRepoAndLegacyManifestIsUpgraded(t *testing.T) {
	empty := newEmptyRemote(t)
	engine := newTestEngine(t, empty, t.TempDir(), t.TempDir())
	engine.cfg.Policy.Includes = []string{"Documents/tool.conf"}
	if err := engine.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkout := cloneRemote(t, empty)
	assertCompleteManifest(t, checkout, engine.cfg.Policy, "Documents/tool.conf")

	legacy := newRemote(t)
	work := cloneRemote(t, legacy)
	writeTestFile(t, work, "legacy.txt", "keep-me")
	writeTestFile(t, work, manifestPath, `{"revision":"old","includes":["custom/path"],"excludes":[".config/noisy"],"max_file_bytes":1024,"max_batch_bytes":2048}`)
	runGit(t, work, "config", "user.name", "Legacy")
	runGit(t, work, "config", "user.email", "legacy@example.test")
	runGit(t, work, "add", "-A")
	runGit(t, work, "commit", "-m", "legacy layout")
	runGit(t, work, "push", "origin", "main")
	legacyEngine := newTestEngine(t, legacy, t.TempDir(), t.TempDir())
	if err := legacyEngine.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	upgraded := cloneRemote(t, legacy)
	assertCompleteManifest(t, upgraded, legacyEngine.cfg.Policy, "custom/path")
	if got := readTestFile(t, upgraded, "legacy.txt"); got != "keep-me" {
		t.Fatalf("legacy tracked content = %q", got)
	}
	var value manifest
	readJSONFile(t, filepath.Join(upgraded, manifestPath), &value)
	if value.MaxFileBytes != 1024 || value.MaxBatchBytes != 2048 {
		t.Fatalf("stricter legacy limits were loosened: %#v", value)
	}
}

func TestManifestRejectsUnsafeTypeAndInconsistentLimits(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".paperboat"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "manifest.json")
	writeTestFile(t, filepath.Dir(outside), filepath.Base(outside), `{"schema_version":1}`)
	if err := os.Symlink(outside, filepath.Join(repo, manifestPath)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readManifest(repo); err == nil {
		t.Fatal("symlinked manifest was accepted")
	}
	if err := os.Remove(filepath.Join(repo, manifestPath)); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, repo, manifestPath, `{"schema_version":1,"max_file_bytes":20,"max_batch_bytes":10}`)
	if _, err := testPolicy().WithManifest(repo); err == nil {
		t.Fatal("inconsistent manifest limits were accepted")
	}
	writeTestFile(t, repo, manifestPath, `{"schema_version":99}`)
	if _, err := testPolicy().WithManifest(repo); err == nil {
		t.Fatal("unsupported manifest schema was accepted")
	}
}

func TestManifestBatchLimitAlsoTightensEffectiveFileLimit(t *testing.T) {
	repo := t.TempDir()
	writeTestFile(t, repo, manifestPath, `{"schema_version":1,"max_batch_bytes":1024}`)
	policy := testPolicy()

	effective, err := policy.WithManifest(repo)
	if err != nil {
		t.Fatal(err)
	}
	if effective.MaxFileBytes != 1024 || effective.MaxBatchBytes != 1024 {
		t.Fatalf("effective limits = file %d batch %d", effective.MaxFileBytes, effective.MaxBatchBytes)
	}
	changed, err := policy.EnsureManifest(repo)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("legacy manifest was not upgraded")
	}
	var upgraded manifest
	readJSONFile(t, filepath.Join(repo, manifestPath), &upgraded)
	if upgraded.MaxFileBytes != 1024 || upgraded.MaxBatchBytes != 1024 {
		t.Fatalf("upgraded limits = file %d batch %d", upgraded.MaxFileBytes, upgraded.MaxBatchBytes)
	}
}

func TestMandatoryExclusionsCannotBeOverridden(t *testing.T) {
	t.Setenv("PAPERBOAT_CONFIG_MANDATORY_EXCLUDES", ".custom-secret")
	fromEnv := PolicyFromEnv()
	for _, required := range []string{".custom-secret", ".config/git/credentials", ".config/hub", ".claude/shell-snapshots", ".codex/log", "**/credentials.*", "**/auth.json", "**/history.*", "**/cache", "**/logs"} {
		if !contains(fromEnv.MandatoryExcludes, required) {
			t.Fatalf("mandatory exclusion %q was replaced by environment policy", required)
		}
	}
	policy := testPolicy()
	policy.Includes = []string{".ssh/**", ".codex/auth.json"}
	if policy.Managed(".ssh/id_rsa") || policy.Managed(".codex/auth.json") {
		t.Fatal("mandatory exclusion was overridden")
	}
	for _, pattern := range []string{"/absolute", "../escape", "safe/../escape"} {
		if validatePattern(pattern) == nil {
			t.Errorf("unsafe pattern %q accepted", pattern)
		}
	}
}

func TestPolicyRejectsSymlinkedHomeOverlap(t *testing.T) {
	protected := t.TempDir()
	homeLink := filepath.Join(t.TempDir(), "home-link")
	if err := os.Symlink(protected, homeLink); err != nil {
		t.Fatal(err)
	}
	err := testPolicy().Validate(homeLink, protected, filepath.Join(t.TempDir(), "runtime", "repository"))
	if err == nil {
		t.Fatal("symlinked home bypassed protected-path overlap validation")
	}
}

func TestPolicyRejectsRelativeHome(t *testing.T) {
	if err := testPolicy().Validate("relative/home", t.TempDir(), filepath.Join(t.TempDir(), "repository")); err == nil {
		t.Fatal("relative config home was accepted")
	}
}

func TestNormalizeStatusSanitizesAndBoundsUntrustedHeartbeatData(t *testing.T) {
	status, err := NormalizeStatus(Status{State: "error", PendingPathCount: 1, MaxFileBytes: 10, MaxBatchBytes: 20, PolicyRevision: "1", UpdatedAt: time.Now().UTC(), ErrorCode: "Git Auth Failed!", ErrorMessage: "git rejected ghp_abcdefghijklmnopqrstuvwxyz123456", Skipped: []PathSummary{{Path: ".config/a", Reason: "Too Large"}, {Path: ".config/b", Reason: "Too Large"}}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if status.ErrorCode != "git_auth_failed" || strings.Contains(status.ErrorMessage, "ghp_") || len(status.Skipped) != 1 {
		t.Fatalf("normalized = %#v", status)
	}
	bad := status
	bad.Skipped = []PathSummary{{Path: "../secret", Reason: "bad"}}
	if _, err := NormalizeStatus(bad, 10); err == nil {
		t.Fatal("path traversal summary accepted")
	}
}

func TestAggregatePrioritizesActionableState(t *testing.T) {
	if got := aggregate([]MachineStatus{{State: "healthy"}, {State: "warning"}, {State: "conflict"}}); got != "conflict" {
		t.Fatalf("aggregate = %s", got)
	}
	if got := stateWithoutHeartbeat("running"); got != "offline" {
		t.Fatalf("running without heartbeat = %s", got)
	}
	if got := stateWithoutHeartbeat("stopped"); got != "idle" {
		t.Fatalf("stopped without heartbeat = %s", got)
	}
	if got := aggregate([]MachineStatus{{State: "idle", LastResultState: "conflict"}}); got != "conflict" {
		t.Fatalf("stopped conflict aggregate = %s", got)
	}
}

func TestSyncBatchesRemoteChangesAndPreservesConflicts(t *testing.T) {
	remote := newRemote(t)
	homeA, runtimeA := t.TempDir(), t.TempDir()
	homeB, runtimeB := t.TempDir(), t.TempDir()
	engineA := newTestEngine(t, remote, homeA, runtimeA)
	engineB := newTestEngine(t, remote, homeB, runtimeB)
	ctx := context.Background()
	if err := engineA.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Restore(ctx); err != nil {
		t.Fatal(err)
	}

	writeTestFile(t, homeA, ".config/a", "from-a")
	if err := engineA.Sync(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Sync(ctx, "remote"); err != nil {
		t.Fatal(err)
	}
	if got := readTestFile(t, homeB, ".config/a"); got != "from-a" {
		t.Fatalf("remote-only restore = %q", got)
	}

	writeTestFile(t, homeA, ".config/shared", "a-version")
	writeTestFile(t, homeB, ".config/shared", "b-version")
	if err := engineA.Sync(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Sync(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	checkout := cloneRemote(t, remote)
	if got := readTestFile(t, checkout, ".config/shared"); got != "b-version" {
		t.Fatalf("later writer = %q", got)
	}
	artifacts, err := filepath.Glob(filepath.Join(checkout, ".paperboat/conflicts/*/*/content"))
	if err != nil || len(artifacts) == 0 {
		t.Fatalf("conflict artifact missing: %v %v", artifacts, err)
	}
	content, err := os.ReadFile(artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "a-version" {
		t.Fatalf("conflict content = %q", content)
	}
	if err := engineB.Sync(ctx, "remote"); err != nil {
		t.Fatal(err)
	}
	status, err := ReadStatus(engineB.StatusPath(), 50)
	if err != nil || status == nil || status.State != "conflict" || !hasReason(status.Conflicts, ".config/shared", "concurrent_update") {
		t.Fatalf("conflict disappeared after routine reconcile: %#v err=%v", status, err)
	}
}

func TestConflictArtifactsHandleLongAndPreviouslyCollidingPaths(t *testing.T) {
	remote := newRemote(t)
	engineA := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engineB := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	ctx := context.Background()
	if err := engineA.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	deep := ".config/" + strings.Repeat("segment0123456789/", 14) + "settings.json"
	paths := []string{".config/a/b", ".config/a__b", deep}
	for index, path := range paths {
		writeTestFile(t, engineA.cfg.Home, path, fmt.Sprintf("remote-%d", index))
		writeTestFile(t, engineB.cfg.Home, path, fmt.Sprintf("local-%d", index))
	}
	if err := engineA.Sync(ctx, "first-writer"); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Sync(ctx, "later-writer"); err != nil {
		t.Fatal(err)
	}
	checkout := cloneRemote(t, remote)
	summaries, err := conflictSummaries(checkout)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != len(paths) {
		t.Fatalf("conflict summaries = %#v", summaries)
	}
	contents, err := filepath.Glob(filepath.Join(checkout, ".paperboat/conflicts/*/*/content"))
	if err != nil || len(contents) != len(paths) {
		t.Fatalf("conflict artifacts = %v, err=%v", contents, err)
	}
	seen := map[string]string{}
	metadataFiles, err := filepath.Glob(filepath.Join(checkout, ".paperboat/conflicts/*/*/metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range metadataFiles {
		var metadata conflictMetadata
		readJSONFile(t, path, &metadata)
		content, err := os.ReadFile(filepath.Join(filepath.Dir(path), "content"))
		if err != nil {
			t.Fatal(err)
		}
		seen[metadata.Path] = string(content)
	}
	for index, path := range paths {
		if got := seen[path]; got != fmt.Sprintf("remote-%d", index) {
			t.Fatalf("preserved conflict %q = %q", path, got)
		}
	}
}

func TestConflictPreservationFailureDoesNotOverwriteCanonicalRemote(t *testing.T) {
	remote := newRemote(t)
	engineA := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engineB := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	ctx := context.Background()
	if err := engineA.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, engineA.cfg.Home, ".config/shared", "canonical")
	writeTestFile(t, engineB.cfg.Home, ".config/shared", "later")
	if err := engineA.Sync(ctx, "first-writer"); err != nil {
		t.Fatal(err)
	}
	work := cloneRemote(t, remote)
	writeTestFile(t, work, ".paperboat/conflicts", "blocks-artifact-directory")
	commitAndPush(t, work, "block conflict directory")
	if err := engineB.Sync(ctx, "later-writer"); err == nil {
		t.Fatal("sync overwrote a conflict whose artifact could not be preserved")
	}
	if !remoteFileEquals(remote, ".config/shared", "canonical") {
		t.Fatal("canonical remote content changed after artifact preservation failure")
	}
	status, err := ReadStatus(engineB.StatusPath(), 50)
	if err != nil || status == nil || status.ErrorCode != "conflict_preservation_failed" {
		t.Fatalf("preservation failure status = %#v err=%v", status, err)
	}
}

func TestBatchLimitDefersDeterministically(t *testing.T) {
	remote := newRemote(t)
	home := t.TempDir()
	engine := newTestEngine(t, remote, home, t.TempDir())
	engine.cfg.Policy.MaxFileBytes = 10
	engine.cfg.Policy.MaxBatchBytes = 10
	if err := engine.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, home, ".config/a", "123456")
	writeTestFile(t, home, ".config/b", "123456")
	if err := engine.Sync(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	status, err := ReadStatus(engine.StatusPath(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if status.PendingPathCount != 1 {
		t.Fatalf("pending = %d", status.PendingPathCount)
	}
	if status.State != "pending" {
		t.Fatalf("deferred batch state = %q", status.State)
	}
	checkout := cloneRemote(t, remote)
	if _, err := os.Stat(filepath.Join(checkout, ".config/a")); err != nil {
		t.Fatal("deterministic first file not pushed")
	}
	if _, err := os.Stat(filepath.Join(checkout, ".config/b")); !os.IsNotExist(err) {
		t.Fatal("deferred file was pushed")
	}
	if err := engine.Sync(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	checkout = cloneRemote(t, remote)
	if got := readTestFile(t, checkout, ".config/b"); got != "123456" {
		t.Fatalf("deferred content = %q", got)
	}
}

func TestDeferredConflictRetainsOldBaselineUntilItCanBePreserved(t *testing.T) {
	remote := newRemote(t)
	engineA := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engineB := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engineB.cfg.Policy.MaxFileBytes = 600
	engineB.cfg.Policy.MaxBatchBytes = 600
	ctx := context.Background()
	if err := engineB.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engineA.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, engineA.cfg.Home, ".config/deferred-conflict", "remote")
	writeTestFile(t, engineB.cfg.Home, ".config/deferred-conflict", "local")
	writeTestFile(t, engineB.cfg.Home, ".config/a-fill", strings.Repeat("f", 600))
	if err := engineA.Sync(ctx, "first-writer"); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Sync(ctx, "deferred"); err != nil {
		t.Fatal(err)
	}
	if !remoteFileEquals(remote, ".config/deferred-conflict", "remote") {
		t.Fatal("deferred conflict changed canonical content")
	}
	status, err := ReadStatus(engineB.StatusPath(), 50)
	if err != nil || status == nil || !hasReason(status.Conflicts, ".config/deferred-conflict", "concurrent_update_pending") {
		t.Fatalf("deferred conflict status = %#v err=%v", status, err)
	}
	if err := engineB.Sync(ctx, "retry-deferred"); err != nil {
		t.Fatal(err)
	}
	if !remoteFileEquals(remote, ".config/deferred-conflict", "local") {
		t.Fatal("deferred conflict was not eventually pushed")
	}
	checkout := cloneRemote(t, remote)
	summaries, err := conflictSummaries(checkout)
	if err != nil || !hasReason(summaries, ".config/deferred-conflict", "concurrent_update") {
		t.Fatalf("eventual conflict preservation = %#v err=%v", summaries, err)
	}
}

func TestConflictFitsWhenBatchEqualsFileLimit(t *testing.T) {
	remote := newRemote(t)
	engineA := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engineB := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engineA.cfg.Policy.MaxFileBytes, engineA.cfg.Policy.MaxBatchBytes = 32, 32
	engineB.cfg.Policy.MaxFileBytes, engineB.cfg.Policy.MaxBatchBytes = 32, 32
	ctx := context.Background()
	if err := engineA.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	remoteVersion := strings.Repeat("R", 32)
	localVersion := strings.Repeat("L", 32)
	writeTestFile(t, engineA.cfg.Home, ".config/exact-conflict", remoteVersion)
	writeTestFile(t, engineB.cfg.Home, ".config/exact-conflict", localVersion)
	if err := engineA.Sync(ctx, "first-writer"); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Sync(ctx, "exact-limit-writer"); err != nil {
		t.Fatal(err)
	}
	if !remoteFileEquals(remote, ".config/exact-conflict", localVersion) {
		t.Fatal("exact-limit conflict was deferred instead of synchronized")
	}
	checkout := cloneRemote(t, remote)
	summaries, err := conflictSummaries(checkout)
	if err != nil || !hasReason(summaries, ".config/exact-conflict", "concurrent_update") {
		t.Fatalf("exact-limit conflict artifact = %#v err=%v", summaries, err)
	}
}

func TestTrackedOversizedFileRetainsRemoteVersionAndStagedGuardRejectsBypass(t *testing.T) {
	remote := newRemote(t)
	work := cloneRemote(t, remote)
	writeTestFile(t, work, ".config/tracked", "remote-safe")
	runGit(t, work, "config", "user.name", "Seed")
	runGit(t, work, "config", "user.email", "seed@example.test")
	runGit(t, work, "add", "-A")
	runGit(t, work, "commit", "-m", "tracked config")
	runGit(t, work, "push", "origin", "main")

	home := t.TempDir()
	engine := newTestEngine(t, remote, home, t.TempDir())
	engine.cfg.Policy.MaxFileBytes = 12
	engine.cfg.Policy.MaxBatchBytes = 24
	if err := engine.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, home, ".config/tracked", strings.Repeat("x", 13))
	if err := engine.Sync(context.Background(), "oversized"); err != nil {
		t.Fatal(err)
	}
	if !remoteFileEquals(remote, ".config/tracked", "remote-safe") {
		t.Fatal("oversized local file replaced the last remote version")
	}
	status, err := ReadStatus(engine.StatusPath(), 50)
	if err != nil || status == nil || status.State != "warning" || !hasReason(status.Skipped, ".config/tracked", "max_file_bytes") {
		t.Fatalf("oversized status = %#v err=%v", status, err)
	}

	writeTestFile(t, engine.repo, ".config/bypass", strings.Repeat("y", 13))
	runGit(t, engine.repo, "add", ".config/bypass")
	if err := engine.verifyStagedBlobs(context.Background(), 12, 24); err == nil {
		t.Fatal("staged object bypassed max_file_bytes")
	}
}

func TestOversizedLocalFileIsNotOverwrittenByConcurrentRemoteChange(t *testing.T) {
	remote := newRemote(t)
	work := cloneRemote(t, remote)
	writeTestFile(t, work, ".config/oversized-conflict", "baseline")
	commitAndPush(t, work, "seed oversized conflict")
	engineA := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engineB := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engineA.cfg.Policy.MaxFileBytes, engineA.cfg.Policy.MaxBatchBytes = 32, 1<<20
	engineB.cfg.Policy.MaxFileBytes, engineB.cfg.Policy.MaxBatchBytes = 32, 1<<20
	ctx := context.Background()
	if err := engineA.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, engineA.cfg.Home, ".config/oversized-conflict", "remote-new")
	if err := engineA.Sync(ctx, "remote-change"); err != nil {
		t.Fatal(err)
	}
	oversized := strings.Repeat("L", 33)
	writeTestFile(t, engineB.cfg.Home, ".config/oversized-conflict", oversized)
	if err := engineB.Sync(ctx, "oversized"); err != nil {
		t.Fatal(err)
	}
	if got := readTestFile(t, engineB.cfg.Home, ".config/oversized-conflict"); got != oversized {
		t.Fatalf("remote reconcile overwrote oversized pending content: %q", got)
	}
	writeTestFile(t, engineB.cfg.Home, ".config/oversized-conflict", "local-valid")
	if err := engineB.Sync(ctx, "oversized-resolved"); err != nil {
		t.Fatal(err)
	}
	if !remoteFileEquals(remote, ".config/oversized-conflict", "local-valid") {
		t.Fatal("valid local conflict did not become canonical")
	}
	checkout := cloneRemote(t, remote)
	summaries, err := conflictSummaries(checkout)
	if err != nil || !hasReason(summaries, ".config/oversized-conflict", "concurrent_update") {
		t.Fatalf("oversized conflict was not preserved: %#v err=%v", summaries, err)
	}
}

func TestOversizedRemoteFileIsNotTreatedAsDeletedOrOverwritten(t *testing.T) {
	remote := newRemote(t)
	work := cloneRemote(t, remote)
	writeTestFile(t, work, ".config/remote-oversized", strings.Repeat("R", 13))
	commitAndPush(t, work, "seed oversized remote")
	engine := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engine.cfg.Policy.MaxFileBytes, engine.cfg.Policy.MaxBatchBytes = 12, 1024
	ctx := context.Background()
	if err := engine.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, engine.cfg.Home, ".config/remote-oversized", "local-safe")
	if err := engine.Sync(ctx, "remote-oversized"); err != nil {
		t.Fatal(err)
	}
	if !remoteFileEquals(remote, ".config/remote-oversized", strings.Repeat("R", 13)) {
		t.Fatal("policy-rejected remote file was overwritten")
	}
	status, err := ReadStatus(engine.StatusPath(), 50)
	if err != nil || status == nil || !hasReason(status.Skipped, ".config/remote-oversized", "remote_max_file_bytes") || status.PendingPathCount != 1 {
		t.Fatalf("remote oversized status = %#v err=%v", status, err)
	}

	work = cloneRemote(t, remote)
	writeTestFile(t, work, ".config/remote-oversized", "remote-safe")
	commitAndPush(t, work, "shrink remote file")
	if err := engine.Sync(ctx, "remote-resolved"); err != nil {
		t.Fatal(err)
	}
	if !remoteFileEquals(remote, ".config/remote-oversized", "local-safe") {
		t.Fatal("pending local file was not pushed after the remote policy violation resolved")
	}
}

func TestSyncHandlesFileDirectoryTypeTransitions(t *testing.T) {
	remote := newRemote(t)
	work := cloneRemote(t, remote)
	writeTestFile(t, work, ".config/switch/child", "child")
	commitAndPush(t, work, "seed directory")
	engine := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	ctx := context.Background()
	if err := engine.Restore(ctx); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(filepath.Join(engine.cfg.Home, ".config/switch")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, engine.cfg.Home, ".config/switch", "now-a-file")
	if err := engine.Sync(ctx, "directory-to-file"); err != nil {
		t.Fatal(err)
	}
	if !remoteFileEquals(remote, ".config/switch", "now-a-file") {
		t.Fatal("directory-to-file transition was not synchronized")
	}

	if err := os.Remove(filepath.Join(engine.cfg.Home, ".config/switch")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, engine.cfg.Home, ".config/switch/child", "back-to-directory")
	if err := engine.Sync(ctx, "file-to-directory"); err != nil {
		t.Fatal(err)
	}
	checkout := cloneRemote(t, remote)
	if got := readTestFile(t, checkout, ".config/switch/child"); got != "back-to-directory" {
		t.Fatalf("file-to-directory content = %q", got)
	}
}

func TestRestoreReconcilesPendingLocalChangesFromDurableBaseline(t *testing.T) {
	remote := newRemote(t)
	work := cloneRemote(t, remote)
	writeTestFile(t, work, ".config/pending-restore", "baseline")
	commitAndPush(t, work, "seed restore baseline")
	engine := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	ctx := context.Background()
	if err := engine.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, engine.cfg.Home, ".config/pending-restore", "local-pending")

	work = cloneRemote(t, remote)
	writeTestFile(t, work, ".config/pending-restore", "remote-new")
	commitAndPush(t, work, "concurrent restore update")
	if err := engine.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if !remoteFileEquals(remote, ".config/pending-restore", "local-pending") {
		t.Fatal("startup restore overwrote a pending local change")
	}
	checkout := cloneRemote(t, remote)
	summaries, err := conflictSummaries(checkout)
	if err != nil || !hasReason(summaries, ".config/pending-restore", "concurrent_update") {
		t.Fatalf("restore conflict preservation = %#v err=%v", summaries, err)
	}
}

func TestNetworkFailureLeavesLocalChangePending(t *testing.T) {
	remote := newRemote(t)
	engine := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	if err := engine.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, engine.cfg.Home, ".config/pending-network", "retain-locally")
	unavailable := remote + ".offline"
	if err := os.Rename(remote, unavailable); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(unavailable, remote)
	if err := engine.Sync(context.Background(), "network-failure"); err == nil {
		t.Fatal("sync unexpectedly succeeded with unavailable remote")
	}
	status, err := ReadStatus(engine.StatusPath(), 50)
	if err != nil || status == nil || status.State != "error" || status.PendingPathCount < 1 {
		t.Fatalf("network failure status = %#v err=%v", status, err)
	}
	if got := readTestFile(t, engine.cfg.Home, ".config/pending-network"); got != "retain-locally" {
		t.Fatalf("pending local content = %q", got)
	}
}

func TestDaemonCoalescesBurstAndRegistersNewDotDirectory(t *testing.T) {
	remote := newRemote(t)
	engine := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engine.cfg.Policy.Debounce = 40 * time.Millisecond
	engine.cfg.Policy.MinPushInterval = 80 * time.Millisecond
	engine.cfg.Policy.MaxDirtyDelay = 500 * time.Millisecond
	engine.cfg.Policy.RemotePollInterval = time.Hour
	if err := engine.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := remoteCommitCount(t, remote)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.RunDaemon(ctx) }()
	waitFor(t, time.Second, func() bool { return readStatusState(engine.StatusPath()) == "watching" })
	for index := 0; index < 8; index++ {
		writeTestFile(t, engine.cfg.Home, ".new-agent/settings.json", strings.Repeat("x", index+1))
		time.Sleep(5 * time.Millisecond)
	}
	waitFor(t, 2*time.Second, func() bool { return remoteFileEquals(remote, ".new-agent/settings.json", strings.Repeat("x", 8)) })
	if got := remoteCommitCount(t, remote); got != before+1 {
		t.Fatalf("burst produced %d commits, want one", got-before)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDaemonStartRetainsUnresolvedConflictState(t *testing.T) {
	remote := newRemote(t)
	engine := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	if err := engine.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := preserveConflict(engine.repo, engine.cfg.ProjectID, ".config/conflicted", fileState{}, false, engine.cfg.Now()); err != nil {
		t.Fatal(err)
	}
	if err := engine.status.write(func(status *Status) {
		status.State = "conflict"
		status.Conflicts = []PathSummary{{Path: ".config/conflicted", Reason: "concurrent_update"}}
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.RunDaemon(ctx) }()
	waitFor(t, time.Second, func() bool { return readStatusState(engine.StatusPath()) == "conflict" })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDaemonHonorsMinimumPushInterval(t *testing.T) {
	remote := newRemote(t)
	engine := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engine.cfg.Policy.Debounce = 20 * time.Millisecond
	engine.cfg.Policy.MinPushInterval = 300 * time.Millisecond
	engine.cfg.Policy.MaxDirtyDelay = time.Second
	engine.cfg.Policy.RemotePollInterval = time.Hour
	if err := engine.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.RunDaemon(ctx) }()
	waitFor(t, time.Second, func() bool { return readStatusState(engine.StatusPath()) == "watching" })
	writeTestFile(t, engine.cfg.Home, ".config/timing", "one")
	waitFor(t, 2*time.Second, func() bool { return remoteFileEquals(remote, ".config/timing", "one") })
	writeTestFile(t, engine.cfg.Home, ".config/timing", "two")
	time.Sleep(100 * time.Millisecond)
	if remoteFileEquals(remote, ".config/timing", "two") {
		t.Fatal("second push bypassed minimum interval")
	}
	waitFor(t, 2*time.Second, func() bool { return remoteFileEquals(remote, ".config/timing", "two") })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDaemonMaximumDirtyDelayFlushesContinuousWrites(t *testing.T) {
	remote := newRemote(t)
	engine := newTestEngine(t, remote, t.TempDir(), t.TempDir())
	engine.cfg.Policy.Debounce = 200 * time.Millisecond
	engine.cfg.Policy.MinPushInterval = time.Second
	engine.cfg.Policy.MaxDirtyDelay = 100 * time.Millisecond
	engine.cfg.Policy.RemotePollInterval = time.Hour
	if err := engine.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.RunDaemon(ctx) }()
	waitFor(t, time.Second, func() bool { return readStatusState(engine.StatusPath()) == "watching" })
	writeTestFile(t, engine.cfg.Home, ".config/continuous", "stable")
	stopNoise := make(chan struct{})
	noiseDone := make(chan struct{})
	go func() {
		defer close(noiseDone)
		for index := 0; ; index++ {
			select {
			case <-stopNoise:
				return
			default:
				writeTestFile(t, engine.cfg.Home, "unmanaged-noise.txt", strings.Repeat("x", index%32+1))
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	waitFor(t, 3*time.Second, func() bool { return remoteFileEquals(remote, ".config/continuous", "stable") })
	close(stopNoise)
	<-noiseDone
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDaemonShutdownFlushAndFailureRemainPending(t *testing.T) {
	t.Run("change before watcher registration", func(t *testing.T) {
		remote := newRemote(t)
		engine := newTestEngine(t, remote, t.TempDir(), t.TempDir())
		if err := engine.Restore(context.Background()); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, engine.cfg.Home, ".config/before-watch", "saved")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := engine.RunDaemon(ctx); err != nil {
			t.Fatal(err)
		}
		if !remoteFileEquals(remote, ".config/before-watch", "saved") {
			t.Fatal("shutdown skipped a change made before watcher registration")
		}
	})

	t.Run("success", func(t *testing.T) {
		remote := newRemote(t)
		engine := newTestEngine(t, remote, t.TempDir(), t.TempDir())
		engine.cfg.Policy.Debounce = time.Hour
		if err := engine.Restore(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- engine.RunDaemon(ctx) }()
		waitFor(t, time.Second, func() bool { return readStatusState(engine.StatusPath()) == "watching" })
		writeTestFile(t, engine.cfg.Home, ".config/shutdown", "saved")
		time.Sleep(30 * time.Millisecond)
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !remoteFileEquals(remote, ".config/shutdown", "saved") {
			t.Fatal("shutdown flush did not push pending file")
		}
	})

	t.Run("failure", func(t *testing.T) {
		remote := newRemote(t)
		engine := newTestEngine(t, remote, t.TempDir(), t.TempDir())
		engine.cfg.Policy.Debounce = time.Hour
		engine.cfg.Policy.ShutdownFlushTimeout = time.Second
		if err := engine.Restore(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- engine.RunDaemon(ctx) }()
		waitFor(t, time.Second, func() bool { return readStatusState(engine.StatusPath()) == "watching" })
		writeTestFile(t, engine.cfg.Home, ".config/pending", "not-lost")
		time.Sleep(30 * time.Millisecond)
		unavailable := remote + ".offline"
		if err := os.Rename(remote, unavailable); err != nil {
			t.Fatal(err)
		}
		defer os.Rename(unavailable, remote)
		cancel()
		if err := <-done; err == nil {
			t.Fatal("shutdown flush failure was reported as success")
		}
		status, err := ReadStatus(engine.StatusPath(), 50)
		if err != nil {
			t.Fatal(err)
		}
		if status.State != "error" || status.PendingPathCount < 1 {
			t.Fatalf("failed flush status = %#v", status)
		}
	})
}

func testPolicy() Policy {
	return Policy{Revision: "test", MandatoryExcludes: append([]string{}, defaultMandatoryExcludes...), MaxFileBytes: 5 << 20, MaxBatchBytes: 25 << 20, Debounce: 10 * time.Millisecond, MinPushInterval: 20 * time.Millisecond, MaxDirtyDelay: 50 * time.Millisecond, RemotePollInterval: 50 * time.Millisecond, RetryLimit: 2, ShutdownFlushTimeout: time.Second, SummaryLimit: 50}
}

func newTestEngine(t *testing.T, remote, home, runtime string) *Engine {
	t.Helper()
	engine, err := New(Config{Home: home, Workspace: filepath.Join(t.TempDir(), "workspace"), RuntimeDir: runtime, RepoURL: remote, Branch: "main", ProjectID: "prj_test", MachineID: "machine_test", AuthorName: "Test", AuthorMail: "test@example.test", Policy: testPolicy(), Now: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func newRemote(t *testing.T) string {
	t.Helper()
	remote := filepath.Join(t.TempDir(), "remote.git")
	runGit(t, "", "init", "--bare", "--initial-branch=main", remote)
	seed := t.TempDir()
	runGit(t, seed, "init", "--initial-branch=main")
	runGit(t, seed, "config", "user.name", "Seed")
	runGit(t, seed, "config", "user.email", "seed@example.test")
	writeTestFile(t, seed, ".paperboat/config-sync.json", `{"revision":"test"}`)
	runGit(t, seed, "add", "-A")
	runGit(t, seed, "commit", "-m", "seed")
	runGit(t, seed, "remote", "add", "origin", remote)
	runGit(t, seed, "push", "origin", "main")
	return remote
}

func newEmptyRemote(t *testing.T) string {
	t.Helper()
	remote := filepath.Join(t.TempDir(), "empty.git")
	runGit(t, "", "init", "--bare", "--initial-branch=main", remote)
	return remote
}

func cloneRemote(t *testing.T, remote string) string {
	t.Helper()
	path := t.TempDir()
	runGit(t, "", "clone", "--branch", "main", remote, path)
	return path
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func commitAndPush(t *testing.T, work, message string) {
	t.Helper()
	runGit(t, work, "config", "user.name", "Test")
	runGit(t, work, "config", "user.email", "test@example.test")
	runGit(t, work, "add", "-A")
	runGit(t, work, "commit", "-m", message)
	runGit(t, work, "push", "origin", "main")
}

func writeTestFile(t *testing.T, root, rel, value string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, root, rel string) string {
	t.Helper()
	value, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func hasReason(items []PathSummary, path, reason string) bool {
	for _, item := range items {
		if item.Path == path && item.Reason == reason {
			return true
		}
	}
	return false
}

func assertCompleteManifest(t *testing.T, checkout string, policy Policy, include string) {
	t.Helper()
	var value manifest
	readJSONFile(t, filepath.Join(checkout, manifestPath), &value)
	if value.SchemaVersion != 1 || value.Revision != policy.Revision || value.MaxFileBytes <= 0 || value.MaxBatchBytes <= 0 || value.DebounceSeconds <= 0 || value.MinPushSeconds <= 0 || value.MaxDirtyDelaySeconds <= 0 || value.RemotePollSeconds <= 0 || value.RetryLimit <= 0 || value.ShutdownSeconds <= 0 || value.SummaryLimit <= 0 {
		t.Fatalf("manifest is incomplete: %#v", value)
	}
	if !contains(value.Includes, include) || !contains(value.MandatoryExcludes, ".ssh") {
		t.Fatalf("manifest policy missing include/exclusions: %#v", value)
	}
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, target); err != nil {
		t.Fatal(err)
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true before timeout")
}

func remoteCommitCount(t *testing.T, remote string) int {
	t.Helper()
	cmd := exec.Command("git", "--git-dir="+remote, "rev-list", "--count", "main")
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &count); err != nil {
		t.Fatal(err)
	}
	return count
}

func remoteFileEquals(remote, rel, wanted string) bool {
	cmd := exec.Command("git", "--git-dir="+remote, "show", "main:"+filepath.ToSlash(rel))
	output, err := cmd.Output()
	return err == nil && string(output) == wanted
}

func remoteHasFile(remote, rel string) bool {
	cmd := exec.Command("git", "--git-dir="+remote, "cat-file", "-e", "main:"+filepath.ToSlash(rel))
	return cmd.Run() == nil
}

func readStatusState(path string) string {
	status, err := ReadStatus(path, 50)
	if err != nil || status == nil {
		return ""
	}
	return status.State
}
