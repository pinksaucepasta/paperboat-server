package configsync

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Home               string
	Workspace          string
	RuntimeDir         string
	RepoURL            string
	Branch             string
	ProjectID          string
	MachineID          string
	AuthorName         string
	AuthorMail         string
	Policy             Policy
	Now                func() time.Time
	ChezmoiBinary      string
	AgeIdentityPath    string
	AgeRecipient       string
	AgeKeyVersion      int
	RequireEncryption  bool
	ClassifierEndpoint string
	MachineCredential  string
	GitToken           string
	PendingJournalPath string
}

type Engine struct {
	cfg          Config
	repo         string
	baselinePath string
	status       *statusWriter
	chezmoi      *chezmoiSource
	classifier   *classificationClient
	mu           sync.Mutex
	lastPush     time.Time
}

func ConfigFromEnv() (Config, error) {
	home := strings.TrimSpace(os.Getenv("PAPERBOAT_CONFIG_HOME"))
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return Config{}, err
		}
	}
	activityTokenEnv := env("PAPERBOAT_ACTIVITY_TOKEN_ENV", "PAPERBOAT_MACHINE_ACTIVITY_TOKEN")
	return Config{
		Home:               home,
		Workspace:          env("PAPERBOAT_WORKSPACE", "/workspace"),
		RuntimeDir:         env("PAPERBOAT_RUNTIME_DIR", "/var/lib/paperboat"),
		RepoURL:            strings.TrimSpace(os.Getenv("PAPERBOAT_CONFIG_REPO_URL")),
		Branch:             env("PAPERBOAT_CONFIG_REPO_BRANCH", "main"),
		ProjectID:          env("PAPERBOAT_PROJECT_ID", "project"),
		MachineID:          env("FLY_MACHINE_ID", os.Getenv("PAPERBOAT_MACHINE_ID")),
		AuthorName:         env("PAPERBOAT_CONFIG_GIT_AUTHOR_NAME", "Paperboat Config Sync"),
		AuthorMail:         env("PAPERBOAT_CONFIG_GIT_AUTHOR_EMAIL", "config-sync@paperboat.invalid"),
		ChezmoiBinary:      env("PAPERBOAT_CHEZMOI_BINARY", "/usr/local/bin/chezmoi"),
		AgeIdentityPath:    env("PAPERBOAT_CONFIG_AGE_IDENTITY_FILE", filepath.Join(env("PAPERBOAT_RUNTIME_DIR", "/var/lib/paperboat"), "config-age-identity.txt")),
		AgeRecipient:       strings.TrimSpace(os.Getenv("PAPERBOAT_CONFIG_AGE_RECIPIENT")),
		AgeKeyVersion:      int(envInt("PAPERBOAT_CONFIG_AGE_KEY_VERSION", 1)),
		RequireEncryption:  envBool("PAPERBOAT_CONFIG_REQUIRE_ENCRYPTION", false),
		ClassifierEndpoint: strings.TrimSpace(os.Getenv("PAPERBOAT_CONFIG_CLASSIFY_ENDPOINT")),
		MachineCredential:  strings.TrimSpace(os.Getenv(activityTokenEnv)),
		GitToken:           strings.TrimSpace(os.Getenv("PAPERBOAT_GITHUB_CONFIG_TOKEN")),
		PendingJournalPath: env("PAPERBOAT_CONFIG_PENDING_JOURNAL", filepath.Join(env("PAPERBOAT_WORKSPACE", "/workspace"), ".paperboat", "system", "config-sync-pending.json")),
		Policy:             PolicyFromEnv(),
		Now:                func() time.Time { return time.Now().UTC() },
	}, nil
}

func New(cfg Config) (*Engine, error) {
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if strings.TrimSpace(cfg.PendingJournalPath) == "" {
		cfg.PendingJournalPath = filepath.Join(cfg.RuntimeDir, "config-sync", "classification-pending.json")
	}
	if cfg.Policy.Revision == "" {
		cfg.Policy = PolicyFromEnv()
	}
	cfg.Policy.MandatoryExcludes = unique(append(append([]string{}, defaultMandatoryExcludes...), cfg.Policy.MandatoryExcludes...))
	repo := filepath.Join(cfg.RuntimeDir, "config-sync", "repository")
	if err := cfg.Policy.Validate(cfg.Home, cfg.Workspace, repo); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(cfg.RuntimeDir, "config-sync"), 0o700); err != nil {
		return nil, err
	}
	var chezmoi *chezmoiSource
	if cfg.AgeRecipient != "" {
		var err error
		chezmoi, err = newChezmoiSource(cfg.ChezmoiBinary, cfg.RuntimeDir, repo, cfg.Home, cfg.AgeIdentityPath, cfg.AgeRecipient)
		if err != nil {
			return nil, err
		}
	}
	if cfg.RequireEncryption {
		if chezmoi == nil || strings.TrimSpace(cfg.ChezmoiBinary) == "" || strings.TrimSpace(cfg.AgeIdentityPath) == "" || cfg.AgeKeyVersion <= 0 {
			return nil, errors.New("encrypted config sync is required but its configuration is incomplete")
		}
		info, err := os.Stat(cfg.AgeIdentityPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("encrypted config sync requires a private age identity file")
		}
		if info, err := os.Stat(cfg.ChezmoiBinary); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			return nil, errors.New("encrypted config sync requires an executable chezmoi binary")
		}
	}
	return &Engine{
		cfg:          cfg,
		repo:         repo,
		baselinePath: filepath.Join(cfg.RuntimeDir, "config-sync", "baseline.json"),
		status:       newStatusWriter(filepath.Join(cfg.RuntimeDir, "config-sync-status.json"), cfg.Policy),
		chezmoi:      chezmoi,
		classifier:   newClassificationClient(cfg.PendingJournalPath, cfg.ClassifierEndpoint, cfg.ProjectID, cfg.MachineID, cfg.MachineCredential),
	}, nil
}

func (e *Engine) StatusPath() string { return e.status.path }

func (e *Engine) Restore(ctx context.Context) error {
	return e.exclusive(func() error {
		now := e.cfg.Now()
		if err := e.status.write(func(status *Status) {
			status.State = "restoring"
			status.LastAttemptAt = &now
			status.ErrorCode, status.ErrorMessage = "", ""
		}); err != nil {
			return err
		}
		if e.cfg.RepoURL == "" {
			return e.recordNoRepository()
		}
		if e.chezmoi != nil {
			return e.restoreEncrypted(ctx)
		}
		if _, err := os.Stat(e.baselinePath); err == nil {
			return e.syncLocked(ctx, "restore")
		} else if !errors.Is(err, os.ErrNotExist) {
			e.recordError("baseline_read_failed", err)
			return err
		}
		if err := e.ensureRepository(ctx); err != nil {
			e.recordError("restore_failed", err)
			return err
		}
		if err := e.ensurePolicyManifest(ctx); err != nil {
			e.recordError("manifest_update_failed", err)
			return err
		}
		policy, err := e.cfg.Policy.WithManifest(e.repo)
		if err != nil {
			e.recordError("manifest_invalid", err)
			return err
		}
		e.cfg.Policy = policy
		e.status.last.MaxFileBytes, e.status.last.MaxBatchBytes = policy.MaxFileBytes, policy.MaxBatchBytes
		remote, err := takeSnapshot(e.repo, policy)
		if err != nil {
			e.recordError("snapshot_failed", err)
			return err
		}
		local, err := takeSnapshot(e.cfg.Home, policy)
		if err != nil {
			e.recordError("snapshot_failed", err)
			return err
		}
		restorePaths := changedPaths(local.Files, remote.Files, remote.Skipped)
		if err := applyChanges(e.repo, e.cfg.Home, remote.Files, restorePaths); err != nil {
			e.recordError("restore_failed", err)
			return err
		}
		if err := e.writeBaseline(remote.Files); err != nil {
			return err
		}
		conflicts, err := conflictSummaries(e.repo)
		if err != nil {
			e.recordError("conflict_metadata_invalid", err)
			return err
		}
		commit, _ := e.gitOutput(ctx, "rev-parse", "HEAD")
		success := e.cfg.Now()
		return e.status.write(func(status *Status) {
			status.State = stateForSummaries(remote.Skipped, conflicts)
			status.LastSuccessfulAt = &success
			status.RemoteCommit = strings.TrimSpace(commit)
			status.Skipped = remote.Skipped
			status.Conflicts = conflicts
			status.PendingPathCount = 0
		})
	})
}

func (e *Engine) Sync(ctx context.Context, operation string) error {
	return e.exclusive(func() error { return e.syncLocked(ctx, operation) })
}

func (e *Engine) Flush(ctx context.Context, operation string) error {
	if e.cfg.RepoURL == "" {
		return e.Sync(ctx, operation)
	}
	for {
		if err := e.Sync(ctx, operation); err != nil {
			return err
		}
		pending, err := e.hasFlushablePending()
		if err != nil || !pending {
			return err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (e *Engine) syncLocked(ctx context.Context, operation string) error {
	if e.chezmoi != nil {
		return e.syncEncryptedLocked(ctx, operation)
	}
	now := e.cfg.Now()
	if err := e.status.write(func(status *Status) {
		status.State = "syncing"
		status.LastAttemptAt = &now
		status.ErrorCode, status.ErrorMessage = "", ""
	}); err != nil {
		return err
	}
	if e.cfg.RepoURL == "" {
		return e.recordNoRepository()
	}
	if err := e.ensureRepository(ctx); err != nil {
		e.recordSyncError("network_error", err)
		return err
	}
	if err := e.ensurePolicyManifest(ctx); err != nil {
		e.recordSyncError("manifest_update_failed", err)
		return err
	}
	policy, err := e.cfg.Policy.WithManifest(e.repo)
	if err != nil {
		e.recordError("manifest_invalid", err)
		return err
	}
	e.cfg.Policy = policy
	e.status.last.MaxFileBytes, e.status.last.MaxBatchBytes = policy.MaxFileBytes, policy.MaxBatchBytes
	local, err := takeSnapshot(e.cfg.Home, policy)
	if err != nil {
		e.recordError("snapshot_failed", err)
		return err
	}
	baseline, err := e.readBaseline()
	if err != nil {
		return err
	}
	changed := changedPaths(baseline, local.Files, local.Skipped)
	protected := append([]string{}, changed...)
	for _, item := range local.Skipped {
		protected = append(protected, item.Path)
	}
	protected = unique(protected)
	for attempt := 0; attempt < policy.RetryLimit; attempt++ {
		if err := e.resetToRemote(ctx); err != nil {
			e.recordSyncError("network_error", err)
			return err
		}
		remote, err := takeSnapshot(e.repo, policy)
		if err != nil {
			return err
		}
		remoteSkipped := remoteSkippedSummaries(remote.Skipped)
		remoteSkippedSet := summaryPathSet(remote.Skipped)
		eligible := make([]string, 0, len(changed))
		blocked := make([]string, 0)
		for _, rel := range changed {
			if _, skip := remoteSkippedSet[rel]; skip {
				blocked = append(blocked, rel)
				continue
			}
			eligible = append(eligible, rel)
		}
		attemptProtected := append([]string{}, protected...)
		for rel := range remoteSkippedSet {
			attemptProtected = append(attemptProtected, rel)
		}
		attemptProtected = unique(attemptProtected)
		newConflicts := make([]PathSummary, 0)
		pendingConflicts := make([]PathSummary, 0)
		remoteChanged := changedPaths(baseline, remote.Files, remote.Skipped)
		protectedSet := toSet(attemptProtected)
		selected, deferred := selectBatch(eligible, local.Files, nil, policy.MaxBatchBytes)
		deferred = append(deferred, blocked...)
		sort.Strings(deferred)
		selectedSet := toSet(selected)
		remoteApply := make([]string, 0, len(remoteChanged))
		for _, rel := range remoteChanged {
			if _, localProtected := protectedSet[rel]; localProtected {
				if !equalState(remote.Files[rel], local.Files[rel]) {
					if _, selectedForPush := selectedSet[rel]; selectedForPush {
						state, exists := remote.Files[rel]
						if err := preserveConflict(e.repo, e.cfg.ProjectID, rel, state, exists, e.cfg.Now()); err != nil {
							e.recordSyncError("conflict_preservation_failed", err)
							return err
						}
						newConflicts = append(newConflicts, PathSummary{Path: rel, Bytes: state.Bytes, Reason: "concurrent_update"})
					} else {
						pendingConflicts = append(pendingConflicts, PathSummary{Path: rel, Bytes: remote.Files[rel].Bytes, Reason: "concurrent_update_pending"})
					}
				}
				continue
			}
			remoteApply = append(remoteApply, rel)
		}
		if err := applyChanges(e.repo, e.cfg.Home, remote.Files, remoteApply); err != nil {
			return err
		}
		if err := applyChanges(e.cfg.Home, e.repo, local.Files, selected); err != nil {
			return err
		}
		if err := e.git(ctx, "add", "-A"); err != nil {
			return err
		}
		if err := e.verifyStagedBlobs(ctx, policy.MaxFileBytes, policy.MaxBatchBytes); err != nil {
			e.recordSyncError("size_limit", err)
			return err
		}
		staged, err := e.stagedPaths(ctx)
		if err != nil {
			return err
		}
		if len(staged) == 0 {
			canonical := mergeBaseline(baseline, remote.Files, local.Files, selected, attemptProtected)
			if err := e.writeBaseline(canonical); err != nil {
				return err
			}
			conflicts, err := e.statusConflicts(pendingConflicts)
			if err != nil {
				return err
			}
			success := e.cfg.Now()
			commit, _ := e.gitOutput(ctx, "rev-parse", "HEAD")
			allSkipped := uniqueSummaries(append(append([]PathSummary{}, local.Skipped...), remoteSkipped...))
			pendingCount := pendingPathCount(deferred, allSkipped)
			return e.status.write(func(status *Status) {
				status.State = stateForResult(allSkipped, conflicts, pendingCount, "healthy")
				status.LastSuccessfulAt = &success
				status.RemoteCommit = strings.TrimSpace(commit)
				status.PendingPathCount = pendingCount
				status.Skipped, status.Conflicts = allSkipped, conflicts
			})
		}
		if err := e.git(ctx, "config", "user.name", e.cfg.AuthorName); err != nil {
			return err
		}
		if err := e.git(ctx, "config", "user.email", e.cfg.AuthorMail); err != nil {
			return err
		}
		allSkipped := uniqueSummaries(append(append([]PathSummary{}, local.Skipped...), remoteSkipped...))
		message := commitMessage(e.cfg.ProjectID, operation, staged, allSkipped, append(newConflicts, pendingConflicts...))
		if err := e.git(ctx, "commit", "-m", message); err != nil {
			return err
		}
		if err := e.git(ctx, "push", "origin", "HEAD:"+e.cfg.Branch); err != nil {
			if attempt+1 < policy.RetryLimit {
				continue
			}
			e.recordSyncError("push_failed", err)
			return err
		}
		e.lastPush = e.cfg.Now()
		canonical, err := takeSnapshot(e.repo, policy)
		if err != nil {
			return err
		}
		if err := e.writeBaseline(mergeBaseline(baseline, canonical.Files, local.Files, selected, attemptProtected)); err != nil {
			return err
		}
		conflicts, err := e.statusConflicts(pendingConflicts)
		if err != nil {
			return err
		}
		commit, _ := e.gitOutput(ctx, "rev-parse", "HEAD")
		success := e.cfg.Now()
		pendingCount := pendingPathCount(deferred, allSkipped)
		return e.status.write(func(status *Status) {
			status.State = stateForResult(allSkipped, conflicts, pendingCount, "healthy")
			status.LastSuccessfulAt = &success
			status.RemoteCommit = strings.TrimSpace(commit)
			status.PendingPathCount = pendingCount
			status.Skipped, status.Conflicts = allSkipped, conflicts
		})
	}
	return errors.New("config sync retry limit reached")
}

func (e *Engine) restoreEncrypted(ctx context.Context) error {
	if err := e.ensureRepository(ctx); err != nil {
		e.recordError("restore_failed", err)
		return err
	}
	if err := validateEncryptedRepository(e.repo); err != nil {
		e.recordError("legacy_repository_format", err)
		return err
	}
	if err := e.ensurePolicyManifest(ctx); err != nil {
		e.recordError("manifest_update_failed", err)
		return err
	}
	policy, err := e.cfg.Policy.WithManifest(e.repo)
	if err != nil {
		e.recordError("manifest_invalid", err)
		return err
	}
	e.cfg.Policy = policy
	e.status.last.MaxFileBytes, e.status.last.MaxBatchBytes = policy.MaxFileBytes, policy.MaxBatchBytes
	format, err := readEncryptedRepositoryFormat(e.repo)
	if err != nil {
		return err
	}
	if format.KeyVersion > e.cfg.AgeKeyVersion {
		return errors.New("repository encryption key version is newer than the VM identity")
	}
	if err := e.chezmoi.applyRestricted(ctx); err != nil {
		e.recordError("restore_failed", err)
		return err
	}
	local, err := takeSnapshot(e.cfg.Home, e.cfg.Policy)
	if err != nil {
		e.recordError("snapshot_failed", err)
		return err
	}
	baseline := local.Files
	if format.KeyVersion < e.cfg.AgeKeyVersion {
		baseline = map[string]fileState{}
	}
	if err := e.writeBaseline(baseline); err != nil {
		return err
	}
	now := e.cfg.Now()
	commit, _ := e.gitOutput(ctx, "rev-parse", "HEAD")
	return e.status.write(func(status *Status) {
		status.State = "healthy"
		status.LastSuccessfulAt = &now
		status.RemoteCommit = strings.TrimSpace(commit)
		status.PendingPathCount = 0
		status.Skipped = local.Skipped
		status.Conflicts = nil
		status.EncryptionKeyVersion = format.KeyVersion
	})
}

var errEncryptedPushRetry = errors.New("encrypted config push requires reconciliation")

func (e *Engine) syncEncryptedLocked(ctx context.Context, operation string) error {
	for attempt := 0; attempt < e.cfg.Policy.RetryLimit; attempt++ {
		err := e.syncEncryptedOnce(ctx, operation)
		if !errors.Is(err, errEncryptedPushRetry) {
			return err
		}
	}
	err := errors.New("encrypted config push retry limit reached")
	e.recordSyncError("push_failed", err)
	return err
}

func (e *Engine) syncEncryptedOnce(ctx context.Context, operation string) error {
	now := e.cfg.Now()
	if err := e.status.write(func(status *Status) {
		status.State = "syncing"
		status.LastAttemptAt = &now
		status.ErrorCode = ""
		status.ErrorMessage = ""
	}); err != nil {
		return err
	}
	if e.cfg.RepoURL == "" {
		return e.recordNoRepository()
	}
	if err := e.ensureRepository(ctx); err != nil {
		e.recordSyncError("network_error", err)
		return err
	}
	if err := validateEncryptedRepository(e.repo); err != nil {
		e.recordError("legacy_repository_format", err)
		return err
	}
	if err := e.ensurePolicyManifest(ctx); err != nil {
		e.recordSyncError("manifest_update_failed", err)
		return err
	}
	policy, err := e.cfg.Policy.WithManifest(e.repo)
	if err != nil {
		e.recordError("manifest_invalid", err)
		return err
	}
	e.cfg.Policy = policy
	e.status.last.MaxFileBytes, e.status.last.MaxBatchBytes = policy.MaxFileBytes, policy.MaxBatchBytes
	local, err := takeSnapshot(e.cfg.Home, e.cfg.Policy)
	if err != nil {
		e.recordError("snapshot_failed", err)
		return err
	}
	baseline, err := e.readBaseline()
	if err != nil {
		return err
	}
	changed := changedPaths(baseline, local.Files, local.Skipped)
	classification, err := e.classifier.classify(ctx, local, changed)
	if err != nil {
		e.recordSyncError("classification_failed", err)
		return err
	}
	for _, result := range classification.Results {
		switch result.Decision {
		case "portable":
		case "exclude", "project_only":
			delete(local.Files, result.Path)
		default:
			if previous, ok := baseline[result.Path]; ok {
				local.Files[result.Path] = previous
			} else {
				delete(local.Files, result.Path)
			}
		}
	}
	changed = changedPaths(baseline, local.Files, local.Skipped)
	e.status.last.ClassifierPending = classification.Pending
	e.status.last.ClassifierPolicyRevision = classification.PolicyRevision
	e.status.last.ClassifierModelRevision = classification.ModelRevision
	e.status.last.ClassifierHealth = classification.Health
	format, err := readEncryptedRepositoryFormat(e.repo)
	if err != nil {
		return err
	}
	if format.KeyVersion > e.cfg.AgeKeyVersion {
		return errors.New("repository encryption key version is newer than the VM identity")
	}
	remoteHome, err := os.MkdirTemp(filepath.Join(e.cfg.RuntimeDir, "config-sync"), "remote-home-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(remoteHome)
	remoteSource, err := newChezmoiSource(e.cfg.ChezmoiBinary, filepath.Join(remoteHome, "runtime"), e.repo, remoteHome, e.cfg.AgeIdentityPath, e.cfg.AgeRecipient)
	if err != nil {
		return err
	}
	if err := remoteSource.applyRestricted(ctx); err != nil {
		return err
	}
	remote, err := takeSnapshot(remoteHome, e.cfg.Policy)
	if err != nil {
		return err
	}
	remoteChanged := toSet(changedPaths(baseline, remote.Files, remote.Skipped))
	conflicts := make([]PathSummary, 0)
	for _, rel := range append([]string{}, changed...) {
		if _, ok := remoteChanged[rel]; !ok || equalState(remote.Files[rel], local.Files[rel]) {
			continue
		}
		summary := PathSummary{Path: rel, Reason: "concurrent_update"}
		if state, exists := remote.Files[rel]; exists {
			conflictRel, conflictState, preserveErr := e.preserveEncryptedConflict(remoteHome, rel, state)
			if preserveErr != nil {
				return preserveErr
			}
			local.Files[conflictRel] = conflictState
			changed = append(changed, conflictRel)
			summary.Bytes = state.Bytes
		}
		conflicts = append(conflicts, summary)
	}
	e.status.last.Conflicts = uniqueSummaries(append(e.status.last.Conflicts, conflicts...))
	selected, deferred := selectBatch(changed, local.Files, nil, e.cfg.Policy.MaxBatchBytes)
	for _, rel := range deferred {
		if previous, ok := baseline[rel]; ok {
			local.Files[rel] = previous
		} else {
			delete(local.Files, rel)
		}
	}
	changed = selected
	e.status.last.PendingPathCount = len(classification.Pending) + len(deferred)
	markerChanged := false
	if format.KeyVersion < e.cfg.AgeKeyVersion {
		format.KeyVersion = e.cfg.AgeKeyVersion
		format.Recipient = e.cfg.AgeRecipient
		if err := writeEncryptedRepositoryFormat(e.repo, format); err != nil {
			return err
		}
		markerChanged = true
	}
	if len(changed) == 0 && !markerChanged {
		if err := e.chezmoi.applyRestricted(ctx); err != nil {
			e.recordSyncError("restore_failed", err)
			return err
		}
		return e.recordEncryptedSuccess(ctx, local, baseline, operation)
	}
	updates := make([]string, 0, len(changed))
	deletions := make([]string, 0)
	for _, rel := range changed {
		if _, ok := local.Files[rel]; ok {
			updates = append(updates, rel)
		} else {
			deletions = append(deletions, rel)
		}
	}
	if err := e.chezmoi.addEncrypted(ctx, updates); err != nil {
		e.recordSyncError("encrypt_failed", err)
		return err
	}
	for _, rel := range deletions {
		if err := e.chezmoi.forget(ctx, rel); err != nil {
			e.recordSyncError("delete_failed", err)
			return err
		}
		_ = removeState(e.cfg.Home, rel)
	}
	if err := e.chezmoi.applyRestricted(ctx); err != nil {
		e.recordSyncError("restore_failed", err)
		return err
	}
	if err := e.git(ctx, "add", "-A"); err != nil {
		return err
	}
	if err := e.verifyStagedBlobs(ctx, e.cfg.Policy.MaxFileBytes, e.cfg.Policy.MaxBatchBytes); err != nil {
		e.recordSyncError("size_limit", err)
		return err
	}
	staged, err := e.stagedPaths(ctx)
	if err != nil {
		return err
	}
	if len(staged) == 0 {
		return e.recordEncryptedSuccess(ctx, local, baseline, operation)
	}
	if err := e.git(ctx, "config", "user.name", e.cfg.AuthorName); err != nil {
		return err
	}
	if err := e.git(ctx, "config", "user.email", e.cfg.AuthorMail); err != nil {
		return err
	}
	if err := e.git(ctx, "commit", "-m", commitMessage(e.cfg.ProjectID, operation, staged, local.Skipped, conflicts)); err != nil {
		return err
	}
	if err := e.git(ctx, "push", "origin", "HEAD:"+e.cfg.Branch); err != nil {
		return errEncryptedPushRetry
	}
	e.lastPush = e.cfg.Now()
	return e.recordEncryptedSuccess(ctx, local, local.Files, operation)
}

func (e *Engine) recordEncryptedSuccess(ctx context.Context, local snapshot, baseline map[string]fileState, operation string) error {
	_ = operation
	if err := e.writeBaseline(local.Files); err != nil {
		return err
	}
	commit, _ := e.gitOutput(ctx, "rev-parse", "HEAD")
	success := e.cfg.Now()
	return e.status.write(func(status *Status) {
		status.State = stateForResult(local.Skipped, status.Conflicts, status.PendingPathCount, "healthy")
		status.LastSuccessfulAt = &success
		status.RemoteCommit = strings.TrimSpace(commit)
		status.EncryptionKeyVersion = e.cfg.AgeKeyVersion
		status.Skipped = local.Skipped
	})
}

func (e *Engine) preserveEncryptedConflict(remoteHome, rel string, state fileState) (string, fileState, error) {
	safeProject := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(e.cfg.ProjectID)
	conflictRel := filepath.ToSlash(filepath.Join(".paperboat-conflicts", safeProject, fmt.Sprintf("%s.remote-%d", filepath.FromSlash(rel), e.cfg.Now().UnixNano())))
	destination := filepath.Join(e.cfg.Home, filepath.FromSlash(conflictRel))
	source := filepath.Join(remoteHome, filepath.FromSlash(rel))
	if err := copyStatePath(source, destination, e.cfg.Home, conflictRel, state); err != nil {
		return "", fileState{}, err
	}
	info, err := os.Lstat(destination)
	if err != nil {
		return "", fileState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return conflictRel, fileState{Mode: os.ModeSymlink, Target: state.Target, Bytes: state.Bytes, Hash: state.Hash}, nil
	}
	copied, stable, err := readStable(destination, info)
	if err != nil || !stable {
		return "", fileState{}, errors.Join(err, errSourceChanged)
	}
	return conflictRel, copied, nil
}

func (e *Engine) exclusive(fn func() error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	lockPath := filepath.Join(e.cfg.RuntimeDir, "config-sync", "sync.lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return fn()
}

func (e *Engine) ensureRepository(ctx context.Context) error {
	if _, err := os.Stat(filepath.Join(e.repo, ".git")); err == nil {
		return e.resetToRemote(ctx)
	}
	_ = os.RemoveAll(e.repo)
	if err := os.MkdirAll(filepath.Dir(e.repo), 0o700); err != nil {
		return err
	}
	if err := cloneRepository(ctx, e.cfg.RepoURL, e.cfg.Branch, e.repo, true, e.cfg.GitToken); err == nil {
		return nil
	}
	_ = os.RemoveAll(e.repo)
	if err := cloneRepository(ctx, e.cfg.RepoURL, e.cfg.Branch, e.repo, false, e.cfg.GitToken); err != nil {
		return err
	}
	return e.ensureLocalBranch(ctx)
}

func (e *Engine) resetToRemote(ctx context.Context) error {
	exists, err := e.remoteBranchExists(ctx)
	if err != nil {
		return err
	}
	if !exists {
		if err := e.ensureLocalBranch(ctx); err != nil {
			return err
		}
		return e.git(ctx, "clean", "-fdx")
	}
	refspec := "+refs/heads/" + e.cfg.Branch + ":refs/remotes/origin/" + e.cfg.Branch
	if err := e.git(ctx, "fetch", "--prune", "origin", refspec); err != nil {
		return err
	}
	if err := e.git(ctx, "reset", "--hard", "origin/"+e.cfg.Branch); err != nil {
		return err
	}
	return e.git(ctx, "clean", "-fdx")
}

func cloneRepository(ctx context.Context, repoURL, branch, destination string, branchOnly bool, gitToken string) error {
	args := []string{"clone"}
	if branchOnly {
		args = append(args, "--single-branch", "--branch", branch)
	}
	args = append(args, repoURL, destination)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = gitEnv(gitToken)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("clone config repository: %s", sanitizeMessage(string(output)))
	}
	return nil
}

func (e *Engine) remoteBranchExists(ctx context.Context) (bool, error) {
	output, err := e.gitOutput(ctx, "ls-remote", "--heads", "origin", "refs/heads/"+e.cfg.Branch)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(output) != "", nil
}

func (e *Engine) ensureLocalBranch(ctx context.Context) error {
	current, _ := e.gitOutput(ctx, "branch", "--show-current")
	if strings.TrimSpace(current) == e.cfg.Branch {
		return nil
	}
	if _, err := e.gitOutput(ctx, "rev-parse", "--verify", "HEAD"); err == nil {
		return e.git(ctx, "checkout", "-B", e.cfg.Branch)
	}
	return e.git(ctx, "checkout", "--orphan", e.cfg.Branch)
}

func (e *Engine) ensurePolicyManifest(ctx context.Context) error {
	for attempt := 0; attempt < e.cfg.Policy.RetryLimit; attempt++ {
		if err := e.resetToRemote(ctx); err != nil {
			return err
		}
		changed, err := e.cfg.Policy.EnsureManifest(e.repo)
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
		if err := e.git(ctx, "add", "--", manifestPath); err != nil {
			return err
		}
		staged, err := e.gitOutput(ctx, "diff", "--cached", "--quiet", "--", manifestPath)
		if err == nil && strings.TrimSpace(staged) == "" {
			return nil
		}
		if err := e.git(ctx, "config", "user.name", e.cfg.AuthorName); err != nil {
			return err
		}
		if err := e.git(ctx, "config", "user.email", e.cfg.AuthorMail); err != nil {
			return err
		}
		if err := e.git(ctx, "commit", "-m", fmt.Sprintf("paperboat(%s): update config policy %s", e.cfg.ProjectID, e.cfg.Policy.Revision)); err != nil {
			return err
		}
		if err := e.git(ctx, "push", "origin", "HEAD:"+e.cfg.Branch); err == nil {
			return nil
		} else if attempt+1 == e.cfg.Policy.RetryLimit {
			return err
		}
	}
	return errors.New("config manifest retry limit reached")
}

func (e *Engine) git(ctx context.Context, args ...string) error {
	_, err := e.gitOutput(ctx, args...)
	return err
}

func (e *Engine) gitOutput(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", e.repo}, args...)...)
	cmd.Env = gitEnv(e.cfg.GitToken)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %s", args[0], sanitizeMessage(string(output)))
	}
	return string(output), nil
}

func gitEnv(token string) []string {
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if token == "" {
		return env
	}
	credential := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return append(env,
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
		"GIT_CONFIG_VALUE_0=Authorization: Basic "+credential,
	)
}

func (e *Engine) verifyStagedBlobs(ctx context.Context, maxFile, maxBatch int64) error {
	paths, err := e.stagedPaths(ctx, "--diff-filter=ACMR")
	if err != nil {
		return err
	}
	headObjects, err := e.headObjectIDs(ctx)
	if err != nil {
		return err
	}
	counted := make(map[string]struct{}, len(paths))
	var total int64
	for _, path := range paths {
		object, err := e.gitOutput(ctx, "rev-parse", ":"+path)
		if err != nil {
			return err
		}
		sizeText, err := e.gitOutput(ctx, "cat-file", "-s", strings.TrimSpace(object))
		if err != nil {
			return err
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeText), 10, 64)
		if err != nil {
			return err
		}
		if size > maxFile && !controlMetadataPath(path) {
			return fmt.Errorf("staged file exceeds max_file_bytes: %s", path)
		}
		if controlMetadataPath(path) {
			continue
		}
		object = strings.TrimSpace(object)
		if _, exists := headObjects[object]; exists {
			continue
		}
		if _, exists := counted[object]; exists {
			continue
		}
		counted[object] = struct{}{}
		total += size
	}
	if total > maxBatch {
		return fmt.Errorf("staged data exceeds max_batch_bytes")
	}
	return nil
}

func (e *Engine) headObjectIDs(ctx context.Context) (map[string]struct{}, error) {
	objects := map[string]struct{}{}
	output, err := e.gitOutput(ctx, "rev-list", "--objects", "HEAD")
	if err != nil {
		if strings.Contains(err.Error(), "unknown revision") || strings.Contains(err.Error(), "bad revision") {
			return objects, nil
		}
		return nil, err
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			objects[fields[0]] = struct{}{}
		}
	}
	return objects, nil
}

func controlMetadataPath(path string) bool {
	return path == manifestPath || (strings.HasPrefix(path, ".paperboat/conflicts/") && strings.HasSuffix(path, "/"+conflictMetadataName))
}

func (e *Engine) stagedPaths(ctx context.Context, extra ...string) ([]string, error) {
	args := append([]string{"diff", "--cached", "--name-only", "-z"}, extra...)
	output, err := e.gitOutput(ctx, args...)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(output, "\x00")
	paths := make([]string, 0, len(parts))
	for _, path := range parts {
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths, nil
}

func applyChanges(source, destination string, files map[string]fileState, paths []string) error {
	deletions := make([]string, 0)
	updates := make([]string, 0)
	for _, rel := range paths {
		if _, exists := files[rel]; exists {
			updates = append(updates, rel)
		} else {
			deletions = append(deletions, rel)
		}
	}
	sort.Slice(deletions, func(i, j int) bool {
		leftDepth := strings.Count(deletions[i], "/")
		rightDepth := strings.Count(deletions[j], "/")
		if leftDepth == rightDepth {
			return deletions[i] > deletions[j]
		}
		return leftDepth > rightDepth
	})
	sort.Strings(updates)
	for _, rel := range deletions {
		if err := removeState(destination, rel); err != nil {
			return err
		}
	}
	for _, rel := range updates {
		if err := copyState(source, destination, rel, files[rel]); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) statusConflicts(pending []PathSummary) ([]PathSummary, error) {
	preserved, err := conflictSummaries(e.repo)
	if err != nil {
		e.recordError("conflict_metadata_invalid", err)
		return nil, err
	}
	return uniqueSummaries(append(preserved, pending...)), nil
}

func removeState(root, rel string) error {
	if err := validatePattern(rel); err != nil {
		return err
	}
	path := filepath.Join(root, filepath.FromSlash(rel))
	if !sameOrInside(path, root) {
		return errors.New("delete path escaped root")
	}
	if err := validateDestinationParent(root, path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("refusing to replace directory at %q with a deletion", rel)
	}
	return os.Remove(path)
}

func (e *Engine) readBaseline() (map[string]fileState, error) {
	b, err := os.ReadFile(e.baselinePath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]fileState{}, nil
	}
	if err != nil {
		return nil, err
	}
	var states map[string]fileState
	if err := json.Unmarshal(b, &states); err != nil {
		return nil, err
	}
	return states, nil
}

func (e *Engine) writeBaseline(states map[string]fileState) error {
	b, err := json.Marshal(states)
	if err != nil {
		return err
	}
	tmp := e.baselinePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.baselinePath)
}

func (e *Engine) recordError(code string, err error) {
	_ = e.status.write(func(status *Status) {
		status.State = "error"
		status.ErrorCode = code
		status.ErrorMessage = err.Error()
	})
}

func (e *Engine) recordSyncError(code string, syncErr error) {
	pending := e.status.last.PendingPathCount
	skipped := e.status.last.Skipped
	if local, err := takeSnapshot(e.cfg.Home, e.cfg.Policy); err == nil {
		if baseline, err := e.readBaseline(); err == nil {
			pending = len(changedPaths(baseline, local.Files, local.Skipped)) + len(local.Skipped)
			skipped = local.Skipped
		}
	}
	_ = e.status.write(func(status *Status) {
		status.State = "error"
		status.ErrorCode = code
		status.ErrorMessage = syncErr.Error()
		status.PendingPathCount = pending
		status.Skipped = skipped
	})
}

func (e *Engine) hasFlushablePending() (bool, error) {
	if e.cfg.RepoURL == "" {
		return false, nil
	}
	local, err := takeSnapshot(e.cfg.Home, e.cfg.Policy)
	if err != nil {
		return false, err
	}
	for _, item := range local.Skipped {
		if item.Reason == "file_changing" {
			return true, nil
		}
	}
	baseline, err := e.readBaseline()
	if err != nil {
		return false, err
	}
	return len(changedPaths(baseline, local.Files, local.Skipped)) > 0, nil
}

func (e *Engine) recordNoRepository() error {
	return e.status.write(func(status *Status) {
		status.State = "healthy"
		status.PendingPathCount = 0
		status.Skipped = nil
		status.Conflicts = nil
		status.ErrorCode, status.ErrorMessage = "", ""
	})
}

func changedPaths(baseline, current map[string]fileState, skipped []PathSummary) []string {
	skippedSet := map[string]struct{}{}
	for _, item := range skipped {
		skippedSet[item.Path] = struct{}{}
	}
	all := map[string]struct{}{}
	for rel := range baseline {
		all[rel] = struct{}{}
	}
	for rel := range current {
		all[rel] = struct{}{}
	}
	changed := make([]string, 0)
	for rel := range all {
		if _, skip := skippedSet[rel]; skip {
			continue
		}
		if !equalState(baseline[rel], current[rel]) {
			changed = append(changed, rel)
		}
	}
	sort.Strings(changed)
	return changed
}

func equalState(left, right fileState) bool {
	return left.Hash == right.Hash && left.Mode == right.Mode && left.Target == right.Target
}

func selectBatch(paths []string, files map[string]fileState, extraBytes map[string]int64, max int64) ([]string, []string) {
	var selected, deferred []string
	var total int64
	for _, rel := range paths {
		size := files[rel].Bytes + extraBytes[rel]
		if total+size > max {
			deferred = append(deferred, rel)
			continue
		}
		selected = append(selected, rel)
		total += size
	}
	return selected, deferred
}

func sortedKeys(values map[string]fileState) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func toSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func summaryPathSet(values []PathSummary) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value.Path] = struct{}{}
	}
	return out
}

func remoteSkippedSummaries(values []PathSummary) []PathSummary {
	out := make([]PathSummary, 0, len(values))
	for _, value := range values {
		value.Reason = "remote_" + value.Reason
		out = append(out, value)
	}
	return out
}

func pendingPathCount(paths []string, summaries []PathSummary) int {
	uniquePaths := toSet(paths)
	for _, summary := range summaries {
		uniquePaths[summary.Path] = struct{}{}
	}
	return len(uniquePaths)
}

func mergeBaseline(baseline, remote, local map[string]fileState, selected, protected []string) map[string]fileState {
	out := map[string]fileState{}
	for path, state := range remote {
		out[path] = state
	}
	selectedSet := toSet(selected)
	for _, path := range protected {
		if _, selected := selectedSet[path]; selected {
			continue
		}
		if state, ok := baseline[path]; ok {
			out[path] = state
		} else {
			delete(out, path)
		}
	}
	for _, path := range selected {
		if state, ok := local[path]; ok {
			out[path] = state
		} else {
			delete(out, path)
		}
	}
	return out
}

func stateForSummaries(skipped, conflicts []PathSummary) string {
	return stateForResult(skipped, conflicts, 0, "healthy")
}

func stateForResult(skipped, conflicts []PathSummary, pending int, fallback string) string {
	if len(conflicts) > 0 {
		return "conflict"
	}
	if len(skipped) > 0 {
		return "warning"
	}
	if pending > 0 {
		return "pending"
	}
	return fallback
}

func commitMessage(projectID, operation string, changed []string, skipped, conflicts []PathSummary) string {
	summary := changed
	if len(summary) > 8 {
		summary = append(summary[:8], fmt.Sprintf("+%d more", len(changed)-8))
	}
	message := fmt.Sprintf("paperboat(%s): %s config", projectID, operation)
	if len(summary) > 0 {
		message += " [" + strings.Join(summary, ", ") + "]"
	}
	if len(skipped) > 0 {
		message += fmt.Sprintf(" skipped=%d", len(skipped))
	}
	if len(conflicts) > 0 {
		message += fmt.Sprintf(" conflicts=%d", len(conflicts))
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}
