package orchestrator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

var ErrVolumeResizeRequiresApproval = errors.New("volume resize requires approved Fly resize or replacement policy")
var ErrOrchestrationLeaseLost = errors.New("orchestration job lease lost")

type Service struct {
	repo              *Repository
	fly               fly.Client
	cfg               config.Config
	beforeStop        func(context.Context, string) error
	issueEnrollment   func(context.Context, string, string, string, time.Duration) (string, error)
	ensureHostedRoute func(context.Context, string, string, string, string) error
	verifyReadiness   func(context.Context, string) error
}

// SetBeforeStop configures best-effort work that must happen while a project
// runtime is still reachable. Failures are recorded but never strand a stop.
func (s *Service) SetBeforeStop(fn func(context.Context, string) error) {
	s.beforeStop = fn
}

func (s *Service) SetHostedEnrollmentIssuer(fn func(context.Context, string, string, string, time.Duration) (string, error)) {
	s.issueEnrollment = fn
}

func (s *Service) SetHostedRouteEnsurer(fn func(context.Context, string, string, string, string) error) {
	s.ensureHostedRoute = fn
}

func (s *Service) SetHostedReadinessVerifier(fn func(context.Context, string) error) {
	s.verifyReadiness = fn
}

func NewService(store *db.DB, flyClient fly.Client, cfg config.Config) *Service {
	repo := NewRepository(store, cfg.Secrets.EncryptionKey)
	repo.lease = cfg.Fly.OrchestrationLease
	if repo.lease <= cfg.Fly.OperationTimeout {
		repo.lease = 5 * time.Minute
	}
	return &Service{
		repo: repo,
		fly:  fly.NewTimeoutClient(flyClient, cfg.Fly.OperationTimeout),
		cfg:  cfg,
	}
}

func (s *Service) RunOnce(ctx context.Context) error {
	job, ok, err := s.repo.ClaimNextJob(ctx)
	if err != nil || !ok {
		return err
	}
	ctx = context.WithValue(ctx, orchestrationJobContextKey{}, job.ID)
	err = s.process(ctx, job)
	if err != nil {
		if errors.Is(err, ErrVolumeResizeRequiresApproval) {
			_ = s.repo.BlockJobAndRestoreProject(ctx, job.ID, job.LeaseToken, job.AggregateID, job.PreviousState, err)
			return err
		}
		_ = s.repo.FailJob(ctx, job.ID, job.LeaseToken, err)
		return err
	}
	return s.repo.CompleteJob(ctx, job.ID, job.LeaseToken)
}

func (s *Service) Worker(interval time.Duration) func(context.Context) error {
	if interval <= 0 {
		interval = time.Second
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := s.RunOnce(ctx); err != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func (s *Service) Reconcile(ctx context.Context) (Run, error) {
	run := Run{ID: newID("recon"), Scope: "fly", State: "running"}
	if err := s.repo.StartReconciliation(ctx, run); err != nil {
		return Run{}, err
	}
	findings, err := s.repo.ReconcileFly(ctx, s.fly)
	run.State = "complete"
	if err != nil {
		run.State = "failed"
		findings = append(findings, Finding{Severity: "error", Message: err.Error()})
	}
	run.Findings = findings
	if finishErr := s.repo.FinishReconciliation(ctx, run); finishErr != nil && err == nil {
		err = finishErr
	}
	return run, err
}

func (s *Service) process(ctx context.Context, job Job) error {
	switch job.Type {
	case "project.create":
		return s.provisionProject(ctx, job.AggregateID)
	case "project.start":
		return s.startProject(ctx, job.AggregateID)
	case "project.stop":
		return s.stopProject(ctx, job.AggregateID)
	case "project.restart":
		return s.restartProject(ctx, job.AggregateID)
	case "project.delete":
		return s.deleteProject(ctx, job.AggregateID)
	default:
		return fmt.Errorf("unknown orchestration job type %q", job.Type)
	}
}

func (s *Service) provisionProject(ctx context.Context, projectID string) error {
	intent, err := s.repo.ProjectIntent(ctx, projectID)
	if err != nil {
		return err
	}
	if s.issueEnrollment != nil {
		if ensureErr := s.repo.EnsureHostedControlEnvironment(ctx, intent.ID, intent.UserID); ensureErr != nil {
			return fmt.Errorf("ensure hosted control environment: %w", ensureErr)
		}
		credential, issueErr := s.issueEnrollment(ctx, intent.UserID, "hosted-create:"+intent.ID, intent.ID, 10*time.Minute)
		if issueErr != nil {
			return fmt.Errorf("issue hosted helper enrollment: %w", issueErr)
		}
		intent.EnrollmentCredential = credential
	}
	if s.ensureHostedRoute != nil {
		host := providerName(s.cfg.Providers.Agentunnel.RouteSubdomainPrefix, intent.ID) + "." + strings.Trim(strings.ToLower(s.cfg.HelperBaseDomain), ".")
		if routeErr := s.ensureHostedRoute(ctx, intent.UserID, "hosted-route:"+intent.ID, intent.ID, host); routeErr != nil {
			return fmt.Errorf("ensure hosted helper route: %w", routeErr)
		}
	}
	volume, err := s.ensureVolume(ctx, intent)
	if err != nil {
		return err
	}
	if _, err := s.ensureMachine(ctx, intent, volume.FlyVolumeID); err != nil {
		return err
	}
	return s.repo.MarkProvisionedStopped(ctx, intent)
}

func (s *Service) startProject(ctx context.Context, projectID string) error {
	machine, err := s.repo.ProjectMachine(ctx, projectID)
	if err != nil {
		return err
	}
	if err := s.reconcileMachineSpecDrift(ctx, projectID, machine.FlyMachineID); err != nil {
		if !errors.Is(err, fly.ErrNotFound) {
			return err
		}
		if machine, err = s.recreateMissingMachine(ctx, projectID); err != nil {
			return err
		}
	}
	observed, err := s.startMachine(ctx, machine.FlyMachineID)
	if errors.Is(err, fly.ErrNotFound) {
		if machine, err = s.recreateMissingMachine(ctx, projectID); err != nil {
			return err
		}
		observed, err = s.startMachine(ctx, machine.FlyMachineID)
	}
	if err != nil {
		return err
	}
	if s.verifyReadiness != nil {
		if err := s.verifyReadiness(ctx, projectID); err != nil {
			if recordErr := s.repo.RecordReadinessFailure(ctx, projectID, err); recordErr != nil {
				return errors.Join(fmt.Errorf("verify hosted helper readiness: %w", err), recordErr)
			}
			return fmt.Errorf("verify hosted helper readiness: %w", err)
		}
		if err := s.repo.RecordReadinessSuccess(ctx, projectID); err != nil {
			return err
		}
	}
	return s.repo.RecordMachineState(ctx, projectID, observed.State, "running")
}

func (s *Service) stopProject(ctx context.Context, projectID string) error {
	machine, err := s.repo.ProjectMachine(ctx, projectID)
	if err != nil {
		return err
	}
	s.snapshotBeforeStop(ctx, projectID)
	observed, err := s.stopMachine(ctx, machine.FlyMachineID)
	if err != nil {
		return err
	}
	observed, err = s.waitMachineState(ctx, machine.FlyMachineID, func(machine fly.Machine) bool { return machine.State == "stopped" })
	if err != nil {
		return err
	}
	return s.repo.RecordMachineState(ctx, projectID, observed.State, "stopped")
}

func (s *Service) restartProject(ctx context.Context, projectID string) error {
	intent, err := s.repo.ProjectIntent(ctx, projectID)
	if err != nil {
		return err
	}
	machine, err := s.repo.ProjectMachine(ctx, projectID)
	if err != nil {
		return err
	}
	volume, err := s.repo.ProjectVolume(ctx, projectID)
	if err != nil {
		return err
	}
	if intent.StorageGB != volume.SizeGB {
		if eventErr := s.repo.RecordProjectEvent(ctx, projectID, "project.resize_blocked", "Pending storage change requires an approved Fly volume resize or replacement policy.", map[string]any{"current_volume_gb": volume.SizeGB, "desired_storage_gb": intent.StorageGB}); eventErr != nil {
			return eventErr
		}
		return ErrVolumeResizeRequiresApproval
	}
	stopStep := "stop_machine:" + machine.FlyMachineID
	stopSucceeded, err := s.repo.ProviderOperationSucceeded(ctx, stopStep)
	if err != nil {
		return err
	}
	recreated := false
	if !stopSucceeded {
		s.snapshotBeforeStop(ctx, projectID)
		_, err = s.stopMachine(ctx, machine.FlyMachineID)
		if err != nil {
			if !errors.Is(err, fly.ErrNotFound) {
				return err
			}
			// The replacement is created stopped with the full desired spec.
			if machine, err = s.recreateMissingMachine(ctx, projectID); err != nil {
				return err
			}
			recreated = true
		} else if _, err = s.waitMachineState(ctx, machine.FlyMachineID, func(machine fly.Machine) bool { return machine.State == "stopped" }); err != nil {
			return err
		}
	}
	if !recreated && intent.PendingRestartApply {
		if _, err := s.updateMachine(ctx, machine.FlyMachineID, s.machineSpec(intent, volume.FlyVolumeID)); err != nil {
			return err
		}
	} else if !recreated {
		if err := s.applyMachineSpecDrift(ctx, intent, machine.FlyMachineID, volume.FlyVolumeID); err != nil {
			return err
		}
	}
	observed, err := s.startMachine(ctx, machine.FlyMachineID)
	if err != nil {
		return err
	}
	if s.verifyReadiness != nil {
		if err := s.verifyReadiness(ctx, projectID); err != nil {
			if recordErr := s.repo.RecordReadinessFailure(ctx, projectID, err); recordErr != nil {
				return errors.Join(fmt.Errorf("verify hosted helper readiness: %w", err), recordErr)
			}
			return fmt.Errorf("verify hosted helper readiness: %w", err)
		}
		if err := s.repo.RecordReadinessSuccess(ctx, projectID); err != nil {
			return err
		}
	}
	if intent.PendingRestartApply {
		if err := s.repo.ApplyRuntimeConfig(ctx, intent); err != nil {
			return err
		}
	}
	return s.repo.RecordMachineState(ctx, projectID, observed.State, "running")
}

func (s *Service) waitMachineState(ctx context.Context, machineID string, ready func(fly.Machine) bool) (fly.Machine, error) {
	timeout := s.cfg.Fly.OperationTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		machine, err := s.fly.GetMachine(waitCtx, machineID)
		if err != nil {
			return fly.Machine{}, err
		}
		if ready(machine) {
			return machine, nil
		}
		select {
		case <-waitCtx.Done():
			return fly.Machine{}, waitCtx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) snapshotBeforeStop(ctx context.Context, projectID string) {
	if s.beforeStop == nil {
		return
	}
	if err := s.beforeStop(ctx, projectID); err != nil {
		slog.Warn("terminal session snapshot failed before project stop", "project_id", projectID, "error", err)
	}
}

func (s *Service) deleteProject(ctx context.Context, projectID string) error {
	if err := s.repo.BeginHostedEnvironmentDelete(ctx, projectID); err != nil {
		return err
	}
	intent, intentErr := s.repo.ProjectIntent(ctx, projectID)
	machine, machineErr := s.repo.ProjectMachine(ctx, projectID)
	if machineErr == nil {
		if _, err := s.stopMachine(ctx, machine.FlyMachineID); err != nil {
			if !errors.Is(err, fly.ErrNotFound) {
				return err
			}
			if err := s.repo.RemoveMachine(ctx, projectID); err != nil {
				return err
			}
		} else {
			if err := s.destroyMachine(ctx, machine.FlyMachineID); err != nil {
				if !errors.Is(err, fly.ErrNotFound) {
					return err
				}
			}
			if err := s.repo.RemoveMachine(ctx, projectID); err != nil {
				return err
			}
		}
	} else if !errors.Is(machineErr, sql.ErrNoRows) {
		return machineErr
	}
	if intentErr == nil {
		if err := s.deleteProviderSecrets(ctx, intent); err != nil {
			return err
		}
	} else if errors.Is(intentErr, secrets.ErrDecrypt) {
		// The project's stored secrets were encrypted under a key that is no
		// longer configured, so we can't read them to clean up provider secrets.
		// Deletion must still complete — otherwise a key change would strand the
		// project (and its storage allocation) in "deleting" forever. The Fly
		// machine and volume are torn down by ID above/below and don't need the
		// decrypted values.
	} else if !errors.Is(intentErr, sql.ErrNoRows) {
		return intentErr
	}
	volume, volumeErr := s.repo.ProjectVolume(ctx, projectID)
	if volumeErr == nil {
		if err := s.destroyVolume(ctx, volume.FlyVolumeID); err != nil {
			if !errors.Is(err, fly.ErrNotFound) {
				return err
			}
		}
		if err := s.repo.RemoveVolume(ctx, projectID); err != nil {
			return err
		}
	} else if !errors.Is(volumeErr, sql.ErrNoRows) {
		return volumeErr
	}
	if err := s.repo.MarkDeletedAndReleaseStorage(ctx, projectID); err != nil {
		return err
	}
	return s.repo.CompleteHostedEnvironmentDelete(ctx, projectID)
}

func (s *Service) ensureVolume(ctx context.Context, intent ProjectIntent) (VolumeRecord, error) {
	if volume, err := s.repo.ProjectVolume(ctx, intent.ID); err == nil {
		return volume, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return VolumeRecord{}, err
	}
	name := providerVolumeName(s.cfg.Fly.VolumeNamePrefix, intent.ID)
	request := struct {
		Name   string            `json:"name"`
		Region string            `json:"region"`
		SizeGB int               `json:"size_gb"`
		Tags   map[string]string `json:"tags"`
	}{Name: name, Region: intent.RegionCode, SizeGB: intent.StorageGB, Tags: resourceTags(intent.ID)}
	if adopted, ok, err := s.findProviderVolume(ctx, name, intent); err != nil || ok {
		if err != nil {
			return VolumeRecord{}, err
		}
		if err := resolveProviderMutationByObservation(ctx, s.repo, "create_volume", "volume", request, ""); err != nil {
			return VolumeRecord{}, err
		}
		return s.repo.RecordVolume(ctx, intent.ID, adopted.ID, intent.StorageGB, intent.RegionCode, adopted.State)
	}
	created, err := executeProviderMutation(ctx, s.repo, "create_volume", "volume", request, func() (fly.Volume, error) {
		return s.fly.CreateVolume(ctx, name, intent.RegionCode, intent.StorageGB, request.Tags)
	})
	if err != nil {
		return VolumeRecord{}, err
	}
	return s.repo.RecordVolume(ctx, intent.ID, created.ID, intent.StorageGB, intent.RegionCode, created.State)
}

func (s *Service) ensureMachine(ctx context.Context, intent ProjectIntent, volumeID string) (MachineRecord, error) {
	if machine, err := s.repo.ProjectMachine(ctx, intent.ID); err == nil {
		return machine, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return MachineRecord{}, err
	}
	spec := s.machineSpec(intent, volumeID)
	if adopted, ok, err := s.findProviderMachine(ctx, spec.Name, intent); err != nil || ok {
		if err != nil {
			return MachineRecord{}, err
		}
		if err := resolveProviderMutationByObservation(ctx, s.repo, "create_machine", "machine", spec, ""); err != nil {
			return MachineRecord{}, err
		}
		return s.repo.RecordMachine(ctx, intent.ID, adopted.ID, adopted.State, s.cfg.Fly.ImageRef, intent.RegionCode, intent.DesiredConfigHash)
	}
	created, err := executeProviderMutation(ctx, s.repo, "create_machine", "machine", spec, func() (fly.Machine, error) {
		return s.fly.CreateMachine(ctx, spec)
	})
	if err != nil {
		return MachineRecord{}, err
	}
	return s.repo.RecordMachine(ctx, intent.ID, created.ID, created.State, s.cfg.Fly.ImageRef, intent.RegionCode, intent.DesiredConfigHash)
}

func (s *Service) findProviderVolume(ctx context.Context, name string, intent ProjectIntent) (fly.Volume, bool, error) {
	volumes, err := s.fly.ListVolumes(ctx)
	if err != nil {
		return fly.Volume{}, false, err
	}
	for _, volume := range volumes {
		if volume.Name == name && volume.Region == intent.RegionCode && volume.SizeGB == intent.StorageGB {
			return volume, true, nil
		}
	}
	return fly.Volume{}, false, nil
}

func (s *Service) findProviderMachine(ctx context.Context, name string, intent ProjectIntent) (fly.Machine, bool, error) {
	machines, err := s.fly.ListMachines(ctx, resourceTags(intent.ID))
	if err != nil {
		return fly.Machine{}, false, err
	}
	for _, machine := range machines {
		if machine.Name == name && machine.Tags["paperboat_project_id"] == intent.ID && machine.Tags["managed_by"] == "paperboat-server" {
			return machine, true, nil
		}
	}
	return fly.Machine{}, false, nil
}

func (s *Service) machineSpec(intent ProjectIntent, volumeID string) fly.MachineSpec {
	machineName := providerName(s.cfg.Fly.MachineNamePrefix, intent.ID)
	flushSeconds := durationSecondsCeil(s.cfg.ConfigSync.ShutdownFlushTimeout)
	graceSeconds := durationSecondsCeil(s.cfg.ConfigSync.ShutdownGracePeriod)
	reportSeconds := durationSecondsCeil(s.cfg.ConfigSync.ShutdownReportTimeout)
	env := map[string]string{
		"PAPERBOAT_HELPER_PROFILE":                   "hosted",
		"PAPERBOAT_HELPER_STATE_ROOT":                "/workspace/.paperboat/helper",
		"PAPERBOAT_HELPER_LISTEN_ADDRESS":            "127.0.0.1:8080",
		"PAPERBOAT_CONTROL_URL":                      strings.TrimRight(s.cfg.HTTP.PublicBaseURL, "/"),
		"PAPERBOAT_CONTROL_ISSUER":                   config.NormalizeIssuer(s.cfg.HTTP.PublicBaseURL),
		"PAPERBOAT_ENROLLMENT_CREDENTIAL_ENV":        s.cfg.Fly.EnrollmentSecret,
		"PAPERBOAT_PROJECT_ID":                       intent.ID,
		"PAPERBOAT_MACHINE_ID":                       machineName,
		"PAPERBOAT_REPOSITORY_URL":                   intent.RepositoryURL,
		"PAPERBOAT_DEFAULT_BRANCH":                   intent.DefaultBranch,
		"PAPERBOAT_PRESET_CODES":                     strings.Join(intent.PresetCodes, ","),
		"PAPERBOAT_IDLE_TIMEOUT_CODE":                intent.IdleTimeoutCode,
		"PAPERBOAT_GITHUB_TOKEN_ENV":                 s.cfg.Fly.GitHubSecret,
		"PAPERBOAT_SETUP_SCRIPT_REF":                 intent.SetupScriptRef,
		"PAPERBOAT_SETUP_SCRIPT_ENV":                 s.cfg.Fly.SetupScriptSecret,
		"PAPERBOAT_DESIRED_CONFIG_SHA":               intent.DesiredConfigHash,
		"PAPERBOAT_ACTIVITY_ENDPOINT":                strings.TrimRight(s.cfg.HTTP.PublicBaseURL, "/") + "/api/machine/activity-heartbeat",
		"PAPERBOAT_CONFIG_HOME":                      s.cfg.ConfigSync.HomeOverride,
		"PAPERBOAT_CONFIG_INCLUDES":                  strings.Join(s.cfg.ConfigSync.Includes, ","),
		"PAPERBOAT_CONFIG_EXCLUDES":                  strings.Join(s.cfg.ConfigSync.Excludes, ","),
		"PAPERBOAT_CONFIG_MANDATORY_EXCLUDES":        strings.Join(s.cfg.ConfigSync.MandatoryExcludes, ","),
		"PAPERBOAT_CONFIG_MAX_FILE_BYTES":            fmt.Sprint(s.cfg.ConfigSync.MaxFileBytes),
		"PAPERBOAT_CONFIG_MAX_BATCH_BYTES":           fmt.Sprint(s.cfg.ConfigSync.MaxBatchBytes),
		"PAPERBOAT_CONFIG_DEBOUNCE_SECONDS":          fmt.Sprint(int64(s.cfg.ConfigSync.Debounce / time.Second)),
		"PAPERBOAT_CONFIG_MIN_PUSH_INTERVAL_SECONDS": fmt.Sprint(int64(s.cfg.ConfigSync.MinPushInterval / time.Second)),
		"PAPERBOAT_CONFIG_MAX_DIRTY_DELAY_SECONDS":   fmt.Sprint(int64(s.cfg.ConfigSync.MaxDirtyDelay / time.Second)),
		"PAPERBOAT_CONFIG_REMOTE_POLL_SECONDS":       fmt.Sprint(int64(s.cfg.ConfigSync.RemotePollInterval / time.Second)),
		"PAPERBOAT_CONFIG_RETRY_LIMIT":               fmt.Sprint(s.cfg.ConfigSync.RetryLimit),
		"PAPERBOAT_CONFIG_SHUTDOWN_DEADLINE_SECONDS": fmt.Sprint(flushSeconds),
		"PAPERBOAT_CONFIG_SHUTDOWN_GRACE_SECONDS":    fmt.Sprint(graceSeconds),
		"PAPERBOAT_ACTIVITY_SHUTDOWN_REPORT_SECONDS": fmt.Sprint(reportSeconds),
		"PAPERBOAT_CONFIG_SUMMARY_LIMIT":             fmt.Sprint(s.cfg.ConfigSync.SummaryLimit),
		"PAPERBOAT_CONFIG_POLICY_REVISION":           s.cfg.ConfigSync.PolicyRevision,
		"PAPERBOAT_CONFIG_AGE_RECIPIENT":             intent.ConfigAgeRecipient,
		"PAPERBOAT_CONFIG_AGE_KEY_VERSION":           fmt.Sprint(intent.ConfigAgeVersion),
		"PAPERBOAT_CONFIG_REQUIRE_ENCRYPTION":        "1",
		"PAPERBOAT_CONFIG_AGE_IDENTITY_FILE":         "/var/lib/paperboat/config-age-identity.txt",
		"PAPERBOAT_CONFIG_CLASSIFY_ENDPOINT":         strings.TrimRight(s.cfg.HTTP.PublicBaseURL, "/") + "/api/machine/config-sync/classify",
	}
	if strings.TrimSpace(intent.GitHubConfigRepoURL) != "" {
		env["PAPERBOAT_CONFIG_REPO_URL"] = intent.GitHubConfigRepoURL
	}
	if strings.TrimSpace(intent.GitHubConfigRepoBranch) != "" {
		env["PAPERBOAT_CONFIG_REPO_BRANCH"] = intent.GitHubConfigRepoBranch
	}
	spec := fly.MachineSpec{
		Name:        machineName,
		Hostname:    s.cfg.Fly.Hostname,
		ImageRef:    s.cfg.Fly.ImageRef,
		Region:      intent.RegionCode,
		Size:        fly.MachineSize{VCPU: intent.VCPU, MemoryMB: intent.MemoryMB},
		VolumeID:    volumeID,
		MountPath:   s.cfg.Fly.MountPath,
		Env:         env,
		Secrets:     s.projectSecrets(intent),
		Command:     s.cfg.Fly.BootCommand,
		StopTimeout: time.Duration(flushSeconds+graceSeconds+reportSeconds) * time.Second,
		ConfigHash:  intent.DesiredConfigHash,
		Tags:        resourceTags(intent.ID),
	}
	spec.Tags[specHashTag] = s.machineSpecHash(spec)
	return spec
}

func durationSecondsCeil(value time.Duration) int64 {
	return int64((value + time.Second - 1) / time.Second)
}

// specHashTag is machine metadata carrying a digest of the full rendered
// machine spec, so drift introduced by server-side settings (hostname, image,
// boot command, env) is detectable against the live Fly machine even when the
// project's own desired config is unchanged.
const specHashTag = "paperboat_spec_hash"

func (s *Service) machineSpecHash(spec fly.MachineSpec) string {
	secretRefs := make([]string, 0, len(spec.Secrets))
	for _, secret := range spec.Secrets {
		ref := secret.EnvVar + "=" + secret.Name
		if secret.EnvVar != s.cfg.Fly.EnrollmentSecret {
			valueHash := sha256.Sum256([]byte(secret.Value))
			ref += ":" + hex.EncodeToString(valueHash[:])
		}
		secretRefs = append(secretRefs, ref)
	}
	sort.Strings(secretRefs)
	payload, _ := json.Marshal(map[string]any{
		"name":         spec.Name,
		"hostname":     spec.Hostname,
		"image_ref":    spec.ImageRef,
		"region":       spec.Region,
		"vcpu":         spec.Size.VCPU,
		"memory_mb":    spec.Size.MemoryMB,
		"volume_id":    spec.VolumeID,
		"mount_path":   spec.MountPath,
		"env":          spec.Env,
		"command":      spec.Command,
		"stop_timeout": spec.StopTimeout.String(),
		"secret_refs":  secretRefs,
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// reconcileMachineSpecDrift loads the project's applied intent and syncs the
// machine config when the rendered spec no longer matches what is on the
// machine. Pending project changes are excluded: those apply on restart only.
func (s *Service) reconcileMachineSpecDrift(ctx context.Context, projectID, machineID string) error {
	intent, err := s.repo.ProjectIntent(ctx, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if intent.PendingRestartApply {
		return nil
	}
	volume, err := s.repo.ProjectVolume(ctx, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	return s.applyMachineSpecDrift(ctx, intent, machineID, volume.FlyVolumeID)
}

// recreateMissingMachine self-heals a project whose Fly machine was destroyed
// out-of-band (host failure, manual deletion): the stale record is dropped and
// a replacement is created against the project's existing volume, so the
// workspace — including the cloned repository — is preserved.
func (s *Service) recreateMissingMachine(ctx context.Context, projectID string) (MachineRecord, error) {
	intent, err := s.repo.ProjectIntent(ctx, projectID)
	if err != nil {
		return MachineRecord{}, err
	}
	volume, err := s.repo.ProjectVolume(ctx, projectID)
	if err != nil {
		return MachineRecord{}, err
	}
	if err := s.repo.RemoveMachine(ctx, projectID); err != nil {
		return MachineRecord{}, err
	}
	machine, err := s.ensureMachine(ctx, intent, volume.FlyVolumeID)
	if err != nil {
		return MachineRecord{}, err
	}
	if err := s.repo.RecordProjectEvent(ctx, projectID, "project.machine_recreated", "Project machine was missing at the provider and was recreated on the existing volume.", map[string]any{"fly_machine_id": machine.FlyMachineID}); err != nil {
		return MachineRecord{}, err
	}
	return machine, nil
}

func (s *Service) applyMachineSpecDrift(ctx context.Context, intent ProjectIntent, machineID, volumeID string) error {
	spec := s.machineSpec(intent, volumeID)
	observed, err := s.fly.GetMachine(ctx, machineID)
	if err != nil {
		return err
	}
	if observed.Tags[specHashTag] == spec.Tags[specHashTag] {
		return nil
	}
	if _, err := s.updateMachine(ctx, machineID, spec); err != nil {
		return err
	}
	return s.repo.RecordProjectEvent(ctx, intent.ID, "project.machine_spec_drift_applied", "Machine configuration was updated to match the current project settings.", map[string]any{"severity": "info", "spec_hash": spec.Tags[specHashTag]})
}

func (s *Service) startMachine(ctx context.Context, machineID string) (fly.Machine, error) {
	request := struct {
		MachineID string `json:"machine_id"`
		Target    string `json:"target"`
	}{MachineID: machineID, Target: "running"}
	return executeMachineMutation(ctx, s.repo, s.fly, "start_machine:"+machineID, request, machineID, func(machine fly.Machine) bool {
		return machine.State == "running" || machine.State == "started"
	}, func() (fly.Machine, error) { return s.fly.StartMachine(ctx, machineID) })
}

func (s *Service) stopMachine(ctx context.Context, machineID string) (fly.Machine, error) {
	request := struct {
		MachineID string `json:"machine_id"`
		Target    string `json:"target"`
	}{MachineID: machineID, Target: "stopped"}
	return executeMachineMutation(ctx, s.repo, s.fly, "stop_machine:"+machineID, request, machineID, func(machine fly.Machine) bool {
		return machine.State == "stopped"
	}, func() (fly.Machine, error) { return s.fly.StopMachine(ctx, machineID) })
}

func (s *Service) updateMachine(ctx context.Context, machineID string, spec fly.MachineSpec) (fly.Machine, error) {
	request := struct {
		MachineID string          `json:"machine_id"`
		Spec      fly.MachineSpec `json:"spec"`
	}{MachineID: machineID, Spec: spec}
	return executeMachineMutation(ctx, s.repo, s.fly, "update_machine:"+machineID, request, machineID, func(machine fly.Machine) bool {
		return machine.ConfigHash == spec.ConfigHash
	}, func() (fly.Machine, error) { return s.fly.UpdateMachine(ctx, machineID, spec) })
}

func (s *Service) destroyMachine(ctx context.Context, machineID string) error {
	request := struct {
		MachineID string `json:"machine_id"`
	}{MachineID: machineID}
	return executeDestroyMutation(ctx, s.repo, "destroy_machine:"+machineID, "machine", request,
		func() error { _, err := s.fly.GetMachine(ctx, machineID); return err },
		func() error { return s.fly.DestroyMachine(ctx, machineID) },
	)
}

func (s *Service) destroyVolume(ctx context.Context, volumeID string) error {
	request := struct {
		VolumeID string `json:"volume_id"`
	}{VolumeID: volumeID}
	return executeDestroyMutation(ctx, s.repo, "destroy_volume:"+volumeID, "volume", request,
		func() error { _, err := s.fly.GetVolume(ctx, volumeID); return err },
		func() error { return s.fly.DestroyVolume(ctx, volumeID) },
	)
}

func (s *Service) projectSecrets(intent ProjectIntent) []fly.MachineSecret {
	out := []fly.MachineSecret{{EnvVar: s.cfg.Fly.EnrollmentSecret, Name: providerSecretName("PBSECRET_ENROLLMENT", intent.ID), Value: intent.EnrollmentCredential}}
	if strings.TrimSpace(intent.ConfigAgeIdentity) != "" {
		out = append(out, fly.MachineSecret{EnvVar: "PAPERBOAT_CONFIG_AGE_IDENTITY", Name: providerSecretName("PBSECRET_CONFIG_AGE", intent.ID), Value: intent.ConfigAgeIdentity})
	}
	if strings.TrimSpace(intent.GitHubConfigToken) != "" {
		out = append(out, fly.MachineSecret{
			EnvVar: s.cfg.Fly.GitHubSecret,
			Name:   providerSecretName("PBSECRET_GITHUB", intent.ID),
			Value:  intent.GitHubConfigToken,
		})
	}
	if strings.TrimSpace(intent.SetupScript) != "" {
		out = append(out, fly.MachineSecret{
			EnvVar: s.cfg.Fly.SetupScriptSecret,
			Name:   providerSecretName("PBSECRET_SETUP", intent.ID),
			Value:  intent.SetupScript,
		})
	}
	return out
}

func (s *Service) deleteProviderSecrets(ctx context.Context, intent ProjectIntent) error {
	for _, secret := range s.projectSecrets(intent) {
		if secret.Name == "" {
			continue
		}
		request := struct {
			Name string `json:"name"`
		}{Name: secret.Name}
		if err := executeNonObservableMutation(ctx, s.repo, "delete_secret:"+secret.Name, "secret", request, func() error {
			return s.fly.DeleteSecret(ctx, secret.Name)
		}); err != nil && !errors.Is(err, fly.ErrNotFound) {
			return err
		}
	}
	return nil
}

func providerName(prefix, projectID string) string {
	value := strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(projectID))
	return strings.Trim(strings.TrimSpace(prefix), "-") + "-" + value
}

func providerSecretName(prefix, projectID string) string {
	value := strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToUpper(projectID))
	return strings.Trim(strings.TrimSpace(prefix), "_") + "_" + value
}

func providerVolumeName(prefix, projectID string) string {
	cleanPrefix := sanitizeVolumePart(prefix)
	if cleanPrefix == "" {
		cleanPrefix = "pbvol"
	}
	if len(cleanPrefix) > 12 {
		cleanPrefix = cleanPrefix[:12]
	}
	sum := sha256.Sum256([]byte(projectID))
	return cleanPrefix + "_" + hex.EncodeToString(sum[:])[:16]
}

func sanitizeVolumePart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_':
			b.WriteRune(r)
		case r == '-' || r == '.':
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func resourceTags(projectID string) map[string]string {
	return map[string]string{"paperboat_project_id": projectID, "managed_by": "paperboat-server"}
}

type Repository struct {
	db            *db.DB
	encryptionKey string
	lease         time.Duration
}

func NewRepository(store *db.DB, encryptionKey string) *Repository {
	return &Repository{db: store, encryptionKey: encryptionKey, lease: 5 * time.Minute}
}

type Job struct {
	ID            string
	Type          string
	AggregateID   string
	PreviousState string
	LeaseToken    string
}

type ProjectIntent struct {
	ID                     string
	RepositoryURL          string
	DefaultBranch          string
	UserID                 string
	StorageGB              int
	MachineTypeCode        string
	VCPU                   int
	MemoryMB               int
	RegionCode             string
	PresetCodes            []string
	IdleTimeoutCode        string
	SetupScriptRef         string
	SetupScript            string
	DesiredConfigHash      string
	PendingRestartApply    bool
	GitHubConfigToken      string
	GitHubConfigRepoURL    string
	GitHubConfigRepoBranch string
	EnrollmentCredential   string
	ConfigAgeIdentity      string
	ConfigAgeRecipient     string
	ConfigAgeVersion       int32
}

type MachineRecord struct {
	FlyMachineID string
	State        string
	FlyVolumeID  string
}

type VolumeRecord struct {
	FlyVolumeID string
	SizeGB      int
	State       string
}

type Run struct {
	ID       string    `json:"id"`
	Scope    string    `json:"scope"`
	State    string    `json:"state"`
	Findings []Finding `json:"findings"`
}

type Finding struct {
	ProjectID string `json:"project_id,omitempty"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
}

func (r *Repository) ClaimNextJob(ctx context.Context) (Job, bool, error) {
	var job Job
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		now := time.Now().UTC()
		leaseToken := newID("lease")
		row, err := tx.Queries().ClaimNextOrchestrationJob(ctx, dbsqlc.ClaimNextOrchestrationJobParams{LeaseToken: leaseToken, LeaseExpiresAt: sql.NullTime{Time: now.Add(r.lease), Valid: true}, Now: now})
		if err != nil {
			return err
		}
		job = Job{ID: row.ID, Type: row.JobType, AggregateID: row.AggregateID, LeaseToken: row.LeaseToken}
		var decoded struct {
			PreviousState string `json:"previous_state"`
		}
		_ = json.Unmarshal(row.Payload, &decoded)
		job.PreviousState = decoded.PreviousState
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, false, nil
	}
	return job, err == nil, err
}

func (r *Repository) CompleteJob(ctx context.Context, jobID, leaseToken string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		rows, err := tx.Queries().CompleteOrchestrationJob(ctx, dbsqlc.CompleteOrchestrationJobParams{ID: jobID, LeaseToken: leaseToken})
		if err == nil && rows != 1 {
			err = ErrOrchestrationLeaseLost
		}
		return err
	})
}

func (r *Repository) EnsureHostedControlEnvironment(ctx context.Context, projectID, ownerID string) error {
	_, err := r.db.Queries().EnsureHostedControlEnvironment(ctx, dbsqlc.EnsureHostedControlEnvironmentParams{ID: projectID, WorkspaceID: projectID, OwnerUserID: sql.NullString{String: ownerID, Valid: ownerID != ""}})
	return err
}

func (r *Repository) BeginHostedEnvironmentDelete(ctx context.Context, projectID string) error {
	environment, err := r.db.Queries().GetControlEnvironment(ctx, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil || environment.DesiredState == "deleting" || environment.DesiredState == "revoked" {
		return err
	}
	_, err = r.db.Queries().UpdateControlEnvironmentDesiredState(ctx, dbsqlc.UpdateControlEnvironmentDesiredStateParams{ID: projectID, DesiredState: "deleting", Now: time.Now().UTC(), ExpectedVersion: environment.DesiredVersion})
	return err
}

func (r *Repository) CompleteHostedEnvironmentDelete(ctx context.Context, projectID string) error {
	environment, err := r.db.Queries().GetControlEnvironment(ctx, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if environment.AppliedState == "deleted" && environment.AppliedVersion == environment.DesiredVersion {
		return nil
	}
	if _, err = r.db.Queries().ApplyControlEnvironmentState(ctx, dbsqlc.ApplyControlEnvironmentStateParams{ID: projectID, AppliedState: "deleted", DesiredVersion: environment.DesiredVersion}); err != nil {
		return err
	}
	return r.db.Queries().DeleteHostedControlEnvironment(ctx, projectID)
}

func (r *Repository) FailJob(ctx context.Context, jobID, leaseToken string, cause error) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		rows, err := tx.Queries().RetryOrchestrationJob(ctx, dbsqlc.RetryOrchestrationJobParams{ID: jobID, LeaseToken: leaseToken, LastError: cause.Error()})
		if err == nil && rows != 1 {
			err = ErrOrchestrationLeaseLost
		}
		return err
	})
}

func (r *Repository) BlockJobAndRestoreProject(ctx context.Context, jobID, leaseToken, projectID, previousState string, cause error) error {
	if previousState == "" || previousState == "restarting" {
		previousState = "ready"
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		rows, err := q.BlockOrchestrationJob(ctx, dbsqlc.BlockOrchestrationJobParams{ID: jobID, LeaseToken: leaseToken, LastError: cause.Error()})
		if err != nil {
			return err
		}
		if rows != 1 {
			return ErrOrchestrationLeaseLost
		}
		return q.RestoreRestartingProjectState(ctx, dbsqlc.RestoreRestartingProjectStateParams{ID: projectID, State: previousState})
	})
}

func (r *Repository) ProjectIntent(ctx context.Context, projectID string) (ProjectIntent, error) {
	row, err := r.db.Queries().GetOrchestrationProjectIntent(ctx, projectID)
	if err != nil {
		return ProjectIntent{}, err
	}
	intent := ProjectIntent{ID: row.ID, UserID: row.UserID, RepositoryURL: row.SourceUrl, DefaultBranch: row.DefaultBranch, StorageGB: int(row.AssignedGb), MachineTypeCode: row.MachineTypeCode, VCPU: int(row.Vcpu), MemoryMB: int(row.MemoryMb), RegionCode: row.RegionCode, IdleTimeoutCode: row.IdleTimeoutCode, SetupScriptRef: row.SetupScriptRef, DesiredConfigHash: row.DesiredConfigHash, PendingRestartApply: row.PendingRestartApply}
	key, keyErr := r.ensureAccountConfigKey(ctx, intent.UserID)
	if keyErr != nil {
		return ProjectIntent{}, keyErr
	}
	intent.ConfigAgeIdentity, intent.ConfigAgeRecipient, intent.ConfigAgeVersion = key.Identity, key.Recipient, key.Version
	_ = json.Unmarshal(databaseBytes(row.PresetCodes), &intent.PresetCodes)
	token, err := r.githubConfigToken(ctx, intent.UserID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ProjectIntent{}, err
	}
	intent.GitHubConfigToken = token
	configRepoURL, configRepoBranch, err := r.githubConfigRepo(ctx, intent.UserID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ProjectIntent{}, err
	}
	intent.GitHubConfigRepoURL = configRepoURL
	intent.GitHubConfigRepoBranch = configRepoBranch
	setupScript, err := r.setupScript(ctx, intent.ID, intent.SetupScriptRef)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ProjectIntent{}, err
	}
	intent.SetupScript = setupScript
	return intent, nil
}

type accountConfigKey struct {
	Identity, Recipient string
	Version             int32
}

func (r *Repository) ensureAccountConfigKey(ctx context.Context, userID string) (accountConfigKey, error) {
	row, err := r.db.Queries().GetAccountConfigKey(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		identity, generateErr := age.GenerateX25519Identity()
		if generateErr != nil {
			return accountConfigKey{}, generateErr
		}
		ciphertext, encryptErr := secrets.Encrypt(r.encryptionKey, identity.String())
		if encryptErr != nil {
			return accountConfigKey{}, encryptErr
		}
		if _, err = r.db.Queries().InsertAccountConfigKey(ctx, dbsqlc.InsertAccountConfigKeyParams{UserID: userID, Recipient: identity.Recipient().String(), EncryptedIdentity: ciphertext}); err != nil {
			return accountConfigKey{}, err
		}
		row, err = r.db.Queries().GetAccountConfigKey(ctx, userID)
	}
	if err != nil {
		return accountConfigKey{}, err
	}
	identity, err := secrets.Decrypt(r.encryptionKey, row.EncryptedIdentity)
	if err != nil {
		return accountConfigKey{}, fmt.Errorf("decrypt account config identity: %w", err)
	}
	if len(row.PreviousEncryptedIdentity) > 0 {
		previous, previousErr := secrets.Decrypt(r.encryptionKey, row.PreviousEncryptedIdentity)
		if previousErr != nil {
			return accountConfigKey{}, fmt.Errorf("decrypt previous account config identity: %w", previousErr)
		}
		identity += "\n" + previous
	}
	return accountConfigKey{Identity: identity, Recipient: row.Recipient, Version: row.KeyVersion}, nil
}

func (r *Repository) githubConfigToken(ctx context.Context, userID string) (string, error) {
	ciphertext, err := r.db.Queries().GetLatestGitHubTokenCiphertext(ctx, userID)
	if err != nil {
		return "", err
	}
	plaintext, err := secrets.Decrypt(r.encryptionKey, ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt GitHub config token: %w", err)
	}
	return plaintext, nil
}

func (r *Repository) githubConfigRepo(ctx context.Context, userID string) (string, string, error) {
	row, err := r.db.Queries().GetGitHubConfigRepository(ctx, userID)
	return row.CloneUrl, row.DefaultBranch, err
}

func (r *Repository) setupScript(ctx context.Context, projectID, setupScriptRef string) (string, error) {
	if strings.TrimSpace(setupScriptRef) == "" {
		return "", nil
	}
	ciphertext, err := r.db.Queries().GetProjectSetupScriptCiphertext(ctx, dbsqlc.GetProjectSetupScriptCiphertextParams{ProjectID: projectID, ID: setupScriptRef})
	if err != nil {
		return "", err
	}
	plaintext, err := secrets.Decrypt(r.encryptionKey, ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt project setup script: %w", err)
	}
	return plaintext, nil
}

func (r *Repository) ProjectMachine(ctx context.Context, projectID string) (MachineRecord, error) {
	row, err := r.db.Queries().GetProjectMachine(ctx, projectID)
	return MachineRecord{FlyMachineID: row.FlyMachineID, State: row.State}, err
}

func (r *Repository) ProjectVolume(ctx context.Context, projectID string) (VolumeRecord, error) {
	row, err := r.db.Queries().GetProjectVolume(ctx, projectID)
	return VolumeRecord{FlyVolumeID: row.FlyVolumeID, SizeGB: int(row.SizeGb), State: row.State}, err
}

func (r *Repository) RecordVolume(ctx context.Context, projectID, flyVolumeID string, sizeGB int, region, state string) (VolumeRecord, error) {
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		err := q.InsertFlyVolumeRecord(ctx, dbsqlc.InsertFlyVolumeRecordParams{ID: newID("flv"), ProjectID: projectID, FlyVolumeID: flyVolumeID, SizeGb: int32(sizeGB), Region: region, State: state})
		if err != nil {
			return err
		}
		return q.SetProjectFlyVolumeID(ctx, dbsqlc.SetProjectFlyVolumeIDParams{ProjectID: projectID, FlyVolumeID: sql.NullString{String: flyVolumeID, Valid: true}})
	})
	if err != nil {
		return VolumeRecord{}, err
	}
	return r.ProjectVolume(ctx, projectID)
}

func (r *Repository) RecordMachine(ctx context.Context, projectID, flyMachineID, state, imageRef, region, configHash string) (MachineRecord, error) {
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().UpsertFlyMachineRecord(ctx, dbsqlc.UpsertFlyMachineRecordParams{ID: newID("flm"), ProjectID: projectID, FlyMachineID: flyMachineID, State: state, ImageRef: imageRef, Region: region, ObservedConfigHash: configHash})
	})
	if err != nil {
		return MachineRecord{}, err
	}
	return r.ProjectMachine(ctx, projectID)
}

func (r *Repository) MarkProvisionedStopped(ctx context.Context, intent ProjectIntent) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := applyRuntimeConfigTx(ctx, tx, intent); err != nil {
			return err
		}
		if err := tx.Queries().MarkProvisionedProjectStopped(ctx, intent.ID); err != nil {
			return err
		}
		return insertEvent(ctx, tx, intent.ID, "project.stopped", "Project machine and storage were provisioned. The machine is stopped until you start it.", map[string]any{"state": "stopped"})
	})
}

func (r *Repository) ApplyRuntimeConfig(ctx context.Context, intent ProjectIntent) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := applyRuntimeConfigTx(ctx, tx, intent); err != nil {
			return err
		}
		return insertEvent(ctx, tx, intent.ID, "project.restart_applied", "Pending project configuration was applied on restart.", map[string]any{"config_hash": intent.DesiredConfigHash})
	})
}

func applyRuntimeConfigTx(ctx context.Context, tx *db.Tx, intent ProjectIntent) error {
	return tx.Queries().ApplyProjectRuntimeConfig(ctx, dbsqlc.ApplyProjectRuntimeConfigParams{ProjectID: intent.ID, AppliedStorageGb: int32(intent.StorageGB)})
}

func (r *Repository) RecordMachineState(ctx context.Context, projectID, providerState, projectState string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if err := q.UpdateOrchestratedMachineState(ctx, dbsqlc.UpdateOrchestratedMachineStateParams{ProjectID: projectID, State: providerState}); err != nil {
			return err
		}
		if err := q.UpdateOrchestratedProjectState(ctx, dbsqlc.UpdateOrchestratedProjectStateParams{ID: projectID, State: projectState}); err != nil {
			return err
		}
		return insertEvent(ctx, tx, projectID, "project."+projectState, "Project machine state changed.", map[string]any{"state": projectState, "provider_state": providerState})
	})
}

func (r *Repository) RecordReadinessSuccess(ctx context.Context, projectID string) error {
	return r.recordReadiness(ctx, projectID, map[string]string{
		"workspace":            "ready",
		"config_restore":       "ready",
		"helper_health":        "ready",
		"connector_admission":  "ready",
		"runtime_dependencies": "ready",
	}, "")
}

func (r *Repository) RecordReadinessFailure(ctx context.Context, projectID string, cause error) error {
	stage, reason := "helper_health", "verification failed"
	var readinessErr *HostedReadinessError
	if errors.As(cause, &readinessErr) {
		stage, reason = readinessErr.Stage, readinessErr.Reason
	}
	return r.recordReadiness(ctx, projectID, map[string]string{stage: "failed"}, reason)
}

func (r *Repository) recordReadiness(ctx context.Context, projectID string, stages map[string]string, reason string) error {
	jobID, hasJob := ctx.Value(orchestrationJobContextKey{}).(string)
	evidence, err := json.Marshal(map[string]string{"source": "helper_route_health_v1"})
	if err != nil {
		return err
	}
	observedAt := time.Now().UTC()
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		stageNames := make([]string, 0, len(stages))
		for stage := range stages {
			stageNames = append(stageNames, stage)
		}
		sort.Strings(stageNames)
		for _, stage := range stageNames {
			if err := tx.Queries().InsertHostedReadinessObservation(ctx, dbsqlc.InsertHostedReadinessObservationParams{
				ID: newID("hro"), ProjectID: projectID,
				OrchestrationJobID: sql.NullString{String: jobID, Valid: hasJob && jobID != ""},
				Stage:              stage, State: stages[stage], Reason: reason, Evidence: evidence, ObservedAt: observedAt,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *Repository) RemoveMachine(ctx context.Context, projectID string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().DeleteProjectMachineRecord(ctx, projectID)
	})
}

func (r *Repository) RemoveVolume(ctx context.Context, projectID string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().DeleteProjectVolumeRecord(ctx, projectID)
	})
}

func (r *Repository) MarkDeletedAndReleaseStorage(ctx context.Context, projectID string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		allocation, err := q.GetProjectStorageForDelete(ctx, projectID)
		if err != nil {
			return err
		}
		key := "project.storage.release.delete:" + projectID
		_, err = q.GetStorageLedgerAmountByKey(ctx, key)
		if errors.Is(err, sql.ErrNoRows) {
			if err := q.DecreaseAllocatedStorage(ctx, dbsqlc.DecreaseAllocatedStorageParams{ID: allocation.StorageAccountID, AllocatedGb: allocation.AssignedGb}); err != nil {
				return err
			}
			if err := q.InsertProjectStorageLedger(ctx, dbsqlc.InsertProjectStorageLedgerParams{ID: newID("sled"), AccountID: allocation.StorageAccountID, EntryType: "release", AmountGb: allocation.AssignedGb, ProjectID: projectID, IdempotencyKey: key}); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if err := q.SupersedeProjectTerminalSessionOperations(ctx, projectID); err != nil {
			return err
		}
		if err := q.TombstoneProjectTerminalSessions(ctx, projectID); err != nil {
			return err
		}
		if err := q.MarkProjectDeleted(ctx, projectID); err != nil {
			return err
		}
		return insertEvent(ctx, tx, projectID, "project.deleted", "Project provider resources were removed and storage was released.", map[string]any{"storage_gb": int(allocation.AssignedGb)})
	})
}

func (r *Repository) StartReconciliation(ctx context.Context, run Run) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().StartReconciliationRun(ctx, dbsqlc.StartReconciliationRunParams{ID: run.ID, Scope: run.Scope, State: run.State})
	})
}

func (r *Repository) FinishReconciliation(ctx context.Context, run Run) error {
	b, _ := json.Marshal(run.Findings)
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().FinishReconciliationRun(ctx, dbsqlc.FinishReconciliationRunParams{ID: run.ID, State: run.State, Column3: b})
	})
}

func (r *Repository) ReconcileFly(ctx context.Context, client fly.Client) ([]Finding, error) {
	rows, err := r.db.Queries().ListRecordedFlyMachines(ctx)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	knownMachineIDs := map[string]bool{}
	for _, row := range rows {
		knownMachineIDs[row.FlyMachineID] = true
		actual, err := client.GetMachine(ctx, row.FlyMachineID)
		if errors.Is(err, fly.ErrNotFound) {
			findings = append(findings, Finding{ProjectID: row.ProjectID, Severity: "error", Message: "fly machine missing"})
			continue
		}
		if err != nil {
			return findings, err
		}
		if actual.State != row.State {
			findings = append(findings, Finding{ProjectID: row.ProjectID, Severity: "warning", Message: fmt.Sprintf("machine state drift: stored=%s actual=%s", row.State, actual.State)})
			// Provider observations must not promote a project to ready/running. Only
			// the lifecycle operation that proves helper readiness may advance the
			// product state; reconciliation records the provider observation alone.
			_ = r.recordObservedMachineState(ctx, row.ProjectID, actual.State)
		}
	}
	machines, err := client.ListMachines(ctx, map[string]string{"managed_by": "paperboat-server"})
	if err != nil {
		return findings, err
	}
	for _, machine := range machines {
		if knownMachineIDs[machine.ID] || machine.Tags["managed_by"] != "paperboat-server" {
			continue
		}
		projectID := machine.Tags["paperboat_project_id"]
		findings = append(findings, Finding{ProjectID: projectID, Severity: "error", Message: "orphan fly machine queued for operator review"})
		if err := r.QueueOrphanRemediation(ctx, machine); err != nil {
			return findings, err
		}
	}
	return findings, nil
}

func (r *Repository) recordObservedMachineState(ctx context.Context, projectID, providerState string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().UpdateOrchestratedMachineState(ctx, dbsqlc.UpdateOrchestratedMachineStateParams{
			ProjectID: projectID,
			State:     providerState,
		})
	})
}

func (r *Repository) QueueOrphanRemediation(ctx context.Context, machine fly.Machine) error {
	payload, _ := json.Marshal(map[string]any{
		"fly_machine_id": machine.ID,
		"name":           machine.Name,
		"state":          machine.State,
		"region":         machine.Region,
		"tags":           machine.Tags,
		"action":         "operator_review_required",
	})
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().UpsertOrphanRemediationJob(ctx, dbsqlc.UpsertOrphanRemediationJobParams{ID: newID("job"), FlyMachineID: machine.ID, IdempotencyKey: "fly.orphan.remediate:" + machine.ID, Payload: payload})
	})
}

func (r *Repository) RecordProjectEvent(ctx context.Context, projectID, eventType, message string, metadata map[string]any) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return insertEvent(ctx, tx, projectID, eventType, message, metadata)
	})
}

func mapProviderState(state string) string {
	if isProviderRunning(state) {
		return "running"
	}
	return "stopped"
}

func isProviderRunning(state string) bool {
	return state == "running" || state == "started"
}

func insertEvent(ctx context.Context, tx *db.Tx, projectID, eventType, message string, metadata map[string]any) error {
	b, _ := json.Marshal(metadata)
	return tx.Queries().InsertOrchestrationProjectEvent(ctx, dbsqlc.InsertOrchestrationProjectEventParams{ID: newID("pevt"), ProjectID: projectID, EventType: eventType, Message: message, Metadata: b})
}

func databaseBytes(value any) []byte {
	switch typed := value.(type) {
	case []byte:
		return typed
	case string:
		return []byte(typed)
	default:
		return nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
