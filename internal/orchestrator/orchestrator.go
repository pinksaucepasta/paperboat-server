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
	"sort"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

var ErrVolumeResizeRequiresApproval = errors.New("volume resize requires approved Fly resize or replacement policy")

type Service struct {
	repo           *Repository
	fly            fly.Client
	cfg            config.Config
	agentunnel     agentunnel.Client
	agentunnelRepo *agentunnel.Repository
}

func NewService(store *db.DB, flyClient fly.Client, cfg config.Config) *Service {
	var agentunnelClient agentunnel.Client
	if cfg.Providers.FakeMode {
		agentunnelClient = agentunnel.FakeClient{BaseURL: cfg.Providers.Agentunnel.BaseURL}
	}
	return NewServiceWithAgentunnel(store, flyClient, cfg, agentunnelClient)
}

func NewServiceWithAgentunnel(store *db.DB, flyClient fly.Client, cfg config.Config, agentunnelClient agentunnel.Client) *Service {
	return &Service{
		repo:           NewRepository(store, cfg.Secrets.EncryptionKey),
		fly:            flyClient,
		cfg:            cfg,
		agentunnel:     agentunnelClient,
		agentunnelRepo: agentunnel.NewRepository(store, cfg.Secrets.EncryptionKey),
	}
}

func (s *Service) RunOnce(ctx context.Context) error {
	job, ok, err := s.repo.ClaimNextJob(ctx)
	if err != nil || !ok {
		return err
	}
	err = s.process(ctx, job)
	if err != nil {
		if errors.Is(err, ErrVolumeResizeRequiresApproval) {
			_ = s.repo.BlockJobAndRestoreProject(ctx, job.ID, job.AggregateID, job.PreviousState, err)
			return err
		}
		_ = s.repo.FailJob(ctx, job.ID, err)
		return err
	}
	return s.repo.CompleteJob(ctx, job.ID)
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
	volume, err := s.ensureVolume(ctx, intent)
	if err != nil {
		return err
	}
	agentunnelErr := s.ensureAgentunnelResource(ctx, &intent)
	if _, err := s.ensureMachine(ctx, intent, volume.FlyVolumeID); err != nil {
		return err
	}
	if agentunnelErr != nil {
		return agentunnelErr
	}
	return s.repo.MarkProvisionedStopped(ctx, intent)
}

func (s *Service) ensureAgentunnelResource(ctx context.Context, intent *ProjectIntent) error {
	if strings.TrimSpace(intent.AgentunnelToken) != "" {
		return nil
	}
	if s.agentunnel == nil {
		if strings.TrimSpace(s.cfg.Secrets.AgentunnelMachineToken) != "" {
			return nil
		}
		return errors.New("agentunnel project resource is required before machine provisioning")
	}
	resource, err := s.agentunnel.EnsureProjectResources(ctx, agentunnel.ProjectRef{ID: intent.ID, Name: intent.ID})
	if err != nil {
		return fmt.Errorf("ensure agentunnel project resources: %w", err)
	}
	resource, err = s.agentunnelRepo.UpsertResource(ctx, intent.ID, resource)
	if err != nil {
		return fmt.Errorf("store agentunnel project resources: %w", err)
	}
	intent.AgentunnelToken = resource.MachineToken
	intent.AgentunnelClientID = resource.ClientID
	intent.AgentunnelTunnelID = resource.TunnelID
	if strings.TrimSpace(intent.AgentunnelToken) == "" {
		reloaded, err := s.repo.agentunnelResource(ctx, intent.ID)
		if err != nil {
			return fmt.Errorf("reload agentunnel project resources: %w", err)
		}
		intent.AgentunnelToken = reloaded.MachineToken
		intent.AgentunnelClientID = reloaded.ClientID
		intent.AgentunnelTunnelID = reloaded.TunnelID
	}
	if strings.TrimSpace(intent.AgentunnelToken) == "" {
		return errors.New("agentunnel project resource did not include a machine token")
	}
	return nil
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
	observed, err := s.fly.StartMachine(ctx, machine.FlyMachineID)
	if errors.Is(err, fly.ErrNotFound) {
		if machine, err = s.recreateMissingMachine(ctx, projectID); err != nil {
			return err
		}
		observed, err = s.fly.StartMachine(ctx, machine.FlyMachineID)
	}
	if err != nil {
		return err
	}
	return s.repo.RecordMachineState(ctx, projectID, observed.State, "running")
}

func (s *Service) stopProject(ctx context.Context, projectID string) error {
	machine, err := s.repo.ProjectMachine(ctx, projectID)
	if err != nil {
		return err
	}
	observed, err := s.fly.StopMachine(ctx, machine.FlyMachineID)
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
	if _, err := s.fly.StopMachine(ctx, machine.FlyMachineID); err != nil {
		if !errors.Is(err, fly.ErrNotFound) {
			return err
		}
		// The machine vanished at the provider; the replacement is created
		// stopped with the full desired spec, so skip the update paths below.
		if machine, err = s.recreateMissingMachine(ctx, projectID); err != nil {
			return err
		}
	} else if intent.PendingRestartApply {
		if _, err := s.fly.UpdateMachine(ctx, machine.FlyMachineID, s.machineSpec(intent, volume.FlyVolumeID)); err != nil {
			return err
		}
		if err := s.repo.ApplyRuntimeConfig(ctx, intent); err != nil {
			return err
		}
	} else if err := s.applyMachineSpecDrift(ctx, intent, machine.FlyMachineID, volume.FlyVolumeID); err != nil {
		return err
	}
	observed, err := s.fly.StartMachine(ctx, machine.FlyMachineID)
	if err != nil {
		return err
	}
	return s.repo.RecordMachineState(ctx, projectID, observed.State, "running")
}

func (s *Service) deleteProject(ctx context.Context, projectID string) error {
	intent, intentErr := s.repo.ProjectIntent(ctx, projectID)
	machine, machineErr := s.repo.ProjectMachine(ctx, projectID)
	if machineErr == nil {
		if _, err := s.fly.StopMachine(ctx, machine.FlyMachineID); err != nil {
			if !errors.Is(err, fly.ErrNotFound) {
				return err
			}
			if err := s.repo.RemoveMachine(ctx, projectID); err != nil {
				return err
			}
		} else {
			if err := s.fly.DestroyMachine(ctx, machine.FlyMachineID); err != nil {
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
	} else if !errors.Is(intentErr, sql.ErrNoRows) {
		return intentErr
	}
	volume, volumeErr := s.repo.ProjectVolume(ctx, projectID)
	if volumeErr == nil {
		if err := s.fly.DestroyVolume(ctx, volume.FlyVolumeID); err != nil {
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
	return s.repo.MarkDeletedAndReleaseStorage(ctx, projectID)
}

func (s *Service) ensureVolume(ctx context.Context, intent ProjectIntent) (VolumeRecord, error) {
	if volume, err := s.repo.ProjectVolume(ctx, intent.ID); err == nil {
		return volume, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return VolumeRecord{}, err
	}
	name := providerVolumeName(s.cfg.Fly.VolumeNamePrefix, intent.ID)
	if adopted, ok, err := s.findProviderVolume(ctx, name, intent); err != nil || ok {
		if err != nil {
			return VolumeRecord{}, err
		}
		return s.repo.RecordVolume(ctx, intent.ID, adopted.ID, intent.StorageGB, intent.RegionCode, adopted.State)
	}
	created, err := s.fly.CreateVolume(ctx, name, intent.RegionCode, intent.StorageGB, resourceTags(intent.ID))
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
		return s.repo.RecordMachine(ctx, intent.ID, adopted.ID, adopted.State, s.cfg.Fly.ImageRef, intent.RegionCode, intent.DesiredConfigHash)
	}
	created, err := s.fly.CreateMachine(ctx, spec)
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
	env := map[string]string{
		"PAPERBOAT_PROJECT_ID":           intent.ID,
		"PAPERBOAT_MACHINE_ID":           machineName,
		"PAPERBOAT_REPOSITORY_URL":       intent.RepositoryURL,
		"PAPERBOAT_DEFAULT_BRANCH":       intent.DefaultBranch,
		"PAPERBOAT_PRESET_CODES":         strings.Join(intent.PresetCodes, ","),
		"PAPERBOAT_IDLE_TIMEOUT_CODE":    intent.IdleTimeoutCode,
		"PAPERBOAT_AGENTUNNEL_TOKEN_ENV": s.cfg.Fly.AgentunnelSecret,
		"PAPERBOAT_GITHUB_TOKEN_ENV":     s.cfg.Fly.GitHubSecret,
		"PAPERBOAT_SETUP_SCRIPT_REF":     intent.SetupScriptRef,
		"PAPERBOAT_SETUP_SCRIPT_ENV":     s.cfg.Fly.SetupScriptSecret,
		"PAPERBOAT_DESIRED_CONFIG_SHA":   intent.DesiredConfigHash,
		"PAPERBOAT_ACTIVITY_ENDPOINT":    strings.TrimRight(s.cfg.HTTP.PublicBaseURL, "/") + "/api/machine/activity-heartbeat",
		"PAPERBOAT_ACTIVITY_TOKEN_ENV":   "PAPERBOAT_MACHINE_ACTIVITY_TOKEN",
	}
	if strings.TrimSpace(intent.GitHubConfigRepoURL) != "" {
		env["PAPERBOAT_CONFIG_REPO_URL"] = intent.GitHubConfigRepoURL
	}
	if strings.TrimSpace(intent.GitHubConfigRepoBranch) != "" {
		env["PAPERBOAT_CONFIG_REPO_BRANCH"] = intent.GitHubConfigRepoBranch
	}
	if strings.TrimSpace(s.cfg.Providers.Agentunnel.BaseURL) != "" {
		env["PAPERBOAT_AGENTUNNEL_SERVER_URL"] = s.cfg.Providers.Agentunnel.BaseURL
	}
	if strings.TrimSpace(s.cfg.Providers.Agentunnel.MachineMode) != "" {
		env["PAPERBOAT_AGENTUNNEL_MODE"] = s.cfg.Providers.Agentunnel.MachineMode
	}
	if strings.TrimSpace(s.cfg.Providers.Agentunnel.PapercodeLocalURL) != "" {
		env["PAPERBOAT_PAPERCODE_LOCAL_URL"] = s.cfg.Providers.Agentunnel.PapercodeLocalURL
	}
	if strings.TrimSpace(intent.AgentunnelClientID) != "" {
		env["PAPERBOAT_AGENTUNNEL_CLIENT_ID"] = intent.AgentunnelClientID
	}
	if strings.TrimSpace(intent.AgentunnelTunnelID) != "" {
		env["PAPERBOAT_AGENTUNNEL_TUNNEL_ID"] = intent.AgentunnelTunnelID
	}
	spec := fly.MachineSpec{
		Name:       machineName,
		Hostname:   s.cfg.Fly.Hostname,
		ImageRef:   s.cfg.Fly.ImageRef,
		Region:     intent.RegionCode,
		Size:       fly.MachineSize{VCPU: intent.VCPU, MemoryMB: intent.MemoryMB},
		VolumeID:   volumeID,
		MountPath:  s.cfg.Fly.MountPath,
		Env:        env,
		Secrets:    s.projectSecrets(intent),
		Command:    s.cfg.Fly.BootCommand,
		ConfigHash: intent.DesiredConfigHash,
		Tags:       resourceTags(intent.ID),
	}
	spec.Tags[specHashTag] = machineSpecHash(spec)
	return spec
}

// specHashTag is machine metadata carrying a digest of the full rendered
// machine spec, so drift introduced by server-side settings (hostname, image,
// boot command, env) is detectable against the live Fly machine even when the
// project's own desired config is unchanged.
const specHashTag = "paperboat_spec_hash"

func machineSpecHash(spec fly.MachineSpec) string {
	secretRefs := make([]string, 0, len(spec.Secrets))
	for _, secret := range spec.Secrets {
		secretRefs = append(secretRefs, secret.EnvVar+"="+secret.Name)
	}
	sort.Strings(secretRefs)
	payload, _ := json.Marshal(map[string]any{
		"name":        spec.Name,
		"hostname":    spec.Hostname,
		"image_ref":   spec.ImageRef,
		"region":      spec.Region,
		"vcpu":        spec.Size.VCPU,
		"memory_mb":   spec.Size.MemoryMB,
		"volume_id":   spec.VolumeID,
		"mount_path":  spec.MountPath,
		"env":         spec.Env,
		"command":     spec.Command,
		"secret_refs": secretRefs,
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
	// The replacement carries the full desired spec, so any change that was
	// waiting for a restart is now applied.
	if intent.PendingRestartApply {
		if err := s.repo.ApplyRuntimeConfig(ctx, intent); err != nil {
			return MachineRecord{}, err
		}
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
	if _, err := s.fly.UpdateMachine(ctx, machineID, spec); err != nil {
		return err
	}
	return s.repo.RecordProjectEvent(ctx, intent.ID, "project.machine_spec_drift_applied", "Machine configuration drifted from the desired spec and was reconciled.", map[string]any{"spec_hash": spec.Tags[specHashTag]})
}

func (s *Service) projectSecrets(intent ProjectIntent) []fly.MachineSecret {
	var out []fly.MachineSecret
	agentunnelToken := firstNonEmpty(intent.AgentunnelToken, s.cfg.Secrets.AgentunnelMachineToken)
	if strings.TrimSpace(agentunnelToken) != "" {
		out = append(out, fly.MachineSecret{
			EnvVar: s.cfg.Fly.AgentunnelSecret,
			Name:   providerSecretName("PBSECRET_AGENTUNNEL", intent.ID),
			Value:  agentunnelToken,
		})
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
	if strings.TrimSpace(agentunnelToken) != "" {
		out = append(out, fly.MachineSecret{
			EnvVar: "PAPERBOAT_MACHINE_ACTIVITY_TOKEN",
			Name:   providerSecretName("PBSECRET_ACTIVITY", intent.ID),
			Value:  agentunnelToken,
		})
	}
	return out
}

func (s *Service) deleteProviderSecrets(ctx context.Context, intent ProjectIntent) error {
	for _, secret := range s.projectSecrets(intent) {
		if secret.Name == "" {
			continue
		}
		if err := s.fly.DeleteSecret(ctx, secret.Name); err != nil && !errors.Is(err, fly.ErrNotFound) {
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
}

func NewRepository(store *db.DB, encryptionKey string) *Repository {
	return &Repository{db: store, encryptionKey: encryptionKey}
}

type Job struct {
	ID            string
	Type          string
	AggregateID   string
	PreviousState string
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
	AgentunnelToken        string
	AgentunnelClientID     string
	AgentunnelTunnelID     string
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
		row, err := tx.Queries().ClaimNextOrchestrationJob(ctx)
		if err != nil {
			return err
		}
		job = Job{ID: row.ID, Type: row.JobType, AggregateID: row.AggregateID}
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

func (r *Repository) CompleteJob(ctx context.Context, jobID string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().CompleteOrchestrationJob(ctx, jobID)
	})
}

func (r *Repository) FailJob(ctx context.Context, jobID string, cause error) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().RetryOrchestrationJob(ctx, dbsqlc.RetryOrchestrationJobParams{ID: jobID, LastError: cause.Error()})
	})
}

func (r *Repository) BlockJobAndRestoreProject(ctx context.Context, jobID, projectID, previousState string, cause error) error {
	if previousState == "" || previousState == "restarting" {
		previousState = "ready"
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if err := q.BlockOrchestrationJob(ctx, dbsqlc.BlockOrchestrationJobParams{ID: jobID, LastError: cause.Error()}); err != nil {
			return err
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
	agentunnelResource, err := r.agentunnelResource(ctx, intent.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ProjectIntent{}, err
	}
	intent.AgentunnelToken = agentunnelResource.MachineToken
	intent.AgentunnelClientID = agentunnelResource.ClientID
	intent.AgentunnelTunnelID = agentunnelResource.TunnelID
	return intent, nil
}

func (r *Repository) githubConfigToken(ctx context.Context, userID string) (string, error) {
	ciphertext, err := r.db.Queries().GetLatestGitHubTokenCiphertext(ctx, userID)
	if err != nil {
		return "", err
	}
	return secrets.Decrypt(r.encryptionKey, ciphertext)
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
	return secrets.Decrypt(r.encryptionKey, ciphertext)
}

type agentunnelResource struct {
	TunnelID     string
	ClientID     string
	MachineToken string
}

func (r *Repository) agentunnelResource(ctx context.Context, projectID string) (agentunnelResource, error) {
	row, err := r.db.Queries().GetOrchestrationAgentunnelResource(ctx, projectID)
	if err != nil {
		return agentunnelResource{}, err
	}
	resource := agentunnelResource{TunnelID: row.TunnelID, ClientID: row.ClientID}
	if strings.TrimSpace(row.MachineTokenCiphertext) == "" {
		return resource, nil
	}
	ciphertext, err := hex.DecodeString(row.MachineTokenCiphertext)
	if err != nil {
		return agentunnelResource{}, err
	}
	resource.MachineToken, err = secrets.Decrypt(r.encryptionKey, ciphertext)
	return resource, err
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
			_ = r.RecordMachineState(ctx, row.ProjectID, actual.State, mapProviderState(actual.State))
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
