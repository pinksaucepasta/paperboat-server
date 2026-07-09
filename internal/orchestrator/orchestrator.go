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
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
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
	observed, err := s.fly.StartMachine(ctx, machine.FlyMachineID)
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
		return err
	}
	if intent.PendingRestartApply {
		if _, err := s.fly.UpdateMachine(ctx, machine.FlyMachineID, s.machineSpec(intent, volume.FlyVolumeID)); err != nil {
			return err
		}
		if err := s.repo.ApplyRuntimeConfig(ctx, intent); err != nil {
			return err
		}
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
	return fly.MachineSpec{
		Name:       machineName,
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
		var payload []byte
		if err := tx.QueryRow(ctx, `
SELECT id, job_type, aggregate_id, payload
FROM orchestration_jobs
WHERE state = 'queued' AND next_run_at <= now()
  AND NOT EXISTS (
    SELECT 1
    FROM projects
    WHERE projects.id = orchestration_jobs.aggregate_id
      AND projects.state = 'deleted'
      AND orchestration_jobs.job_type <> 'project.delete'
  )
ORDER BY created_at
FOR UPDATE SKIP LOCKED
LIMIT 1`).Scan(&job.ID, &job.Type, &job.AggregateID, &payload); err != nil {
			return err
		}
		var decoded struct {
			PreviousState string `json:"previous_state"`
		}
		_ = json.Unmarshal(payload, &decoded)
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
		_, err := tx.Exec(ctx, `UPDATE orchestration_jobs SET state = 'succeeded', last_error = '', version = version + 1, updated_at = now() WHERE id = $1`, jobID)
		return err
	})
}

func (r *Repository) FailJob(ctx context.Context, jobID string, cause error) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE orchestration_jobs SET state = 'queued', attempts = attempts + 1, next_run_at = now() + interval '30 seconds', last_error = $2, version = version + 1, updated_at = now() WHERE id = $1`, jobID, cause.Error())
		return err
	})
}

func (r *Repository) BlockJobAndRestoreProject(ctx context.Context, jobID, projectID, previousState string, cause error) error {
	if previousState == "" || previousState == "restarting" {
		previousState = "ready"
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE orchestration_jobs SET state = 'blocked', attempts = attempts + 1, last_error = $2, version = version + 1, updated_at = now() WHERE id = $1`, jobID, cause.Error()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE projects SET state = $2, version = version + 1, updated_at = now() WHERE id = $1 AND state = 'restarting'`, projectID, previousState)
		return err
	})
}

func (r *Repository) ProjectIntent(ctx context.Context, projectID string) (ProjectIntent, error) {
	var intent ProjectIntent
	var presetsJSON []byte
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT p.id, p.user_id, pr.source_url, pr.default_branch, psa.assigned_gb,
       mt.code, mtv.vcpu, mtv.memory_mb, rg.code,
       coalesce(json_agg(vp.code ORDER BY vp.code) FILTER (WHERE vp.code IS NOT NULL), '[]'::json),
       ito.code, prc.setup_script_ref, prc.desired_config_hash, prc.pending_restart_apply
FROM paperboat.projects p
JOIN paperboat.project_repositories pr ON pr.project_id = p.id
JOIN paperboat.project_storage_allocations psa ON psa.project_id = p.id
JOIN paperboat.project_runtime_configs prc ON prc.project_id = p.id
JOIN paperboat.machine_type_versions mtv ON mtv.id = prc.machine_type_version_id
JOIN paperboat.machine_types mt ON mt.id = mtv.machine_type_id
JOIN paperboat.regions rg ON rg.id = prc.region_id
JOIN paperboat.idle_timeout_options ito ON ito.id = prc.idle_timeout_option_id
LEFT JOIN paperboat.vm_preset_versions vpv ON vpv.id = ANY(prc.preset_version_ids)
LEFT JOIN paperboat.vm_presets vp ON vp.id = vpv.preset_id
WHERE p.id = $1
GROUP BY p.id, pr.project_id, psa.project_id, prc.project_id, mt.code, mtv.vcpu, mtv.memory_mb, rg.code, ito.code`, projectID).Scan(&intent.ID, &intent.UserID, &intent.RepositoryURL, &intent.DefaultBranch, &intent.StorageGB, &intent.MachineTypeCode, &intent.VCPU, &intent.MemoryMB, &intent.RegionCode, &presetsJSON, &intent.IdleTimeoutCode, &intent.SetupScriptRef, &intent.DesiredConfigHash, &intent.PendingRestartApply)
	if err != nil {
		return ProjectIntent{}, err
	}
	_ = json.Unmarshal(presetsJSON, &intent.PresetCodes)
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
	var ciphertext []byte
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT token_ciphertext
FROM paperboat.github_oauth_tokens
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY updated_at DESC
LIMIT 1`, userID).Scan(&ciphertext)
	if err != nil {
		return "", err
	}
	return secrets.Decrypt(r.encryptionKey, ciphertext)
}

func (r *Repository) githubConfigRepo(ctx context.Context, userID string) (string, string, error) {
	var cloneURL, branch string
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT clone_url, default_branch
FROM paperboat.github_config_repositories
WHERE user_id = $1 AND provisioned_at IS NOT NULL
LIMIT 1`, userID).Scan(&cloneURL, &branch)
	return cloneURL, branch, err
}

func (r *Repository) setupScript(ctx context.Context, projectID, setupScriptRef string) (string, error) {
	if strings.TrimSpace(setupScriptRef) == "" {
		return "", nil
	}
	var ciphertext []byte
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT script_ciphertext
FROM paperboat.project_setup_script_revisions
WHERE project_id = $1 AND id = $2`, projectID, setupScriptRef).Scan(&ciphertext)
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
	var resource agentunnelResource
	var encoded string
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT tunnel_id, client_id, metadata->>'machine_token_ciphertext'
FROM paperboat.agentunnel_resources
WHERE project_id = $1`, projectID).Scan(&resource.TunnelID, &resource.ClientID, &encoded)
	if err != nil {
		return agentunnelResource{}, err
	}
	if strings.TrimSpace(encoded) == "" {
		return resource, nil
	}
	ciphertext, err := hex.DecodeString(encoded)
	if err != nil {
		return agentunnelResource{}, err
	}
	resource.MachineToken, err = secrets.Decrypt(r.encryptionKey, ciphertext)
	return resource, err
}

func (r *Repository) ProjectMachine(ctx context.Context, projectID string) (MachineRecord, error) {
	var machine MachineRecord
	err := r.db.SQL().QueryRowContext(ctx, `SELECT fly_machine_id, state FROM paperboat.fly_machines WHERE project_id = $1`, projectID).Scan(&machine.FlyMachineID, &machine.State)
	return machine, err
}

func (r *Repository) ProjectVolume(ctx context.Context, projectID string) (VolumeRecord, error) {
	var volume VolumeRecord
	err := r.db.SQL().QueryRowContext(ctx, `SELECT fly_volume_id, size_gb, state FROM paperboat.fly_volumes WHERE project_id = $1`, projectID).Scan(&volume.FlyVolumeID, &volume.SizeGB, &volume.State)
	return volume, err
}

func (r *Repository) RecordVolume(ctx context.Context, projectID, flyVolumeID string, sizeGB int, region, state string) (VolumeRecord, error) {
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO fly_volumes (id, project_id, fly_volume_id, size_gb, region, state)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (project_id) DO UPDATE SET fly_volume_id = fly_volumes.fly_volume_id
`, newID("flv"), projectID, flyVolumeID, sizeGB, region, state)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE project_storage_allocations SET fly_volume_id = $2, updated_at = now() WHERE project_id = $1`, projectID, flyVolumeID)
		return err
	})
	if err != nil {
		return VolumeRecord{}, err
	}
	return r.ProjectVolume(ctx, projectID)
}

func (r *Repository) RecordMachine(ctx context.Context, projectID, flyMachineID, state, imageRef, region, configHash string) (MachineRecord, error) {
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO fly_machines (id, project_id, fly_machine_id, state, image_ref, region, observed_config_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (project_id) DO UPDATE SET
    fly_machine_id = EXCLUDED.fly_machine_id,
    state = EXCLUDED.state,
    image_ref = EXCLUDED.image_ref,
    region = EXCLUDED.region,
    observed_config_hash = EXCLUDED.observed_config_hash,
    updated_at = now()
`, newID("flm"), projectID, flyMachineID, state, imageRef, region, configHash)
		return err
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
		if _, err := tx.Exec(ctx, `UPDATE projects SET state = 'stopped', version = version + 1, updated_at = now() WHERE id = $1 AND state <> 'deleted'`, intent.ID); err != nil {
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
	_, err := tx.Exec(ctx, `
UPDATE project_runtime_configs
SET applied_storage_gb = $2,
    applied_machine_type_version_id = machine_type_version_id,
    applied_preset_version_ids = preset_version_ids,
    applied_setup_script_ref = setup_script_ref,
    applied_idle_timeout_option_id = idle_timeout_option_id,
    applied_region_id = region_id,
    applied_config_hash = desired_config_hash,
    pending_restart_apply = false,
    version = version + 1,
    updated_at = now()
WHERE project_id = $1`, intent.ID, intent.StorageGB)
	return err
}

func (r *Repository) RecordMachineState(ctx context.Context, projectID, providerState, projectState string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE fly_machines SET state = $2, version = version + 1, updated_at = now() WHERE project_id = $1`, projectID, providerState); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE projects SET state = $2, version = version + 1, updated_at = now() WHERE id = $1 AND state <> 'deleted'`, projectID, projectState); err != nil {
			return err
		}
		return insertEvent(ctx, tx, projectID, "project."+projectState, "Project machine state changed.", map[string]any{"state": projectState, "provider_state": providerState})
	})
}

func (r *Repository) RemoveMachine(ctx context.Context, projectID string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM fly_machines WHERE project_id = $1`, projectID)
		return err
	})
}

func (r *Repository) RemoveVolume(ctx context.Context, projectID string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM fly_volumes WHERE project_id = $1`, projectID)
		return err
	})
}

func (r *Repository) MarkDeletedAndReleaseStorage(ctx context.Context, projectID string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var accountID string
		var assigned int
		if err := tx.QueryRow(ctx, `SELECT storage_account_id, assigned_gb FROM project_storage_allocations WHERE project_id = $1 FOR UPDATE`, projectID).Scan(&accountID, &assigned); err != nil {
			return err
		}
		var existing int
		key := "project.storage.release.delete:" + projectID
		err := tx.QueryRow(ctx, `SELECT amount_gb FROM storage_ledger_entries WHERE idempotency_key = $1`, key).Scan(&existing)
		if errors.Is(err, sql.ErrNoRows) {
			if _, err := tx.Exec(ctx, `UPDATE storage_accounts SET allocated_gb = allocated_gb - $2, version = version + 1, updated_at = now() WHERE id = $1`, accountID, assigned); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO storage_ledger_entries (id, account_id, entry_type, amount_gb, source_type, source_id, idempotency_key) VALUES ($1, $2, 'release', $3, 'project', $4, $5)`, newID("sled"), accountID, assigned, projectID, key); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE projects SET state = 'deleted', version = version + 1, updated_at = now() WHERE id = $1`, projectID); err != nil {
			return err
		}
		return insertEvent(ctx, tx, projectID, "project.deleted", "Project provider resources were removed and storage was released.", map[string]any{"storage_gb": assigned})
	})
}

func (r *Repository) StartReconciliation(ctx context.Context, run Run) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO reconciliation_runs (id, scope, state) VALUES ($1, $2, $3)`, run.ID, run.Scope, run.State)
		return err
	})
}

func (r *Repository) FinishReconciliation(ctx context.Context, run Run) error {
	b, _ := json.Marshal(run.Findings)
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE reconciliation_runs SET state = $2, findings = $3::jsonb, finished_at = now() WHERE id = $1`, run.ID, run.State, string(b))
		return err
	})
}

func (r *Repository) ReconcileFly(ctx context.Context, client fly.Client) ([]Finding, error) {
	rows, err := r.db.SQL().QueryContext(ctx, `SELECT project_id, fly_machine_id, state FROM paperboat.fly_machines`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []Finding
	knownMachineIDs := map[string]bool{}
	for rows.Next() {
		var projectID, machineID, storedState string
		if err := rows.Scan(&projectID, &machineID, &storedState); err != nil {
			return findings, err
		}
		knownMachineIDs[machineID] = true
		actual, err := client.GetMachine(ctx, machineID)
		if errors.Is(err, fly.ErrNotFound) {
			findings = append(findings, Finding{ProjectID: projectID, Severity: "error", Message: "fly machine missing"})
			continue
		}
		if err != nil {
			return findings, err
		}
		if actual.State != storedState {
			findings = append(findings, Finding{ProjectID: projectID, Severity: "warning", Message: fmt.Sprintf("machine state drift: stored=%s actual=%s", storedState, actual.State)})
			_ = r.RecordMachineState(ctx, projectID, actual.State, mapProviderState(actual.State))
		}
	}
	if err := rows.Err(); err != nil {
		return findings, err
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
		_, err := tx.Exec(ctx, `
INSERT INTO orchestration_jobs (id, job_type, aggregate_type, aggregate_id, idempotency_key, state, payload, last_error)
VALUES ($1, 'fly.orphan.remediate', 'fly_machine', $2, $3, 'needs_review', $4::jsonb, 'Operator approval required before deleting or adopting orphan Fly machine.')
ON CONFLICT (idempotency_key) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`,
			newID("job"), machine.ID, "fly.orphan.remediate:"+machine.ID, string(payload))
		return err
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
	_, err := tx.Exec(ctx, `INSERT INTO project_events (id, project_id, event_type, message, metadata) VALUES ($1, $2, $3, $4, $5::jsonb)`, newID("pevt"), projectID, eventType, message, string(b))
	return err
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
