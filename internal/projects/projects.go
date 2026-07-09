package projects

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

const MaxSetupScriptBytes = 64 * 1024

var (
	ErrIdempotencyKeyRequired = errors.New("idempotency key is required")
	ErrIdempotencyConflict    = errors.New("idempotency key conflicts with existing project")
	ErrVersionRequired        = errors.New("project version is required")
	ErrVersionConflict        = errors.New("project version conflicts with current project")
	ErrInvalidRepositoryURL   = errors.New("repository_url must be an https git url")
	ErrInvalidStorage         = errors.New("storage_gb must be positive")
	ErrInvalidSetupScript     = errors.New("setup script exceeds maximum size")
	ErrCatalogUnavailable     = errors.New("catalog entry is disabled or unavailable")
	ErrNotFound               = errors.New("project not found")
	ErrDeleted                = errors.New("project is deleted")
	ErrInvalidState           = errors.New("project state does not allow this operation")
	ErrInvalidKeepAlive       = errors.New("keep alive duration is outside configured bounds")
	ErrInvalidActivitySource  = errors.New("activity source is not accepted")
	ErrInsufficientStorage    = metering.ErrInsufficientStorage
	ErrInsufficientCredits    = errors.New("insufficient credits to start project")
)

type Service struct {
	repo                     *Repository
	audit                    *audit.Writer
	minimumStartCreditWindow time.Duration
	maxKeepAliveDuration     time.Duration
}

func NewService(store *db.DB, auditWriter *audit.Writer, cfg config.Config) *Service {
	return &Service{
		repo:                     NewRepository(store, cfg.Secrets.EncryptionKey),
		audit:                    auditWriter,
		minimumStartCreditWindow: cfg.Metering.MinimumStartCreditWindow,
		maxKeepAliveDuration:     cfg.Metering.MaxKeepAliveDuration,
	}
}

type CreateInput struct {
	UserID          string
	IdempotencyKey  string
	Name            string
	RepositoryURL   string
	DefaultBranch   string
	StorageGB       int
	MachineTypeCode string
	RegionCode      string
	PresetCodes     []string
	IdleTimeoutCode string
	SetupScript     string
}

type UpdateInput struct {
	UserID          string
	ProjectID       string
	ExpectedVersion *int64
	StorageGB       *int
	MachineTypeCode *string
	RegionCode      *string
	PresetCodes     *[]string
	IdleTimeoutCode *string
	SetupScript     *string
}

type ActivityInput struct {
	UserID     string
	ProjectID  string
	Source     string
	ObservedAt time.Time
	Metadata   map[string]any
}

type Project struct {
	ID                   string    `json:"id"`
	Version              int64     `json:"version"`
	Name                 string    `json:"name"`
	State                string    `json:"state"`
	Repository           Repo      `json:"repository"`
	CurrentConfig        Config    `json:"current_config"`
	DesiredConfig        Config    `json:"desired_config"`
	PendingRestartApply  bool      `json:"pending_restart_apply"`
	RestartRequired      bool      `json:"restart_required"`
	SetupScriptRevisions int       `json:"setup_script_revisions"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

func (p Project) normalized() Project {
	p.CurrentConfig = p.CurrentConfig.normalized()
	p.DesiredConfig = p.DesiredConfig.normalized()
	return p
}

type Repo struct {
	Provider      string `json:"provider"`
	SourceURL     string `json:"source_url"`
	DefaultBranch string `json:"default_branch"`
}

type Config struct {
	StorageGB       int      `json:"storage_gb"`
	MachineTypeCode string   `json:"machine_type_code"`
	RegionCode      string   `json:"region_code"`
	PresetCodes     []string `json:"preset_codes"`
	IdleTimeoutCode string   `json:"idle_timeout_code"`
	SetupScriptRef  string   `json:"setup_script_ref,omitempty"`
	ConfigHash      string   `json:"config_hash"`
}

func (c Config) normalized() Config {
	if c.PresetCodes == nil {
		c.PresetCodes = []string{}
	}
	return c
}

type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Message   string         `json:"message"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt time.Time      `json:"created_at"`
}

func (s *Service) Create(ctx context.Context, input CreateInput) (Project, bool, error) {
	if strings.TrimSpace(input.IdempotencyKey) == "" {
		return Project{}, false, ErrIdempotencyKeyRequired
	}
	normalized, err := validateCreateInput(input)
	if err != nil {
		return Project{}, false, err
	}
	requestHash := createRequestHash(normalized)
	if existing, ok, err := s.repo.FindByIdempotencyKey(ctx, input.UserID, input.IdempotencyKey, requestHash); err != nil || ok {
		return existing, ok, err
	}
	refs, err := s.repo.ResolveCatalog(ctx, normalized.MachineTypeCode, normalized.RegionCode, normalized.PresetCodes, normalized.IdleTimeoutCode)
	if err != nil {
		return Project{}, false, err
	}
	project, err := s.repo.CreateIntent(ctx, normalized, refs)
	if err != nil {
		if isUniqueViolation(err) {
			if existing, ok, readErr := s.repo.FindByIdempotencyKey(ctx, input.UserID, input.IdempotencyKey, requestHash); readErr == nil && ok {
				return existing, true, nil
			} else if errors.Is(readErr, ErrIdempotencyConflict) {
				return Project{}, false, readErr
			}
		}
		if errors.Is(err, metering.ErrInsufficientStorage) {
			return Project{}, false, ErrInsufficientStorage
		}
		return Project{}, false, err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: input.UserID, ActorType: audit.ActorUser, EventType: "project.created", ResourceType: "project", ResourceID: project.ID, IdempotencyKey: "project.created:" + input.IdempotencyKey, Metadata: map[string]any{"storage_gb": input.StorageGB}})
	return project.Project, false, nil
}

func (s *Service) List(ctx context.Context, userID string) ([]Project, error) {
	return s.repo.List(ctx, userID)
}

func (s *Service) Get(ctx context.Context, userID, projectID string) (Project, error) {
	return s.repo.Get(ctx, userID, projectID)
}

func (s *Service) Update(ctx context.Context, input UpdateInput) (Project, error) {
	current, err := s.repo.Get(ctx, input.UserID, input.ProjectID)
	if err != nil {
		return Project{}, err
	}
	if current.State == "deleted" || current.State == "deleting" {
		return Project{}, ErrDeleted
	}
	change, err := s.buildDesiredChange(ctx, current, input)
	if err != nil {
		return Project{}, err
	}
	if change.configHash == current.DesiredConfig.ConfigHash {
		if err := s.repo.CheckUpdateVersion(ctx, input.UserID, input.ProjectID, input.ExpectedVersion); err != nil {
			return Project{}, err
		}
		return current, nil
	}
	project, err := s.repo.UpdateDesiredConfig(ctx, input.UserID, input.ProjectID, change, input.ExpectedVersion)
	if err != nil {
		return Project{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: input.UserID, ActorType: audit.ActorUser, EventType: "project.updated", ResourceType: "project", ResourceID: input.ProjectID, IdempotencyKey: "project.updated:" + input.ProjectID + ":" + project.DesiredConfig.ConfigHash, Metadata: map[string]any{"restart_required": project.RestartRequired}})
	return project, nil
}

func (s *Service) Delete(ctx context.Context, userID, projectID string) (Project, error) {
	project, err := s.repo.MarkDeleting(ctx, userID, projectID)
	if err != nil {
		return Project{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "project.delete_requested", ResourceType: "project", ResourceID: projectID, IdempotencyKey: "project.delete_requested:" + projectID, Metadata: map[string]any{"storage_release_deferred": project.State == "deleting"}})
	return project, nil
}

func (s *Service) Start(ctx context.Context, userID, projectID string) (Project, error) {
	if err := s.repo.EnsureStartCredits(ctx, userID, projectID, s.minimumStartCreditWindow, false); err != nil {
		return Project{}, err
	}
	project, err := s.repo.QueueLifecycleJob(ctx, userID, projectID, "project.start", "starting")
	if err != nil {
		return Project{}, err
	}
	_ = s.repo.RecordActivity(ctx, projectID, time.Now().UTC(), "connect_session", map[string]any{"trigger": "project.start"})
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "project.start_requested", ResourceType: "project", ResourceID: projectID, IdempotencyKey: "project.start_requested:" + projectID + ":" + project.UpdatedAt.Format(time.RFC3339Nano)})
	return project, nil
}

func (s *Service) Stop(ctx context.Context, userID, projectID string) (Project, error) {
	project, err := s.repo.QueueLifecycleJob(ctx, userID, projectID, "project.stop", "stopping")
	if err != nil {
		return Project{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "project.stop_requested", ResourceType: "project", ResourceID: projectID, IdempotencyKey: "project.stop_requested:" + projectID + ":" + project.UpdatedAt.Format(time.RFC3339Nano)})
	return project, nil
}

func (s *Service) Restart(ctx context.Context, userID, projectID string) (Project, error) {
	if err := s.repo.EnsureStartCredits(ctx, userID, projectID, s.minimumStartCreditWindow, true); err != nil {
		return Project{}, err
	}
	project, err := s.repo.QueueLifecycleJob(ctx, userID, projectID, "project.restart", "restarting")
	if err != nil {
		return Project{}, err
	}
	_ = s.repo.RecordActivity(ctx, projectID, time.Now().UTC(), "connect_session", map[string]any{"trigger": "project.restart"})
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "project.restart_requested", ResourceType: "project", ResourceID: projectID, IdempotencyKey: "project.restart_requested:" + projectID + ":" + project.UpdatedAt.Format(time.RFC3339Nano)})
	return project, nil
}

func (s *Service) Events(ctx context.Context, userID, projectID string) ([]Event, error) {
	return s.repo.Events(ctx, userID, projectID)
}

func (s *Service) RecordClientActivity(ctx context.Context, input ActivityInput) (Project, error) {
	source := strings.TrimSpace(input.Source)
	switch source {
	case "papercode_activity", "cli_activity":
	default:
		return Project{}, ErrInvalidActivitySource
	}
	project, err := s.repo.Get(ctx, input.UserID, input.ProjectID)
	if err != nil {
		return Project{}, err
	}
	if project.State == "deleted" || project.State == "deleting" {
		return Project{}, ErrDeleted
	}
	metadata := input.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	if !input.ObservedAt.IsZero() {
		metadata["client_observed_at"] = input.ObservedAt.UTC().Format(time.RFC3339Nano)
	}
	if err := s.repo.RecordActivity(ctx, input.ProjectID, time.Now().UTC(), source, metadata); err != nil {
		return Project{}, err
	}
	return project, nil
}

func (s *Service) SetKeepAlive(ctx context.Context, userID, projectID string, duration time.Duration) (Project, *time.Time, error) {
	if duration < 0 || duration > s.maxKeepAliveDuration {
		return Project{}, nil, ErrInvalidKeepAlive
	}
	project, err := s.repo.Get(ctx, userID, projectID)
	if err != nil {
		return Project{}, nil, err
	}
	if project.State == "deleted" || project.State == "deleting" {
		return Project{}, nil, ErrDeleted
	}
	var until *time.Time
	if duration > 0 {
		t := time.Now().UTC().Add(duration)
		until = &t
	}
	if err := s.repo.SetKeepAlive(ctx, userID, projectID, until); err != nil {
		return Project{}, nil, err
	}
	eventType := "project.keep_alive_cleared"
	metadata := map[string]any{}
	if until != nil {
		eventType = "project.keep_alive_set"
		metadata["keep_alive_until"] = until.UTC().Format(time.RFC3339Nano)
		metadata["duration_seconds"] = int(duration.Seconds())
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: eventType, ResourceType: "project", ResourceID: projectID, IdempotencyKey: eventType + ":" + projectID + ":" + time.Now().UTC().Format(time.RFC3339Nano), Metadata: metadata})
	return project, until, nil
}

func (s *Service) buildDesiredChange(ctx context.Context, current Project, input UpdateInput) (desiredChange, error) {
	storageGB := current.DesiredConfig.StorageGB
	if input.StorageGB != nil {
		if *input.StorageGB <= 0 {
			return desiredChange{}, ErrInvalidStorage
		}
		storageGB = *input.StorageGB
	}
	machine := current.DesiredConfig.MachineTypeCode
	if input.MachineTypeCode != nil {
		machine = strings.TrimSpace(*input.MachineTypeCode)
	}
	region := current.DesiredConfig.RegionCode
	if input.RegionCode != nil {
		region = strings.TrimSpace(*input.RegionCode)
	}
	presets := slices.Clone(current.DesiredConfig.PresetCodes)
	if input.PresetCodes != nil {
		presets = normalizeCodes(*input.PresetCodes)
	}
	idle := current.DesiredConfig.IdleTimeoutCode
	if input.IdleTimeoutCode != nil {
		idle = strings.TrimSpace(*input.IdleTimeoutCode)
	}
	var script *setupScript
	if input.SetupScript != nil {
		normalized := strings.TrimRight(*input.SetupScript, "\n")
		if len([]byte(normalized)) > MaxSetupScriptBytes {
			return desiredChange{}, ErrInvalidSetupScript
		}
		if strings.TrimSpace(normalized) != "" {
			script = &setupScript{plain: normalized, sha256: sha256Hex(normalized)}
		}
	}
	refs, err := s.repo.ResolveCatalog(ctx, machine, region, presets, idle)
	if err != nil {
		return desiredChange{}, err
	}
	desired := configHashInput{StorageGB: storageGB, MachineVersionID: refs.machineTypeVersionID, RegionID: refs.regionID, PresetVersionIDs: refs.presetVersionIDs, IdleTimeoutID: refs.idleTimeoutID}
	if script != nil {
		desired.SetupScriptSHA256 = script.sha256
	} else {
		desired.SetupScriptRef = current.DesiredConfig.SetupScriptRef
	}
	return desiredChange{storageGB: storageGB, refs: refs, setup: script, configHash: hashConfig(desired), restartRequired: true}, nil
}

func validateCreateInput(input CreateInput) (CreateInput, error) {
	input.RepositoryURL = strings.TrimSpace(input.RepositoryURL)
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		input.Name = defaultProjectName(input.RepositoryURL)
	}
	if !validRepositoryURL(input.RepositoryURL) {
		return input, ErrInvalidRepositoryURL
	}
	if input.StorageGB <= 0 {
		return input, ErrInvalidStorage
	}
	input.SetupScript = strings.TrimRight(input.SetupScript, "\n")
	if len([]byte(input.SetupScript)) > MaxSetupScriptBytes {
		return input, ErrInvalidSetupScript
	}
	input.MachineTypeCode = strings.TrimSpace(input.MachineTypeCode)
	input.RegionCode = strings.TrimSpace(input.RegionCode)
	input.IdleTimeoutCode = strings.TrimSpace(input.IdleTimeoutCode)
	input.PresetCodes = normalizeCodes(input.PresetCodes)
	input.DefaultBranch = strings.TrimSpace(input.DefaultBranch)
	return input, nil
}

func validRepositoryURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return false
	}
	return strings.HasSuffix(u.Path, ".git") || strings.Count(strings.Trim(u.Path, "/"), "/") >= 1
}

func defaultProjectName(repoURL string) string {
	u, err := url.Parse(repoURL)
	if err != nil {
		return "Project"
	}
	name := strings.TrimSuffix(strings.Trim(strings.TrimSpace(u.Path), "/"), ".git")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		return "Project"
	}
	return name
}

func normalizeCodes(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func hashConfig(input configHashInput) string {
	b, _ := json.Marshal(input)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func createRequestHash(input CreateInput) string {
	setupSHA := ""
	if strings.TrimSpace(input.SetupScript) != "" {
		setupSHA = sha256Hex(strings.TrimRight(input.SetupScript, "\n"))
	}
	b, _ := json.Marshal(createRequestHashInput{
		Name:            input.Name,
		RepositoryURL:   input.RepositoryURL,
		DefaultBranch:   input.DefaultBranch,
		StorageGB:       input.StorageGB,
		MachineTypeCode: input.MachineTypeCode,
		RegionCode:      input.RegionCode,
		PresetCodes:     input.PresetCodes,
		IdleTimeoutCode: input.IdleTimeoutCode,
		SetupScriptSHA:  setupSHA,
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

type persistedProject struct {
	Project
}

type storageAllocation struct {
	accountID      string
	assignedGB     int
	version        int64
	projectVersion int64
	state          string
}

type catalogRefs struct {
	machineTypeVersionID string
	regionID             string
	presetVersionIDs     []string
	idleTimeoutID        string
}

type setupScript struct {
	plain  string
	sha256 string
}

type desiredChange struct {
	storageGB       int
	refs            catalogRefs
	setup           *setupScript
	configHash      string
	restartRequired bool
}

type configHashInput struct {
	StorageGB         int      `json:"storage_gb"`
	MachineVersionID  string   `json:"machine_type_version_id"`
	RegionID          string   `json:"region_id"`
	PresetVersionIDs  []string `json:"preset_version_ids"`
	IdleTimeoutID     string   `json:"idle_timeout_id"`
	SetupScriptRef    string   `json:"setup_script_ref,omitempty"`
	SetupScriptSHA256 string   `json:"setup_script_sha256,omitempty"`
}

type createRequestHashInput struct {
	Name            string   `json:"name"`
	RepositoryURL   string   `json:"repository_url"`
	DefaultBranch   string   `json:"default_branch"`
	StorageGB       int      `json:"storage_gb"`
	MachineTypeCode string   `json:"machine_type_code"`
	RegionCode      string   `json:"region_code"`
	PresetCodes     []string `json:"preset_codes"`
	IdleTimeoutCode string   `json:"idle_timeout_code"`
	SetupScriptSHA  string   `json:"setup_script_sha256,omitempty"`
}

type Repository struct {
	db            *db.DB
	encryptionKey string
}

func NewRepository(store *db.DB, encryptionKey string) *Repository {
	return &Repository{db: store, encryptionKey: encryptionKey}
}

func (r *Repository) FindByIdempotencyKey(ctx context.Context, userID, key, requestHash string) (Project, bool, error) {
	var id, existingHash string
	err := r.db.SQL().QueryRowContext(ctx, `SELECT id, create_request_hash FROM paperboat.projects WHERE user_id = $1 AND idempotency_key = $2`, userID, key).Scan(&id, &existingHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, false, nil
	}
	if err != nil {
		return Project{}, false, fmt.Errorf("find project idempotency key: %w", err)
	}
	if existingHash != requestHash {
		return Project{}, true, ErrIdempotencyConflict
	}
	project, err := r.Get(ctx, userID, id)
	return project, true, err
}

func (r *Repository) ResolveCatalog(ctx context.Context, machineTypeCode, regionCode string, presetCodes []string, idleTimeoutCode string) (catalogRefs, error) {
	refs := catalogRefs{presetVersionIDs: []string{}}
	if machineTypeCode == "" || regionCode == "" || idleTimeoutCode == "" {
		return refs, ErrCatalogUnavailable
	}
	if err := r.db.SQL().QueryRowContext(ctx, `
SELECT mt.current_version_id
FROM paperboat.machine_types mt
WHERE mt.code = $1 AND mt.active AND mt.current_version_id IS NOT NULL`, machineTypeCode).Scan(&refs.machineTypeVersionID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return refs, ErrCatalogUnavailable
		}
		return refs, err
	}
	if err := r.db.SQL().QueryRowContext(ctx, `SELECT id FROM paperboat.regions WHERE code = $1 AND enabled`, regionCode).Scan(&refs.regionID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return refs, ErrCatalogUnavailable
		}
		return refs, err
	}
	if err := r.db.SQL().QueryRowContext(ctx, `SELECT id FROM paperboat.idle_timeout_options WHERE code = $1 AND active`, idleTimeoutCode).Scan(&refs.idleTimeoutID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return refs, ErrCatalogUnavailable
		}
		return refs, err
	}
	for _, code := range presetCodes {
		var versionID string
		if err := r.db.SQL().QueryRowContext(ctx, `
SELECT current_version_id
FROM paperboat.vm_presets
WHERE code = $1 AND active AND current_version_id IS NOT NULL`, code).Scan(&versionID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return refs, ErrCatalogUnavailable
			}
			return refs, err
		}
		refs.presetVersionIDs = append(refs.presetVersionIDs, versionID)
	}
	return refs, nil
}

func (r *Repository) CreateIntent(ctx context.Context, input CreateInput, refs catalogRefs) (persistedProject, error) {
	var projectID string
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		projectID, err = r.createIntentOnce(ctx, input, refs)
		if !isSerializationFailure(err) {
			break
		}
	}
	if err != nil {
		return persistedProject{}, err
	}
	project, err := r.Get(ctx, input.UserID, projectID)
	return persistedProject{Project: project}, err
}

func (r *Repository) createIntentOnce(ctx context.Context, input CreateInput, refs catalogRefs) (string, error) {
	projectID := newID("prj")
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		accountID, err := ensureStorageAccount(ctx, tx, input.UserID)
		if err != nil {
			return err
		}
		if err := ensureFreeStorage(ctx, tx, input.UserID, accountID); err != nil {
			return err
		}
		setupRef := ""
		setupSHA := ""
		if strings.TrimSpace(input.SetupScript) != "" {
			setupSHA = sha256Hex(strings.TrimRight(input.SetupScript, "\n"))
			setupRef = newID("pss")
		}
		hash := hashConfig(configHashInput{StorageGB: input.StorageGB, MachineVersionID: refs.machineTypeVersionID, RegionID: refs.regionID, PresetVersionIDs: refs.presetVersionIDs, IdleTimeoutID: refs.idleTimeoutID, SetupScriptRef: setupRef, SetupScriptSHA256: setupSHA})
		if _, err := tx.Exec(ctx, `INSERT INTO projects (id, user_id, name, state, idempotency_key, create_request_hash) VALUES ($1, $2, $3, 'creating', $4, $5)`, projectID, input.UserID, input.Name, input.IdempotencyKey, createRequestHash(input)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO project_repositories (project_id, provider, source_url, default_branch) VALUES ($1, 'github', $2, $3)`, projectID, input.RepositoryURL, input.DefaultBranch); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO project_storage_allocations (project_id, storage_account_id, assigned_gb) VALUES ($1, $2, $3)`, projectID, accountID, input.StorageGB); err != nil {
			return err
		}
		if err := reserveStorageTx(ctx, tx, accountID, projectID, input.StorageGB, "project.storage.allocate:"+projectID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO project_runtime_configs (project_id, machine_type_version_id, preset_version_ids, setup_script_ref, idle_timeout_option_id, region_id, pending_restart_apply, desired_config_hash)
VALUES ($1, $2, $3, $4, $5, $6, true, $7)`, projectID, refs.machineTypeVersionID, refs.presetVersionIDs, setupRef, refs.idleTimeoutID, refs.regionID, hash); err != nil {
			return err
		}
		if setupRef != "" {
			ciphertext, err := secrets.Encrypt(r.encryptionKey, input.SetupScript)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
INSERT INTO project_setup_script_revisions (id, project_id, revision_number, script_sha256, script_ciphertext, guidance, created_by_user_id)
VALUES ($1, $2, 1, $3, $4, $5, $6)`, setupRef, projectID, setupSHA, ciphertext, "Do not include secrets in setup scripts; use provider-managed project credentials for secret material.", input.UserID); err != nil {
				return err
			}
		}
		if err := insertEvent(ctx, tx, projectID, "project.created", "Project intent was recorded.", map[string]any{"state": "creating"}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE projects SET state = 'provisioning_storage', version = version + 1, updated_at = now() WHERE id = $1 AND user_id = $2`, projectID, input.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO orchestration_jobs (id, job_type, aggregate_type, aggregate_id, idempotency_key, state, payload)
VALUES ($1, 'project.create', 'project', $2, $3, 'queued', $4::jsonb)
ON CONFLICT (idempotency_key) DO NOTHING`, newID("job"), projectID, "project.create:"+projectID, `{"phase":"provision_storage"}`); err != nil {
			return err
		}
		return insertEvent(ctx, tx, projectID, "project.provisioning_queued", "Project provisioning was queued.", map[string]any{"state": "provisioning_storage"})
	})
	return projectID, err
}

func (r *Repository) List(ctx context.Context, userID string) ([]Project, error) {
	rows, err := r.db.SQL().QueryContext(ctx, `
SELECT p.id
FROM paperboat.projects p
WHERE p.user_id = $1 AND p.state <> 'deleted'
ORDER BY p.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		project, err := r.Get(ctx, userID, id)
		if err != nil {
			return nil, err
		}
		out = append(out, project)
	}
	return out, rows.Err()
}

func (r *Repository) Get(ctx context.Context, userID, projectID string) (Project, error) {
	row := r.db.SQL().QueryRowContext(ctx, projectSelectSQL+` WHERE p.id = $1 AND p.user_id = $2 `+projectGroupSQL, projectID, userID)
	return scanProject(row)
}

func (r *Repository) UpdateDesiredConfig(ctx context.Context, userID, projectID string, change desiredChange, expectedVersion *int64) (Project, error) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = r.updateDesiredConfigOnce(ctx, userID, projectID, change, expectedVersion)
		if !isSerializationFailure(err) {
			break
		}
	}
	if err != nil {
		return Project{}, err
	}
	return r.Get(ctx, userID, projectID)
}

func (r *Repository) CheckUpdateVersion(ctx context.Context, userID, projectID string, expectedVersion *int64) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		allocation, err := projectStorageAllocationTx(ctx, tx, userID, projectID)
		if err != nil {
			return err
		}
		if expectedVersion != nil && allocation.projectVersion != *expectedVersion {
			return ErrVersionConflict
		}
		if allocation.state == "deleting" || allocation.state == "deleted" {
			return ErrDeleted
		}
		return nil
	})
}

func (r *Repository) updateDesiredConfigOnce(ctx context.Context, userID, projectID string, change desiredChange, expectedVersion *int64) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		allocation, err := projectStorageAllocationTx(ctx, tx, userID, projectID)
		if err != nil {
			return err
		}
		if expectedVersion != nil && allocation.projectVersion != *expectedVersion {
			return ErrVersionConflict
		}
		if allocation.state == "deleting" || allocation.state == "deleted" {
			return ErrDeleted
		}
		delta := change.storageGB - allocation.assignedGB
		resizeKey := fmt.Sprintf("project.storage.resize:%s:%d:%d:%d", projectID, allocation.version, allocation.assignedGB, change.storageGB)
		switch {
		case delta > 0:
			if err := reserveStorageTx(ctx, tx, allocation.accountID, projectID, delta, resizeKey); err != nil {
				return err
			}
		case delta < 0:
			if err := releaseStorageReservationTx(ctx, tx, allocation.accountID, projectID, -delta, resizeKey); err != nil {
				return err
			}
		}
		if change.setup != nil {
			var next int
			if err := tx.QueryRow(ctx, `SELECT coalesce(max(revision_number), 0) + 1 FROM project_setup_script_revisions WHERE project_id = $1`, projectID).Scan(&next); err != nil {
				return err
			}
			ref := newID("pss")
			ciphertext, err := secrets.Encrypt(r.encryptionKey, change.setup.plain)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
INSERT INTO project_setup_script_revisions (id, project_id, revision_number, script_sha256, script_ciphertext, guidance, created_by_user_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)`, ref, projectID, next, change.setup.sha256, ciphertext, "Do not include secrets in setup scripts; use provider-managed project credentials for secret material.", userID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE project_runtime_configs SET setup_script_ref = $2 WHERE project_id = $1`, projectID, ref); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
UPDATE project_runtime_configs
SET machine_type_version_id = $3,
    preset_version_ids = $4,
    idle_timeout_option_id = $5,
    region_id = $6,
    pending_restart_apply = true,
    desired_config_hash = $7,
    version = version + 1,
    updated_at = now()
WHERE project_id = $1 AND EXISTS (SELECT 1 FROM projects WHERE id = $1 AND user_id = $2)`, projectID, userID, change.refs.machineTypeVersionID, change.refs.presetVersionIDs, change.refs.idleTimeoutID, change.refs.regionID, change.configHash); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
UPDATE project_storage_allocations
SET assigned_gb = $3, version = version + 1, updated_at = now()
WHERE project_id = $1 AND EXISTS (SELECT 1 FROM projects WHERE id = $1 AND user_id = $2)`, projectID, userID, change.storageGB); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE projects SET version = version + 1, updated_at = now() WHERE id = $1 AND user_id = $2`, projectID, userID); err != nil {
			return err
		}
		return insertEvent(ctx, tx, projectID, "project.config_updated", "Desired project configuration was updated.", map[string]any{"restart_required": true})
	})
}

func projectStorageAllocationTx(ctx context.Context, tx *db.Tx, userID, projectID string) (storageAllocation, error) {
	var allocation storageAllocation
	err := tx.QueryRow(ctx, `
SELECT psa.storage_account_id, psa.assigned_gb, psa.version, p.version, p.state
FROM project_storage_allocations psa
JOIN projects p ON p.id = psa.project_id
WHERE p.id = $1 AND p.user_id = $2
FOR UPDATE OF p, psa`, projectID, userID).Scan(&allocation.accountID, &allocation.assignedGB, &allocation.version, &allocation.projectVersion, &allocation.state)
	if errors.Is(err, sql.ErrNoRows) {
		return storageAllocation{}, ErrNotFound
	}
	if err != nil {
		return storageAllocation{}, err
	}
	return allocation, nil
}

func reserveStorageTx(ctx context.Context, tx *db.Tx, accountID, projectID string, amountGB int, idempotencyKey string) error {
	var existing int
	err := tx.QueryRow(ctx, `
SELECT amount_gb
FROM storage_ledger_entries
WHERE idempotency_key = $1 AND account_id = $2 AND source_type = 'project' AND source_id = $3 AND entry_type = 'allocation'`, idempotencyKey, accountID, projectID).Scan(&existing)
	if err == nil {
		if existing == amountGB {
			return nil
		}
		return ErrIdempotencyConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var included, purchased, allocated int
	if err := tx.QueryRow(ctx, `SELECT included_gb, purchased_gb, allocated_gb FROM storage_accounts WHERE id = $1 FOR UPDATE`, accountID).Scan(&included, &purchased, &allocated); err != nil {
		return err
	}
	if allocated+amountGB > included+purchased {
		return ErrInsufficientStorage
	}
	if _, err := tx.Exec(ctx, `UPDATE storage_accounts SET allocated_gb = allocated_gb + $2, version = version + 1, updated_at = now() WHERE id = $1`, accountID, amountGB); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO storage_ledger_entries (id, account_id, entry_type, amount_gb, source_type, source_id, idempotency_key)
VALUES ($1, $2, 'allocation', $3, 'project', $4, $5)`, newID("sled"), accountID, amountGB, projectID, idempotencyKey)
	return err
}

func releaseStorageReservationTx(ctx context.Context, tx *db.Tx, accountID, projectID string, amountGB int, idempotencyKey string) error {
	var existing int
	err := tx.QueryRow(ctx, `
SELECT amount_gb
FROM storage_ledger_entries
WHERE idempotency_key = $1 AND account_id = $2 AND source_type = 'project' AND source_id = $3 AND entry_type = 'release'`, idempotencyKey, accountID, projectID).Scan(&existing)
	if err == nil {
		if existing == amountGB {
			return nil
		}
		return ErrIdempotencyConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var allocated int
	if err := tx.QueryRow(ctx, `SELECT allocated_gb FROM storage_accounts WHERE id = $1 FOR UPDATE`, accountID).Scan(&allocated); err != nil {
		return err
	}
	if allocated < amountGB {
		return fmt.Errorf("storage release exceeds allocated storage")
	}
	if _, err := tx.Exec(ctx, `UPDATE storage_accounts SET allocated_gb = allocated_gb - $2, version = version + 1, updated_at = now() WHERE id = $1`, accountID, amountGB); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO storage_ledger_entries (id, account_id, entry_type, amount_gb, source_type, source_id, idempotency_key)
VALUES ($1, $2, 'release', $3, 'project', $4, $5)`, newID("sled"), accountID, amountGB, projectID, idempotencyKey)
	return err
}

func (r *Repository) MarkDeleting(ctx context.Context, userID, projectID string) (Project, error) {
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		res, err := tx.Exec(ctx, `UPDATE projects SET state = 'deleting', version = version + 1, updated_at = now() WHERE id = $1 AND user_id = $2 AND state <> 'deleted'`, projectID, userID)
		if err != nil {
			return err
		}
		affected, _ := res.RowsAffected()
		if affected == 0 {
			return ErrNotFound
		}
		// Deletion supersedes any lifecycle work still waiting in the queue;
		// a stale create/start/restart must never run for a deleting project.
		if _, err := tx.Exec(ctx, `
UPDATE orchestration_jobs SET state = 'superseded', updated_at = now()
WHERE aggregate_type = 'project' AND aggregate_id = $1 AND state = 'queued' AND job_type <> 'project.delete'`, projectID); err != nil {
			return err
		}
		var provisioned bool
		if err := tx.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM fly_volumes WHERE project_id = $1)
    OR EXISTS (SELECT 1 FROM fly_machines WHERE project_id = $1)
    OR EXISTS (SELECT 1 FROM agentunnel_resources WHERE project_id = $1)`, projectID).Scan(&provisioned); err != nil {
			return err
		}
		if provisioned {
			if _, err := tx.Exec(ctx, `
INSERT INTO orchestration_jobs (id, job_type, aggregate_type, aggregate_id, idempotency_key, state, payload)
VALUES ($1, 'project.delete', 'project', $2, $3, 'queued', '{}'::jsonb)
ON CONFLICT (idempotency_key) DO NOTHING`, newID("job"), projectID, "project.delete:"+projectID); err != nil {
				return err
			}
			return insertEvent(ctx, tx, projectID, "project.delete_queued", "Project deletion was queued.", map[string]any{"storage_release": "after_provider_cleanup"})
		}
		// Nothing exists at the provider yet: delete inline and release the
		// storage allocation immediately instead of queueing orchestration.
		return markDeletedAndReleaseStorageTx(ctx, tx, projectID)
	})
	if err != nil {
		return Project{}, err
	}
	return r.Get(ctx, userID, projectID)
}

// markDeletedAndReleaseStorageTx finalizes deletion of a project with no
// provider resources: the storage allocation returns to the user's pool (once,
// keyed by the same ledger idempotency key the orchestrator uses) and the
// project is marked deleted.
func markDeletedAndReleaseStorageTx(ctx context.Context, tx *db.Tx, projectID string) error {
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
	return insertEvent(ctx, tx, projectID, "project.deleted", "Project was deleted before provisioning; storage was released.", map[string]any{"storage_gb": assigned})
}

func (r *Repository) QueueLifecycleJob(ctx context.Context, userID, projectID, jobType, nextState string) (Project, error) {
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM projects WHERE id = $1 AND user_id = $2 FOR UPDATE`, projectID, userID).Scan(&state); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if state == "deleted" || state == "deleting" {
			return ErrDeleted
		}
		if state == "creating" || state == "provisioning_storage" || state == "provisioning_machine" || state == "failed" || state == "suspended" {
			return ErrInvalidState
		}
		if _, err := tx.Exec(ctx, `UPDATE projects SET state = $3, version = version + 1, updated_at = now() WHERE id = $1 AND user_id = $2`, projectID, userID, nextState); err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]string{"previous_state": state})
		if _, err := tx.Exec(ctx, `
INSERT INTO orchestration_jobs (id, job_type, aggregate_type, aggregate_id, idempotency_key, state, payload)
VALUES ($1, $2, 'project', $3, $4, 'queued', $5::jsonb)
ON CONFLICT (idempotency_key) DO UPDATE SET state = 'queued', payload = EXCLUDED.payload, next_run_at = now(), updated_at = now()`, newID("job"), jobType, projectID, jobType+":"+projectID, string(payload)); err != nil {
			return err
		}
		return insertEvent(ctx, tx, projectID, jobType+"_queued", "Project lifecycle operation was queued.", map[string]any{"state": nextState})
	})
	if err != nil {
		return Project{}, err
	}
	return r.Get(ctx, userID, projectID)
}

func (r *Repository) EnsureStartCredits(ctx context.Context, userID, projectID string, window time.Duration, useDesiredConfig bool) error {
	if window <= 0 {
		return fmt.Errorf("minimum start credit window must be positive")
	}
	var enough bool
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT coalesce(ca.balance, 0)::numeric >= ((($3::numeric / 3600.0) * mtv.credit_weight)::numeric(18,6))
FROM paperboat.projects p
JOIN paperboat.project_runtime_configs prc ON prc.project_id = p.id
JOIN paperboat.machine_type_versions mtv ON mtv.id = CASE WHEN $4 THEN prc.machine_type_version_id ELSE prc.applied_machine_type_version_id END
LEFT JOIN paperboat.credit_accounts ca ON ca.user_id = p.user_id
WHERE p.id = $1 AND p.user_id = $2`, projectID, userID, int(window.Seconds()), useDesiredConfig).Scan(&enough)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !enough {
		return ErrInsufficientCredits
	}
	return nil
}

func (r *Repository) RecordActivity(ctx context.Context, projectID string, at time.Time, source string, metadata map[string]any) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("activity source is required")
	}
	if !validActivitySource(source) {
		return fmt.Errorf("activity source %q is not accepted", source)
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	b, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO project_activity_markers (project_id, last_activity_at, source, metadata)
VALUES ($1, $2, $3, $4::jsonb)
ON CONFLICT (project_id) DO UPDATE
SET last_activity_at = greatest(project_activity_markers.last_activity_at, EXCLUDED.last_activity_at),
    source = EXCLUDED.source,
    metadata = EXCLUDED.metadata,
    updated_at = now()`, projectID, at, source, string(b))
		return err
	})
}

func (r *Repository) SetKeepAlive(ctx context.Context, userID, projectID string, until *time.Time) error {
	if _, err := r.Get(ctx, userID, projectID); err != nil {
		return err
	}
	var value any
	eventType := "project.keep_alive_cleared"
	message := "Project keep-alive pin was cleared."
	metadata := map[string]any{}
	if until != nil {
		value = until.UTC()
		eventType = "project.keep_alive_set"
		message = "Project keep-alive pin was set."
		metadata["keep_alive_until"] = until.UTC().Format(time.RFC3339Nano)
	} else {
		value = nil
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO project_activity_markers (project_id, last_activity_at, source, metadata, keep_alive_until, idle_warning_sent_at)
VALUES ($1, now(), 'connect_session', '{}'::jsonb, $2, NULL)
ON CONFLICT (project_id) DO UPDATE
SET keep_alive_until = EXCLUDED.keep_alive_until,
    idle_warning_sent_at = NULL,
    updated_at = now()`, projectID, value)
		if err != nil {
			return err
		}
		return insertEvent(ctx, tx, projectID, eventType, message, metadata)
	})
}

func validActivitySource(source string) bool {
	switch source {
	case "connect_session", "agentunnel_connection", "papercode_activity", "cli_activity", "vm_heartbeat":
		return true
	default:
		return false
	}
}

func (r *Repository) Events(ctx context.Context, userID, projectID string) ([]Event, error) {
	if _, err := r.Get(ctx, userID, projectID); err != nil {
		return nil, err
	}
	rows, err := r.db.SQL().QueryContext(ctx, `
SELECT id, event_type, message, metadata, created_at
FROM paperboat.project_events
WHERE project_id = $1
ORDER BY created_at ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var event Event
		var metadata []byte
		if err := rows.Scan(&event.ID, &event.Type, &event.Message, &metadata, &event.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(metadata, &event.Metadata)
		if event.Metadata == nil {
			event.Metadata = map[string]any{}
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

const projectSelectSQL = `
SELECT p.id, p.version, p.name, p.state, p.created_at, p.updated_at,
       pr.provider, pr.source_url, pr.default_branch,
       psa.assigned_gb,
       mt.code, r.code, coalesce(string_agg(DISTINCT vp.code, ',' ORDER BY vp.code) FILTER (WHERE vp.code IS NOT NULL), '') AS preset_codes,
       ito.code, prc.setup_script_ref, prc.pending_restart_apply, prc.desired_config_hash, prc.applied_config_hash,
       prc.applied_storage_gb,
       coalesce(amt.code, ''), coalesce(ar.code, ''), coalesce(string_agg(DISTINCT avp.code, ',' ORDER BY avp.code) FILTER (WHERE avp.code IS NOT NULL), '') AS applied_preset_codes,
       coalesce(aito.code, ''), prc.applied_setup_script_ref,
       (SELECT count(*) FROM paperboat.project_setup_script_revisions psr WHERE psr.project_id = p.id)
FROM paperboat.projects p
JOIN paperboat.project_repositories pr ON pr.project_id = p.id
JOIN paperboat.project_storage_allocations psa ON psa.project_id = p.id
JOIN paperboat.project_runtime_configs prc ON prc.project_id = p.id
LEFT JOIN paperboat.machine_type_versions mtv ON mtv.id = prc.machine_type_version_id
LEFT JOIN paperboat.machine_types mt ON mt.id = mtv.machine_type_id
LEFT JOIN paperboat.regions r ON r.id = prc.region_id
LEFT JOIN paperboat.idle_timeout_options ito ON ito.id = prc.idle_timeout_option_id
LEFT JOIN paperboat.vm_preset_versions vpv ON vpv.id = ANY(prc.preset_version_ids)
LEFT JOIN paperboat.vm_presets vp ON vp.id = vpv.preset_id
LEFT JOIN paperboat.machine_type_versions amtv ON amtv.id = prc.applied_machine_type_version_id
LEFT JOIN paperboat.machine_types amt ON amt.id = amtv.machine_type_id
LEFT JOIN paperboat.regions ar ON ar.id = prc.applied_region_id
LEFT JOIN paperboat.idle_timeout_options aito ON aito.id = prc.applied_idle_timeout_option_id
LEFT JOIN paperboat.vm_preset_versions avpv ON avpv.id = ANY(prc.applied_preset_version_ids)
LEFT JOIN paperboat.vm_presets avp ON avp.id = avpv.preset_id`

const projectGroupSQL = `
GROUP BY p.id, pr.project_id, psa.project_id, prc.project_id, mt.code, r.code, ito.code, amt.code, ar.code, aito.code`

func scanProject(row *sql.Row) (Project, error) {
	var p Project
	var presetCodes string
	var appliedMachine, appliedRegion, appliedPresets, appliedIdle string
	var appliedHash string
	err := row.Scan(&p.ID, &p.Version, &p.Name, &p.State, &p.CreatedAt, &p.UpdatedAt, &p.Repository.Provider, &p.Repository.SourceURL, &p.Repository.DefaultBranch, &p.DesiredConfig.StorageGB, &p.DesiredConfig.MachineTypeCode, &p.DesiredConfig.RegionCode, &presetCodes, &p.DesiredConfig.IdleTimeoutCode, &p.DesiredConfig.SetupScriptRef, &p.PendingRestartApply, &p.DesiredConfig.ConfigHash, &appliedHash, &p.CurrentConfig.StorageGB, &appliedMachine, &appliedRegion, &appliedPresets, &appliedIdle, &p.CurrentConfig.SetupScriptRef, &p.SetupScriptRevisions)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, err
	}
	if presetCodes != "" {
		p.DesiredConfig.PresetCodes = strings.Split(presetCodes, ",")
	}
	p.CurrentConfig.ConfigHash = appliedHash
	p.CurrentConfig.MachineTypeCode = appliedMachine
	p.CurrentConfig.RegionCode = appliedRegion
	p.CurrentConfig.IdleTimeoutCode = appliedIdle
	if appliedPresets != "" {
		p.CurrentConfig.PresetCodes = strings.Split(appliedPresets, ",")
	}
	if p.DesiredConfig.ConfigHash == p.CurrentConfig.ConfigHash {
		p.CurrentConfig = p.DesiredConfig
		p.PendingRestartApply = false
	}
	p.RestartRequired = p.PendingRestartApply
	return p.normalized(), nil
}

func ensureStorageAccount(ctx context.Context, tx *db.Tx, userID string) (string, error) {
	id := newID("stor")
	if err := tx.QueryRow(ctx, `
INSERT INTO storage_accounts (id, user_id)
VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET updated_at = storage_accounts.updated_at
RETURNING id`, id, userID).Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}

func ensureFreeStorage(ctx context.Context, tx *db.Tx, userID, accountID string) error {
	var hasPaid bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (
	SELECT 1 FROM subscriptions
	WHERE user_id = $1
	  AND state IN ('active', 'trialing')
	  AND (current_period_end IS NULL OR current_period_end > now())
)`, userID).Scan(&hasPaid); err != nil {
		return err
	}
	if hasPaid {
		return nil
	}
	var planVersionID string
	var includedGB int
	err := tx.QueryRow(ctx, `
SELECT pv.id, pv.included_storage_gb
FROM plans p
JOIN plan_versions pv ON pv.id = p.current_version_id
WHERE p.code = 'free' AND p.active
LIMIT 1`).Scan(&planVersionID, &includedGB)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	idempotencyKey := "free-plan:" + planVersionID + ":storage:" + userID
	var existing int
	err = tx.QueryRow(ctx, `
SELECT amount_gb
FROM storage_ledger_entries
WHERE idempotency_key = $1 AND account_id = $2 AND source_type = 'plan' AND source_id = $3 AND entry_type = 'included_set'`, idempotencyKey, accountID, planVersionID).Scan(&existing)
	if err == nil {
		if existing == includedGB {
			return nil
		}
		return ErrIdempotencyConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var purchased, allocated int
	if err := tx.QueryRow(ctx, `SELECT purchased_gb, allocated_gb FROM storage_accounts WHERE id = $1 FOR UPDATE`, accountID).Scan(&purchased, &allocated); err != nil {
		return err
	}
	if allocated > includedGB+purchased {
		return ErrInsufficientStorage
	}
	if _, err := tx.Exec(ctx, `UPDATE storage_accounts SET included_gb = $2, version = version + 1, updated_at = now() WHERE id = $1`, accountID, includedGB); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO storage_ledger_entries (id, account_id, entry_type, amount_gb, source_type, source_id, idempotency_key, metadata)
VALUES ($1, $2, 'included_set', $3, 'plan', $4, $5, $6::jsonb)`, newID("sled"), accountID, includedGB, planVersionID, idempotencyKey, `{"plan_code":"free"}`)
	return err
}

func insertEvent(ctx context.Context, tx *db.Tx, projectID, eventType, message string, metadata map[string]any) error {
	b, _ := json.Marshal(metadata)
	_, err := tx.Exec(ctx, `INSERT INTO project_events (id, project_id, event_type, message, metadata) VALUES ($1, $2, $3, $4, $5::jsonb)`, newID("pevt"), projectID, eventType, message, string(b))
	return err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}
