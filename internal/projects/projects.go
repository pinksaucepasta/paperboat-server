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
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
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
	row, err := r.db.Queries().FindProjectByIdempotencyKey(ctx, dbsqlc.FindProjectByIdempotencyKeyParams{UserID: userID, IdempotencyKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, false, nil
	}
	if err != nil {
		return Project{}, false, fmt.Errorf("find project idempotency key: %w", err)
	}
	if row.CreateRequestHash != requestHash {
		return Project{}, true, ErrIdempotencyConflict
	}
	project, err := r.Get(ctx, userID, row.ID)
	return project, true, err
}

func (r *Repository) ResolveCatalog(ctx context.Context, machineTypeCode, regionCode string, presetCodes []string, idleTimeoutCode string) (catalogRefs, error) {
	refs := catalogRefs{presetVersionIDs: []string{}}
	if machineTypeCode == "" || regionCode == "" || idleTimeoutCode == "" {
		return refs, ErrCatalogUnavailable
	}
	machineVersion, err := r.db.Queries().GetActiveMachineTypeVersion(ctx, machineTypeCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return refs, ErrCatalogUnavailable
		}
		return refs, err
	}
	refs.machineTypeVersionID = machineVersion.String
	refs.regionID, err = r.db.Queries().GetEnabledRegionID(ctx, regionCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return refs, ErrCatalogUnavailable
		}
		return refs, err
	}
	refs.idleTimeoutID, err = r.db.Queries().GetActiveIdleTimeoutID(ctx, idleTimeoutCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return refs, ErrCatalogUnavailable
		}
		return refs, err
	}
	for _, code := range presetCodes {
		version, err := r.db.Queries().GetActivePresetVersion(ctx, code)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return refs, ErrCatalogUnavailable
			}
			return refs, err
		}
		refs.presetVersionIDs = append(refs.presetVersionIDs, version.String)
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
		q := tx.Queries()
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
		if err := q.InsertProject(ctx, dbsqlc.InsertProjectParams{ID: projectID, UserID: input.UserID, Name: input.Name, IdempotencyKey: input.IdempotencyKey, CreateRequestHash: createRequestHash(input)}); err != nil {
			return err
		}
		if _, err := q.CreateControlEnvironment(ctx, dbsqlc.CreateControlEnvironmentParams{ID: projectID, WorkspaceID: projectID, OwnerUserID: sql.NullString{String: input.UserID, Valid: true}, DesiredState: "active"}); err != nil {
			return err
		}
		if err := q.InsertProjectRepository(ctx, dbsqlc.InsertProjectRepositoryParams{ProjectID: projectID, SourceUrl: input.RepositoryURL, DefaultBranch: input.DefaultBranch}); err != nil {
			return err
		}
		if err := q.InsertProjectStorageAllocation(ctx, dbsqlc.InsertProjectStorageAllocationParams{ProjectID: projectID, StorageAccountID: accountID, AssignedGb: int32(input.StorageGB)}); err != nil {
			return err
		}
		if err := reserveStorageTx(ctx, tx, accountID, projectID, input.StorageGB, "project.storage.allocate:"+projectID); err != nil {
			return err
		}
		if err := q.InsertProjectRuntimeConfig(ctx, dbsqlc.InsertProjectRuntimeConfigParams{ProjectID: projectID, MachineTypeVersionID: sql.NullString{String: refs.machineTypeVersionID, Valid: true}, PresetVersionIds: refs.presetVersionIDs, SetupScriptRef: setupRef, IdleTimeoutOptionID: sql.NullString{String: refs.idleTimeoutID, Valid: true}, RegionID: sql.NullString{String: refs.regionID, Valid: true}, DesiredConfigHash: hash}); err != nil {
			return err
		}
		if err := q.CreateDefaultTerminalSession(ctx, dbsqlc.CreateDefaultTerminalSessionParams{ID: newID("pts"), ProjectID: projectID}); err != nil {
			return err
		}
		if setupRef != "" {
			ciphertext, err := secrets.Encrypt(r.encryptionKey, input.SetupScript)
			if err != nil {
				return err
			}
			if err := q.InsertProjectSetupScriptRevision(ctx, dbsqlc.InsertProjectSetupScriptRevisionParams{ID: setupRef, ProjectID: projectID, RevisionNumber: 1, ScriptSha256: setupSHA, ScriptCiphertext: ciphertext, Guidance: "Do not include secrets in setup scripts; use provider-managed project credentials for secret material.", CreatedByUserID: input.UserID}); err != nil {
				return err
			}
		}
		if err := insertEvent(ctx, tx, projectID, "project.created", "Project intent was recorded.", map[string]any{"state": "creating"}); err != nil {
			return err
		}
		if err := q.MarkProjectProvisioningStorage(ctx, dbsqlc.MarkProjectProvisioningStorageParams{ID: projectID, UserID: input.UserID}); err != nil {
			return err
		}
		if err := q.InsertProjectCreateJob(ctx, dbsqlc.InsertProjectCreateJobParams{ID: newID("job"), AggregateID: projectID, IdempotencyKey: "project.create:" + projectID, Column4: json.RawMessage(`{"phase":"provision_storage"}`)}); err != nil {
			return err
		}
		return insertEvent(ctx, tx, projectID, "project.provisioning_queued", "Project provisioning was queued.", map[string]any{"state": "provisioning_storage"})
	})
	return projectID, err
}

func (r *Repository) List(ctx context.Context, userID string) ([]Project, error) {
	ids, err := r.db.Queries().ListProjectIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Project, 0, len(ids))
	for _, id := range ids {
		project, err := r.Get(ctx, userID, id)
		if err != nil {
			return nil, err
		}
		out = append(out, project)
	}
	return out, nil
}

func (r *Repository) Get(ctx context.Context, userID, projectID string) (Project, error) {
	row, err := r.db.Queries().GetProject(ctx, dbsqlc.GetProjectParams{ID: projectID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, err
	}
	return projectFromRow(row), nil
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
			q := tx.Queries()
			next, err := q.NextProjectSetupScriptRevision(ctx, projectID)
			if err != nil {
				return err
			}
			ref := newID("pss")
			ciphertext, err := secrets.Encrypt(r.encryptionKey, change.setup.plain)
			if err != nil {
				return err
			}
			if err := q.InsertProjectSetupScriptRevision(ctx, dbsqlc.InsertProjectSetupScriptRevisionParams{ID: ref, ProjectID: projectID, RevisionNumber: next, ScriptSha256: change.setup.sha256, ScriptCiphertext: ciphertext, Guidance: "Do not include secrets in setup scripts; use provider-managed project credentials for secret material.", CreatedByUserID: userID}); err != nil {
				return err
			}
			if err := q.SetProjectSetupScriptRef(ctx, dbsqlc.SetProjectSetupScriptRefParams{ProjectID: projectID, SetupScriptRef: ref}); err != nil {
				return err
			}
		}
		q := tx.Queries()
		if err := q.UpdateProjectDesiredRuntimeConfig(ctx, dbsqlc.UpdateProjectDesiredRuntimeConfigParams{ProjectID: projectID, UserID: userID, MachineTypeVersionID: sql.NullString{String: change.refs.machineTypeVersionID, Valid: true}, PresetVersionIds: change.refs.presetVersionIDs, IdleTimeoutOptionID: sql.NullString{String: change.refs.idleTimeoutID, Valid: true}, RegionID: sql.NullString{String: change.refs.regionID, Valid: true}, DesiredConfigHash: change.configHash}); err != nil {
			return err
		}
		if err := q.UpdateProjectAssignedStorage(ctx, dbsqlc.UpdateProjectAssignedStorageParams{ProjectID: projectID, UserID: userID, AssignedGb: int32(change.storageGB)}); err != nil {
			return err
		}
		if err := q.TouchProjectVersion(ctx, dbsqlc.TouchProjectVersionParams{ID: projectID, UserID: userID}); err != nil {
			return err
		}
		return insertEvent(ctx, tx, projectID, "project.config_updated", "Desired project configuration was updated.", map[string]any{"restart_required": true})
	})
}

func projectStorageAllocationTx(ctx context.Context, tx *db.Tx, userID, projectID string) (storageAllocation, error) {
	row, err := tx.Queries().GetProjectStorageAllocationForUpdate(ctx, dbsqlc.GetProjectStorageAllocationForUpdateParams{ID: projectID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return storageAllocation{}, ErrNotFound
	}
	if err != nil {
		return storageAllocation{}, err
	}
	return storageAllocation{accountID: row.StorageAccountID, assignedGB: int(row.AssignedGb), version: row.AllocationVersion, projectVersion: row.ProjectVersion, state: row.State}, nil
}

func reserveStorageTx(ctx context.Context, tx *db.Tx, accountID, projectID string, amountGB int, idempotencyKey string) error {
	q := tx.Queries()
	existing, err := q.GetProjectStorageLedgerAmount(ctx, dbsqlc.GetProjectStorageLedgerAmountParams{IdempotencyKey: idempotencyKey, AccountID: accountID, ProjectID: projectID, EntryType: "allocation"})
	if err == nil {
		if int(existing) == amountGB {
			return nil
		}
		return ErrIdempotencyConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	account, err := q.GetStorageAccountForUpdate(ctx, accountID)
	if err != nil {
		return err
	}
	if int(account.AllocatedGb)+amountGB > int(account.IncludedGb+account.PurchasedGb) {
		return ErrInsufficientStorage
	}
	if err := q.IncreaseAllocatedStorage(ctx, dbsqlc.IncreaseAllocatedStorageParams{ID: accountID, AllocatedGb: int32(amountGB)}); err != nil {
		return err
	}
	return q.InsertProjectStorageLedger(ctx, dbsqlc.InsertProjectStorageLedgerParams{ID: newID("sled"), AccountID: accountID, EntryType: "allocation", AmountGb: int32(amountGB), ProjectID: projectID, IdempotencyKey: idempotencyKey})
}

func releaseStorageReservationTx(ctx context.Context, tx *db.Tx, accountID, projectID string, amountGB int, idempotencyKey string) error {
	q := tx.Queries()
	existing, err := q.GetProjectStorageLedgerAmount(ctx, dbsqlc.GetProjectStorageLedgerAmountParams{IdempotencyKey: idempotencyKey, AccountID: accountID, ProjectID: projectID, EntryType: "release"})
	if err == nil {
		if int(existing) == amountGB {
			return nil
		}
		return ErrIdempotencyConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	allocated, err := q.GetAllocatedStorageForUpdate(ctx, accountID)
	if err != nil {
		return err
	}
	if int(allocated) < amountGB {
		return fmt.Errorf("storage release exceeds allocated storage")
	}
	if err := q.DecreaseAllocatedStorage(ctx, dbsqlc.DecreaseAllocatedStorageParams{ID: accountID, AllocatedGb: int32(amountGB)}); err != nil {
		return err
	}
	return q.InsertProjectStorageLedger(ctx, dbsqlc.InsertProjectStorageLedgerParams{ID: newID("sled"), AccountID: accountID, EntryType: "release", AmountGb: int32(amountGB), ProjectID: projectID, IdempotencyKey: idempotencyKey})
}

func (r *Repository) MarkDeleting(ctx context.Context, userID, projectID string) (Project, error) {
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		affected, err := q.MarkProjectDeleting(ctx, dbsqlc.MarkProjectDeletingParams{ID: projectID, UserID: userID})
		if err != nil {
			return err
		}
		if affected == 0 {
			return ErrNotFound
		}
		// Deletion supersedes any lifecycle work still waiting in the queue;
		// a stale create/start/restart must never run for a deleting project.
		if err := q.SupersedeQueuedProjectJobs(ctx, projectID); err != nil {
			return err
		}
		provisioned, err := q.ProjectHasProviderResources(ctx, projectID)
		if err != nil {
			return err
		}
		if provisioned.Valid && provisioned.Bool {
			if err := q.InsertProjectDeleteJob(ctx, dbsqlc.InsertProjectDeleteJobParams{ID: newID("job"), AggregateID: projectID, IdempotencyKey: "project.delete:" + projectID}); err != nil {
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
	terminalSessions, err := q.ListActiveTerminalSessions(ctx, projectID)
	if err != nil {
		return err
	}
	for _, terminalSession := range terminalSessions {
		if err := q.QueueTerminalSessionOperation(ctx, dbsqlc.QueueTerminalSessionOperationParams{ID: newID("tso"), ProjectID: projectID, TerminalSessionID: terminalSession.ID, Operation: "delete_history"}); err != nil {
			return err
		}
	}
	if err := q.TombstoneProjectTerminalSessions(ctx, projectID); err != nil {
		return err
	}
	if err := q.MarkProjectDeleted(ctx, projectID); err != nil {
		return err
	}
	return insertEvent(ctx, tx, projectID, "project.deleted", "Project was deleted before provisioning; storage was released.", map[string]any{"storage_gb": int(allocation.AssignedGb)})
}

func (r *Repository) QueueLifecycleJob(ctx context.Context, userID, projectID, jobType, nextState string) (Project, error) {
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		locked, err := q.GetProjectStateForUpdate(ctx, dbsqlc.GetProjectStateForUpdateParams{ID: projectID, UserID: userID})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		state := locked.State
		if state == "deleted" || state == "deleting" {
			return ErrDeleted
		}
		if state == "creating" || state == "provisioning_storage" || state == "provisioning_machine" || state == "failed" || state == "suspended" {
			return ErrInvalidState
		}
		if state == nextState {
			return nil
		}
		if err := q.UpdateProjectLifecycleState(ctx, dbsqlc.UpdateProjectLifecycleStateParams{ID: projectID, UserID: userID, State: nextState}); err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]string{"previous_state": state})
		jobKey := fmt.Sprintf("%s:%s:%d", jobType, projectID, locked.Version)
		if err := q.UpsertProjectLifecycleJob(ctx, dbsqlc.UpsertProjectLifecycleJobParams{ID: newID("job"), JobType: jobType, ProjectID: projectID, IdempotencyKey: jobKey, Payload: payload}); err != nil {
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
	enough, err := r.db.Queries().HasProjectStartCredits(ctx, dbsqlc.HasProjectStartCreditsParams{WindowSeconds: int64(window.Seconds()), UseDesiredConfig: useDesiredConfig, ProjectID: projectID, UserID: userID})
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
		return tx.Queries().UpsertProjectActivityRecord(ctx, dbsqlc.UpsertProjectActivityRecordParams{ProjectID: projectID, LastActivityAt: at, Source: source, Metadata: b})
	})
}

func (r *Repository) SetKeepAlive(ctx context.Context, userID, projectID string, until *time.Time) error {
	if _, err := r.Get(ctx, userID, projectID); err != nil {
		return err
	}
	var value sql.NullTime
	eventType := "project.keep_alive_cleared"
	message := "Project keep-alive pin was cleared."
	metadata := map[string]any{}
	if until != nil {
		value = sql.NullTime{Time: until.UTC(), Valid: true}
		eventType = "project.keep_alive_set"
		message = "Project keep-alive pin was set."
		metadata["keep_alive_until"] = until.UTC().Format(time.RFC3339Nano)
	} else {
		value = sql.NullTime{}
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		err := tx.Queries().UpsertProjectKeepAlive(ctx, dbsqlc.UpsertProjectKeepAliveParams{ProjectID: projectID, KeepAliveUntil: value})
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
	rows, err := r.db.Queries().ListProjectEvents(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(rows))
	for _, row := range rows {
		event := Event{ID: row.ID, Type: row.EventType, Message: row.Message, CreatedAt: row.CreatedAt}
		_ = json.Unmarshal(row.Metadata, &event.Metadata)
		if event.Metadata == nil {
			event.Metadata = map[string]any{}
		}
		out = append(out, event)
	}
	return out, nil
}

func projectFromRow(row dbsqlc.GetProjectRow) Project {
	p := Project{ID: row.ID, Version: row.Version, Name: row.Name, State: row.State, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		Repository:          Repo{Provider: row.Provider, SourceURL: row.SourceUrl, DefaultBranch: row.DefaultBranch},
		DesiredConfig:       Config{StorageGB: int(row.AssignedGb), MachineTypeCode: row.MachineTypeCode.String, RegionCode: row.RegionCode.String, IdleTimeoutCode: row.IdleTimeoutCode.String, SetupScriptRef: row.SetupScriptRef, ConfigHash: row.DesiredConfigHash},
		CurrentConfig:       Config{StorageGB: int(row.AppliedStorageGb), MachineTypeCode: row.AppliedMachineTypeCode, RegionCode: row.AppliedRegionCode, IdleTimeoutCode: row.AppliedIdleTimeoutCode, SetupScriptRef: row.AppliedSetupScriptRef, ConfigHash: row.AppliedConfigHash},
		PendingRestartApply: row.PendingRestartApply, SetupScriptRevisions: int(row.SetupScriptRevisions)}
	presetCodes := databaseText(row.PresetCodes)
	if presetCodes != "" {
		p.DesiredConfig.PresetCodes = strings.Split(presetCodes, ",")
	}
	appliedPresets := databaseText(row.AppliedPresetCodes)
	if appliedPresets != "" {
		p.CurrentConfig.PresetCodes = strings.Split(appliedPresets, ",")
	}
	if p.DesiredConfig.ConfigHash == p.CurrentConfig.ConfigHash {
		p.CurrentConfig = p.DesiredConfig
		p.PendingRestartApply = false
	}
	p.RestartRequired = p.PendingRestartApply
	return p.normalized()
}

func databaseText(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return ""
	}
}

func ensureStorageAccount(ctx context.Context, tx *db.Tx, userID string) (string, error) {
	return tx.Queries().EnsureStorageAccount(ctx, dbsqlc.EnsureStorageAccountParams{ID: newID("stor"), UserID: userID})
}

func ensureFreeStorage(ctx context.Context, tx *db.Tx, userID, accountID string) error {
	q := tx.Queries()
	hasPaid, err := q.UserHasActiveSubscription(ctx, userID)
	if err != nil {
		return err
	}
	if hasPaid {
		return nil
	}
	plan, err := q.GetFreePlanStorage(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	idempotencyKey := "free-plan:" + plan.ID + ":storage:" + userID
	existing, err := q.GetFreePlanStorageLedgerAmount(ctx, dbsqlc.GetFreePlanStorageLedgerAmountParams{IdempotencyKey: idempotencyKey, AccountID: accountID, PlanVersionID: plan.ID})
	if err == nil {
		if existing == plan.IncludedStorageGb {
			return nil
		}
		return ErrIdempotencyConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	usage, err := q.GetStorageUsageForUpdate(ctx, accountID)
	if err != nil {
		return err
	}
	if usage.AllocatedGb > plan.IncludedStorageGb+usage.PurchasedGb {
		return ErrInsufficientStorage
	}
	if err := q.SetIncludedStorage(ctx, dbsqlc.SetIncludedStorageParams{ID: accountID, IncludedGb: plan.IncludedStorageGb}); err != nil {
		return err
	}
	return q.InsertFreePlanStorageLedger(ctx, dbsqlc.InsertFreePlanStorageLedgerParams{ID: newID("sled"), AccountID: accountID, AmountGb: plan.IncludedStorageGb, PlanVersionID: plan.ID, IdempotencyKey: idempotencyKey})
}

func insertEvent(ctx context.Context, tx *db.Tx, projectID, eventType, message string, metadata map[string]any) error {
	b, _ := json.Marshal(metadata)
	return tx.Queries().InsertProjectEvent(ctx, dbsqlc.InsertProjectEventParams{ID: newID("pevt"), ProjectID: projectID, EventType: eventType, Message: message, Metadata: b})
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}
