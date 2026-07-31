package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var ErrConfigRuntimeInvalid = errors.New("config runtime request is invalid")

type ConfigRuntimePolicy struct {
	Format                  string        `json:"format"`
	Revision                string        `json:"revision"`
	ManifestContract        string        `json:"manifest_contract"`
	ManifestMaxBytes        int           `json:"manifest_max_bytes"`
	ManifestMaxLines        int           `json:"manifest_max_lines"`
	ManifestMaxPatternBytes int           `json:"manifest_max_pattern_bytes"`
	MaxFileBytes            int64         `json:"max_file_bytes"`
	MaxBatchBytes           int64         `json:"max_batch_bytes"`
	Debounce                time.Duration `json:"debounce"`
	MinimumPushInterval     time.Duration `json:"minimum_push_interval"`
	MaximumDirtyDelay       time.Duration `json:"maximum_dirty_delay"`
	RemotePollInterval      time.Duration `json:"remote_poll_interval"`
	RetryLimit              int           `json:"retry_limit"`
	ShutdownFlushTimeout    time.Duration `json:"shutdown_flush_timeout"`
	SummaryLimit            int           `json:"summary_limit"`
}

type ConfigRuntimeDescriptor struct {
	WriteMode              string              `json:"write_mode"`
	Mode                   string              `json:"mode"`
	RepositoryID           string              `json:"repository_id"`
	AssignmentID           string              `json:"assignment_id"`
	EnvironmentID          string              `json:"environment_id"`
	MachineID              string              `json:"machine_id"`
	InstallationGeneration int64               `json:"installation_generation"`
	SyncRevisionFloor      int64               `json:"sync_revision_floor"`
	WarningRevision        string              `json:"warning_revision"`
	Policy                 ConfigRuntimePolicy `json:"policy"`
}

type ConfigRuntimeService struct {
	store  *db.DB
	leases *ConfigLeaseService
	policy config.ConfigSync
}

func NewConfigRuntimeService(store *db.DB, leases *ConfigLeaseService, policy config.ConfigSync) *ConfigRuntimeService {
	return &ConfigRuntimeService{store: store, leases: leases, policy: policy}
}

func (s *ConfigRuntimeService) Get(ctx context.Context, identityToken, credential string, proof, body []byte, method, path string) (ConfigRuntimeDescriptor, error) {
	if s == nil || s.store == nil || s.leases == nil {
		return ConfigRuntimeDescriptor{}, ErrConfigRuntimeInvalid
	}
	holder, err := s.leases.Authenticate(ctx, identityToken, credential, proof, body, method, path)
	if err != nil {
		return ConfigRuntimeDescriptor{}, ErrConfigRuntimeInvalid
	}
	assignment, err := s.store.Queries().GetControlConfigAssignment(ctx, holder.EnvironmentID)
	if err != nil || !assignment.WarningRevision.Valid {
		return ConfigRuntimeDescriptor{}, ErrConfigRuntimeInvalid
	}
	syncRevisionFloor, err := s.store.Queries().GetControlConfigSyncRevision(ctx, dbsqlc.GetControlConfigSyncRevisionParams{
		EnvironmentID: holder.EnvironmentID, AssignmentID: holder.AssignmentID,
		MachineID: holder.MachineID, InstallationGeneration: holder.InstallationGeneration,
	})
	if errors.Is(err, sql.ErrNoRows) {
		syncRevisionFloor = 0
	} else if err != nil {
		return ConfigRuntimeDescriptor{}, ErrConfigRuntimeInvalid
	}
	return ConfigRuntimeDescriptor{
		WriteMode: s.policy.Mode, Mode: assignment.Mode,
		RepositoryID: holder.RepositoryID, AssignmentID: holder.AssignmentID, EnvironmentID: holder.EnvironmentID,
		MachineID: holder.MachineID, WarningRevision: assignment.WarningRevision.String,
		InstallationGeneration: holder.InstallationGeneration, SyncRevisionFloor: syncRevisionFloor,
		Policy: ConfigRuntimePolicy{
			Format: "paperboat-config-plaintext-v1", Revision: s.policy.PolicyRevision,
			ManifestContract: s.policy.ManifestContract, ManifestMaxBytes: s.policy.ManifestMaxBytes,
			ManifestMaxLines: s.policy.ManifestMaxLines, ManifestMaxPatternBytes: s.policy.ManifestMaxPatternBytes,
			MaxFileBytes: s.policy.MaxFileBytes, MaxBatchBytes: s.policy.MaxBatchBytes,
			Debounce: s.policy.Debounce, MinimumPushInterval: s.policy.MinPushInterval,
			MaximumDirtyDelay: s.policy.MaxDirtyDelay, RemotePollInterval: s.policy.RemotePollInterval,
			RetryLimit: s.policy.RetryLimit, ShutdownFlushTimeout: s.policy.ShutdownFlushTimeout,
			SummaryLimit: s.policy.SummaryLimit,
		},
	}, nil
}
