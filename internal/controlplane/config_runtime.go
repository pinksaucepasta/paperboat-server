package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var ErrConfigRuntimeInvalid = errors.New("config runtime request is invalid")

type ConfigKeyMaterial struct {
	Version   int32
	Recipient string
	Identity  string
}

type ConfigKeySource interface {
	EnsureConfigKey(context.Context, string) (ConfigKeyMaterial, error)
}

type ConfigKeySourceFunc func(context.Context, string) (ConfigKeyMaterial, error)

func (f ConfigKeySourceFunc) EnsureConfigKey(ctx context.Context, userID string) (ConfigKeyMaterial, error) {
	return f(ctx, userID)
}

type ConfigRuntimePolicy struct {
	Format                  string        `json:"format"`
	Revision                string        `json:"revision"`
	Includes                []string      `json:"includes"`
	Excludes                []string      `json:"excludes"`
	MandatoryExclusions     []string      `json:"mandatory_exclusions"`
	MaxFileBytes            int64         `json:"max_file_bytes"`
	MaxBatchBytes           int64         `json:"max_batch_bytes"`
	Debounce                time.Duration `json:"debounce"`
	MinimumPushInterval     time.Duration `json:"minimum_push_interval"`
	MaximumDirtyDelay       time.Duration `json:"maximum_dirty_delay"`
	RemotePollInterval      time.Duration `json:"remote_poll_interval"`
	RetryLimit              int           `json:"retry_limit"`
	ShutdownFlushTimeout    time.Duration `json:"shutdown_flush_timeout"`
	SummaryLimit            int           `json:"summary_limit"`
	ClassifierEnabled       bool          `json:"classifier_enabled"`
	ClassifierRevision      string        `json:"classifier_revision"`
	ClassifierModelRevision string        `json:"classifier_model_revision"`
}

type ConfigRuntimeDescriptor struct {
	WriteMode         string              `json:"write_mode"`
	RepositoryID      string              `json:"repository_id"`
	AssignmentID      string              `json:"assignment_id"`
	EnvironmentID     string              `json:"environment_id"`
	HelperID          string              `json:"helper_id"`
	HelperGeneration  int64               `json:"helper_generation"`
	SyncRevisionFloor int64               `json:"sync_revision_floor"`
	WarningRevision   string              `json:"warning_revision"`
	Policy            ConfigRuntimePolicy `json:"policy"`
	KeyVersion        int32               `json:"key_version"`
	AgeRecipient      string              `json:"age_recipient"`
	AgeIdentities     string              `json:"age_identities"`
}

type ConfigRuntimeService struct {
	store      *db.DB
	leases     *ConfigLeaseService
	keys       ConfigKeySource
	policy     config.ConfigSync
	classifier config.Classifier
}

func NewConfigRuntimeService(store *db.DB, leases *ConfigLeaseService, keys ConfigKeySource, policy config.ConfigSync, classifier config.Classifier) *ConfigRuntimeService {
	return &ConfigRuntimeService{store: store, leases: leases, keys: keys, policy: policy, classifier: classifier}
}

func (s *ConfigRuntimeService) Get(ctx context.Context, identityToken, credential string, proof, body []byte, method, path string) (ConfigRuntimeDescriptor, error) {
	if s == nil || s.store == nil || s.leases == nil || s.keys == nil {
		return ConfigRuntimeDescriptor{}, ErrConfigRuntimeInvalid
	}
	holder, err := s.leases.Authenticate(ctx, identityToken, credential, proof, body, method, path)
	if err != nil {
		return ConfigRuntimeDescriptor{}, ErrConfigRuntimeInvalid
	}
	repository, err := s.store.Queries().GetActiveControlConfigRepository(ctx, holder.RepositoryID)
	if err != nil {
		return ConfigRuntimeDescriptor{}, ErrConfigRuntimeInvalid
	}
	key, err := s.keys.EnsureConfigKey(ctx, repository.OwnerUserID)
	if err != nil || key.Version < 1 || !strings.HasPrefix(key.Recipient, "age1") || strings.TrimSpace(key.Identity) == "" {
		return ConfigRuntimeDescriptor{}, ErrConfigRuntimeInvalid
	}
	assignment, err := s.store.Queries().GetControlConfigAssignment(ctx, holder.EnvironmentID)
	if err != nil || !assignment.WarningRevision.Valid {
		return ConfigRuntimeDescriptor{}, ErrConfigRuntimeInvalid
	}
	syncRevisionFloor, err := s.store.Queries().GetControlConfigSyncRevision(ctx, dbsqlc.GetControlConfigSyncRevisionParams{
		EnvironmentID: holder.EnvironmentID, AssignmentID: holder.AssignmentID,
		HelperID: holder.HelperID, HelperGeneration: holder.HelperGeneration,
	})
	if errors.Is(err, sql.ErrNoRows) {
		syncRevisionFloor = 0
	} else if err != nil {
		return ConfigRuntimeDescriptor{}, ErrConfigRuntimeInvalid
	}
	return ConfigRuntimeDescriptor{
		WriteMode:    s.policy.Mode,
		RepositoryID: holder.RepositoryID, AssignmentID: holder.AssignmentID, EnvironmentID: holder.EnvironmentID,
		HelperID: holder.HelperID, WarningRevision: assignment.WarningRevision.String,
		HelperGeneration: holder.HelperGeneration, SyncRevisionFloor: syncRevisionFloor,
		Policy: ConfigRuntimePolicy{
			Format: "paperboat-chezmoi-age-v1", Revision: s.policy.PolicyRevision,
			Includes: append([]string(nil), s.policy.Includes...), Excludes: append([]string(nil), s.policy.Excludes...),
			MandatoryExclusions: append([]string(nil), s.policy.MandatoryExcludes...),
			MaxFileBytes:        s.policy.MaxFileBytes, MaxBatchBytes: s.policy.MaxBatchBytes,
			Debounce: s.policy.Debounce, MinimumPushInterval: s.policy.MinPushInterval,
			MaximumDirtyDelay: s.policy.MaxDirtyDelay, RemotePollInterval: s.policy.RemotePollInterval,
			RetryLimit: s.policy.RetryLimit, ShutdownFlushTimeout: s.policy.ShutdownFlushTimeout,
			SummaryLimit: s.policy.SummaryLimit, ClassifierEnabled: strings.TrimSpace(s.classifier.BaseURL) != "" && strings.TrimSpace(s.classifier.Model) != "",
			ClassifierRevision: s.classifier.Revision, ClassifierModelRevision: s.classifier.ModelRevision,
		},
		KeyVersion: key.Version, AgeRecipient: key.Recipient, AgeIdentities: key.Identity,
	}, nil
}
