package controlplane

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/pinksaucepasta/paperboat-server/internal/classifier"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

var ErrConfigClassificationInvalid = errors.New("config classification request is invalid")

type ConfigClassificationService struct {
	store      *db.DB
	leases     *ConfigLeaseService
	classifier *classifier.Controller
	policy     config.ConfigSync
}

func NewConfigClassificationService(store *db.DB, leases *ConfigLeaseService, controller *classifier.Controller, policy config.ConfigSync) *ConfigClassificationService {
	return &ConfigClassificationService{store: store, leases: leases, classifier: controller, policy: policy}
}

func (s *ConfigClassificationService) Classify(
	ctx context.Context,
	identityToken, credential string,
	proof, body []byte,
	method, requestPath string,
	candidates []classifier.Candidate,
) (classifier.ClassifiedResponse, error) {
	if s == nil || s.store == nil || s.leases == nil || s.classifier == nil ||
		len(candidates) == 0 || len(candidates) > 256 {
		return classifier.ClassifiedResponse{}, ErrConfigClassificationInvalid
	}
	holder, err := s.leases.Authenticate(ctx, identityToken, credential, proof, body, method, requestPath)
	if err != nil {
		return classifier.ClassifiedResponse{}, errors.Join(ErrConfigClassificationInvalid, err)
	}
	repository, err := s.store.Queries().GetActiveControlConfigRepository(ctx, holder.RepositoryID)
	if err != nil {
		return classifier.ClassifiedResponse{}, ErrConfigClassificationInvalid
	}
	seen := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		normalized := path.Clean(strings.ReplaceAll(candidate.Path, "\\", "/"))
		if normalized != candidate.Path || !managedClassificationPath(normalized, s.policy) || seen[normalized] {
			return classifier.ClassifiedResponse{}, ErrConfigClassificationInvalid
		}
		seen[normalized] = true
	}
	return s.classifier.Classify(ctx, repository.OwnerUserID, candidates)
}

func managedClassificationPath(value string, policy config.ConfigSync) bool {
	if value == "." || value == ".." || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "/") {
		return false
	}
	for _, pattern := range append(append([]string{}, policy.MandatoryExcludes...), policy.Excludes...) {
		if matched, err := doublestar.PathMatch(pattern, value); err == nil && matched {
			return false
		}
	}
	if len(policy.Includes) == 0 {
		return strings.HasPrefix(strings.Split(value, "/")[0], ".")
	}
	for _, pattern := range policy.Includes {
		if matched, err := doublestar.PathMatch(pattern, value); err == nil && matched {
			return true
		}
	}
	return false
}
