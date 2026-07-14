package classifier

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/configsyncpolicy"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

type Provider interface {
	Classify(context.Context, []Candidate) (Response, error)
}

type Controller struct {
	db             *db.DB
	provider       Provider
	cfg            config.Classifier
	policyRevision string
	mu             sync.Mutex
	health         string
	rate           map[string][]time.Time
	audit          *audit.Writer
}

type ClassifiedResult struct {
	Result
	Source  string `json:"source"`
	Pending bool   `json:"pending"`
}

type ClassifiedResponse struct {
	Results            []ClassifiedResult `json:"results"`
	PolicyRevision     string             `json:"policy_revision"`
	ModelRevision      string             `json:"model_revision"`
	ClassifierRevision string             `json:"classifier_revision"`
	Health             string             `json:"health"`
}

func NewController(store *db.DB, provider Provider, cfg config.Classifier, policyRevision string, auditWriter *audit.Writer) *Controller {
	health := "healthy"
	if provider == nil {
		health = "disabled"
	}
	return &Controller{db: store, provider: provider, cfg: cfg, policyRevision: policyRevision, health: health, rate: make(map[string][]time.Time), audit: auditWriter}
}

var ErrRateLimited = errors.New("classification rate limit exceeded")

func (c *Controller) ProjectOwner(ctx context.Context, projectID string) (string, error) {
	return c.db.Queries().GetConfigSyncProjectOwner(ctx, projectID)
}

func (c *Controller) Classify(ctx context.Context, userID string, candidates []Candidate) (ClassifiedResponse, error) {
	if !c.allow(userID) {
		return ClassifiedResponse{}, ErrRateLimited
	}
	if len(candidates) == 0 || len(candidates) > c.cfg.MaxCandidates {
		return ClassifiedResponse{}, errors.New("classifier candidate count is invalid")
	}
	out := ClassifiedResponse{Results: make([]ClassifiedResult, len(candidates)), PolicyRevision: c.policyRevision, ModelRevision: c.cfg.ModelRevision, ClassifierRevision: c.cfg.Revision}
	unknown := make([]Candidate, 0)
	positions := make([]int, 0)
	for i := range candidates {
		if err := validateCandidate(&candidates[i]); err != nil {
			return ClassifiedResponse{}, err
		}
		if result, ok, err := c.precedence(ctx, userID, candidates[i]); err != nil {
			return ClassifiedResponse{}, err
		} else if ok {
			out.Results[i] = result
			continue
		}
		unknown, positions = append(unknown, candidates[i]), append(positions, i)
	}
	if len(unknown) > 0 {
		if c.provider == nil {
			for index, candidate := range unknown {
				out.Results[positions[index]] = pending(candidate.Path, "provider_unavailable")
			}
			c.setHealth("unavailable")
		} else {
			response, err := c.classifyWithRetry(ctx, unknown)
			if err != nil {
				for index, candidate := range unknown {
					out.Results[positions[index]] = pending(candidate.Path, "provider_unavailable")
				}
				c.setHealth("unavailable")
				c.recordFailure(ctx, userID)
			} else {
				c.setHealth("healthy")
				for index, result := range response.Results {
					classified := ClassifiedResult{Result: result, Source: "model", Pending: result.Decision == Uncertain}
					if classified.Pending {
						classified.ReasonCode = "classifier_uncertain"
					}
					out.Results[positions[index]] = classified
					if err := c.cache(ctx, userID, unknown[index], classified); err != nil {
						return ClassifiedResponse{}, err
					}
				}
			}
		}
	}
	out.Health = c.getHealth()
	return out, nil
}

func (c *Controller) recordFailure(ctx context.Context, userID string) {
	if c.audit == nil {
		return
	}
	_ = c.audit.Write(ctx, audit.Event{ActorType: audit.ActorSystem, EventType: "config_sync.classification_failed", ResourceType: "user", ResourceID: userID, IdempotencyKey: "classification-failure:" + userID + ":" + time.Now().UTC().Format(time.RFC3339Nano), Metadata: map[string]any{"error": "provider_unavailable"}})
}

func (c *Controller) precedence(ctx context.Context, userID string, candidate Candidate) (ClassifiedResult, bool, error) {
	if matches(configsyncpolicy.MandatoryExcludes(), candidate.Path) {
		return classified(candidate.Path, Exclude, 1, "mandatory_exclusion", "mandatory"), true, nil
	}
	override, err := c.db.Queries().GetConfigClassificationOverride(ctx, dbsqlc.GetConfigClassificationOverrideParams{UserID: userID, NormalizedPath: candidate.Path})
	if err == nil {
		return classified(candidate.Path, Decision(override), 1, "user_override", "override"), true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ClassifiedResult{}, false, err
	}
	if matches(c.cfg.ExcludePatterns, candidate.Path) {
		return classified(candidate.Path, Exclude, 1, "catalog_exclusion", "catalog"), true, nil
	}
	if matches(c.cfg.PortablePatterns, candidate.Path) {
		return classified(candidate.Path, Portable, 1, "catalog_portable", "catalog"), true, nil
	}
	if matches(c.cfg.ProjectOnlyPatterns, candidate.Path) {
		return classified(candidate.Path, ProjectOnly, 1, "catalog_project_only", "catalog"), true, nil
	}
	hash := metadataHash(candidate)
	row, err := c.db.Queries().GetConfigClassificationCache(ctx, dbsqlc.GetConfigClassificationCacheParams{UserID: userID, NormalizedPath: candidate.Path, MetadataHash: hash, PolicyRevision: c.policyRevision, ModelRevision: c.cfg.ModelRevision, ClassifierRevision: c.cfg.Revision})
	if err == nil {
		return ClassifiedResult{Result: Result{Path: candidate.Path, Decision: Decision(row.Decision), Confidence: row.Confidence, ReasonCode: row.ReasonCode}, Source: "cache", Pending: row.Decision == string(Uncertain)}, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ClassifiedResult{}, false, err
	}
	return ClassifiedResult{}, false, nil
}

func (c *Controller) classifyWithRetry(ctx context.Context, candidates []Candidate) (Response, error) {
	var response Response
	var err error
	for attempt := 0; attempt <= c.cfg.RetryLimit; attempt++ {
		response, err = c.provider.Classify(ctx, candidates)
		if err == nil {
			return response, nil
		}
		if attempt < c.cfg.RetryLimit {
			select {
			case <-ctx.Done():
				return Response{}, ctx.Err()
			case <-time.After(c.cfg.RetryBackoff * time.Duration(attempt+1)):
			}
		}
	}
	return Response{}, err
}

func (c *Controller) cache(ctx context.Context, userID string, candidate Candidate, result ClassifiedResult) error {
	return c.db.Queries().UpsertConfigClassificationCache(ctx, dbsqlc.UpsertConfigClassificationCacheParams{UserID: userID, NormalizedPath: candidate.Path, MetadataHash: metadataHash(candidate), Decision: string(result.Decision), Source: result.Source, Confidence: result.Confidence, ReasonCode: result.ReasonCode, PolicyRevision: c.policyRevision, ModelRevision: c.cfg.ModelRevision, ClassifierRevision: c.cfg.Revision, ExpiresAt: time.Now().UTC().Add(c.cfg.CacheTTL)})
}

func metadataHash(candidate Candidate) string {
	b, _ := json.Marshal(candidate)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func matches(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if ok, _ := doublestar.PathMatch(pattern, value); ok {
			return true
		}
	}
	return false
}
func classified(pathValue string, decision Decision, confidence float64, reason, source string) ClassifiedResult {
	return ClassifiedResult{Result: Result{Path: path.Clean(strings.ReplaceAll(pathValue, "\\", "/")), Decision: decision, Confidence: confidence, ReasonCode: reason}, Source: source}
}
func pending(pathValue, reason string) ClassifiedResult {
	result := classified(pathValue, Uncertain, 0, reason, "pending")
	result.Pending = true
	return result
}
func (c *Controller) setHealth(value string) { c.mu.Lock(); c.health = value; c.mu.Unlock() }
func (c *Controller) getHealth() string      { c.mu.Lock(); defer c.mu.Unlock(); return c.health }
func (c *Controller) allow(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now, cutoff := time.Now().UTC(), time.Now().UTC().Add(-time.Minute)
	values := c.rate[key][:0]
	for _, seen := range c.rate[key] {
		if seen.After(cutoff) {
			values = append(values, seen)
		}
	}
	if len(values) >= c.cfg.RequestsPerMinute {
		c.rate[key] = values
		return false
	}
	c.rate[key] = append(values, now)
	return true
}
