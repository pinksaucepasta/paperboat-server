package diagnosticuploads

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	MaximumBundleBytes = 25 << 20
	IntentLifetime     = 15 * time.Minute
	DefaultRetention   = 7 * 24 * time.Hour
)

var (
	ErrInvalid             = errors.New("invalid diagnostic upload request")
	ErrIdempotencyConflict = errors.New("idempotency key conflicts with an existing diagnostic upload")
	ErrNotFound            = errors.New("diagnostic upload intent not found")
	ErrExpired             = errors.New("diagnostic upload intent expired")
	ErrUploadMismatch      = errors.New("diagnostic upload does not match its intent")
	ErrUnavailable         = errors.New("diagnostic upload storage unavailable")
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type CreateRequest struct {
	UserID             string
	CLIClientSessionID string
	OperationKey       string
	CorrelationID      string
	Bytes              int64
	SHA256             string
	Categories         []string
}

type Intent struct {
	ID                 string
	UserID             string
	CLIClientSessionID string
	OperationKey       string
	RequestHash        [32]byte
	CorrelationID      string
	ObjectKey          string
	Bytes              int64
	SHA256             [32]byte
	Categories         []string
	State              string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	RetainUntil        time.Time
	UploadedAt         time.Time
	ObjectETag         string
}

type UploadAuthority struct {
	URL     string
	Headers map[string]string
}

type ObjectMetadata struct {
	Bytes  int64
	SHA256 [32]byte
	ETag   string
}

type Repository interface {
	Reserve(context.Context, CreateRequest, [32]byte, Intent) (Intent, error)
	Get(context.Context, string, string) (Intent, error)
	Complete(context.Context, string, string, ObjectMetadata, time.Time) (Intent, error)
}

type ObjectStore interface {
	AuthorizePut(context.Context, string, int64, [32]byte, time.Time) (UploadAuthority, error)
	Stat(context.Context, string) (ObjectMetadata, error)
}

type CleanupItem struct {
	ID          string
	ObjectKey   string
	State       string
	ExpiresAt   time.Time
	RetainUntil time.Time
}

type CleanupRepository interface {
	CleanupCandidates(context.Context, time.Time, int) ([]CleanupItem, error)
	MarkExpired(context.Context, string, time.Time) error
	DeleteRetained(context.Context, string, time.Time) error
}

type ObjectCleaner interface {
	Delete(context.Context, string) error
}

type Service struct {
	repository Repository
	objects    ObjectStore
	clock      func() time.Time
	random     func([]byte) error
	retention  time.Duration
}

func New(repository Repository, objects ObjectStore) (*Service, error) {
	if repository == nil || objects == nil {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, objects: objects, clock: time.Now, random: randomBytes, retention: DefaultRetention}, nil
}

func (s *Service) SetRetention(retention time.Duration) error {
	if s == nil || retention < time.Hour || retention > 30*24*time.Hour {
		return ErrInvalid
	}
	s.retention = retention
	return nil
}

func (s *Service) Create(ctx context.Context, request CreateRequest) (Intent, UploadAuthority, error) {
	request, digest, err := normalizeRequest(request)
	if err != nil {
		return Intent{}, UploadAuthority{}, err
	}
	now := s.clock().UTC()
	id, err := s.randomID("diag_", 16)
	if err != nil {
		return Intent{}, UploadAuthority{}, err
	}
	objectNonce, err := s.randomID("", 16)
	if err != nil {
		return Intent{}, UploadAuthority{}, err
	}
	proposed := Intent{
		ID: id, UserID: request.UserID, CLIClientSessionID: request.CLIClientSessionID,
		OperationKey: request.OperationKey, RequestHash: digest, CorrelationID: request.CorrelationID,
		ObjectKey: "diagnostics/" + id + "/" + objectNonce + ".zip", Bytes: request.Bytes,
		SHA256: mustDecodeSHA256(request.SHA256), Categories: slices.Clone(request.Categories), State: "pending",
		CreatedAt: now, ExpiresAt: now.Add(IntentLifetime), RetainUntil: now.Add(s.retention),
	}
	intent, err := s.repository.Reserve(ctx, request, digest, proposed)
	if err != nil {
		return Intent{}, UploadAuthority{}, err
	}
	if intent.State == "expired" || !intent.ExpiresAt.After(now) {
		return Intent{}, UploadAuthority{}, ErrExpired
	}
	if intent.State == "uploaded" {
		return intent, UploadAuthority{}, nil
	}
	authority, err := s.objects.AuthorizePut(ctx, intent.ObjectKey, intent.Bytes, intent.SHA256, intent.ExpiresAt)
	if err != nil {
		return Intent{}, UploadAuthority{}, errors.Join(ErrUnavailable, err)
	}
	if err := validateAuthority(authority); err != nil {
		return Intent{}, UploadAuthority{}, errors.Join(ErrUnavailable, err)
	}
	return intent, authority, nil
}

func (s *Service) Complete(ctx context.Context, userID, intentID string) (Intent, error) {
	if !validIdentifier(userID, 1, 128) || !strings.HasPrefix(intentID, "diag_") || !validIdentifier(intentID, 21, 133) {
		return Intent{}, ErrInvalid
	}
	intent, err := s.repository.Get(ctx, userID, intentID)
	if err != nil {
		return Intent{}, err
	}
	if intent.State == "uploaded" {
		return intent, nil
	}
	now := s.clock().UTC()
	if intent.State != "pending" || !intent.ExpiresAt.After(now) {
		return Intent{}, ErrExpired
	}
	metadata, err := s.objects.Stat(ctx, intent.ObjectKey)
	if err != nil {
		return Intent{}, errors.Join(ErrUnavailable, err)
	}
	if metadata.Bytes != intent.Bytes || metadata.SHA256 != intent.SHA256 || !validETag(metadata.ETag) {
		return Intent{}, ErrUploadMismatch
	}
	return s.repository.Complete(ctx, userID, intentID, metadata, now)
}

func (s *Service) Cleanup(ctx context.Context, limit int) error {
	repository, repositoryOK := s.repository.(CleanupRepository)
	objects, objectsOK := s.objects.(ObjectCleaner)
	if !repositoryOK || !objectsOK || limit < 1 || limit > 1000 {
		return ErrInvalid
	}
	now := s.clock().UTC()
	items, err := repository.CleanupCandidates(ctx, now, limit)
	if err != nil {
		return err
	}
	var result error
	for _, item := range items {
		if err := objects.Delete(ctx, item.ObjectKey); err != nil && !errors.Is(err, ErrNotFound) {
			result = errors.Join(result, fmt.Errorf("delete diagnostic object %s: %w", item.ID, err))
			continue
		}
		if !item.RetainUntil.After(now) {
			result = errors.Join(result, repository.DeleteRetained(ctx, item.ID, now))
		} else if item.State == "pending" && !item.ExpiresAt.After(now) {
			result = errors.Join(result, repository.MarkExpired(ctx, item.ID, now))
		}
	}
	return result
}

func (s *Service) Worker(interval time.Duration, logger *slog.Logger) func(context.Context) error {
	return func(ctx context.Context) error {
		if interval <= 0 || interval > time.Hour {
			return ErrInvalid
		}
		if logger == nil {
			logger = slog.Default()
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := s.Cleanup(ctx, 100); err != nil && !errors.Is(err, context.Canceled) {
				logger.WarnContext(ctx, "diagnostic upload cleanup failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func normalizeRequest(request CreateRequest) (CreateRequest, [32]byte, error) {
	request.UserID = strings.TrimSpace(request.UserID)
	request.CLIClientSessionID = strings.TrimSpace(request.CLIClientSessionID)
	request.OperationKey = strings.TrimSpace(request.OperationKey)
	request.CorrelationID = strings.TrimSpace(request.CorrelationID)
	request.SHA256 = strings.ToLower(strings.TrimSpace(request.SHA256))
	if !validIdentifier(request.UserID, 1, 128) || !validIdentifier(request.CLIClientSessionID, 1, 128) ||
		len(request.OperationKey) < 16 || len(request.OperationKey) > 200 || request.Bytes < 1 || request.Bytes > MaximumBundleBytes ||
		len(request.CorrelationID) != 35 || !strings.HasPrefix(request.CorrelationID, "pb-") || !validLowerHex(request.CorrelationID[3:], 32) ||
		!validLowerHex(request.SHA256, 64) || !slices.Equal(request.Categories, []string{"manifest", "recent_events", "redacted_events", "status"}) {
		return CreateRequest{}, [32]byte{}, ErrInvalid
	}
	canonical, err := json.Marshal(struct {
		Schema             string   `json:"schema"`
		CLIClientSessionID string   `json:"cli_client_session_id"`
		CorrelationID      string   `json:"correlation_id"`
		Bytes              int64    `json:"bytes"`
		SHA256             string   `json:"sha256"`
		Categories         []string `json:"categories"`
	}{"paperboat.diagnostic-upload-intent-request/v1", request.CLIClientSessionID, request.CorrelationID, request.Bytes, request.SHA256, request.Categories})
	if err != nil {
		return CreateRequest{}, [32]byte{}, err
	}
	return request, sha256.Sum256(canonical), nil
}

func validateAuthority(authority UploadAuthority) error {
	if !strings.HasPrefix(authority.URL, "https://") || len(authority.URL) > 8192 || len(authority.Headers) == 0 || len(authority.Headers) > 8 {
		return ErrInvalid
	}
	for name, value := range authority.Headers {
		if len(name) == 0 || len(name) > 128 || len(value) == 0 || len(value) > 1024 || strings.ContainsAny(name+value, "\r\n") {
			return ErrInvalid
		}
	}
	return nil
}

func (s *Service) randomID(prefix string, size int) (string, error) {
	buffer := make([]byte, size)
	if err := s.random(buffer); err != nil {
		return "", fmt.Errorf("generate diagnostic upload identifier: %w", err)
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func randomBytes(buffer []byte) error { _, err := rand.Read(buffer); return err }
func mustDecodeSHA256(value string) (result [32]byte) {
	decoded, _ := hex.DecodeString(value)
	copy(result[:], decoded)
	return
}
func validIdentifier(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && identifierPattern.MatchString(value)
}
func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validETag(value string) bool {
	return len(value) >= 1 && len(value) <= 256 && !strings.ContainsAny(value, "\r\n")
}
