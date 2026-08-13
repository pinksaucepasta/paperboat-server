package diagnosticuploads

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

type memoryRepository struct{ intent Intent }

func (r *memoryRepository) Reserve(_ context.Context, _ CreateRequest, hash [32]byte, proposed Intent) (Intent, error) {
	if r.intent.ID != "" {
		if r.intent.RequestHash != hash {
			return Intent{}, ErrIdempotencyConflict
		}
		return r.intent, nil
	}
	r.intent = proposed
	return proposed, nil
}
func (r *memoryRepository) Get(_ context.Context, userID, intentID string) (Intent, error) {
	if r.intent.UserID != userID || r.intent.ID != intentID {
		return Intent{}, ErrNotFound
	}
	return r.intent, nil
}
func (r *memoryRepository) Complete(_ context.Context, userID, intentID string, metadata ObjectMetadata, now time.Time) (Intent, error) {
	if r.intent.UserID != userID || r.intent.ID != intentID {
		return Intent{}, ErrNotFound
	}
	if r.intent.State == "uploaded" {
		return r.intent, nil
	}
	r.intent.State, r.intent.UploadedAt, r.intent.ObjectETag = "uploaded", now, metadata.ETag
	return r.intent, nil
}

type memoryObjects struct {
	metadata  ObjectMetadata
	statErr   error
	deleteErr error
	deleted   []string
}

func (m *memoryObjects) AuthorizePut(_ context.Context, _ string, _ int64, _ [32]byte, _ time.Time) (UploadAuthority, error) {
	return UploadAuthority{URL: "https://objects.example/upload", Headers: map[string]string{"x-checksum-sha256": "bound"}}, nil
}
func (m *memoryObjects) Stat(_ context.Context, _ string) (ObjectMetadata, error) {
	return m.metadata, m.statErr
}
func (m *memoryObjects) Delete(_ context.Context, key string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deleted = append(m.deleted, key)
	return nil
}

type cleanupRepository struct {
	items   []CleanupItem
	expired []string
	deleted []string
}

func (r *cleanupRepository) Reserve(context.Context, CreateRequest, [32]byte, Intent) (Intent, error) {
	return Intent{}, ErrInvalid
}
func (r *cleanupRepository) Get(context.Context, string, string) (Intent, error) {
	return Intent{}, ErrInvalid
}
func (r *cleanupRepository) Complete(context.Context, string, string, ObjectMetadata, time.Time) (Intent, error) {
	return Intent{}, ErrInvalid
}
func (r *cleanupRepository) CleanupCandidates(context.Context, time.Time, int) ([]CleanupItem, error) {
	return append([]CleanupItem(nil), r.items...), nil
}
func (r *cleanupRepository) MarkExpired(_ context.Context, id string, _ time.Time) error {
	r.expired = append(r.expired, id)
	return nil
}
func (r *cleanupRepository) DeleteRetained(_ context.Context, id string, _ time.Time) error {
	r.deleted = append(r.deleted, id)
	return nil
}

func TestCreateAndCompleteExactUpload(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	repository := &memoryRepository{}
	objects := &memoryObjects{}
	service, err := New(repository, objects)
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return now }
	service.random = deterministicRandom()
	request := validRequest()
	intent, authority, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if authority.URL == "" || intent.ExpiresAt.Sub(now) != IntentLifetime || intent.Bytes != request.Bytes {
		t.Fatalf("unexpected intent: %#v %#v", intent, authority)
	}
	objects.metadata = ObjectMetadata{Bytes: intent.Bytes, SHA256: intent.SHA256, ETag: "etag-1"}
	completed, err := service.Complete(context.Background(), request.UserID, intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != "uploaded" || completed.CorrelationID != request.CorrelationID {
		t.Fatalf("unexpected completion: %#v", completed)
	}
	objects.statErr = errors.New("must not stat completed replay")
	replayed, err := service.Complete(context.Background(), request.UserID, intent.ID)
	if err != nil || replayed.ObjectETag != "etag-1" {
		t.Fatalf("completion replay: %#v %v", replayed, err)
	}
}

func TestCreateIdempotencyReplayAndConflict(t *testing.T) {
	repository := &memoryRepository{}
	service, _ := New(repository, &memoryObjects{})
	service.random = deterministicRandom()
	request := validRequest()
	first, _, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := service.Create(context.Background(), request)
	if err != nil || first.ID != second.ID || first.ObjectKey != second.ObjectKey {
		t.Fatalf("replay changed intent: %#v %#v %v", first, second, err)
	}
	request.Bytes++
	if _, _, err := service.Create(context.Background(), request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestCompleteRejectsMismatchAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	repository := &memoryRepository{}
	objects := &memoryObjects{}
	service, _ := New(repository, objects)
	service.clock = func() time.Time { return now }
	service.random = deterministicRandom()
	intent, _, err := service.Create(context.Background(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	objects.metadata = ObjectMetadata{Bytes: intent.Bytes + 1, SHA256: intent.SHA256, ETag: "etag"}
	if _, err := service.Complete(context.Background(), intent.UserID, intent.ID); !errors.Is(err, ErrUploadMismatch) {
		t.Fatalf("length mismatch = %v", err)
	}
	objects.metadata.Bytes, objects.metadata.SHA256[0] = intent.Bytes, intent.SHA256[0]^0xff
	if _, err := service.Complete(context.Background(), intent.UserID, intent.ID); !errors.Is(err, ErrUploadMismatch) {
		t.Fatalf("hash mismatch = %v", err)
	}
	service.clock = func() time.Time { return intent.ExpiresAt }
	if _, err := service.Complete(context.Background(), intent.UserID, intent.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry = %v", err)
	}
}

func TestCreateRejectsInvalidCategoriesAndSize(t *testing.T) {
	service, _ := New(&memoryRepository{}, &memoryObjects{})
	request := validRequest()
	request.Categories[0] = "paths"
	if _, _, err := service.Create(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("categories = %v", err)
	}
	request = validRequest()
	request.Bytes = MaximumBundleBytes + 1
	if _, _, err := service.Create(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("size = %v", err)
	}
}

func TestCleanupDeletesObjectsBeforeChangingAuthority(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	repository := &cleanupRepository{items: []CleanupItem{
		{ID: "pending", ObjectKey: "diagnostics/diag_0123456789abcdef/0123456789abcdef.zip", State: "pending", ExpiresAt: now, RetainUntil: now.Add(time.Hour)},
		{ID: "retained", ObjectKey: "diagnostics/diag_fedcba9876543210/fedcba9876543210.zip", State: "uploaded", ExpiresAt: now.Add(-time.Hour), RetainUntil: now},
	}}
	objects := &memoryObjects{}
	service, _ := New(repository, objects)
	service.clock = func() time.Time { return now }
	if err := service.Cleanup(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(repository.expired, []string{"pending"}) || !slices.Equal(repository.deleted, []string{"retained"}) || len(objects.deleted) != 2 {
		t.Fatalf("expired=%v metadata deleted=%v objects=%v", repository.expired, repository.deleted, objects.deleted)
	}
	repository.expired, repository.deleted = nil, nil
	objects.deleteErr = errors.New("storage down")
	if err := service.Cleanup(context.Background(), 100); err == nil || len(repository.expired) != 0 || len(repository.deleted) != 0 {
		t.Fatalf("failure changed metadata: expired=%v deleted=%v error=%v", repository.expired, repository.deleted, err)
	}
}

func validRequest() CreateRequest {
	return CreateRequest{UserID: "usr_test", CLIClientSessionID: "cli_test", OperationKey: "operation-key-0001",
		CorrelationID: "pb-0123456789abcdef0123456789abcdef", Bytes: 1024,
		SHA256:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Categories: []string{"manifest", "recent_events", "redacted_events", "status"}}
}

func deterministicRandom() func([]byte) error {
	var value byte
	return func(buffer []byte) error {
		for index := range buffer {
			value++
			buffer[index] = value
		}
		return nil
	}
}
