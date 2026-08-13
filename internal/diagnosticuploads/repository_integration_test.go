package diagnosticuploads

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

type integrationObjects struct {
	mu       sync.Mutex
	metadata map[string]ObjectMetadata
	deleted  []string
}

func (s *integrationObjects) AuthorizePut(_ context.Context, key string, _ int64, _ [32]byte, _ time.Time) (UploadAuthority, error) {
	return UploadAuthority{URL: "https://objects.example.test/" + key, Headers: map[string]string{"If-None-Match": "*"}}, nil
}
func (s *integrationObjects) Stat(_ context.Context, key string) (ObjectMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	metadata, ok := s.metadata[key]
	if !ok {
		return ObjectMetadata{}, ErrNotFound
	}
	return metadata, nil
}
func (s *integrationObjects) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.metadata, key)
	s.deleted = append(s.deleted, key)
	return nil
}

func TestSQLRepositoryDiagnosticUploadLifecycle(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run diagnostic upload repository integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	suffix := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_")) + strings.ReplaceAll(now.Format("150405.000000000"), ".", "")
	userA, userB := "diag_user_a_"+suffix, "diag_user_b_"+suffix
	clientA, clientB := "diag_cli_a_"+suffix, "diag_cli_b_"+suffix
	for _, userID := range []string{userA, userB} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []struct{ id, user string }{{clientA, userA}, {clientB, userB}} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'Diagnostics test','desktop','test',ARRAY['diagnostics:upload'],'active',$4,$4)`, value.id, value.user, "client_"+value.id, now); err != nil {
			t.Fatal(err)
		}
	}
	repository, err := NewSQLRepository(store, audit.NewWriter(store))
	if err != nil {
		t.Fatal(err)
	}
	objects := &integrationObjects{metadata: make(map[string]ObjectMetadata)}
	service, err := New(repository, objects)
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return now }
	request := validRequest()
	request.UserID, request.CLIClientSessionID, request.OperationKey = userA, clientA, "diagnostic-operation-"+suffix
	intent, _, err := service.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	replay, _, err := service.Create(ctx, request)
	if err != nil || replay.ID != intent.ID || replay.ObjectKey != intent.ObjectKey {
		t.Fatalf("replay=%#v error=%v", replay, err)
	}
	conflict := request
	conflict.Bytes++
	if _, _, err := service.Create(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict=%v", err)
	}
	if _, err := service.Complete(ctx, userB, intent.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-user completion=%v", err)
	}
	objects.metadata[intent.ObjectKey] = ObjectMetadata{Bytes: intent.Bytes, SHA256: intent.SHA256, ETag: "etag-integration"}
	const workers = 8
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			completed, completeErr := service.Complete(ctx, userA, intent.ID)
			if completeErr == nil && (completed.State != "uploaded" || completed.CorrelationID != request.CorrelationID) {
				completeErr = fmt.Errorf("invalid completion: %#v", completed)
			}
			errorsByWorker <- completeErr
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatal(err)
		}
	}
	var completionAudits int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.audit_events WHERE resource_type='diagnostic_upload' AND resource_id=$1 AND event_type='diagnostic_upload.completed'`, intent.ID).Scan(&completionAudits); err != nil {
		t.Fatal(err)
	}
	if completionAudits != 1 {
		t.Fatalf("completion audits=%d", completionAudits)
	}
	expiring := request
	expiring.OperationKey += "-expired"
	expiring.CorrelationID = "pb-fedcba9876543210fedcba9876543210"
	expiredIntent, _, err := service.Create(ctx, expiring)
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return expiredIntent.ExpiresAt }
	if _, err := service.Complete(ctx, userA, expiredIntent.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired completion=%v", err)
	}
	if _, _, err := service.Create(ctx, expiring); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired replay=%v", err)
	}
	if err := service.Cleanup(ctx, 100); err != nil {
		t.Fatal(err)
	}
	var expiredState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.diagnostic_upload_intents WHERE id=$1`, expiredIntent.ID).Scan(&expiredState); err != nil || expiredState != "expired" {
		t.Fatalf("expired state=%q error=%v", expiredState, err)
	}
	service.clock = func() time.Time { return expiredIntent.RetainUntil }
	if err := service.Cleanup(ctx, 100); err != nil {
		t.Fatal(err)
	}
	var retainedRows int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.diagnostic_upload_intents WHERE id IN ($1,$2)`, intent.ID, expiredIntent.ID).Scan(&retainedRows); err != nil || retainedRows != 0 {
		t.Fatalf("retained rows=%d error=%v", retainedRows, err)
	}
	if len(objects.deleted) < 2 {
		t.Fatalf("deleted objects=%v", objects.deleted)
	}
	_ = clientB
}
