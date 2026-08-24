package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestMigrateBeforeServeFailsClosed(t *testing.T) {
	err := migrateBeforeServe(context.Background(), config.Database{Driver: "sqlite", DSN: "ignored"})
	if err == nil || !strings.Contains(err.Error(), "postgres is required") {
		t.Fatalf("error=%v", err)
	}
}

func TestMigrateBeforeServeAppliesLatestMigrationConcurrentlyAndHonorsCancellation(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run startup migration integration tests")
	}
	database := config.Database{Driver: "postgres", DSN: dsn}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			errs <- migrateBeforeServe(context.Background(), database)
		}()
	}
	ready.Wait()
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	store, err := db.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var applied bool
	if err := store.SQL().QueryRow(`SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id=116 AND is_applied)`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("startup migration did not apply migration 116")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := migrateBeforeServe(canceled, database); err == nil {
		t.Fatal("startup migration accepted a canceled context")
	}
}

func TestRunAdminRejectsUnknownOperation(t *testing.T) {
	err := runAdmin([]string{"usage-key", "revoke"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "project delete") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunAdminDeleteProjectRequiresExplicitOwnerAndProject(t *testing.T) {
	err := runAdmin([]string{"project", "delete", "--user-id", "usr_1"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || err.Error() != "admin project delete requires --user-id and --project-id" {
		t.Fatalf("error = %v", err)
	}
}

func TestRunAdminProvisionUsageKeyValidatesPublicKeyBeforeConfiguration(t *testing.T) {
	err := runAdmin([]string{
		"usage-key", "provision",
		"-public-key", "not-base64url!",
		"-not-before", "2026-07-22T00:00:00Z",
		"-expires-at", "2026-07-23T00:00:00Z",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || err.Error() != "public-key must be unpadded base64url" {
		t.Fatalf("error = %v", err)
	}
}

func TestRunAdminProvisionUsageKeyValidatesTimestampsBeforeConfiguration(t *testing.T) {
	err := runAdmin([]string{
		"usage-key", "provision",
		"-public-key", strings.Repeat("A", 43),
		"-not-before", "yesterday",
		"-expires-at", "2026-07-23T00:00:00Z",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || err.Error() != "not-before must be RFC3339" {
		t.Fatalf("error = %v", err)
	}
}
