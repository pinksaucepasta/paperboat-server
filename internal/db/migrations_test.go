package db_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestMigrateRequiresPostgresIntegrationDSN(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres migration integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	var applied bool
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM paperboat.schema_migrations WHERE version = 1)`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("migration version 1 was not recorded")
	}
}

func TestConcurrentMigrateCallsAreSerialized(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres migration integration tests")
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	start := make(chan struct{})
	errs := make(chan error, 4)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- db.Migrate(ctx, store)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migrate failed: %v", err)
		}
	}
}

func TestTransactionRollsBackOnError(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres transaction integration tests")
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("force rollback")
	err = store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Exec(ctx, `
INSERT INTO users (id, workos_subject, primary_email, status)
VALUES ('user_rollback_test', 'workos_rollback_test', 'rollback@example.com', 'active')
ON CONFLICT (id) DO UPDATE SET primary_email = EXCLUDED.primary_email`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want sentinel", err)
	}
	var exists bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM paperboat.users WHERE id = 'user_rollback_test')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("rolled back transaction still inserted user")
	}
}
