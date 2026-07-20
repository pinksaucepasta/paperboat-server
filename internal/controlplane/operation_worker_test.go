package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestOperationRunnerLeasesOnceAndCompletes(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	operationID := "worker_op_" + suffix
	seedControlOperation(t, store, operationID, "worker_key_"+suffix)

	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	runner := NewOperationRunner(store, 3, time.Minute, 30*time.Second)
	runner.now = func() time.Time { return now }

	var wg sync.WaitGroup
	leased := make(chan dbsqlc.ControlOperation, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			operations, err := runner.Lease(ctx, 1)
			if err != nil {
				t.Error(err)
				return
			}
			for _, operation := range operations {
				leased <- operation
			}
		}()
	}
	wg.Wait()
	close(leased)
	var leasedOperations []dbsqlc.ControlOperation
	for operation := range leased {
		leasedOperations = append(leasedOperations, operation)
	}
	if len(leasedOperations) != 1 || leasedOperations[0].ID != operationID {
		t.Fatalf("leased operations = %v, want [%s]", leasedOperations, operationID)
	}
	operation := leasedOperations[0]
	if err := runner.Succeed(ctx, operation, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := runner.Succeed(ctx, operation, []byte(`{"ok":true}`)); !errors.Is(err, ErrOperationLeaseLost) {
		t.Fatalf("second completion error = %v, want ErrOperationLeaseLost", err)
	}
	var state string
	var attempts int
	if err := store.SQL().QueryRowContext(ctx, `SELECT state, attempts FROM paperboat.control_operations WHERE id=$1`, operationID).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != "succeeded" || attempts != 1 {
		t.Fatalf("state = %s, attempts = %d, want succeeded/1", state, attempts)
	}
}

func TestOperationRunnerRetriesUncertainAndDeadLetters(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	operationID := "retry_op_" + suffix
	seedControlOperation(t, store, operationID, "retry_key_"+suffix)

	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	runner := NewOperationRunner(store, 2, time.Minute, 30*time.Second)
	runner.now = func() time.Time { return now }
	operations, err := runner.Lease(ctx, 1)
	if err != nil || len(operations) != 1 {
		t.Fatalf("first lease = %v, %v", operations, err)
	}
	if err := runner.Uncertain(ctx, operations[0], "provider outcome unknown"); err != nil {
		t.Fatal(err)
	}
	if operations, err = runner.Lease(ctx, 1); err != nil || len(operations) != 0 {
		t.Fatalf("lease before retry = %v, %v", operations, err)
	}
	now = now.Add(time.Minute)
	if operations, err = runner.Lease(ctx, 1); err != nil || len(operations) != 1 {
		t.Fatalf("retry lease = %v, %v", operations, err)
	}
	if err := runner.Fail(ctx, operations[0], "provider rejected request"); err != nil {
		t.Fatal(err)
	}
	var state, lastError string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state, last_error FROM paperboat.control_operations WHERE id=$1`, operationID).Scan(&state, &lastError); err != nil {
		t.Fatal(err)
	}
	if state != "dead_letter" || lastError != "provider rejected request" {
		t.Fatalf("state/error = %q/%q, want dead_letter/provider rejected request", state, lastError)
	}
}

func TestOperationRunnerReclaimsExpiredLeaseAndFencesStaleWorker(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	operationID := "reclaim_op_" + suffix
	seedControlOperation(t, store, operationID, "reclaim_key_"+suffix)

	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	runner := NewOperationRunner(store, 3, time.Minute, 30*time.Second)
	runner.now = func() time.Time { return now }
	first, err := runner.Lease(ctx, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first lease = %v, %v", first, err)
	}
	now = now.Add(31 * time.Second)
	second, err := runner.Lease(ctx, 1)
	if err != nil || len(second) != 1 {
		t.Fatalf("reclaimed lease = %v, %v", second, err)
	}
	if second[0].Attempts != 2 || !second[0].LeaseExpiresAt.Time.After(first[0].LeaseExpiresAt.Time) {
		t.Fatalf("reclaimed operation = %#v, want attempt 2 with newer lease", second[0])
	}
	if err := runner.Succeed(ctx, first[0], []byte(`{"worker":"stale"}`)); !errors.Is(err, ErrOperationLeaseLost) {
		t.Fatalf("stale completion error = %v, want ErrOperationLeaseLost", err)
	}
	if err := runner.Succeed(ctx, second[0], []byte(`{"worker":"current"}`)); err != nil {
		t.Fatal(err)
	}
}

func seedControlOperation(t *testing.T, store *db.DB, operationID, operationKey string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_operations WHERE id=$1`, operationID)
	})
	if _, err := store.SQL().ExecContext(context.Background(), `
		INSERT INTO paperboat.control_operations (id, operation_key, operation_type, request_hash)
		VALUES ($1, $2, 'worker_test', $3)`, operationID, operationKey, []byte("request-hash")); err != nil {
		t.Fatal(err)
	}
}
