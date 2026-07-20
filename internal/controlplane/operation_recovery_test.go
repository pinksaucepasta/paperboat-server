package controlplane

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestOperationRecoveryIsAuditedAndIdempotent(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	actorID := "recovery_user_" + suffix
	operationID := "recovery_op_" + suffix
	seedRecoveryUser(t, store, actorID, suffix)
	seedControlOperation(t, store, operationID, "recovery_source_"+suffix)
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_operations SET state='dead_letter', attempts=4, last_error='terminal failure' WHERE id=$1`, operationID); err != nil {
		t.Fatal(err)
	}

	service := NewOperationRecoveryService(store, audit.NewWriter(store))
	key := "recover_key_" + suffix
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	if err := service.Recover(ctx, actorID, key, operationID, now); err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(ctx, actorID, key, operationID, now.Add(time.Minute)); err != nil {
		t.Fatalf("exact replay: %v", err)
	}

	var state string
	var attempts int
	if err := store.SQL().QueryRowContext(ctx, `SELECT state, attempts FROM paperboat.control_operations WHERE id=$1`, operationID).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || attempts != 0 {
		t.Fatalf("state/attempts = %s/%d, want pending/0", state, attempts)
	}
	var audits int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.audit_events WHERE event_type='control.operation_recovered' AND resource_id=$1 AND idempotency_key=$2`, operationID, key).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("audit count = %d, want 1", audits)
	}

	otherID := "recovery_other_" + suffix
	seedControlOperation(t, store, otherID, "recovery_other_key_"+suffix)
	if err := service.Recover(ctx, actorID, key, otherID, now); !errors.Is(err, ErrRecoveryKeyConflict) {
		t.Fatalf("conflicting replay error = %v, want ErrRecoveryKeyConflict", err)
	}
}

func TestOperationRecoveryRollsBackReservationForNonDeadLetter(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	operationID := "non_dead_op_" + suffix
	seedControlOperation(t, store, operationID, "non_dead_source_"+suffix)
	key := "non_dead_recovery_" + suffix

	service := NewOperationRecoveryService(store, nil)
	if err := service.Recover(ctx, "", key, operationID, time.Now()); !errors.Is(err, ErrOperationNotDeadLettered) {
		t.Fatalf("recovery error = %v, want ErrOperationNotDeadLettered", err)
	}
	var count int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.control_operation_recoveries WHERE operation_key=$1`, key).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("recovery reservation count = %d, want 0", count)
	}
}

func seedRecoveryUser(t *testing.T, store *db.DB, actorID, suffix string) {
	t.Helper()
	if _, err := store.SQL().ExecContext(context.Background(), `
		INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
		VALUES ($1, $2, $3, 'active')`, actorID, "workos_"+suffix, suffix+"@recovery.example.test"); err != nil {
		t.Fatal(err)
	}
}
