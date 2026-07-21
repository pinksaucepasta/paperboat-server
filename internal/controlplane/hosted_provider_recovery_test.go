package controlplane

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
)

func TestHostedProviderRecoveryIsEvidenceBoundAndIdempotent(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	actor := "hosted_recovery_user_" + suffix
	seedRecoveryUser(t, store, actor, suffix)
	job := "hosted_recovery_job_" + suffix
	op := "hosted_recovery_op_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.orchestration_jobs (id,job_type,aggregate_type,aggregate_id,idempotency_key,state) VALUES ($1,'project.delete','project',$2,$1,'queued')`, job, "project_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.hosted_provider_operations (id,orchestration_job_id,step,resource_type,request_hash,state,outcome) VALUES ($1,$2,'delete_secret:test','secret','\x01','uncertain','uncertain')`, op, job); err != nil {
		t.Fatal(err)
	}
	service := NewHostedProviderRecoveryService(store, audit.NewWriter(store))
	key := "hosted_recovery_key_" + suffix
	if err := service.Recover(ctx, actor, key, op, "confirm_deleted", "fly-console-case-123"); err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(ctx, actor, key, op, "confirm_deleted", "fly-console-case-123"); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if err := service.Recover(ctx, actor, key, op, "retry", "different-evidence"); !errors.Is(err, ErrRecoveryKeyConflict) {
		t.Fatalf("conflict = %v", err)
	}
	var state, outcome string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,outcome FROM paperboat.hosted_provider_operations WHERE id=$1`, op).Scan(&state, &outcome); err != nil {
		t.Fatal(err)
	}
	if state != "succeeded" || outcome != "success" {
		t.Fatalf("state/outcome = %s/%s", state, outcome)
	}
	var audits int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.audit_events WHERE event_type='hosted.provider_operation_recovered' AND resource_id=$1`, op).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("audit count = %d", audits)
	}
	var storedEvidence string
	if err := store.SQL().QueryRowContext(ctx, `SELECT evidence_reference FROM paperboat.hosted_provider_operation_recoveries WHERE operation_key=$1`, key).Scan(&storedEvidence); err != nil {
		t.Fatal(err)
	}
	if storedEvidence == "fly-console-case-123" || len(storedEvidence) != 64 {
		t.Fatalf("stored evidence was not hashed: %q", storedEvidence)
	}
}
