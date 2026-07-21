package controlplane

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestDiagnosticsMetricsReportDurableBacklogs(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	now := time.Now().UTC()
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.hosted_provider_operations WHERE orchestration_job_id LIKE $1`, "%"+suffix)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.orchestration_jobs WHERE id LIKE $1`, "%"+suffix)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.projects WHERE id=$1`, "diag_project_"+suffix)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=$1`, "diag_user_"+suffix)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_operations WHERE operation_type='diagnostics_test' AND operation_key LIKE $1`, "%"+suffix)
	})

	for i, state := range []string{"pending", "failed", "uncertain", "dead_letter"} {
		_, err := store.SQL().ExecContext(ctx, `
			INSERT INTO paperboat.control_operations
				(id, operation_key, operation_type, request_hash, state, created_at, updated_at)
			VALUES ($1, $2, 'diagnostics_test', $3, $4, $5, $5)`,
			fmt.Sprintf("diag_op_%d_%s", i, suffix), fmt.Sprintf("diag_key_%d_%s", i, suffix), "hash_"+suffix, state, now.Add(-5*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `
		INSERT INTO paperboat.control_environments (id, workspace_id)
		VALUES ($1, $2)`, "diag_env_"+suffix, "diag_workspace_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
		INSERT INTO paperboat.control_reconciliation_attempts
			(id, environment_id, desired_version, state, started_at)
		VALUES ($1, $2, 1, 'uncertain', $3)`, "diag_reconcile_"+suffix, "diag_env_"+suffix, now.Add(-4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
		INSERT INTO paperboat.control_tunnel_nodes
			(id, edge_pool, protocol_version, process_epoch, state, last_heartbeat_at)
		VALUES ($1, 'default', '1.0', $2, 'ready', $3)`, "diag_node_"+suffix, "diag_epoch_"+suffix, now.Add(-3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`,
		"diag_user_"+suffix, "diag_subject_"+suffix, "diag_"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.projects (id,user_id,name,state,idempotency_key,created_at) VALUES ($1,$2,'diagnostics','running',$3,$4)`,
		"diag_project_"+suffix, "diag_user_"+suffix, "diag_project_key_"+suffix, now.Add(-7*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, job := range []struct{ id, jobType, state string }{
		{"diag_job_queued_" + suffix, "project.start", "queued"},
		{"diag_job_expired_" + suffix, "project.stop", "running"},
		{"diag_job_orphan_" + suffix, "fly.orphan.remediate", "needs_review"},
	} {
		_, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.orchestration_jobs (id,job_type,aggregate_type,aggregate_id,idempotency_key,state,lease_expires_at,created_at) VALUES ($1,$2,'project',$3,$4,$5,$6,$7)`,
			job.id, job.jobType, "diag_project_"+suffix, "key_"+job.id, job.state, now.Add(-time.Minute), now.Add(-6*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, state := range []string{"uncertain", "pending"} {
		_, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.hosted_provider_operations (id,orchestration_job_id,step,resource_type,request_hash,state,created_at) VALUES ($1,$2,$3,'secret',$4,$5,$6)`,
			fmt.Sprintf("diag_provider_%d_%s", i, suffix), "diag_job_queued_"+suffix, fmt.Sprintf("step_%d", i), []byte("hash_"+suffix), state, now.Add(-5*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.hosted_readiness_observations (id,project_id,orchestration_job_id,stage,state,reason,observed_at) VALUES ($1,$2,$3,'helper_health','failed','diagnostics',$4)`,
		"diag_readiness_"+suffix, "diag_project_"+suffix, "diag_job_queued_"+suffix, now.Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}

	metrics, err := NewDiagnosticsService(store).Metrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if metrics["control_operation_queue_depth"] < 3 {
		t.Fatalf("operation depth = %d, want at least 3", metrics["control_operation_queue_depth"])
	}
	if metrics["control_operation_dead_letter_depth"] < 1 {
		t.Fatalf("dead-letter depth = %d, want at least 1", metrics["control_operation_dead_letter_depth"])
	}
	if metrics["control_operation_oldest_age_seconds"] < 299 {
		t.Fatalf("operation oldest age = %d, want at least 299", metrics["control_operation_oldest_age_seconds"])
	}
	if metrics["control_reconciliation_queue_depth"] < 1 {
		t.Fatalf("reconciliation depth = %d, want at least 1", metrics["control_reconciliation_queue_depth"])
	}
	if metrics["control_reconciliation_oldest_age_seconds"] < 239 {
		t.Fatalf("reconciliation oldest age = %d, want at least 239", metrics["control_reconciliation_oldest_age_seconds"])
	}
	if metrics["control_stale_node_depth"] < 1 {
		t.Fatalf("stale node depth = %d, want at least 1", metrics["control_stale_node_depth"])
	}
	for key, minimum := range map[string]int64{
		"hosted_orchestration_queue_depth":            2,
		"hosted_orchestration_expired_lease_depth":    1,
		"hosted_orchestration_oldest_age_seconds":     359,
		"hosted_provider_uncertain_depth":             1,
		"hosted_provider_retryable_depth":             1,
		"hosted_provider_oldest_age_seconds":          299,
		"hosted_readiness_failure_depth":              1,
		"hosted_readiness_recent_failure_age_seconds": 119,
		"hosted_orphan_review_depth":                  1,
	} {
		if metrics[key] < minimum {
			t.Fatalf("%s = %d, want at least %d", key, metrics[key], minimum)
		}
	}
}
