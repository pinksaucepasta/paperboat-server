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
}
