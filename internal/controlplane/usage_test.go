package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/connectedmachines"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestValidateUsageReport(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	valid := usageReport("op_valid_01", "epoch_valid_01", 100, now)
	for name, mutate := range map[string]func(*UsageReport){
		"missing operation": func(r *UsageReport) { r.OperationID = "" },
		"negative bytes":    func(r *UsageReport) { r.Bytes = -1 },
		"bad direction":     func(r *UsageReport) { r.Direction = "sideways" },
		"bad revision":      func(r *UsageReport) { r.RouteRevision = 0 },
		"reversed interval": func(r *UsageReport) { r.IntervalEnd = r.IntervalStart.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			report := valid
			mutate(&report)
			if err := validateUsageReport(report); !errors.Is(err, ErrInvalidUsageReport) {
				t.Fatalf("error = %v, want ErrInvalidUsageReport", err)
			}
		})
	}
}

func TestReconcileUsageAbsoluteCounters(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUsageScope(t, store, suffix)

	report := usageReport("op_usage_1_"+suffix, "epoch_usage_1_"+suffix, 100, now)
	report.EdgeNodeID, report.EnvironmentID, report.RouteID = "node_"+suffix, "env_"+suffix, "route_"+suffix
	first, err := ReconcileUsage(ctx, store, report, now)
	if err != nil || first.DeltaBytes != 100 || first.Duplicate {
		t.Fatalf("first receipt = %#v, %v", first, err)
	}
	replay, err := ReconcileUsage(ctx, store, report, now.Add(time.Second))
	if err != nil || replay.DeltaBytes != 100 || !replay.Duplicate {
		t.Fatalf("replay receipt = %#v, %v", replay, err)
	}

	higher := report
	higher.OperationID, higher.Bytes = "op_usage_2_"+suffix, 160
	higher.IntervalStart, higher.IntervalEnd = report.IntervalEnd, report.IntervalEnd.Add(time.Minute)
	receipt, err := ReconcileUsage(ctx, store, higher, now.Add(time.Minute))
	if err != nil || receipt.DeltaBytes != 60 {
		t.Fatalf("higher receipt = %#v, %v", receipt, err)
	}

	lower := higher
	lower.OperationID, lower.Bytes = "op_usage_3_"+suffix, 120
	lower.IntervalStart, lower.IntervalEnd = higher.IntervalEnd, higher.IntervalEnd.Add(time.Minute)
	receipt, err = ReconcileUsage(ctx, store, lower, now.Add(2*time.Minute))
	if err != nil || receipt.DeltaBytes != 0 {
		t.Fatalf("lower receipt = %#v, %v", receipt, err)
	}

	reset := lower
	reset.OperationID, reset.CounterEpoch, reset.Bytes = "op_usage_4_"+suffix, "epoch_usage_2_"+suffix, 10
	reset.IntervalStart, reset.IntervalEnd = lower.IntervalEnd, lower.IntervalEnd.Add(time.Minute)
	receipt, err = ReconcileUsage(ctx, store, reset, now.Add(3*time.Minute))
	if err != nil || receipt.DeltaBytes != 10 {
		t.Fatalf("epoch reset receipt = %#v, %v", receipt, err)
	}
}

func TestReconcileUsageRejectsConflictingOperationReplay(t *testing.T) {
	store := openControlPlaneTestDB(t)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUsageScope(t, store, suffix)
	report := usageReport("op_conflict_"+suffix, "epoch_conflict_"+suffix, 10, now)
	report.EdgeNodeID, report.EnvironmentID, report.RouteID = "node_"+suffix, "env_"+suffix, "route_"+suffix
	if _, err := ReconcileUsage(context.Background(), store, report, now); err != nil {
		t.Fatal(err)
	}
	report.Bytes = 11
	if _, err := ReconcileUsage(context.Background(), store, report, now); !errors.Is(err, ErrUsageOperationConflict) {
		t.Fatalf("error = %v, want ErrUsageOperationConflict", err)
	}
}

func TestReconcileUsageAcceptsIntervalOnlyRetry(t *testing.T) {
	store := openControlPlaneTestDB(t)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUsageScope(t, store, suffix)
	report := usageReport("op_interval_retry_"+suffix, "epoch_interval_retry_"+suffix, 10, now)
	report.EdgeNodeID, report.EnvironmentID, report.RouteID = "node_"+suffix, "env_"+suffix, "route_"+suffix
	if _, err := ReconcileUsage(context.Background(), store, report, now); err != nil {
		t.Fatal(err)
	}
	report.IntervalStart = report.IntervalStart.Add(time.Hour)
	report.IntervalEnd = report.IntervalEnd.Add(time.Hour)
	retry, err := ReconcileUsage(context.Background(), store, report, now.Add(time.Hour))
	if err != nil || !retry.Duplicate || retry.DeltaBytes != 10 {
		t.Fatalf("retry = %#v, %v", retry, err)
	}
}

func TestEdgeUsageRequiresActiveNodeSignature(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUsageScope(t, store, suffix)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := "usage_key_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_usage_verification_keys (key_id,edge_node_id,public_key,not_before,expires_at) VALUES ($1,$2,$3,$4,$5)`, keyID, "node_"+suffix, []byte(publicKey), now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	request := edgeUsageRequest{OperationID: "op_signed_" + suffix, Node: "node_" + suffix, Epoch: "epoch_signed_" + suffix, Environment: "env_" + suffix, Route: "route_" + suffix, Revision: 1, Direction: "egress", Bytes: 25, Start: now.Add(-time.Minute), End: now}
	document := signedUsageDocument{OperationID: request.OperationID, Key: signedUsageKey{Node: request.Node, Epoch: request.Epoch, Environment: request.Environment, Route: request.Route, Direction: request.Direction, Revision: request.Revision}, Bytes: request.Bytes, Start: request.Start, End: request.End}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(signedUsageEnvelope{Algorithm: "EdDSA", KeyID: keyID, Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))})
	if err != nil {
		t.Fatal(err)
	}
	request.Payload = envelope
	service := NewEdgeService(store, "unused-test-credential")
	service.SetClock(func() time.Time { return now })
	receipt, err := service.Usage(ctx, request)
	if err != nil || receipt.DeltaBytes != 25 {
		t.Fatalf("signed usage = %#v, %v", receipt, err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_usage_verification_keys SET revoked_at=$2 WHERE key_id=$1`, keyID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Usage(ctx, request); !errors.Is(err, ErrUsageSignature) {
		t.Fatalf("revoked replay error = %v, want ErrUsageSignature", err)
	}
}

func TestReconcileUsageDebitsBYODBandwidthAndSuspendsOnExhaustion(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUsageScope(t, store, suffix)
	userID, machineID := "usage_bw_user_"+suffix, "usage_bw_machine_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machine_entitlements (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end) VALUES ($1,$2,$3,'byod-test','active',1,100,$4,$5)`, "ent_"+suffix, userID, "sub_"+suffix, now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,$4,'linux','amd64','/home/test','online','occupied',true)`, machineID, userID, "env_"+suffix, "Usage "+suffix); err != nil {
		t.Fatal(err)
	}
	debit := connectedmachines.New(store, audit.NewWriter(store), connectedmachines.Policy{}, nil)
	report := usageReport("op_bw_"+suffix, "epoch_bw_"+suffix, 120, now)
	report.EdgeNodeID, report.EnvironmentID, report.RouteID = "node_"+suffix, "env_"+suffix, "route_"+suffix
	receipt, err := ReconcileUsageWithBandwidth(ctx, store, report, now, debit)
	if err != nil || receipt.DeltaBytes != 120 {
		t.Fatalf("receipt = %#v, %v", receipt, err)
	}
	replay, err := ReconcileUsageWithBandwidth(ctx, store, report, now.Add(time.Second), debit)
	if err != nil || !replay.Duplicate || replay.DeltaBytes != 120 {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	var consumed int64
	if err := store.SQL().QueryRowContext(ctx, `SELECT consumed_included_bytes FROM paperboat.connected_machine_bandwidth_periods WHERE connected_machine_id=$1`, machineID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if consumed != 100 {
		t.Fatalf("consumed bandwidth = %d, want 100", consumed)
	}
	var desired string
	if err := store.SQL().QueryRowContext(ctx, `SELECT desired_state FROM paperboat.control_environments WHERE id=$1`, "env_"+suffix).Scan(&desired); err != nil {
		t.Fatal(err)
	}
	if desired != "suspended" {
		t.Fatalf("environment desired state = %q, want suspended", desired)
	}
}

func usageReport(operationID, epoch string, bytes int64, now time.Time) UsageReport {
	return UsageReport{OperationID: operationID, EdgeNodeID: "node", CounterEpoch: epoch, EnvironmentID: "env", RouteID: "route", RouteRevision: 1, Direction: "ingress", Bytes: bytes, IntervalStart: now.Add(-time.Minute), IntervalEnd: now}
}

func openControlPlaneTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run control-plane PostgreSQL integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	return store
}

func seedUsageScope(t *testing.T, store *db.DB, suffix string) {
	t.Helper()
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_usage_receipts WHERE environment_id=$1`, "env_"+suffix)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_usage_counters WHERE environment_id=$1`, "env_"+suffix)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_routes WHERE environment_id=$1`, "env_"+suffix)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_tunnel_nodes WHERE id=$1`, "node_"+suffix)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_environments WHERE id=$1`, "env_"+suffix)
	})
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id, workspace_id) VALUES ($1,$2)`, "env_"+suffix, "workspace_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch) VALUES ($1,'default','1.0',$2)`, "node_"+suffix, "process_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port) VALUES ($1,$2,'helper_https_wss',$3,'127.0.0.1',8443)`, "route_"+suffix, "env_"+suffix, "route-"+suffix+".example.test"); err != nil {
		t.Fatal(err)
	}
}
