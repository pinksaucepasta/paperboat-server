package observability

import "testing"

func TestMetricsSnapshotTracksBoundedPlatformCounters(t *testing.T) {
	before := MetricsSnapshot()
	DeviceRequested()
	DeviceCompleted(25)
	ConnectAttempted()
	ConnectApproved()
	ConnectDenied()
	RouteReady()
	CredentialsMinted()
	RevocationPropagated()
	TerminalSessionCreated()
	TerminalSessionClosed()
	TerminalSessionDeleted()
	TerminalOperationApplied()
	TerminalOperationRetried()
	TerminalOperationAlerted()
	TerminalSnapshot()
	TerminalSnapshotFailed()
	after := MetricsSnapshot()
	for _, key := range []string{"device_requested_total", "device_completed_total", "connect_attempts_total", "connect_approved_total", "connect_denied_total", "route_ready_total", "credentials_minted_total", "revocations_propagated_total", "terminal_sessions_created_total", "terminal_sessions_closed_total", "terminal_sessions_deleted_total", "terminal_operations_applied_total", "terminal_operation_retries_total", "terminal_operation_alerts_total", "terminal_snapshots_total", "terminal_snapshot_failures_total"} {
		if after[key] != before[key]+1 {
			t.Fatalf("%s = %d, want %d", key, after[key], before[key]+1)
		}
	}
	if after["device_login_latency_ms_total"] != before["device_login_latency_ms_total"]+25 {
		t.Fatalf("latency total = %d", after["device_login_latency_ms_total"])
	}
	if after["device_login_latency_ms_max"] < 25 {
		t.Fatalf("latency max = %d", after["device_login_latency_ms_max"])
	}
}
