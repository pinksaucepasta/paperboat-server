package observability

import "sync/atomic"

var platformMetrics struct {
	deviceRequested           atomic.Int64
	deviceCompleted           atomic.Int64
	deviceLoginLatencyMS      atomic.Int64
	deviceLoginLatencyMax     atomic.Int64
	connectAttempts           atomic.Int64
	connectApproved           atomic.Int64
	connectDenied             atomic.Int64
	routeReady                atomic.Int64
	credentialsMinted         atomic.Int64
	revocationsPropagated     atomic.Int64
	terminalSessionsCreated   atomic.Int64
	terminalSessionsClosed    atomic.Int64
	terminalSessionsDeleted   atomic.Int64
	terminalOperationsApplied atomic.Int64
	terminalOperationRetries  atomic.Int64
	terminalOperationAlerts   atomic.Int64
	terminalSnapshots         atomic.Int64
	terminalSnapshotFailures  atomic.Int64
}

func DeviceRequested() { platformMetrics.deviceRequested.Add(1) }
func DeviceCompleted(latencyMS int64) {
	platformMetrics.deviceCompleted.Add(1)
	platformMetrics.deviceLoginLatencyMS.Add(max(0, latencyMS))
	updateMax(&platformMetrics.deviceLoginLatencyMax, latencyMS)
}
func ConnectAttempted()         { platformMetrics.connectAttempts.Add(1) }
func ConnectApproved()          { platformMetrics.connectApproved.Add(1) }
func ConnectDenied()            { platformMetrics.connectDenied.Add(1) }
func RouteReady()               { platformMetrics.routeReady.Add(1) }
func CredentialsMinted()        { platformMetrics.credentialsMinted.Add(1) }
func RevocationPropagated()     { platformMetrics.revocationsPropagated.Add(1) }
func TerminalSessionCreated()   { platformMetrics.terminalSessionsCreated.Add(1) }
func TerminalSessionClosed()    { platformMetrics.terminalSessionsClosed.Add(1) }
func TerminalSessionDeleted()   { platformMetrics.terminalSessionsDeleted.Add(1) }
func TerminalOperationApplied() { platformMetrics.terminalOperationsApplied.Add(1) }
func TerminalOperationRetried() { platformMetrics.terminalOperationRetries.Add(1) }
func TerminalOperationAlerted() { platformMetrics.terminalOperationAlerts.Add(1) }
func TerminalSnapshot()         { platformMetrics.terminalSnapshots.Add(1) }
func TerminalSnapshotFailed()   { platformMetrics.terminalSnapshotFailures.Add(1) }

func MetricsSnapshot() map[string]int64 {
	return map[string]int64{
		"device_requested_total":            platformMetrics.deviceRequested.Load(),
		"device_completed_total":            platformMetrics.deviceCompleted.Load(),
		"device_login_latency_ms_total":     platformMetrics.deviceLoginLatencyMS.Load(),
		"device_login_latency_ms_max":       platformMetrics.deviceLoginLatencyMax.Load(),
		"connect_attempts_total":            platformMetrics.connectAttempts.Load(),
		"connect_approved_total":            platformMetrics.connectApproved.Load(),
		"connect_denied_total":              platformMetrics.connectDenied.Load(),
		"route_ready_total":                 platformMetrics.routeReady.Load(),
		"credentials_minted_total":          platformMetrics.credentialsMinted.Load(),
		"revocations_propagated_total":      platformMetrics.revocationsPropagated.Load(),
		"terminal_sessions_created_total":   platformMetrics.terminalSessionsCreated.Load(),
		"terminal_sessions_closed_total":    platformMetrics.terminalSessionsClosed.Load(),
		"terminal_sessions_deleted_total":   platformMetrics.terminalSessionsDeleted.Load(),
		"terminal_operations_applied_total": platformMetrics.terminalOperationsApplied.Load(),
		"terminal_operation_retries_total":  platformMetrics.terminalOperationRetries.Load(),
		"terminal_operation_alerts_total":   platformMetrics.terminalOperationAlerts.Load(),
		"terminal_snapshots_total":          platformMetrics.terminalSnapshots.Load(),
		"terminal_snapshot_failures_total":  platformMetrics.terminalSnapshotFailures.Load(),
	}
}

func updateMax(value *atomic.Int64, candidate int64) {
	for current := value.Load(); candidate > current; current = value.Load() {
		if value.CompareAndSwap(current, candidate) {
			return
		}
	}
}
