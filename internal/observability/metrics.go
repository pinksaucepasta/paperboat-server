package observability

import "sync/atomic"

var platformMetrics struct {
	deviceRequested       atomic.Int64
	deviceCompleted       atomic.Int64
	deviceLoginLatencyMS  atomic.Int64
	deviceLoginLatencyMax atomic.Int64
	connectAttempts       atomic.Int64
	connectApproved       atomic.Int64
	connectDenied         atomic.Int64
	routeReady            atomic.Int64
	credentialsMinted     atomic.Int64
	revocationsPropagated atomic.Int64
}

func DeviceRequested() { platformMetrics.deviceRequested.Add(1) }
func DeviceCompleted(latencyMS int64) {
	platformMetrics.deviceCompleted.Add(1)
	platformMetrics.deviceLoginLatencyMS.Add(max(0, latencyMS))
	updateMax(&platformMetrics.deviceLoginLatencyMax, latencyMS)
}
func ConnectAttempted()     { platformMetrics.connectAttempts.Add(1) }
func ConnectApproved()      { platformMetrics.connectApproved.Add(1) }
func ConnectDenied()        { platformMetrics.connectDenied.Add(1) }
func RouteReady()           { platformMetrics.routeReady.Add(1) }
func CredentialsMinted()    { platformMetrics.credentialsMinted.Add(1) }
func RevocationPropagated() { platformMetrics.revocationsPropagated.Add(1) }

func MetricsSnapshot() map[string]int64 {
	return map[string]int64{
		"device_requested_total":        platformMetrics.deviceRequested.Load(),
		"device_completed_total":        platformMetrics.deviceCompleted.Load(),
		"device_login_latency_ms_total": platformMetrics.deviceLoginLatencyMS.Load(),
		"device_login_latency_ms_max":   platformMetrics.deviceLoginLatencyMax.Load(),
		"connect_attempts_total":        platformMetrics.connectAttempts.Load(),
		"connect_approved_total":        platformMetrics.connectApproved.Load(),
		"connect_denied_total":          platformMetrics.connectDenied.Load(),
		"route_ready_total":             platformMetrics.routeReady.Load(),
		"credentials_minted_total":      platformMetrics.credentialsMinted.Load(),
		"revocations_propagated_total":  platformMetrics.revocationsPropagated.Load(),
	}
}

func updateMax(value *atomic.Int64, candidate int64) {
	for current := value.Load(); candidate > current; current = value.Load() {
		if value.CompareAndSwap(current, candidate) {
			return
		}
	}
}
