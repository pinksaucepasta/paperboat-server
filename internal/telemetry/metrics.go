package telemetry

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
	"sync"
)

type MetricKind string

const (
	MetricCounter   MetricKind = "counter"
	MetricGauge     MetricKind = "gauge"
	MetricHistogram MetricKind = "histogram"
)

const (
	MetricAccessDecisions   = "paperboat_edge_access_decisions_total"
	MetricCertificateOps    = "paperboat_edge_certificate_operations_total"
	MetricHealthDimension   = "paperboat_edge_health_dimension"
	MetricHealthTransitions = "paperboat_edge_health_transitions_total"
	MetricOriginConnections = "paperboat_edge_origin_connections_total"
	MetricEdgeRequests      = "paperboat_edge_requests_total"
	MetricRouteRequests     = "paperboat_edge_route_requests_total"
	MetricUpdateOperations  = "paperboat_edge_update_operations_total"
	MetricOperationLatency  = "paperboat_edge_operation_latency_seconds"

	// Server-owned observability names. Labels below are finite enums only;
	// account, tunnel, route, hostname, URL, request, and credential values are
	// deliberately not representable in this registry.
	MetricDNSVerificationDuration   = "paperboat_server_dns_verification_duration_seconds"
	MetricDNSVerificationFailures   = "paperboat_server_dns_verification_failures_total"
	MetricCertificateExpiryHorizon  = "paperboat_server_certificate_expiry_horizon_seconds"
	MetricPreviewAllocation         = "paperboat_server_preview_allocations_total"
	MetricPreviewLeaseCleanup       = "paperboat_server_preview_lease_cleanup_total"
	MetricOperationIdempotency      = "paperboat_server_operation_idempotency_total"
	MetricServiceUptime             = "paperboat_server_service_uptime_seconds"
	MetricServiceRestarts           = "paperboat_server_service_restarts_total"
	MetricServiceWatchdog           = "paperboat_server_service_watchdog_total"
	MetricServiceCrashLoop          = "paperboat_server_service_crash_loop"
	MetricConnectorSessions         = "paperboat_server_connector_sessions"
	MetricConnectorConnections      = "paperboat_server_connector_connections_total"
	MetricConnectorReconnects       = "paperboat_server_connector_reconnects_total"
	MetricConnectorBackoff          = "paperboat_server_connector_backoff_seconds"
	MetricConnectorHandshakeLatency = "paperboat_server_connector_handshake_latency_seconds"
	MetricConnectorDisconnects      = "paperboat_server_connector_disconnects_total"
	MetricConfigGenerations         = "paperboat_server_config_generations"
	MetricActiveStreams             = "paperboat_server_active_streams"
	MetricQueueDepth                = "paperboat_server_queue_depth"
	MetricFlowControlStalls         = "paperboat_server_flow_control_stalls_total"
	MetricBytes                     = "paperboat_server_bytes_total"
	MetricStreamDuration            = "paperboat_server_stream_duration_seconds"
	MetricStreamCancellations       = "paperboat_server_stream_cancellations_total"
	MetricRouteErrors               = "paperboat_server_route_errors_total"
	MetricRouteLatency              = "paperboat_server_route_latency_seconds"
	MetricProtocolUpgrades          = "paperboat_server_protocol_upgrades_total"
	MetricHealthProbes              = "paperboat_server_health_probes_total"
	MetricHTTPRequests              = "paperboat_server_http_requests_total"
	MetricHTTPDuration              = "paperboat_server_http_request_duration_seconds"
)

// Singular/plural aliases keep producer code readable without introducing a
// second metric name or descriptor.
const (
	MetricDNSVerificationFailure          = MetricDNSVerificationFailures
	MetricPreviewAllocations              = MetricPreviewAllocation
	MetricPreviewCleanup                  = MetricPreviewLeaseCleanup
	MetricOperationIdempotencyReuse       = MetricOperationIdempotency
	MetricServiceCrashLoops               = MetricServiceCrashLoop
	MetricDNSVerificationDurationSeconds  = MetricDNSVerificationDuration
	MetricDNSVerificationFailuresTotal    = MetricDNSVerificationFailures
	MetricCertificateExpiryHorizonSeconds = MetricCertificateExpiryHorizon
	MetricPreviewAllocationsTotal         = MetricPreviewAllocation
	MetricPreviewLeaseCleanupTotal        = MetricPreviewLeaseCleanup
	MetricOperationIdempotencyTotal       = MetricOperationIdempotency
	MetricServiceUptimeSeconds            = MetricServiceUptime
	MetricServiceRestartsTotal            = MetricServiceRestarts
	MetricServiceWatchdogTotal            = MetricServiceWatchdog
	MetricServiceCrashLoopState           = MetricServiceCrashLoop
)

type LabelDescriptor struct {
	Name          string   `json:"name"`
	AllowedValues []string `json:"allowed_values"`
}

type HistogramDescriptor struct {
	Buckets []float64 `json:"buckets"`
}

type MetricDescriptor struct {
	Name      string               `json:"name"`
	Kind      MetricKind           `json:"kind"`
	Labels    []LabelDescriptor    `json:"labels"`
	Histogram *HistogramDescriptor `json:"histogram,omitempty"`
}

var fixedMetricDescriptors = []MetricDescriptor{
	{Name: MetricAccessDecisions, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "decision", AllowedValues: []string{"allowed", "denied", "unavailable"}}}},
	{Name: MetricCertificateOps, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "operation", AllowedValues: []string{"issue", "renew", "replace", "revoke"}}, {Name: "outcome", AllowedValues: []string{"success", "failed", "canceled"}}}},
	{Name: MetricHealthDimension, Kind: MetricGauge, Labels: []LabelDescriptor{{Name: "dimension", AllowedValues: []string{"service", "edge", "config", "route", "origin", "dns", "certificate", "access", "update"}}, {Name: "status", AllowedValues: []string{"unknown", "ready", "degraded", "down", "not_applicable"}}}},
	{Name: MetricHealthTransitions, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "dimension", AllowedValues: []string{"service", "edge", "config", "route", "origin", "dns", "certificate", "access", "update"}}, {Name: "from", AllowedValues: []string{"unknown", "ready", "degraded", "down", "not_applicable"}}, {Name: "to", AllowedValues: []string{"unknown", "ready", "degraded", "down", "not_applicable"}}}},
	{Name: MetricOriginConnections, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "protocol", AllowedValues: []string{"http1", "http2", "h2c", "tcp", "websocket"}}, {Name: "outcome", AllowedValues: []string{"success", "failed", "canceled", "timeout"}}}},
	{Name: MetricEdgeRequests, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "protocol", AllowedValues: []string{"http", "https", "tcp", "websocket"}}, {Name: "outcome", AllowedValues: []string{"success", "rejected", "failed", "canceled"}}}},
	{Name: MetricRouteRequests, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "route_kind", AllowedValues: []string{"preview_public_https_wss", "tunnel_https_wss", "tunnel_tcp", "tunnel_private_tcp"}}, {Name: "outcome", AllowedValues: []string{"success", "rejected", "failed", "canceled"}}}},
	{Name: MetricUpdateOperations, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "phase", AllowedValues: []string{"download", "verify", "stage", "activate", "health_gate", "rollback", "quarantine"}}, {Name: "outcome", AllowedValues: []string{"success", "failed", "canceled"}}}},
	{Name: MetricOperationLatency, Kind: MetricHistogram, Labels: []LabelDescriptor{{Name: "operation", AllowedValues: []string{"create", "update", "delete", "reconcile", "certificate", "access"}}}, Histogram: &HistogramDescriptor{Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10}}},
	{Name: MetricDNSVerificationDuration, Kind: MetricHistogram, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"success", "failed", "waiting"}}}, Histogram: &HistogramDescriptor{Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600}}},
	{Name: MetricDNSVerificationFailures, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "failure_class", AllowedValues: []string{"nxdomain", "timeout", "conflict", "provider", "unauthorized", "invalid", "unknown"}}}},
	{Name: MetricCertificateExpiryHorizon, Kind: MetricGauge, Labels: []LabelDescriptor{{Name: "horizon", AllowedValues: []string{"expired", "under_1h", "under_24h", "under_7d", "under_14d", "over_14d"}}}},
	{Name: MetricPreviewAllocation, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"success", "failed", "rejected", "canceled"}}}},
	{Name: MetricPreviewLeaseCleanup, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"success", "failed", "already_clean"}}}},
	{Name: MetricOperationIdempotency, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"new", "reused", "conflict"}}}},
	{Name: MetricServiceUptime, Kind: MetricGauge, Labels: []LabelDescriptor{{Name: "state", AllowedValues: []string{"running", "degraded", "stopped"}}}},
	{Name: MetricServiceRestarts, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"success", "failed"}}}},
	{Name: MetricServiceWatchdog, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"healthy", "failed", "restarted"}}}},
	{Name: MetricServiceCrashLoop, Kind: MetricGauge, Labels: []LabelDescriptor{{Name: "state", AllowedValues: []string{"clear", "detected"}}}},
	{Name: MetricConnectorSessions, Kind: MetricGauge, Labels: []LabelDescriptor{{Name: "state", AllowedValues: []string{"active", "draining", "closed"}}}},
	{Name: MetricConnectorConnections, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"opened", "closed", "failed"}}}},
	{Name: MetricConnectorReconnects, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"success", "failed"}}}},
	{Name: MetricConnectorBackoff, Kind: MetricGauge, Labels: []LabelDescriptor{{Name: "state", AllowedValues: []string{"scheduled", "exhausted"}}}},
	{Name: MetricConnectorHandshakeLatency, Kind: MetricHistogram, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"success", "failed"}}}, Histogram: &HistogramDescriptor{Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5}}},
	{Name: MetricConnectorDisconnects, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "reason", AllowedValues: []string{"auth", "network", "server", "protocol", "shutdown", "unknown"}}}},
	{Name: MetricConfigGenerations, Kind: MetricGauge, Labels: []LabelDescriptor{{Name: "state", AllowedValues: []string{"desired", "applied"}}}},
	{Name: MetricActiveStreams, Kind: MetricGauge, Labels: []LabelDescriptor{{Name: "protocol", AllowedValues: []string{"http", "https", "h2c", "tcp", "websocket"}}}},
	{Name: MetricQueueDepth, Kind: MetricGauge, Labels: []LabelDescriptor{{Name: "queue", AllowedValues: []string{"control", "data", "event"}}}},
	{Name: MetricFlowControlStalls, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "direction", AllowedValues: []string{"inbound", "outbound"}}}},
	{Name: MetricBytes, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "direction", AllowedValues: []string{"inbound", "outbound"}}}},
	{Name: MetricStreamDuration, Kind: MetricHistogram, Labels: []LabelDescriptor{{Name: "protocol", AllowedValues: []string{"http", "https", "h2c", "tcp", "websocket"}}}, Histogram: &HistogramDescriptor{Buckets: []float64{0.01, 0.1, 1, 5, 10, 30, 60, 300, 900}}},
	{Name: MetricStreamCancellations, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "reason", AllowedValues: []string{"client", "origin", "connector", "deadline", "shutdown", "unknown"}}}},
	{Name: MetricRouteErrors, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "class", AllowedValues: []string{"not_found", "conflict", "paused", "unauthorized", "origin", "edge", "internal"}}}},
	{Name: MetricRouteLatency, Kind: MetricHistogram, Labels: []LabelDescriptor{{Name: "protocol", AllowedValues: []string{"http", "https", "h2c", "tcp", "websocket"}}}, Histogram: &HistogramDescriptor{Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10}}},
	{Name: MetricProtocolUpgrades, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "protocol", AllowedValues: []string{"websocket", "h2c", "http2"}}}},
	{Name: MetricHealthProbes, Kind: MetricCounter, Labels: []LabelDescriptor{{Name: "outcome", AllowedValues: []string{"success", "failed", "timeout", "canceled"}}}},
	{Name: MetricHTTPRequests, Kind: MetricCounter, Labels: []LabelDescriptor{
		{Name: "method", AllowedValues: []string{"get", "post", "put", "patch", "delete", "other"}},
		{Name: "route_family", AllowedValues: []string{"health", "public_api", "edge_control", "release", "internal", "other"}},
		{Name: "status_class", AllowedValues: []string{"1xx", "2xx", "3xx", "4xx", "5xx"}},
	}},
	{Name: MetricHTTPDuration, Kind: MetricHistogram, Labels: []LabelDescriptor{
		{Name: "route_family", AllowedValues: []string{"health", "public_api", "edge_control", "release", "internal", "other"}},
		{Name: "status_class", AllowedValues: []string{"1xx", "2xx", "3xx", "4xx", "5xx"}},
	}, Histogram: &HistogramDescriptor{Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10}}},
}

func MetricDescriptors() []MetricDescriptor {
	result := make([]MetricDescriptor, len(fixedMetricDescriptors))
	for index, descriptor := range fixedMetricDescriptors {
		result[index] = cloneDescriptor(descriptor)
	}
	return result
}

type MetricLabels map[string]string

type MetricLabel struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HistogramBucket struct {
	UpperBound float64 `json:"upper_bound"`
	Count      uint64  `json:"count"`
}

type MetricSample struct {
	Name    string            `json:"name"`
	Kind    MetricKind        `json:"kind"`
	Labels  []MetricLabel     `json:"labels"`
	Value   uint64            `json:"value,omitempty"`
	Count   uint64            `json:"count,omitempty"`
	Sum     float64           `json:"sum,omitempty"`
	Buckets []HistogramBucket `json:"buckets,omitempty"`
}

type metricKey struct {
	name   string
	values string
}

type metricValue struct {
	value   uint64
	count   uint64
	sum     float64
	buckets []uint64
}

type Metrics struct {
	mu          sync.RWMutex
	descriptors map[string]MetricDescriptor
	values      map[metricKey]metricValue
	maxSeries   int
}

const defaultMaximumMetricSeries = 1024

func NewMetrics() *Metrics { return NewMetricsWithLimit(defaultMaximumMetricSeries) }

func NewMetricsWithLimit(maxSeries int) *Metrics {
	if maxSeries <= 0 {
		maxSeries = defaultMaximumMetricSeries
	}
	descriptors := make(map[string]MetricDescriptor, len(fixedMetricDescriptors))
	for _, descriptor := range fixedMetricDescriptors {
		descriptors[descriptor.Name] = cloneDescriptor(descriptor)
	}
	return &Metrics{descriptors: descriptors, values: make(map[metricKey]metricValue), maxSeries: maxSeries}
}

func (m *Metrics) AddCounter(name string, labels MetricLabels, delta uint64) error {
	return m.mutate(name, labels, MetricCounter, delta, true)
}

func (m *Metrics) IncCounter(name string, labels MetricLabels) error {
	return m.AddCounter(name, labels, 1)
}

func (m *Metrics) SetGauge(name string, labels MetricLabels, value uint64) error {
	return m.mutate(name, labels, MetricGauge, value, false)
}

func (m *Metrics) ObserveHistogram(name string, labels MetricLabels, observation float64) error {
	if math.IsNaN(observation) || math.IsInf(observation, 0) || observation < 0 {
		return newError(ErrorInvalidObservation, "record control-plane metric")
	}
	descriptor, key, err := m.prepare(name, labels, MetricHistogram)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	value, exists := m.values[key]
	if !exists {
		if len(m.values) >= m.maxSeries {
			return newError(ErrorMetricCardinality, "record control-plane metric")
		}
		value.buckets = make([]uint64, len(descriptor.Histogram.Buckets))
	}
	if value.count == ^uint64(0) {
		return newError(ErrorMetricOverflow, "record control-plane metric")
	}
	newSum := value.sum + observation
	if math.IsInf(newSum, 0) {
		return newError(ErrorMetricOverflow, "record control-plane metric")
	}
	value.count++
	value.sum = newSum
	for index, upper := range descriptor.Histogram.Buckets {
		if observation <= upper {
			if value.buckets[index] == ^uint64(0) {
				return newError(ErrorMetricOverflow, "record control-plane metric")
			}
			value.buckets[index]++
		}
	}
	m.values[key] = value
	return nil
}

func (m *Metrics) mutate(name string, labels MetricLabels, kind MetricKind, value uint64, add bool) error {
	_, key, err := m.prepare(name, labels, kind)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.values[key]
	if !exists && len(m.values) >= m.maxSeries {
		return newError(ErrorMetricCardinality, "record control-plane metric")
	}
	if add {
		if ^uint64(0)-current.value < value {
			return newError(ErrorMetricOverflow, "record control-plane metric")
		}
		current.value += value
	} else {
		current.value = value
	}
	m.values[key] = current
	return nil
}

func (m *Metrics) prepare(name string, labels MetricLabels, kind MetricKind) (MetricDescriptor, metricKey, error) {
	if m == nil {
		return MetricDescriptor{}, metricKey{}, newError(ErrorClosed, "record control-plane metric")
	}
	descriptor, ok := m.descriptors[name]
	if !ok {
		return MetricDescriptor{}, metricKey{}, newError(ErrorUnknownMetric, "record control-plane metric")
	}
	if descriptor.Kind != kind {
		return MetricDescriptor{}, metricKey{}, newError(ErrorMetricKindMismatch, "record control-plane metric")
	}
	key, err := validateMetricLabels(descriptor, labels)
	return descriptor, key, err
}

func (m *Metrics) Snapshot() []MetricSample {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	keys := make([]metricKey, 0, len(m.values))
	values := make(map[metricKey]metricValue, len(m.values))
	for key, value := range m.values {
		keys = append(keys, key)
		value.buckets = append([]uint64(nil), value.buckets...)
		values[key] = value
	}
	descriptors := make(map[string]MetricDescriptor, len(m.descriptors))
	for name, descriptor := range m.descriptors {
		descriptors[name] = descriptor
	}
	m.mu.RUnlock()
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return keys[i].values < keys[j].values
	})
	result := make([]MetricSample, 0, len(keys))
	for _, key := range keys {
		descriptor := descriptors[key.name]
		valuesForLabels := strings.Split(key.values, "\x1f")
		labels := make([]MetricLabel, len(descriptor.Labels))
		for index, label := range descriptor.Labels {
			labels[index] = MetricLabel{Name: label.Name, Value: valuesForLabels[index]}
		}
		value := values[key]
		sample := MetricSample{Name: key.name, Kind: descriptor.Kind, Labels: labels, Value: value.value, Count: value.count, Sum: value.sum}
		if descriptor.Kind == MetricHistogram {
			sample.Buckets = make([]HistogramBucket, len(descriptor.Histogram.Buckets))
			for index, upper := range descriptor.Histogram.Buckets {
				sample.Buckets[index] = HistogramBucket{UpperBound: upper, Count: value.buckets[index]}
			}
		}
		result = append(result, sample)
	}
	return result
}

func (m *Metrics) JSON() ([]byte, error) { return json.Marshal(m.Snapshot()) }

func validateMetricLabels(descriptor MetricDescriptor, labels MetricLabels) (metricKey, error) {
	values := make([]string, len(descriptor.Labels))
	for index, label := range descriptor.Labels {
		value, ok := labels[label.Name]
		if !ok {
			return metricKey{}, newError(ErrorMissingLabel, "record control-plane metric")
		}
		if !containsString(label.AllowedValues, value) {
			return metricKey{}, newError(ErrorLabelValueRejected, "record control-plane metric")
		}
		values[index] = value
	}
	for name := range labels {
		if !descriptorHasLabel(descriptor, name) {
			return metricKey{}, newError(ErrorUnknownLabel, "record control-plane metric")
		}
	}
	return metricKey{name: descriptor.Name, values: strings.Join(values, "\x1f")}, nil
}

func descriptorHasLabel(descriptor MetricDescriptor, name string) bool {
	for _, label := range descriptor.Labels {
		if label.Name == name {
			return true
		}
	}
	return false
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func cloneDescriptor(descriptor MetricDescriptor) MetricDescriptor {
	result := descriptor
	result.Labels = make([]LabelDescriptor, len(descriptor.Labels))
	for index, label := range descriptor.Labels {
		result.Labels[index] = LabelDescriptor{Name: label.Name, AllowedValues: append([]string(nil), label.AllowedValues...)}
	}
	if descriptor.Histogram != nil {
		result.Histogram = &HistogramDescriptor{Buckets: append([]float64(nil), descriptor.Histogram.Buckets...)}
	}
	return result
}
