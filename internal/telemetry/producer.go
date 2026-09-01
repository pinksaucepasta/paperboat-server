package telemetry

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Producer is the server-owned facade for telemetry emitted by adapters. It
// deliberately accepts only finite enums and opaque identities. Provider
// responses, URLs, host names, headers, request bodies and errors never enter
// a producer record.
//
// The sinks are optional so a producer can be composed into an application in
// stages. A nil sink makes the corresponding operation a no-op while keeping
// the input validation and event construction policy identical.
type Producer struct {
	Metrics         *Metrics
	Events          *EventLog
	EventLog        *EventLog
	Health          *HealthTracker
	LifecycleEvents *LifecycleEventLog
	LifecycleLog    *LifecycleLog
	Now             func() time.Time
	Clock           func() time.Time

	healthMu    sync.Mutex
	sequence    atomic.Uint64
	ownedEvents bool
}

// TelemetryProducer and ServerTelemetry are descriptive aliases for callers
// that prefer a name which makes the ownership boundary explicit.
type TelemetryProducer = Producer
type ServerTelemetry = Producer

type ProducerOptions struct {
	Metrics         *Metrics
	Events          *EventLog
	Health          *HealthTracker
	LifecycleEvents *LifecycleEventLog
	LifecycleLog    *LifecycleLog
	Now             func() time.Time
}

// NewProducer creates a fully usable producer with bounded in-memory sinks.
// Callers that already own sinks should pass them in ProducerOptions. The
// constructor cannot fail because all default capacities are fixed constants;
// a caller may still set any sink to nil when only selected signals are wanted.
func NewProducer(options ProducerOptions) *Producer {
	producer := &Producer{
		Metrics:         options.Metrics,
		Events:          options.Events,
		Health:          options.Health,
		LifecycleEvents: options.LifecycleEvents,
		LifecycleLog:    options.LifecycleLog,
		Now:             options.Now,
	}
	if producer.Metrics == nil {
		producer.Metrics = NewMetrics()
	}
	if producer.Events == nil {
		producer.Events, _ = NewEventLog(256)
		producer.ownedEvents = producer.Events != nil
	}
	if producer.Health == nil {
		producer.Health, _ = NewHealthTracker(producer.now)
	}
	return producer
}

func NewTelemetryProducer(options ProducerOptions) *Producer { return NewProducer(options) }

// Close releases sinks created by NewProducer. Caller-owned sinks are left
// open so one producer cannot unexpectedly terminate another component's
// telemetry stream.
func (p *Producer) Close() error {
	if p == nil {
		return nil
	}
	if p.ownedEvents && p.Events != nil {
		return p.Events.Close()
	}
	return nil
}

func (p *Producer) now() time.Time {
	if p == nil {
		return normalizeTime(time.Now())
	}
	clock := p.Now
	if clock == nil {
		clock = p.Clock
	}
	if clock == nil {
		clock = time.Now
	}
	return normalizeTime(clock())
}

func (p *Producer) nextID(prefix string) string {
	if p == nil {
		return prefix + "0"
	}
	return prefix + itoa(p.sequence.Add(1))
}

// itoa is intentionally tiny and allocation-free for the common bounded
// producer path. Values are not exposed as labels, only as opaque event IDs.
func itoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

// ProducerIdentity carries only fields that are already opaque and safe to
// correlate. Resource and operation values are used for the richer lifecycle
// stream only when all required lifecycle identities are present.
type ProducerIdentity struct {
	RequestID     string
	CorrelationID string
	ResourceKind  string
	ResourceID    string
	OperationKind string
	OperationID   string
	ActorType     string
	ActorID       string
	IDs           SafeIDs
}

// Identity is a shorter alias used by operation input types.
type Identity = ProducerIdentity

func (p *Producer) eventIdentity(identity ProducerIdentity) (string, SafeIDs) {
	correlationID := identity.CorrelationID
	if !validCorrelationID(correlationID) {
		correlationID = p.nextID("cor_producer_")
	}
	ids := safeProducerIDs(identity.IDs)
	if validOptionalLogIdentity(identity.RequestID, "request_", "req_") {
		ids.RequestID = ""
	}
	return correlationID, ids
}

func safeProducerIDs(ids SafeIDs) SafeIDs {
	if !optionalSafeID(ids.AccountID, "account_") {
		ids.AccountID = ""
	}
	if !optionalSafeID(ids.ActorID, "actor_") {
		ids.ActorID = ""
	}
	if !optionalSafeID(ids.TunnelID, "tunnel_") {
		ids.TunnelID = ""
	}
	if !optionalSafeID(ids.RouteID, "route_") {
		ids.RouteID = ""
	}
	if !optionalSafeID(ids.ConnectorID, "connector_") {
		ids.ConnectorID = ""
	}
	if !optionalSafeID(ids.DomainID, "domain_") {
		ids.DomainID = ""
	}
	if !optionalSafeID(ids.CertificateID, "certificate_") {
		ids.CertificateID = ""
	}
	if !optionalSafeID(ids.AssignmentID, "assignment_") {
		ids.AssignmentID = ""
	}
	if !optionalSafeID(ids.HostID, "host_") {
		ids.HostID = ""
	}
	if !optionalSafeID(ids.DeviceID, "device_") {
		ids.DeviceID = ""
	}
	if !optionalSafeID(ids.SessionID, "session_", "carrier_") {
		ids.SessionID = ""
	}
	if !optionalSafeID(ids.OperationID, "operation_", "op_") {
		ids.OperationID = ""
	}
	if !optionalSafeID(ids.RequestID, "request_", "req_") {
		ids.RequestID = ""
	}
	if !optionalSafeID(ids.EdgeNodeID, "edge_") {
		ids.EdgeNodeID = ""
	}
	return ids
}

func (p *Producer) recordEvent(identity ProducerIdentity, name, code string, outcome EventOutcome, severity EventSeverity, message string, retry RetryDecision, nextRetryAt time.Time) error {
	return p.recordEventWithGenerations(identity, name, code, outcome, severity, message, retry, nextRetryAt, Generations{})
}

func (p *Producer) recordEventWithGenerations(identity ProducerIdentity, name, code string, outcome EventOutcome, severity EventSeverity, message string, retry RetryDecision, nextRetryAt time.Time, generations Generations) error {
	if p == nil {
		return nil
	}
	if retry == "" {
		retry = RetryNone
	}
	if retry == RetryScheduled && nextRetryAt.IsZero() {
		nextRetryAt = p.now().Add(time.Minute)
	}
	correlationID, ids := p.eventIdentity(identity)
	requestID := identity.RequestID
	if !validOptionalLogIdentity(requestID, "request_", "req_") {
		requestID = ""
	}
	if requestID != "" {
		identity.IDs.RequestID = ""
	}
	input := EventInput{
		At: p.now(), Severity: severity, Component: componentForEvent(identity, name), Name: name,
		Code: code, Outcome: outcome, Message: message, CorrelationID: correlationID,
		IDs: ids, Generations: generations, RequestID: requestID, Retry: retry, NextRetryAt: nextRetryAt,
	}
	if p.events() != nil {
		if _, err := p.events().Record(input); err != nil {
			return err
		}
	}
	if p.LifecycleEvents != nil {
		p.recordLifecycle(identity, name, code, outcome, severity, message, retry, nextRetryAt, correlationID, generations)
	}
	return nil
}

func componentForEvent(identity ProducerIdentity, name string) Dimension {
	// Event component is selected by the fixed event family, never caller text.
	switch name {
	case "dns_verification":
		return DimensionDNS
	case "certificate_lifecycle", "certificate_expiry":
		return DimensionCertificate
	case "preview_allocation", "preview_cleanup", "route_error", "route_latency":
		return DimensionRoute
	case "connector_session", "connector_connection", "connector_reconnect", "connector_backoff", "connector_handshake", "connector_disconnect":
		return DimensionEdge
	case "config_apply":
		return DimensionConfig
	case "service_lifecycle", "service_watchdog", "service_crash_loop":
		return DimensionService
	default:
		if validDimension(identityResourceDimension(identity)) {
			return identityResourceDimension(identity)
		}
		return DimensionService
	}
}

func identityResourceDimension(identity ProducerIdentity) Dimension {
	if strings.HasPrefix(identity.ResourceKind, "dns") {
		return DimensionDNS
	}
	if strings.HasPrefix(identity.ResourceKind, "certificate") {
		return DimensionCertificate
	}
	if strings.HasPrefix(identity.ResourceKind, "route") || strings.HasPrefix(identity.ResourceKind, "preview") {
		return DimensionRoute
	}
	if strings.HasPrefix(identity.ResourceKind, "connector") || strings.HasPrefix(identity.ResourceKind, "tunnel") {
		return DimensionEdge
	}
	if strings.HasPrefix(identity.ResourceKind, "config") {
		return DimensionConfig
	}
	return DimensionService
}

func (p *Producer) events() *EventLog {
	if p == nil {
		return nil
	}
	if p.Events != nil {
		return p.Events
	}
	return p.EventLog
}

func (p *Producer) recordLifecycle(identity ProducerIdentity, name, code string, outcome EventOutcome, severity EventSeverity, message string, retry RetryDecision, nextRetryAt time.Time, correlationID string, generations Generations) {
	if p == nil || p.LifecycleEvents == nil {
		return
	}
	requestID := identity.RequestID
	if !validOptionalLogIdentity(requestID, "request_", "req_") || !validCorrelationID(correlationID) || !validEventResourceKind(identity.ResourceKind) || !validOpaqueID(identity.ResourceID) || !validOptionalLogIdentity(identity.OperationID, "operation_", "op_") || identity.OperationID == "" {
		return
	}
	if identity.OperationKind != "" && !stableCodePattern.MatchString(identity.OperationKind) {
		return
	}
	actorType, actorID := identity.ActorType, identity.ActorID
	if actorType != "" || actorID != "" {
		if !validActorType(actorType) || !validOpaqueID(actorID) {
			return
		}
	}
	_, _ = p.LifecycleEvents.Record(LifecycleEventInput{
		At: p.now(), Severity: severity, Component: componentForEvent(identity, name), EventType: lifecycleEventType(name),
		Code: code, Outcome: outcome, Message: message, RequestID: requestID, CorrelationID: correlationID,
		ResourceKind: identity.ResourceKind, ResourceID: identity.ResourceID, OperationKind: identity.OperationKind, OperationID: identity.OperationID,
		ActorType: actorType, ActorID: actorID, Generations: generations, Retry: retry, NextRetryAt: nextRetryAt,
	})
}

func lifecycleEventType(name string) string {
	switch name {
	case "dns_verification":
		return "dns.verification"
	case "certificate_lifecycle":
		return "certificate.lifecycle"
	case "certificate_expiry":
		return "certificate.expiry"
	case "preview_allocation":
		return "preview.allocation"
	case "preview_cleanup":
		return "preview.cleanup"
	case "connector_session":
		return "connector.session"
	case "connector_connection":
		return "connector.connection"
	case "connector_reconnect":
		return "connector.reconnect"
	case "connector_backoff":
		return "connector.backoff"
	case "connector_handshake":
		return "connector.handshake"
	case "connector_disconnect":
		return "connector.disconnect"
	case "config_apply":
		return "config.apply"
	case "route_error":
		return "route.error"
	case "route_latency":
		return "route.latency"
	case "service_lifecycle":
		return "service.lifecycle"
	case "service_watchdog":
		return "service.watchdog"
	case "service_crash_loop":
		return "service.crash_loop"
	default:
		return "service.lifecycle"
	}
}

func (p *Producer) updateHealth(dimension Dimension, status HealthStatus, code, summary, repair, correlationID string, retry RetryDecision, nextRetryAt time.Time) error {
	if p == nil || p.Health == nil {
		return nil
	}
	if retry == "" {
		retry = RetryNone
	}
	if retry == RetryScheduled && nextRetryAt.IsZero() {
		nextRetryAt = p.now().Add(time.Minute)
	}
	p.healthMu.Lock()
	before := p.Health.Snapshot()
	err := p.Health.Update(HealthUpdate{Dimension: dimension, Status: status, Code: code, Summary: summary, RepairAction: repair, CorrelationID: correlationID, Retry: retry, NextRetryAt: nextRetryAt})
	after := p.Health.Snapshot()
	p.healthMu.Unlock()
	if err != nil {
		return err
	}
	if p.Metrics == nil {
		return nil
	}
	stateBefore, stateAfter := before.Dimensions.Get(dimension), after.Dimensions.Get(dimension)
	if stateBefore.Status == stateAfter.Status && stateBefore.Code == stateAfter.Code {
		return nil
	}
	if err := p.Metrics.SetGauge(MetricHealthDimension, MetricLabels{"dimension": string(dimension), "status": string(stateAfter.Status)}, 1); err != nil {
		return err
	}
	return p.Metrics.IncCounter(MetricHealthTransitions, MetricLabels{"dimension": string(dimension), "from": string(stateBefore.Status), "to": string(stateAfter.Status)})
}

func boundedSeconds(duration time.Duration) (float64, error) {
	if duration < 0 || duration > 24*time.Hour {
		return 0, newError(ErrorInvalidObservation, "record control-plane telemetry")
	}
	return duration.Seconds(), nil
}

func normalizedCorrelation(identity ProducerIdentity, p *Producer) string {
	if validCorrelationID(identity.CorrelationID) {
		return identity.CorrelationID
	}
	return p.nextID("cor_producer_")
}

// DNSVerificationOutcome reports the result of DNS verification.
type DNSVerificationOutcome string

const (
	DNSVerificationSucceeded DNSVerificationOutcome = "success"
	DNSVerificationFailed    DNSVerificationOutcome = "failed"
	DNSVerificationWaiting   DNSVerificationOutcome = "waiting"
)

type DNSFailureClass string

const (
	DNSFailureNXDomain     DNSFailureClass = "nxdomain"
	DNSFailureTimeout      DNSFailureClass = "timeout"
	DNSFailureConflict     DNSFailureClass = "conflict"
	DNSFailureProvider     DNSFailureClass = "provider"
	DNSFailureUnauthorized DNSFailureClass = "unauthorized"
	DNSFailureInvalid      DNSFailureClass = "invalid"
	DNSFailureUnknown      DNSFailureClass = "unknown"
)

type DNSVerificationInput struct {
	Outcome       DNSVerificationOutcome
	FailureClass  DNSFailureClass
	Duration      time.Duration
	Retry         RetryDecision
	NextRetryAt   time.Time
	At            time.Time
	Identity      ProducerIdentity
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

type DNSVerificationObservation = DNSVerificationInput

func (p *Producer) RecordDNSVerification(input DNSVerificationInput) error {
	outcome := input.Outcome
	if outcome != DNSVerificationSucceeded && outcome != DNSVerificationFailed && outcome != DNSVerificationWaiting {
		outcome = DNSVerificationWaiting
	}
	duration, err := boundedSeconds(input.Duration)
	if err != nil {
		return err
	}
	failureClass := normalizeDNSFailure(input.FailureClass)
	metricOutcome := string(outcome)
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.ObserveHistogram(MetricDNSVerificationDuration, MetricLabels{"outcome": metricOutcome}, duration); err != nil {
			return err
		}
		if outcome == DNSVerificationFailed {
			if err := p.Metrics.IncCounter(MetricDNSVerificationFailures, MetricLabels{"failure_class": string(failureClass)}); err != nil {
				return err
			}
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := dnsHealth(outcome, failureClass, input.Retry, input.NextRetryAt, p)
	if err := p.updateHealth(DimensionDNS, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEvent(identity, "dns_verification", code, dnsEventOutcome(outcome), dnsSeverity(outcome), dnsMessage(outcome), retry, next)
}

func (p *Producer) DNSVerification(input DNSVerificationInput) error {
	return p.RecordDNSVerification(input)
}

func normalizeDNSFailure(value DNSFailureClass) DNSFailureClass {
	switch value {
	case DNSFailureNXDomain, DNSFailureTimeout, DNSFailureConflict, DNSFailureProvider, DNSFailureUnauthorized, DNSFailureInvalid, DNSFailureUnknown:
		return value
	default:
		return DNSFailureUnknown
	}
}

func dnsHealth(outcome DNSVerificationOutcome, failure DNSFailureClass, retry RetryDecision, next time.Time, p *Producer) (HealthStatus, string, string, string, RetryDecision, time.Time) {
	switch outcome {
	case DNSVerificationSucceeded:
		return StatusReady, "dns_verified", "DNS verification is complete.", "No action is required.", RetryNone, time.Time{}
	case DNSVerificationWaiting:
		if retry == "" {
			retry = RetryWaitForChange
		}
		return StatusDegraded, "dns_verification_waiting", "DNS verification is waiting for an authoritative observation.", "Publish the requested DNS record, then verify again.", retry, next
	default:
		if retry == "" {
			if failure == DNSFailureConflict || failure == DNSFailureUnauthorized || failure == DNSFailureInvalid {
				retry = RetryNotRetryable
			} else {
				retry = RetryScheduled
			}
		}
		if retry == RetryScheduled && next.IsZero() {
			next = p.now().Add(time.Minute)
		}
		return StatusDegraded, "dns_verification_failed", "DNS verification did not complete.", "Check the DNS instructions and retry verification.", retry, next
	}
}

func dnsEventOutcome(outcome DNSVerificationOutcome) EventOutcome {
	if outcome == DNSVerificationSucceeded {
		return OutcomeSuccess
	}
	if outcome == DNSVerificationWaiting {
		return OutcomeStateChange
	}
	return OutcomeFailed
}

func dnsSeverity(outcome DNSVerificationOutcome) EventSeverity {
	if outcome == DNSVerificationSucceeded {
		return SeverityInfo
	}
	if outcome == DNSVerificationWaiting {
		return SeverityWarn
	}
	return SeverityError
}

func dnsMessage(outcome DNSVerificationOutcome) string {
	switch outcome {
	case DNSVerificationSucceeded:
		return "DNS verification completed."
	case DNSVerificationWaiting:
		return "DNS verification is waiting for an observation."
	default:
		return "DNS verification failed."
	}
}

// CertificateOperation identifies a certificate lifecycle operation.
type CertificateOperation string

const (
	CertificateIssue   CertificateOperation = "issue"
	CertificateRenew   CertificateOperation = "renew"
	CertificateReplace CertificateOperation = "replace"
	CertificateRevoke  CertificateOperation = "revoke"
)

type CertificateOperationOutcome string

const (
	CertificateSucceeded CertificateOperationOutcome = "success"
	CertificateFailed    CertificateOperationOutcome = "failed"
	CertificateCanceled  CertificateOperationOutcome = "canceled"
)

type CertificateLifecycleInput struct {
	Operation     CertificateOperation
	Outcome       CertificateOperationOutcome
	At            time.Time
	Retry         RetryDecision
	NextRetryAt   time.Time
	Identity      ProducerIdentity
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

type CertificateInput = CertificateLifecycleInput

type CertificateExpiryHorizon string

const (
	CertificateExpired  CertificateExpiryHorizon = "expired"
	CertificateUnder1H  CertificateExpiryHorizon = "under_1h"
	CertificateUnder24H CertificateExpiryHorizon = "under_24h"
	CertificateUnder7D  CertificateExpiryHorizon = "under_7d"
	CertificateUnder14D CertificateExpiryHorizon = "under_14d"
	CertificateOver14D  CertificateExpiryHorizon = "over_14d"
)

type CertificateExpiryInput struct {
	Horizon       CertificateExpiryHorizon
	At            time.Time
	Identity      ProducerIdentity
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordCertificateLifecycle(input CertificateLifecycleInput) error {
	operation := normalizeCertificateOperation(input.Operation)
	outcome := normalizeCertificateOutcome(input.Outcome)
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.IncCounter(MetricCertificateOps, MetricLabels{"operation": string(operation), "outcome": string(outcome)}); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := certificateHealth(outcome, input.Retry, input.NextRetryAt, p)
	if err := p.updateHealth(DimensionCertificate, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEvent(identity, "certificate_lifecycle", code, certificateEventOutcome(outcome), certificateSeverity(outcome), certificateMessage(operation, outcome), retry, next)
}

func (p *Producer) CertificateLifecycle(input CertificateLifecycleInput) error {
	return p.RecordCertificateLifecycle(input)
}

func normalizeCertificateOperation(value CertificateOperation) CertificateOperation {
	switch value {
	case CertificateIssue, CertificateRenew, CertificateReplace, CertificateRevoke:
		return value
	default:
		return CertificateIssue
	}
}

func normalizeCertificateOutcome(value CertificateOperationOutcome) CertificateOperationOutcome {
	switch value {
	case CertificateSucceeded, CertificateFailed, CertificateCanceled:
		return value
	default:
		return CertificateFailed
	}
}

func certificateHealth(outcome CertificateOperationOutcome, retry RetryDecision, next time.Time, p *Producer) (HealthStatus, string, string, string, RetryDecision, time.Time) {
	switch outcome {
	case CertificateSucceeded:
		return StatusReady, "certificate_ready", "Certificate lifecycle operation completed.", "No action is required.", RetryNone, time.Time{}
	case CertificateCanceled:
		if retry == "" {
			retry = RetryWaitForChange
		}
		return StatusDegraded, "certificate_canceled", "Certificate lifecycle operation was canceled.", "Retry the certificate operation when the service is available.", retry, next
	default:
		if retry == "" {
			retry = RetryScheduled
		}
		if retry == RetryScheduled && next.IsZero() {
			next = p.now().Add(time.Minute)
		}
		return StatusDegraded, "certificate_operation_failed", "Certificate lifecycle operation failed.", "Inspect certificate readiness and retry the operation.", retry, next
	}
}

func certificateEventOutcome(value CertificateOperationOutcome) EventOutcome {
	switch value {
	case CertificateSucceeded:
		return OutcomeSuccess
	case CertificateCanceled:
		return OutcomeCanceled
	default:
		return OutcomeFailed
	}
}

func certificateSeverity(value CertificateOperationOutcome) EventSeverity {
	if value == CertificateSucceeded {
		return SeverityInfo
	}
	return SeverityError
}

func certificateMessage(operation CertificateOperation, outcome CertificateOperationOutcome) string {
	if outcome == CertificateSucceeded {
		return "Certificate " + string(operation) + " operation completed."
	}
	if outcome == CertificateCanceled {
		return "Certificate " + string(operation) + " operation was canceled."
	}
	return "Certificate " + string(operation) + " operation failed."
}

func (p *Producer) RecordCertificateExpiry(input CertificateExpiryInput) error {
	horizon := normalizeCertificateHorizon(input.Horizon)
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.SetGauge(MetricCertificateExpiryHorizon, MetricLabels{"horizon": string(horizon)}, 1); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair := certificateExpiryHealth(horizon)
	if err := p.updateHealth(DimensionCertificate, status, code, summary, repair, correlationID, RetryNone, time.Time{}); err != nil {
		return err
	}
	return p.recordEvent(identity, "certificate_expiry", code, certificateExpiryOutcome(horizon), certificateExpirySeverity(horizon), certificateExpiryMessage(horizon), RetryNone, time.Time{})
}

func (p *Producer) CertificateExpiry(input CertificateExpiryInput) error {
	return p.RecordCertificateExpiry(input)
}

func normalizeCertificateHorizon(value CertificateExpiryHorizon) CertificateExpiryHorizon {
	switch value {
	case CertificateExpired, CertificateUnder1H, CertificateUnder24H, CertificateUnder7D, CertificateUnder14D, CertificateOver14D:
		return value
	default:
		return CertificateOver14D
	}
}

func certificateExpiryHealth(horizon CertificateExpiryHorizon) (HealthStatus, string, string, string) {
	switch horizon {
	case CertificateExpired:
		return StatusDown, "certificate_expired", "The certificate has expired.", "Renew or replace the certificate before accepting traffic."
	case CertificateUnder1H:
		return StatusDegraded, "certificate_expiry_imminent", "The certificate expires within one hour.", "Renew the certificate immediately."
	case CertificateUnder24H:
		return StatusDegraded, "certificate_expiry_soon", "The certificate expires within one day.", "Renew the certificate soon."
	case CertificateUnder7D:
		return StatusDegraded, "certificate_expiry_warning", "The certificate expires within seven days.", "Schedule certificate renewal."
	case CertificateUnder14D:
		return StatusDegraded, "certificate_expiry_notice", "The certificate expires within fourteen days.", "Ensure renewal is scheduled."
	default:
		return StatusReady, "certificate_expiry_clear", "The certificate expiry horizon is healthy.", "No action is required."
	}
}

func certificateExpiryOutcome(horizon CertificateExpiryHorizon) EventOutcome {
	if horizon == CertificateOver14D {
		return OutcomeSuccess
	}
	return OutcomeStateChange
}

func certificateExpirySeverity(horizon CertificateExpiryHorizon) EventSeverity {
	if horizon == CertificateOver14D {
		return SeverityInfo
	}
	return SeverityWarn
}

func certificateExpiryMessage(horizon CertificateExpiryHorizon) string {
	if horizon == CertificateExpired {
		return "Certificate expiry requires immediate action."
	}
	return "Certificate expiry horizon updated."
}

// PreviewAllocationOutcome reports the result of preview allocation or cleanup.
type PreviewAllocationOutcome string

const (
	PreviewAllocationSucceeded PreviewAllocationOutcome = "success"
	PreviewAllocationFailed    PreviewAllocationOutcome = "failed"
	PreviewAllocationRejected  PreviewAllocationOutcome = "rejected"
	PreviewAllocationCanceled  PreviewAllocationOutcome = "canceled"
)

type PreviewAllocationInput struct {
	Outcome       PreviewAllocationOutcome
	At            time.Time
	Retry         RetryDecision
	NextRetryAt   time.Time
	Identity      ProducerIdentity
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

type PreviewCleanupOutcome string

const (
	PreviewCleanupSucceeded    PreviewCleanupOutcome = "success"
	PreviewCleanupFailed       PreviewCleanupOutcome = "failed"
	PreviewCleanupAlreadyClean PreviewCleanupOutcome = "already_clean"
)

type PreviewCleanupInput struct {
	Outcome       PreviewCleanupOutcome
	At            time.Time
	Retry         RetryDecision
	NextRetryAt   time.Time
	Identity      ProducerIdentity
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordPreviewAllocation(input PreviewAllocationInput) error {
	outcome := normalizePreviewAllocationOutcome(input.Outcome)
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.IncCounter(MetricPreviewAllocation, MetricLabels{"outcome": string(outcome)}); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := previewHealth(string(outcome), input.Retry, input.NextRetryAt, p)
	if err := p.updateHealth(DimensionRoute, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEvent(identity, "preview_allocation", code, previewEventOutcome(string(outcome)), previewSeverity(string(outcome)), previewMessage("allocation", string(outcome)), retry, next)
}

func (p *Producer) PreviewAllocation(input PreviewAllocationInput) error {
	return p.RecordPreviewAllocation(input)
}

func normalizePreviewAllocationOutcome(value PreviewAllocationOutcome) PreviewAllocationOutcome {
	switch value {
	case PreviewAllocationSucceeded, PreviewAllocationFailed, PreviewAllocationRejected, PreviewAllocationCanceled:
		return value
	default:
		return PreviewAllocationFailed
	}
}

func (p *Producer) RecordPreviewCleanup(input PreviewCleanupInput) error {
	outcome := normalizePreviewCleanupOutcome(input.Outcome)
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.IncCounter(MetricPreviewLeaseCleanup, MetricLabels{"outcome": string(outcome)}); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := previewHealth(string(outcome), input.Retry, input.NextRetryAt, p)
	if err := p.updateHealth(DimensionRoute, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEvent(identity, "preview_cleanup", code, previewEventOutcome(string(outcome)), previewSeverity(string(outcome)), previewMessage("cleanup", string(outcome)), retry, next)
}

func (p *Producer) PreviewCleanup(input PreviewCleanupInput) error {
	return p.RecordPreviewCleanup(input)
}

func normalizePreviewCleanupOutcome(value PreviewCleanupOutcome) PreviewCleanupOutcome {
	switch value {
	case PreviewCleanupSucceeded, PreviewCleanupFailed, PreviewCleanupAlreadyClean:
		return value
	default:
		return PreviewCleanupFailed
	}
}

func previewHealth(outcome string, retry RetryDecision, next time.Time, p *Producer) (HealthStatus, string, string, string, RetryDecision, time.Time) {
	switch outcome {
	case string(PreviewAllocationSucceeded), string(PreviewCleanupAlreadyClean):
		return StatusReady, "route_ready", "Preview route state is healthy.", "No action is required.", RetryNone, time.Time{}
	case string(PreviewAllocationRejected):
		return StatusDegraded, "preview_allocation_rejected", "Preview allocation was rejected.", "Correct the request and retry allocation.", RetryNotRetryable, time.Time{}
	case string(PreviewAllocationCanceled):
		if retry == "" {
			retry = RetryWaitForChange
		}
		return StatusDegraded, "preview_allocation_canceled", "Preview allocation was canceled.", "Retry allocation when ready.", retry, next
	default:
		if retry == "" {
			retry = RetryScheduled
		}
		if retry == RetryScheduled && next.IsZero() {
			next = p.now().Add(time.Minute)
		}
		return StatusDegraded, "preview_operation_failed", "Preview operation failed.", "Retry the preview operation after checking service health.", retry, next
	}
}

func previewEventOutcome(outcome string) EventOutcome {
	switch outcome {
	case string(PreviewAllocationSucceeded), string(PreviewCleanupAlreadyClean):
		return OutcomeSuccess
	case string(PreviewAllocationRejected):
		return OutcomeRejected
	case string(PreviewAllocationCanceled):
		return OutcomeCanceled
	default:
		return OutcomeFailed
	}
}

func previewSeverity(outcome string) EventSeverity {
	if outcome == string(PreviewAllocationSucceeded) || outcome == string(PreviewCleanupSucceeded) || outcome == string(PreviewCleanupAlreadyClean) {
		return SeverityInfo
	}
	if outcome == string(PreviewAllocationRejected) {
		return SeverityWarn
	}
	return SeverityError
}

func previewMessage(operation, outcome string) string {
	return "Preview " + operation + " " + outcome + "."
}

// ConnectorSessionState reports the lifecycle state of a connector session.
type ConnectorSessionState string

const (
	ConnectorSessionActive   ConnectorSessionState = "active"
	ConnectorSessionDraining ConnectorSessionState = "draining"
	ConnectorSessionClosed   ConnectorSessionState = "closed"
)

type ConnectorSessionInput struct {
	State         ConnectorSessionState
	At            time.Time
	Identity      ProducerIdentity
	Generations   Generations
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordConnectorSession(input ConnectorSessionInput) error {
	state := normalizeConnectorSessionState(input.State)
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.SetGauge(MetricConnectorSessions, MetricLabels{"state": string(state)}, 1); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair := connectorSessionHealth(state)
	if err := p.updateHealth(DimensionEdge, status, code, summary, repair, correlationID, RetryNone, time.Time{}); err != nil {
		return err
	}
	return p.recordEventWithGenerations(identity, "connector_session", code, connectorStateOutcome(state), connectorStateSeverity(state), connectorStateMessage(state), RetryNone, time.Time{}, input.Generations)
}

func (p *Producer) ConnectorSession(input ConnectorSessionInput) error {
	return p.RecordConnectorSession(input)
}

func normalizeConnectorSessionState(value ConnectorSessionState) ConnectorSessionState {
	switch value {
	case ConnectorSessionActive, ConnectorSessionDraining, ConnectorSessionClosed:
		return value
	default:
		return ConnectorSessionClosed
	}
}

func connectorSessionHealth(state ConnectorSessionState) (HealthStatus, string, string, string) {
	switch state {
	case ConnectorSessionActive:
		return StatusReady, "connector_ready", "Connector session is active.", "No action is required."
	case ConnectorSessionDraining:
		return StatusDegraded, "connector_draining", "Connector session is draining.", "Wait for a replacement connector session."
	default:
		return StatusDegraded, "connector_closed", "Connector session is closed.", "Reconnect the connector."
	}
}

func connectorStateOutcome(state ConnectorSessionState) EventOutcome {
	if state == ConnectorSessionActive {
		return OutcomeSuccess
	}
	return OutcomeStateChange
}

func connectorStateSeverity(state ConnectorSessionState) EventSeverity {
	if state == ConnectorSessionActive {
		return SeverityInfo
	}
	return SeverityWarn
}

func connectorStateMessage(state ConnectorSessionState) string {
	return "Connector session is " + string(state) + "."
}

type ConnectorConnectionOutcome string

const (
	ConnectorConnectionOpened ConnectorConnectionOutcome = "opened"
	ConnectorConnectionClosed ConnectorConnectionOutcome = "closed"
	ConnectorConnectionFailed ConnectorConnectionOutcome = "failed"
)

type ConnectorConnectionInput struct {
	Outcome       ConnectorConnectionOutcome
	At            time.Time
	Identity      ProducerIdentity
	Generations   Generations
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordConnectorConnection(input ConnectorConnectionInput) error {
	outcome := normalizeConnectorConnectionOutcome(input.Outcome)
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.IncCounter(MetricConnectorConnections, MetricLabels{"outcome": string(outcome)}); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := connectorOutcomeHealth(string(outcome), RetryNone, time.Time{}, p)
	if err := p.updateHealth(DimensionEdge, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEventWithGenerations(identity, "connector_connection", code, connectorConnectionEventOutcome(outcome), connectorConnectionSeverity(outcome), "Connector connection "+string(outcome)+".", retry, next, input.Generations)
}

func (p *Producer) ConnectorConnection(input ConnectorConnectionInput) error {
	return p.RecordConnectorConnection(input)
}

func normalizeConnectorConnectionOutcome(value ConnectorConnectionOutcome) ConnectorConnectionOutcome {
	switch value {
	case ConnectorConnectionOpened, ConnectorConnectionClosed, ConnectorConnectionFailed:
		return value
	default:
		return ConnectorConnectionFailed
	}
}

type ConnectorReconnectOutcome string

const (
	ConnectorReconnectSucceeded ConnectorReconnectOutcome = "success"
	ConnectorReconnectFailed    ConnectorReconnectOutcome = "failed"
)

type ConnectorReconnectInput struct {
	Outcome       ConnectorReconnectOutcome
	At            time.Time
	Retry         RetryDecision
	NextRetryAt   time.Time
	Identity      ProducerIdentity
	Generations   Generations
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordConnectorReconnect(input ConnectorReconnectInput) error {
	outcome := input.Outcome
	if outcome != ConnectorReconnectSucceeded && outcome != ConnectorReconnectFailed {
		outcome = ConnectorReconnectFailed
	}
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.IncCounter(MetricConnectorReconnects, MetricLabels{"outcome": string(outcome)}); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := connectorOutcomeHealth(string(outcome), input.Retry, input.NextRetryAt, p)
	if err := p.updateHealth(DimensionEdge, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEventWithGenerations(identity, "connector_reconnect", code, connectorReconnectEventOutcome(outcome), connectorReconnectSeverity(outcome), "Connector reconnect "+string(outcome)+".", retry, next, input.Generations)
}

func (p *Producer) ConnectorReconnect(input ConnectorReconnectInput) error {
	return p.RecordConnectorReconnect(input)
}

func connectorOutcomeHealth(outcome string, retry RetryDecision, next time.Time, p *Producer) (HealthStatus, string, string, string, RetryDecision, time.Time) {
	if outcome == string(ConnectorConnectionOpened) || outcome == string(ConnectorReconnectSucceeded) {
		return StatusReady, "connector_ready", "Connector connectivity is healthy.", "No action is required.", RetryNone, time.Time{}
	}
	if retry == "" {
		retry = RetryScheduled
	}
	if retry == RetryScheduled && next.IsZero() {
		next = p.now().Add(time.Minute)
	}
	return StatusDegraded, "connector_connection_failed", "Connector connectivity failed.", "Reconnect the connector and retry the operation.", retry, next
}

func connectorConnectionEventOutcome(value ConnectorConnectionOutcome) EventOutcome {
	if value == ConnectorConnectionOpened {
		return OutcomeSuccess
	}
	if value == ConnectorConnectionClosed {
		return OutcomeStateChange
	}
	return OutcomeFailed
}

func connectorConnectionSeverity(value ConnectorConnectionOutcome) EventSeverity {
	if value == ConnectorConnectionFailed {
		return SeverityError
	}
	return SeverityInfo
}

func connectorReconnectEventOutcome(value ConnectorReconnectOutcome) EventOutcome {
	if value == ConnectorReconnectSucceeded {
		return OutcomeSuccess
	}
	return OutcomeFailed
}

func connectorReconnectSeverity(value ConnectorReconnectOutcome) EventSeverity {
	if value == ConnectorReconnectSucceeded {
		return SeverityInfo
	}
	return SeverityError
}

type ConnectorBackoffState string

const (
	ConnectorBackoffScheduled ConnectorBackoffState = "scheduled"
	ConnectorBackoffExhausted ConnectorBackoffState = "exhausted"
)

type ConnectorBackoffInput struct {
	State         ConnectorBackoffState
	Duration      time.Duration
	At            time.Time
	Identity      ProducerIdentity
	Generations   Generations
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordConnectorBackoff(input ConnectorBackoffInput) error {
	state := normalizeConnectorBackoffState(input.State)
	duration, err := boundedSeconds(input.Duration)
	if err != nil {
		return err
	}
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.SetGauge(MetricConnectorBackoff, MetricLabels{"state": string(state)}, uint64(duration)); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := connectorBackoffHealth(state, p)
	if err := p.updateHealth(DimensionEdge, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEventWithGenerations(identity, "connector_backoff", code, connectorBackoffEventOutcome(state), connectorBackoffSeverity(state), "Connector backoff state updated.", retry, next, input.Generations)
}

func (p *Producer) ConnectorBackoff(input ConnectorBackoffInput) error {
	return p.RecordConnectorBackoff(input)
}

func normalizeConnectorBackoffState(value ConnectorBackoffState) ConnectorBackoffState {
	if value == ConnectorBackoffScheduled {
		return value
	}
	return ConnectorBackoffExhausted
}

func connectorBackoffHealth(state ConnectorBackoffState, p *Producer) (HealthStatus, string, string, string, RetryDecision, time.Time) {
	if state == ConnectorBackoffScheduled {
		return StatusDegraded, "connector_retry_scheduled", "Connector retry is scheduled.", "Wait for the next retry attempt.", RetryScheduled, p.now().Add(time.Minute)
	}
	return StatusDown, "connector_retry_exhausted", "Connector retries are exhausted.", "Repair connector connectivity before retrying.", RetryNotRetryable, time.Time{}
}

func connectorBackoffEventOutcome(state ConnectorBackoffState) EventOutcome {
	if state == ConnectorBackoffScheduled {
		return OutcomeStateChange
	}
	return OutcomeFailed
}

func connectorBackoffSeverity(state ConnectorBackoffState) EventSeverity {
	if state == ConnectorBackoffScheduled {
		return SeverityWarn
	}
	return SeverityError
}

type ConnectorHandshakeOutcome string

const (
	ConnectorHandshakeSucceeded ConnectorHandshakeOutcome = "success"
	ConnectorHandshakeFailed    ConnectorHandshakeOutcome = "failed"
)

type ConnectorHandshakeInput struct {
	Outcome       ConnectorHandshakeOutcome
	Duration      time.Duration
	At            time.Time
	Identity      ProducerIdentity
	Generations   Generations
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordConnectorHandshake(input ConnectorHandshakeInput) error {
	outcome := input.Outcome
	if outcome != ConnectorHandshakeSucceeded && outcome != ConnectorHandshakeFailed {
		outcome = ConnectorHandshakeFailed
	}
	duration, err := boundedSeconds(input.Duration)
	if err != nil {
		return err
	}
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.ObserveHistogram(MetricConnectorHandshakeLatency, MetricLabels{"outcome": string(outcome)}, duration); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := connectorOutcomeHealth(string(outcome), RetryNone, time.Time{}, p)
	if err := p.updateHealth(DimensionEdge, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEventWithGenerations(identity, "connector_handshake", code, connectorHandshakeEventOutcome(outcome), connectorHandshakeSeverity(outcome), "Connector handshake "+string(outcome)+".", retry, next, input.Generations)
}

func (p *Producer) ConnectorHandshake(input ConnectorHandshakeInput) error {
	return p.RecordConnectorHandshake(input)
}

func connectorHandshakeEventOutcome(value ConnectorHandshakeOutcome) EventOutcome {
	if value == ConnectorHandshakeSucceeded {
		return OutcomeSuccess
	}
	return OutcomeFailed
}

func connectorHandshakeSeverity(value ConnectorHandshakeOutcome) EventSeverity {
	if value == ConnectorHandshakeSucceeded {
		return SeverityInfo
	}
	return SeverityError
}

type ConnectorDisconnectReason string

const (
	ConnectorDisconnectAuth     ConnectorDisconnectReason = "auth"
	ConnectorDisconnectNetwork  ConnectorDisconnectReason = "network"
	ConnectorDisconnectServer   ConnectorDisconnectReason = "server"
	ConnectorDisconnectProtocol ConnectorDisconnectReason = "protocol"
	ConnectorDisconnectShutdown ConnectorDisconnectReason = "shutdown"
	ConnectorDisconnectUnknown  ConnectorDisconnectReason = "unknown"
)

type ConnectorDisconnectInput struct {
	Reason        ConnectorDisconnectReason
	At            time.Time
	Identity      ProducerIdentity
	Generations   Generations
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordConnectorDisconnect(input ConnectorDisconnectInput) error {
	reason := normalizeConnectorDisconnectReason(input.Reason)
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.IncCounter(MetricConnectorDisconnects, MetricLabels{"reason": string(reason)}); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := connectorOutcomeHealth(string(ConnectorConnectionFailed), RetryScheduled, time.Time{}, p)
	if reason == ConnectorDisconnectShutdown {
		status, code, summary, repair, retry, next = StatusReady, "connector_shutdown", "Connector shutdown completed.", "No action is required.", RetryNone, time.Time{}
	}
	if err := p.updateHealth(DimensionEdge, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEventWithGenerations(identity, "connector_disconnect", code, OutcomeStateChange, SeverityWarn, "Connector disconnected.", retry, next, input.Generations)
}

func (p *Producer) ConnectorDisconnect(input ConnectorDisconnectInput) error {
	return p.RecordConnectorDisconnect(input)
}

func normalizeConnectorDisconnectReason(value ConnectorDisconnectReason) ConnectorDisconnectReason {
	switch value {
	case ConnectorDisconnectAuth, ConnectorDisconnectNetwork, ConnectorDisconnectServer, ConnectorDisconnectProtocol, ConnectorDisconnectShutdown, ConnectorDisconnectUnknown:
		return value
	default:
		return ConnectorDisconnectUnknown
	}
}

// ConfigGenerationState reports whether a configuration generation is desired or applied.
type ConfigGenerationState string

const (
	ConfigGenerationDesired ConfigGenerationState = "desired"
	ConfigGenerationApplied ConfigGenerationState = "applied"
)

type ConfigApplyInput struct {
	State         ConfigGenerationState
	Generation    uint64
	At            time.Time
	Retry         RetryDecision
	NextRetryAt   time.Time
	Identity      ProducerIdentity
	Generations   Generations
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordConfigApply(input ConfigApplyInput) error {
	state := input.State
	if state != ConfigGenerationDesired && state != ConfigGenerationApplied {
		state = ConfigGenerationDesired
	}
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.SetGauge(MetricConfigGenerations, MetricLabels{"state": string(state)}, input.Generation); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := configHealth(state, input.Retry, input.NextRetryAt, p)
	if err := p.updateHealth(DimensionConfig, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	generations := input.Generations
	if generations.Config == 0 {
		generations.Config = input.Generation
	}
	return p.recordEventWithGenerations(identity, "config_apply", code, configEventOutcome(state), configSeverity(state), configMessage(state), retry, next, generations)
}

func (p *Producer) ConfigApply(input ConfigApplyInput) error {
	return p.RecordConfigApply(input)
}

func configHealth(state ConfigGenerationState, retry RetryDecision, next time.Time, p *Producer) (HealthStatus, string, string, string, RetryDecision, time.Time) {
	if state == ConfigGenerationApplied {
		return StatusReady, "config_applied", "The desired configuration is applied.", "No action is required.", RetryNone, time.Time{}
	}
	if retry == "" {
		retry = RetryWaitForChange
	}
	return StatusDegraded, "config_pending", "The desired configuration is waiting to be applied.", "Wait for the configuration worker to apply the desired generation.", retry, next
}

func configEventOutcome(state ConfigGenerationState) EventOutcome {
	if state == ConfigGenerationApplied {
		return OutcomeSuccess
	}
	return OutcomeStateChange
}

func configSeverity(state ConfigGenerationState) EventSeverity {
	if state == ConfigGenerationApplied {
		return SeverityInfo
	}
	return SeverityWarn
}

func configMessage(state ConfigGenerationState) string {
	if state == ConfigGenerationApplied {
		return "Configuration generation applied."
	}
	return "Configuration generation is pending."
}

type RouteErrorClass string

const (
	RouteErrorNotFound     RouteErrorClass = "not_found"
	RouteErrorConflict     RouteErrorClass = "conflict"
	RouteErrorPaused       RouteErrorClass = "paused"
	RouteErrorUnauthorized RouteErrorClass = "unauthorized"
	RouteErrorOrigin       RouteErrorClass = "origin"
	RouteErrorEdge         RouteErrorClass = "edge"
	RouteErrorInternal     RouteErrorClass = "internal"
)

type RouteErrorInput struct {
	Class         RouteErrorClass
	At            time.Time
	Identity      ProducerIdentity
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordRouteError(input RouteErrorInput) error {
	class := normalizeRouteErrorClass(input.Class)
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.IncCounter(MetricRouteErrors, MetricLabels{"class": string(class)}); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	retry, next := routeErrorRetry(class, p)
	if err := p.updateHealth(DimensionRoute, StatusDegraded, "route_error", "A route request failed.", "Check route, edge, and origin health before retrying.", correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEvent(identity, "route_error", "route_error", OutcomeFailed, SeverityError, "Route request failed.", retry, next)
}

func (p *Producer) RouteError(input RouteErrorInput) error {
	return p.RecordRouteError(input)
}

func normalizeRouteErrorClass(value RouteErrorClass) RouteErrorClass {
	switch value {
	case RouteErrorNotFound, RouteErrorConflict, RouteErrorPaused, RouteErrorUnauthorized, RouteErrorOrigin, RouteErrorEdge, RouteErrorInternal:
		return value
	default:
		return RouteErrorInternal
	}
}

func routeErrorRetry(class RouteErrorClass, p *Producer) (RetryDecision, time.Time) {
	switch class {
	case RouteErrorNotFound, RouteErrorConflict, RouteErrorUnauthorized:
		return RetryNotRetryable, time.Time{}
	case RouteErrorPaused:
		return RetryWaitForChange, time.Time{}
	default:
		return RetryScheduled, p.now().Add(time.Minute)
	}
}

type RouteProtocol string

const (
	RouteProtocolHTTP      RouteProtocol = "http"
	RouteProtocolHTTPS     RouteProtocol = "https"
	RouteProtocolH2C       RouteProtocol = "h2c"
	RouteProtocolTCP       RouteProtocol = "tcp"
	RouteProtocolWebsocket RouteProtocol = "websocket"
)

type RouteLatencyInput struct {
	Protocol      RouteProtocol
	Duration      time.Duration
	At            time.Time
	Identity      ProducerIdentity
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordRouteLatency(input RouteLatencyInput) error {
	protocol := normalizeRouteProtocol(input.Protocol)
	duration, err := boundedSeconds(input.Duration)
	if err != nil {
		return err
	}
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.ObserveHistogram(MetricRouteLatency, MetricLabels{"protocol": string(protocol)}, duration); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	if err := p.updateHealth(DimensionRoute, StatusReady, "route_ready", "Route connectivity is healthy.", "No action is required.", correlationID, RetryNone, time.Time{}); err != nil {
		return err
	}
	return p.recordEvent(identity, "route_latency", "route_latency_observed", OutcomeSuccess, SeverityInfo, "Route latency observed.", RetryNone, time.Time{})
}

func (p *Producer) RouteLatency(input RouteLatencyInput) error {
	return p.RecordRouteLatency(input)
}

func normalizeRouteProtocol(value RouteProtocol) RouteProtocol {
	switch value {
	case RouteProtocolHTTP, RouteProtocolHTTPS, RouteProtocolH2C, RouteProtocolTCP, RouteProtocolWebsocket:
		return value
	default:
		return RouteProtocolHTTP
	}
}

// ServiceState reports the lifecycle state of the service for service, watchdog, and crash-loop telemetry.
type ServiceState string

const (
	ServiceRunning  ServiceState = "running"
	ServiceDegraded ServiceState = "degraded"
	ServiceStopped  ServiceState = "stopped"
)

type ServiceLifecycleInput struct {
	State         ServiceState
	Uptime        time.Duration
	At            time.Time
	Identity      ProducerIdentity
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

type ServiceRestartOutcome string

const (
	ServiceRestartSucceeded ServiceRestartOutcome = "success"
	ServiceRestartFailed    ServiceRestartOutcome = "failed"
)

type ServiceRestartInput struct {
	Outcome       ServiceRestartOutcome
	At            time.Time
	Identity      ProducerIdentity
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordServiceLifecycle(input ServiceLifecycleInput) error {
	state := normalizeServiceState(input.State)
	if p != nil && p.Metrics != nil {
		if input.Uptime < 0 {
			return newError(ErrorInvalidObservation, "record control-plane service uptime")
		}
		uptime := uint64(input.Uptime / time.Second)
		for _, candidate := range []ServiceState{ServiceRunning, ServiceDegraded, ServiceStopped} {
			value := uint64(0)
			if candidate == state {
				value = uptime
			}
			if err := p.Metrics.SetGauge(MetricServiceUptime, MetricLabels{"state": string(candidate)}, value); err != nil {
				return err
			}
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := serviceHealth(state, p)
	if err := p.updateHealth(DimensionService, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEvent(identity, "service_lifecycle", code, serviceEventOutcome(state), serviceSeverity(state), "Service state is "+string(state)+".", retry, next)
}

func (p *Producer) ServiceLifecycle(input ServiceLifecycleInput) error {
	return p.RecordServiceLifecycle(input)
}

func (p *Producer) RecordServiceRestart(input ServiceRestartInput) error {
	outcome := input.Outcome
	if outcome != ServiceRestartSucceeded && outcome != ServiceRestartFailed {
		outcome = ServiceRestartFailed
	}
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.IncCounter(MetricServiceRestarts, MetricLabels{"outcome": string(outcome)}); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := serviceRestartHealth(outcome, p)
	if err := p.updateHealth(DimensionService, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEvent(identity, "service_lifecycle", code, serviceRestartEventOutcome(outcome), serviceRestartSeverity(outcome), "Service restart "+string(outcome)+".", retry, next)
}

func (p *Producer) ServiceRestart(input ServiceRestartInput) error {
	return p.RecordServiceRestart(input)
}

func serviceRestartHealth(outcome ServiceRestartOutcome, p *Producer) (HealthStatus, string, string, string, RetryDecision, time.Time) {
	if outcome == ServiceRestartSucceeded {
		return StatusReady, "service_ready", "The control-plane service restarted successfully.", "No action is required.", RetryNone, time.Time{}
	}
	return StatusDegraded, "service_restart_failed", "The control-plane service restart failed.", "Inspect service health before retrying the restart.", RetryScheduled, p.now().Add(time.Minute)
}

func serviceRestartEventOutcome(outcome ServiceRestartOutcome) EventOutcome {
	if outcome == ServiceRestartSucceeded {
		return OutcomeSuccess
	}
	return OutcomeFailed
}

func serviceRestartSeverity(outcome ServiceRestartOutcome) EventSeverity {
	if outcome == ServiceRestartSucceeded {
		return SeverityInfo
	}
	return SeverityError
}

func normalizeServiceState(value ServiceState) ServiceState {
	switch value {
	case ServiceRunning, ServiceDegraded, ServiceStopped:
		return value
	default:
		return ServiceDegraded
	}
}

func serviceHealth(state ServiceState, p *Producer) (HealthStatus, string, string, string, RetryDecision, time.Time) {
	switch state {
	case ServiceRunning:
		return StatusReady, "service_ready", "The control-plane service is running.", "No action is required.", RetryNone, time.Time{}
	case ServiceStopped:
		return StatusDown, "service_stopped", "The control-plane service is stopped.", "Start the control-plane service.", RetryNotRetryable, time.Time{}
	default:
		return StatusDegraded, "service_degraded", "The control-plane service is degraded.", "Inspect service health and retry affected operations.", RetryScheduled, p.now().Add(time.Minute)
	}
}

func serviceEventOutcome(state ServiceState) EventOutcome {
	if state == ServiceRunning {
		return OutcomeSuccess
	}
	return OutcomeStateChange
}

func serviceSeverity(state ServiceState) EventSeverity {
	if state == ServiceRunning {
		return SeverityInfo
	}
	return SeverityWarn
}

type WatchdogOutcome string

const (
	WatchdogHealthy   WatchdogOutcome = "healthy"
	WatchdogFailed    WatchdogOutcome = "failed"
	WatchdogRestarted WatchdogOutcome = "restarted"
)

type WatchdogInput struct {
	Outcome       WatchdogOutcome
	At            time.Time
	Identity      ProducerIdentity
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordWatchdog(input WatchdogInput) error {
	outcome := normalizeWatchdogOutcome(input.Outcome)
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.IncCounter(MetricServiceWatchdog, MetricLabels{"outcome": string(outcome)}); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := watchdogHealth(outcome, p)
	if err := p.updateHealth(DimensionService, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEvent(identity, "service_watchdog", code, watchdogEventOutcome(outcome), watchdogSeverity(outcome), "Service watchdog "+string(outcome)+".", retry, next)
}

func (p *Producer) Watchdog(input WatchdogInput) error { return p.RecordWatchdog(input) }

func normalizeWatchdogOutcome(value WatchdogOutcome) WatchdogOutcome {
	switch value {
	case WatchdogHealthy, WatchdogFailed, WatchdogRestarted:
		return value
	default:
		return WatchdogFailed
	}
}

func watchdogHealth(outcome WatchdogOutcome, p *Producer) (HealthStatus, string, string, string, RetryDecision, time.Time) {
	switch outcome {
	case WatchdogHealthy:
		return StatusReady, "service_ready", "The service watchdog is healthy.", "No action is required.", RetryNone, time.Time{}
	case WatchdogRestarted:
		return StatusDegraded, "service_restarted", "The service watchdog restarted the service.", "Confirm service stability before retrying.", RetryScheduled, p.now().Add(time.Minute)
	default:
		return StatusDegraded, "service_watchdog_failed", "The service watchdog detected a failure.", "Inspect service health and retry after recovery.", RetryScheduled, p.now().Add(time.Minute)
	}
}

func watchdogEventOutcome(value WatchdogOutcome) EventOutcome {
	if value == WatchdogHealthy {
		return OutcomeSuccess
	}
	return OutcomeFailed
}

func watchdogSeverity(value WatchdogOutcome) EventSeverity {
	if value == WatchdogHealthy {
		return SeverityInfo
	}
	return SeverityError
}

type CrashLoopState string

const (
	CrashLoopClear    CrashLoopState = "clear"
	CrashLoopDetected CrashLoopState = "detected"
)

type CrashLoopInput struct {
	State         CrashLoopState
	At            time.Time
	Identity      ProducerIdentity
	RequestID     string
	CorrelationID string
	IDs           SafeIDs
}

func (p *Producer) RecordCrashLoop(input CrashLoopInput) error {
	state := input.State
	if state != CrashLoopClear && state != CrashLoopDetected {
		state = CrashLoopDetected
	}
	if p != nil && p.Metrics != nil {
		if err := p.Metrics.SetGauge(MetricServiceCrashLoop, MetricLabels{"state": string(state)}, 1); err != nil {
			return err
		}
	}
	identity := mergeIdentity(input.Identity, input.RequestID, input.CorrelationID, input.IDs)
	correlationID := normalizedCorrelation(identity, p)
	status, code, summary, repair, retry, next := crashLoopHealth(state, p)
	if err := p.updateHealth(DimensionService, status, code, summary, repair, correlationID, retry, next); err != nil {
		return err
	}
	return p.recordEvent(identity, "service_crash_loop", code, crashLoopEventOutcome(state), crashLoopSeverity(state), "Service crash-loop state updated.", retry, next)
}

func (p *Producer) CrashLoop(input CrashLoopInput) error { return p.RecordCrashLoop(input) }

func crashLoopHealth(state CrashLoopState, p *Producer) (HealthStatus, string, string, string, RetryDecision, time.Time) {
	if state == CrashLoopClear {
		return StatusReady, "service_ready", "The service crash-loop condition is clear.", "No action is required.", RetryNone, time.Time{}
	}
	return StatusDown, "service_crash_loop", "The service is restarting repeatedly.", "Stop the crash loop and repair the service before retrying.", RetryNotRetryable, time.Time{}
}

func crashLoopEventOutcome(state CrashLoopState) EventOutcome {
	if state == CrashLoopClear {
		return OutcomeSuccess
	}
	return OutcomeFailed
}

func crashLoopSeverity(state CrashLoopState) EventSeverity {
	if state == CrashLoopClear {
		return SeverityInfo
	}
	return SeverityError
}

func mergeIdentity(identity ProducerIdentity, requestID, correlationID string, ids SafeIDs) ProducerIdentity {
	if identity.RequestID == "" {
		identity.RequestID = requestID
	}
	if identity.CorrelationID == "" {
		identity.CorrelationID = correlationID
	}
	identity.IDs = mergeSafeIDs(identity.IDs, ids)
	return identity
}

func mergeSafeIDs(left, right SafeIDs) SafeIDs {
	if left.AccountID == "" {
		left.AccountID = right.AccountID
	}
	if left.ActorID == "" {
		left.ActorID = right.ActorID
	}
	if left.TunnelID == "" {
		left.TunnelID = right.TunnelID
	}
	if left.RouteID == "" {
		left.RouteID = right.RouteID
	}
	if left.ConnectorID == "" {
		left.ConnectorID = right.ConnectorID
	}
	if left.DomainID == "" {
		left.DomainID = right.DomainID
	}
	if left.CertificateID == "" {
		left.CertificateID = right.CertificateID
	}
	if left.AssignmentID == "" {
		left.AssignmentID = right.AssignmentID
	}
	if left.HostID == "" {
		left.HostID = right.HostID
	}
	if left.DeviceID == "" {
		left.DeviceID = right.DeviceID
	}
	if left.SessionID == "" {
		left.SessionID = right.SessionID
	}
	if left.OperationID == "" {
		left.OperationID = right.OperationID
	}
	if left.RequestID == "" {
		left.RequestID = right.RequestID
	}
	if left.EdgeNodeID == "" {
		left.EdgeNodeID = right.EdgeNodeID
	}
	return left
}

// Context helpers allow HTTP/router assembly to pass safe identities without
// exposing a request, route, host, or body to this package.
type producerIdentityContextKey struct{}

func WithProducerIdentity(ctx context.Context, identity ProducerIdentity) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, producerIdentityContextKey{}, identity)
}

func ProducerIdentityFromContext(ctx context.Context) (ProducerIdentity, bool) {
	if ctx == nil {
		return ProducerIdentity{}, false
	}
	identity, ok := ctx.Value(producerIdentityContextKey{}).(ProducerIdentity)
	return identity, ok
}

// ProducerActivity describes one bounded producer activity snapshot. Keep these imports and helpers deliberately local to this additive adapter
// file. They also provide deterministic, bounded snapshots for tests and
// callers that need to inspect producer activity without an exporter.
type ProducerActivity struct {
	Name      string
	Outcome   EventOutcome
	Dimension Dimension
	Count     uint64
}

type producerActivityKey struct {
	name      string
	outcome   EventOutcome
	dimension Dimension
}

type ProducerActivityLog struct {
	mu      sync.RWMutex
	values  map[producerActivityKey]uint64
	max     int
	dropped atomic.Uint64
}

func NewProducerActivityLog(maxSeries int) *ProducerActivityLog {
	if maxSeries <= 0 {
		maxSeries = 256
	}
	return &ProducerActivityLog{values: make(map[producerActivityKey]uint64), max: maxSeries}
}

func (l *ProducerActivityLog) Record(name string, dimension Dimension, outcome EventOutcome) {
	if l == nil || !validDimension(dimension) || !stableCodePattern.MatchString(name) || !validEventOutcome(outcome) {
		return
	}
	key := producerActivityKey{name: name, outcome: outcome, dimension: dimension}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.values[key]; !ok && len(l.values) >= l.max {
		l.dropped.Add(1)
		return
	}
	l.values[key]++
}

func (l *ProducerActivityLog) Snapshot() []ProducerActivity {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	result := make([]ProducerActivity, 0, len(l.values))
	for key, count := range l.values {
		result = append(result, ProducerActivity{Name: key.name, Outcome: key.outcome, Dimension: key.dimension, Count: count})
	}
	l.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		if result[i].Dimension != result[j].Dimension {
			return result[i].Dimension < result[j].Dimension
		}
		return result[i].Outcome < result[j].Outcome
	})
	return result
}

func (l *ProducerActivityLog) Dropped() uint64 {
	if l == nil {
		return 0
	}
	return l.dropped.Load()
}
