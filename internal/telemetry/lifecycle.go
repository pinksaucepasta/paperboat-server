package telemetry

import (
	"bytes"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// Lifecycle records use the same versioned resource envelope as the rest of
// the preview/tunnel API. They are intentionally richer than Event, which is
// the small edge-compatible transport event retained for existing producers.
const LifecycleSchemaV1 = ContractSchemaV1

const (
	maximumLifecycleEventType = 80
	maximumLifecycleCode      = 64
	maximumLifecycleLogSize   = 4096
)

// LifecycleEventInput is the server-owned lifecycle boundary. Request,
// correlation, resource, and operation identities are required. All other
// values are metadata and are redacted or rejected before the record is
// returned to the caller.
type LifecycleEventInput struct {
	ID     string
	Cursor string

	At         time.Time
	OccurredAt time.Time

	Severity  EventSeverity
	Level     EventSeverity
	Component Dimension

	EventType string
	Name      string
	Code      string
	Outcome   EventOutcome
	Message   string

	RequestID     string
	CorrelationID string

	ResourceKind string
	ResourceID   string
	Resource     ResourceIdentity

	OperationID   string
	OperationKind string
	Operation     OperationIdentity

	ActorType string
	ActorID   string

	Generations  Generations
	Retry        RetryDecision
	NextRetryAt  time.Time
	Metadata     map[string]any
	SafeMetadata map[string]any
}

// ResourceIdentity is a typed, opaque resource reference. It never carries a
// hostname, URL, route expression, or user-provided name.
type ResourceIdentity struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// OperationIdentity is a typed reference to the durable operation that caused
// a lifecycle transition.
type OperationIdentity struct {
	Kind string `json:"kind,omitempty"`
	ID   string `json:"id"`
}

// LifecycleEvent is the immutable structured record retained in the
// lifecycle stream. Metadata is a deep copy made by the constructor.
type LifecycleEvent struct {
	Schema        string            `json:"schema"`
	Kind          string            `json:"kind"`
	ID            string            `json:"id,omitempty"`
	Cursor        string            `json:"cursor,omitempty"`
	EventType     string            `json:"event_type"`
	OccurredAt    time.Time         `json:"occurred_at"`
	Severity      EventSeverity     `json:"severity"`
	Component     Dimension         `json:"component"`
	Code          string            `json:"code"`
	Outcome       EventOutcome      `json:"outcome"`
	Message       string            `json:"message"`
	RequestID     string            `json:"request_id"`
	CorrelationID string            `json:"correlation_id"`
	Resource      ResourceIdentity  `json:"resource"`
	Operation     OperationIdentity `json:"operation"`
	Actor         *CanonicalActor   `json:"actor,omitempty"`
	Generations   Generations       `json:"generations,omitempty"`
	Retry         RetryDecision     `json:"retry"`
	NextRetryAt   *time.Time        `json:"next_retry_at,omitempty"`
	Metadata      map[string]any    `json:"metadata"`
}

// LifecycleEventRecord is a descriptive alias used by persistence adapters.
type LifecycleEventRecord = LifecycleEvent

// NewLifecycleEvent constructs and validates one lifecycle event. It resolves
// the old Name/At aliases for callers that share input structs with Event.
func NewLifecycleEvent(input LifecycleEventInput) (LifecycleEvent, error) {
	normalized, err := normalizeLifecycleInput(input)
	if err != nil {
		return LifecycleEvent{}, err
	}
	event := LifecycleEvent{
		Schema:        LifecycleSchemaV1,
		Kind:          KindLifecycleEvent,
		ID:            normalized.id,
		Cursor:        normalized.cursor,
		EventType:     normalized.eventType,
		OccurredAt:    normalized.at,
		Severity:      normalized.severity,
		Component:     normalized.component,
		Code:          normalized.code,
		Outcome:       normalized.outcome,
		Message:       normalized.message,
		RequestID:     normalized.requestID,
		CorrelationID: normalized.correlationID,
		Resource:      normalized.resource,
		Operation:     normalized.operation,
		Generations:   normalized.generations,
		Retry:         normalized.retry,
		Metadata:      normalized.metadata,
	}
	if normalized.actor != nil {
		actor := *normalized.actor
		event.Actor = &actor
	}
	if !normalized.nextRetryAt.IsZero() {
		next := normalized.nextRetryAt
		event.NextRetryAt = &next
	}
	return event, event.Validate()
}

func NewLifecycleEventRecord(input LifecycleEventInput) (LifecycleEventRecord, error) {
	return NewLifecycleEvent(input)
}

func (e LifecycleEvent) Validate() error {
	if e.Schema != LifecycleSchemaV1 || e.Kind != KindLifecycleEvent || !validOptionalOpaqueID(e.ID) || !validOptionalOpaqueID(e.Cursor) || !canonicalEventTypePattern.MatchString(e.EventType) || len(e.EventType) > maximumLifecycleEventType || e.OccurredAt.IsZero() || !validEventSeverity(e.Severity) || !validDimension(e.Component) || !stableCodePattern.MatchString(e.Code) || len(e.Code) > maximumLifecycleCode || !validEventOutcome(e.Outcome) || !storedSafeText(e.Message, maximumMessageBytes) || !validOptionalLogIdentity(e.RequestID, "request_", "req_") || !validCorrelationID(e.CorrelationID) || !validEventResourceKind(e.Resource.Kind) || !validOpaqueID(e.Resource.ID) || !validOptionalLogIdentity(e.Operation.ID, "operation_", "op_") || e.Operation.ID == "" || (e.Operation.Kind != "" && !stableCodePattern.MatchString(e.Operation.Kind)) || !validRetry(e.Retry, timeValue(e.NextRetryAt)) {
		return newError(ErrorInvalidEvent, "validate lifecycle event")
	}
	if e.RequestID == "" {
		return newError(ErrorIdentityRequired, "validate lifecycle event")
	}
	if e.Actor != nil && (!validActorType(e.Actor.Type) || !validOpaqueID(e.Actor.ID)) {
		return newError(ErrorInvalidID, "validate lifecycle event")
	}
	if !metadataIsSafe(e.Metadata) {
		return newError(ErrorUnsafeField, "validate lifecycle event")
	}
	return nil
}

func (e LifecycleEvent) JSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// LogRecord is the structured diagnostic counterpart to LifecycleEvent.
// It carries the same required identities so an operator can correlate logs,
// events, and API requests without searching unstructured text.
type LogRecord struct {
	Schema        string            `json:"schema"`
	Kind          string            `json:"kind"`
	ID            string            `json:"id,omitempty"`
	Cursor        string            `json:"cursor,omitempty"`
	OccurredAt    time.Time         `json:"occurred_at"`
	Level         EventSeverity     `json:"level"`
	Component     Dimension         `json:"component"`
	Code          string            `json:"code"`
	Message       string            `json:"message"`
	RequestID     string            `json:"request_id"`
	CorrelationID string            `json:"correlation_id"`
	Resource      ResourceIdentity  `json:"resource"`
	Operation     OperationIdentity `json:"operation"`
	Generations   Generations       `json:"generations,omitempty"`
	Retry         RetryDecision     `json:"retry"`
	NextRetryAt   *time.Time        `json:"next_retry_at,omitempty"`
	Metadata      map[string]any    `json:"metadata"`
}

type LifecycleLogRecord = LogRecord
type StructuredLogRecord = LogRecord

type LogRecordInput struct {
	ID     string
	Cursor string

	At         time.Time
	OccurredAt time.Time
	Level      EventSeverity
	Severity   EventSeverity
	Component  Dimension
	Code       string
	Message    string

	RequestID     string
	CorrelationID string
	ResourceKind  string
	ResourceID    string
	Resource      ResourceIdentity
	OperationID   string
	OperationKind string
	Operation     OperationIdentity

	Generations Generations
	Retry       RetryDecision
	NextRetryAt time.Time
	Metadata    map[string]any
}

type LifecycleLogInput = LogRecordInput

func NewLogRecord(input LogRecordInput) (LogRecord, error) {
	normalized, err := normalizeLogInput(input)
	if err != nil {
		return LogRecord{}, err
	}
	record := LogRecord{
		Schema:        LifecycleSchemaV1,
		Kind:          KindLifecycleLog,
		ID:            normalized.id,
		Cursor:        normalized.cursor,
		OccurredAt:    normalized.at,
		Level:         normalized.level,
		Component:     normalized.component,
		Code:          normalized.code,
		Message:       normalized.message,
		RequestID:     normalized.requestID,
		CorrelationID: normalized.correlationID,
		Resource:      normalized.resource,
		Operation:     normalized.operation,
		Generations:   normalized.generations,
		Retry:         normalized.retry,
		Metadata:      normalized.metadata,
	}
	if !normalized.nextRetryAt.IsZero() {
		next := normalized.nextRetryAt
		record.NextRetryAt = &next
	}
	return record, record.Validate()
}

func NewLifecycleLogRecord(input LogRecordInput) (LifecycleLogRecord, error) {
	return NewLogRecord(input)
}

func (r LogRecord) Validate() error {
	if r.Schema != LifecycleSchemaV1 || r.Kind != KindLifecycleLog || !validOptionalOpaqueID(r.ID) || !validOptionalOpaqueID(r.Cursor) || r.OccurredAt.IsZero() || !validEventSeverity(r.Level) || !validDimension(r.Component) || !stableCodePattern.MatchString(r.Code) || !storedSafeText(r.Message, maximumMessageBytes) || !validOptionalLogIdentity(r.RequestID, "request_", "req_") || !validCorrelationID(r.CorrelationID) || !validEventResourceKind(r.Resource.Kind) || !validOpaqueID(r.Resource.ID) || !validOptionalLogIdentity(r.Operation.ID, "operation_", "op_") || r.Operation.ID == "" || (r.Operation.Kind != "" && !stableCodePattern.MatchString(r.Operation.Kind)) || !validRetry(r.Retry, timeValue(r.NextRetryAt)) {
		return newError(ErrorInvalidEvent, "validate lifecycle log")
	}
	if r.RequestID == "" {
		return newError(ErrorIdentityRequired, "validate lifecycle log")
	}
	if !metadataIsSafe(r.Metadata) {
		return newError(ErrorUnsafeField, "validate lifecycle log")
	}
	return nil
}

func (r LogRecord) JSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

type lifecycleNormalized struct {
	id, cursor, eventType, requestID, correlationID string
	at                                              time.Time
	severity                                        EventSeverity
	component                                       Dimension
	code                                            string
	outcome                                         EventOutcome
	message                                         string
	resource                                        ResourceIdentity
	operation                                       OperationIdentity
	actor                                           *CanonicalActor
	generations                                     Generations
	retry                                           RetryDecision
	nextRetryAt                                     time.Time
	metadata                                        map[string]any
}

type logNormalized struct {
	id, cursor, requestID, correlationID string
	at                                   time.Time
	level                                EventSeverity
	component                            Dimension
	code, message                        string
	resource                             ResourceIdentity
	operation                            OperationIdentity
	generations                          Generations
	retry                                RetryDecision
	nextRetryAt                          time.Time
	metadata                             map[string]any
}

func normalizeLifecycleInput(input LifecycleEventInput) (lifecycleNormalized, error) {
	at := input.OccurredAt
	if at.IsZero() {
		at = input.At
	}
	at = normalizeTime(at)
	if at.IsZero() {
		return lifecycleNormalized{}, newError(ErrorInvalidTime, "construct lifecycle event")
	}
	severity := input.Severity
	if severity == "" {
		severity = input.Level
	}
	if !validEventSeverity(severity) || !validDimension(input.Component) {
		return lifecycleNormalized{}, newError(ErrorInvalidEvent, "construct lifecycle event")
	}
	eventType := input.EventType
	if eventType == "" {
		eventType = input.Name
	}
	if !canonicalEventTypePattern.MatchString(eventType) || len(eventType) > maximumLifecycleEventType || !stableCodePattern.MatchString(input.Code) || len(input.Code) > maximumLifecycleCode || !validEventOutcome(input.Outcome) {
		return lifecycleNormalized{}, newError(ErrorInvalidEvent, "construct lifecycle event")
	}
	requestID, correlationID, resource, operation, err := normalizeIdentities(input.RequestID, input.CorrelationID, input.ResourceKind, input.ResourceID, input.Resource, input.OperationID, input.OperationKind, input.Operation)
	if err != nil {
		return lifecycleNormalized{}, err
	}
	message, err := safeBoundedString(input.Message, maximumMessageBytes, true)
	if err != nil {
		return lifecycleNormalized{}, err
	}
	metadata, err := selectMetadata(input.Metadata, input.SafeMetadata)
	if err != nil {
		return lifecycleNormalized{}, err
	}
	retry := input.Retry
	if retry == "" {
		retry = RetryNone
	}
	if !validRetry(retry, input.NextRetryAt) {
		return lifecycleNormalized{}, newError(ErrorInvalidRetry, "construct lifecycle event")
	}
	var actor *CanonicalActor
	if input.ActorType != "" || input.ActorID != "" {
		if !validActorType(input.ActorType) || !validOpaqueID(input.ActorID) {
			return lifecycleNormalized{}, newError(ErrorInvalidID, "construct lifecycle event")
		}
		actor = &CanonicalActor{Type: input.ActorType, ID: input.ActorID}
	}
	return lifecycleNormalized{id: input.ID, cursor: input.Cursor, eventType: eventType, at: at, severity: severity, component: input.Component, code: input.Code, outcome: input.Outcome, message: message, requestID: requestID, correlationID: correlationID, resource: resource, operation: operation, actor: actor, generations: input.Generations, retry: retry, nextRetryAt: normalizeTime(input.NextRetryAt), metadata: metadata}, nil
}

func normalizeLogInput(input LogRecordInput) (logNormalized, error) {
	at := input.OccurredAt
	if at.IsZero() {
		at = input.At
	}
	at = normalizeTime(at)
	if at.IsZero() {
		return logNormalized{}, newError(ErrorInvalidTime, "construct lifecycle log")
	}
	level := input.Level
	if level == "" {
		level = input.Severity
	}
	if !validEventSeverity(level) || !validDimension(input.Component) || !stableCodePattern.MatchString(input.Code) {
		return logNormalized{}, newError(ErrorInvalidEvent, "construct lifecycle log")
	}
	requestID, correlationID, resource, operation, err := normalizeIdentities(input.RequestID, input.CorrelationID, input.ResourceKind, input.ResourceID, input.Resource, input.OperationID, input.OperationKind, input.Operation)
	if err != nil {
		return logNormalized{}, err
	}
	message, err := safeBoundedString(input.Message, maximumMessageBytes, true)
	if err != nil {
		return logNormalized{}, err
	}
	metadata, err := safeMetadata(input.Metadata)
	if err != nil {
		return logNormalized{}, err
	}
	retry := input.Retry
	if retry == "" {
		retry = RetryNone
	}
	if !validRetry(retry, input.NextRetryAt) {
		return logNormalized{}, newError(ErrorInvalidRetry, "construct lifecycle log")
	}
	return logNormalized{id: input.ID, cursor: input.Cursor, at: at, level: level, component: input.Component, code: input.Code, message: message, requestID: requestID, correlationID: correlationID, resource: resource, operation: operation, generations: input.Generations, retry: retry, nextRetryAt: normalizeTime(input.NextRetryAt), metadata: metadata}, nil
}

func normalizeIdentities(requestID, correlationID, resourceKind, resourceID string, resource ResourceIdentity, operationID, operationKind string, operation OperationIdentity) (string, string, ResourceIdentity, OperationIdentity, error) {
	if resource.Kind != "" || resource.ID != "" {
		if resourceKind != "" && resourceKind != resource.Kind || resourceID != "" && resourceID != resource.ID {
			return "", "", ResourceIdentity{}, OperationIdentity{}, newError(ErrorIdentityMismatch, "construct lifecycle telemetry")
		}
		if resourceKind == "" {
			resourceKind = resource.Kind
		}
		if resourceID == "" {
			resourceID = resource.ID
		}
	}
	if operation.Kind != "" || operation.ID != "" {
		if operationID != "" && operationID != operation.ID || operationKind != "" && operationKind != operation.Kind {
			return "", "", ResourceIdentity{}, OperationIdentity{}, newError(ErrorIdentityMismatch, "construct lifecycle telemetry")
		}
		if operationID == "" {
			operationID = operation.ID
		}
		if operationKind == "" {
			operationKind = operation.Kind
		}
	}
	if !validOptionalLogIdentity(requestID, "request_", "req_") || requestID == "" || !validCorrelationID(correlationID) || !validEventResourceKind(resourceKind) || !validOpaqueID(resourceID) || !validOptionalLogIdentity(operationID, "operation_", "op_") || operationID == "" || (operationKind != "" && !stableCodePattern.MatchString(operationKind)) {
		return "", "", ResourceIdentity{}, OperationIdentity{}, newError(ErrorIdentityRequired, "construct lifecycle telemetry")
	}
	return requestID, correlationID, ResourceIdentity{Kind: resourceKind, ID: resourceID}, OperationIdentity{Kind: operationKind, ID: operationID}, nil
}

func selectMetadata(metadata, safe map[string]any) (map[string]any, error) {
	if metadata != nil && safe != nil {
		left, err := safeMetadata(metadata)
		if err != nil {
			return nil, err
		}
		right, err := safeMetadata(safe)
		if err != nil {
			return nil, err
		}
		leftJSON, _ := json.Marshal(left)
		rightJSON, _ := json.Marshal(right)
		if !bytes.Equal(leftJSON, rightJSON) {
			return nil, newError(ErrorIdentityMismatch, "construct lifecycle telemetry")
		}
		return left, nil
	}
	if safe != nil {
		return safeMetadata(safe)
	}
	return safeMetadata(metadata)
}

func validOptionalOpaqueID(value string) bool {
	return value == "" || validOpaqueID(value)
}

func metadataIsSafe(metadata map[string]any) bool {
	clean, err := safeMetadata(metadata)
	if err != nil {
		return false
	}
	left, err := json.Marshal(clean)
	if err != nil {
		return false
	}
	right, err := json.Marshal(metadata)
	return err == nil && bytes.Equal(left, right)
}

// LifecycleEventLog and LifecycleLog retain separate bounded streams. They
// use TryLock so a slow snapshot never adds producer backpressure; dropped
// records remain observable through Dropped.
type LifecycleEventLog struct {
	mu       sync.RWMutex
	capacity int
	events   []LifecycleEvent
	dropped  atomic.Uint64
	closed   atomic.Bool
}

func NewLifecycleEventLog(capacity int) (*LifecycleEventLog, error) {
	if capacity <= 0 || capacity > maximumLifecycleLogSize {
		return nil, newError(ErrorInvalidCapacity, "construct lifecycle event log")
	}
	return &LifecycleEventLog{capacity: capacity, events: make([]LifecycleEvent, 0, capacity)}, nil
}

func (l *LifecycleEventLog) Record(input LifecycleEventInput) (LifecycleEvent, error) {
	event, err := NewLifecycleEvent(input)
	if err != nil {
		return LifecycleEvent{}, err
	}
	if l == nil || l.closed.Load() {
		return event, nil
	}
	if !l.mu.TryLock() {
		l.dropped.Add(1)
		return event, nil
	}
	defer l.mu.Unlock()
	if l.closed.Load() {
		l.dropped.Add(1)
		return event, nil
	}
	if len(l.events) == l.capacity {
		copy(l.events, l.events[1:])
		l.events[len(l.events)-1] = cloneLifecycleEvent(event)
		l.dropped.Add(1)
	} else {
		l.events = append(l.events, cloneLifecycleEvent(event))
	}
	return event, nil
}

func (l *LifecycleEventLog) TryRecord(input LifecycleEventInput) (LifecycleEvent, bool, error) {
	event, err := NewLifecycleEvent(input)
	if err != nil {
		return LifecycleEvent{}, false, err
	}
	if l == nil || l.closed.Load() || !l.mu.TryLock() {
		if l != nil {
			l.dropped.Add(1)
		}
		return event, false, nil
	}
	defer l.mu.Unlock()
	if l.closed.Load() {
		l.dropped.Add(1)
		return event, false, nil
	}
	if len(l.events) == l.capacity {
		copy(l.events, l.events[1:])
		l.events[len(l.events)-1] = cloneLifecycleEvent(event)
		l.dropped.Add(1)
	} else {
		l.events = append(l.events, cloneLifecycleEvent(event))
	}
	return event, true, nil
}

func (l *LifecycleEventLog) Snapshot() []LifecycleEvent {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]LifecycleEvent, len(l.events))
	for index, event := range l.events {
		result[index] = cloneLifecycleEvent(event)
	}
	return result
}

func (l *LifecycleEventLog) Dropped() uint64 {
	if l == nil {
		return 0
	}
	return l.dropped.Load()
}

func (l *LifecycleEventLog) Close() error {
	if l != nil {
		l.mu.Lock()
		l.closed.Store(true)
		l.mu.Unlock()
	}
	return nil
}

type LifecycleLog struct {
	mu       sync.RWMutex
	capacity int
	entries  []LogRecord
	dropped  atomic.Uint64
	closed   atomic.Bool
}

func NewLifecycleLog(capacity int) (*LifecycleLog, error) {
	if capacity <= 0 || capacity > maximumLifecycleLogSize {
		return nil, newError(ErrorInvalidCapacity, "construct lifecycle log")
	}
	return &LifecycleLog{capacity: capacity, entries: make([]LogRecord, 0, capacity)}, nil
}

func (l *LifecycleLog) Record(input LogRecordInput) (LogRecord, error) {
	record, err := NewLogRecord(input)
	if err != nil {
		return LogRecord{}, err
	}
	if l == nil || l.closed.Load() {
		return record, nil
	}
	if !l.mu.TryLock() {
		l.dropped.Add(1)
		return record, nil
	}
	defer l.mu.Unlock()
	if l.closed.Load() {
		l.dropped.Add(1)
		return record, nil
	}
	if len(l.entries) == l.capacity {
		copy(l.entries, l.entries[1:])
		l.entries[len(l.entries)-1] = cloneLogRecord(record)
		l.dropped.Add(1)
	} else {
		l.entries = append(l.entries, cloneLogRecord(record))
	}
	return record, nil
}

func (l *LifecycleLog) TryRecord(input LogRecordInput) (LogRecord, bool, error) {
	record, err := NewLogRecord(input)
	if err != nil {
		return LogRecord{}, false, err
	}
	if l == nil || l.closed.Load() || !l.mu.TryLock() {
		if l != nil {
			l.dropped.Add(1)
		}
		return record, false, nil
	}
	defer l.mu.Unlock()
	if l.closed.Load() {
		l.dropped.Add(1)
		return record, false, nil
	}
	if len(l.entries) == l.capacity {
		copy(l.entries, l.entries[1:])
		l.entries[len(l.entries)-1] = cloneLogRecord(record)
		l.dropped.Add(1)
	} else {
		l.entries = append(l.entries, cloneLogRecord(record))
	}
	return record, true, nil
}

func (l *LifecycleLog) Snapshot() []LogRecord {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]LogRecord, len(l.entries))
	for index, entry := range l.entries {
		result[index] = cloneLogRecord(entry)
	}
	return result
}

func (l *LifecycleLog) Dropped() uint64 {
	if l == nil {
		return 0
	}
	return l.dropped.Load()
}

func (l *LifecycleLog) Close() error {
	if l != nil {
		l.mu.Lock()
		l.closed.Store(true)
		l.mu.Unlock()
	}
	return nil
}

func cloneLifecycleEvent(event LifecycleEvent) LifecycleEvent {
	if event.NextRetryAt != nil {
		event.NextRetryAt = cloneTime(event.NextRetryAt)
	}
	if event.Actor != nil {
		actor := *event.Actor
		event.Actor = &actor
	}
	event.Metadata, _ = safeMetadata(event.Metadata)
	return event
}

func cloneLogRecord(record LogRecord) LogRecord {
	if record.NextRetryAt != nil {
		record.NextRetryAt = cloneTime(record.NextRetryAt)
	}
	record.Metadata, _ = safeMetadata(record.Metadata)
	return record
}
