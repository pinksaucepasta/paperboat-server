package telemetry

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// ContractSchemaV1 is the language-neutral resource schema shared by the
// server, host runtime, edge and dashboard.
const ContractSchemaV1 = "paperboat.preview-tunnel/v1"

// ResourceSchemaV1 is retained as the descriptive name used by the edge
// package. Both names identify the same language-neutral v1 envelope.
const ResourceSchemaV1 = ContractSchemaV1

const (
	KindHealth         = "health"
	KindEvent          = "event"
	KindLog            = "log_entry"
	KindError          = "error"
	KindLifecycleEvent = "lifecycle_event"
	KindLifecycleLog   = "lifecycle_log"
)

const DimensionControl Dimension = "control"

var (
	resourceIDPattern     = regexp.MustCompile(`^[A-Za-z0-9._:-]{3,128}$`)
	healthResourceKindSet = map[string]struct{}{
		"preview_lease": {}, "tunnel": {}, "route": {}, "domain_binding": {}, "connector": {},
	}
	actorTypeSet              = map[string]struct{}{"user": {}, "host": {}, "system": {}, "edge": {}}
	metadataKeyPattern        = regexp.MustCompile(`(?i)(token|secret|private[_-]?key|authorization|password|cookie)`)
	canonicalEventTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,79}$`)
	componentPattern          = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
)

type CanonicalHealthDimension struct {
	Status HealthStatus `json:"status"`
	Code   string       `json:"code"`
}

// ResourceHealthDimension and ResourceHealthDimensions are compatibility
// names for callers that describe the canonical projection as a resource.
// They are aliases, so there is still one wire shape and one source of truth.
type ResourceHealthDimension = CanonicalHealthDimension

type CanonicalHealthDimensions struct {
	Service     CanonicalHealthDimension `json:"service"`
	Edge        CanonicalHealthDimension `json:"edge"`
	Config      CanonicalHealthDimension `json:"config"`
	Route       CanonicalHealthDimension `json:"route"`
	Origin      CanonicalHealthDimension `json:"origin"`
	DNS         CanonicalHealthDimension `json:"dns"`
	Certificate CanonicalHealthDimension `json:"certificate"`
	Access      CanonicalHealthDimension `json:"access"`
	Update      CanonicalHealthDimension `json:"update"`
}

type ResourceHealthDimensions = CanonicalHealthDimensions

// HealthResourceBinding supplies the durable identity that a local health
// tracker cannot know. It is intentionally limited to opaque IDs.
type HealthResourceBinding struct {
	ResourceKind  string
	ResourceID    string
	CorrelationID string
}

func (d CanonicalHealthDimensions) Get(dimension Dimension) CanonicalHealthDimension {
	switch dimension {
	case DimensionService:
		return d.Service
	case DimensionEdge:
		return d.Edge
	case DimensionConfig:
		return d.Config
	case DimensionRoute:
		return d.Route
	case DimensionOrigin:
		return d.Origin
	case DimensionDNS:
		return d.DNS
	case DimensionCertificate:
		return d.Certificate
	case DimensionAccess:
		return d.Access
	case DimensionUpdate:
		return d.Update
	default:
		return CanonicalHealthDimension{}
	}
}

type HealthResource struct {
	Schema        string                    `json:"schema"`
	Kind          string                    `json:"kind"`
	ResourceKind  string                    `json:"resource_kind"`
	ResourceID    string                    `json:"resource_id"`
	OverallCode   string                    `json:"overall_code"`
	Dimensions    CanonicalHealthDimensions `json:"dimensions"`
	Summary       string                    `json:"summary"`
	Since         time.Time                 `json:"since"`
	Retrying      bool                      `json:"retrying"`
	NextRetryAt   *time.Time                `json:"next_retry_at,omitempty"`
	RepairAction  string                    `json:"repair_action"`
	CorrelationID string                    `json:"correlation_id"`
}

type HealthResourceInput struct {
	ResourceKind  string
	ResourceID    string
	Snapshot      HealthSnapshot
	CorrelationID string
}

func NewHealthResource(input HealthResourceInput) (HealthResource, error) {
	if !validHealthResourceKind(input.ResourceKind) || !validOpaqueID(input.ResourceID) {
		return HealthResource{}, newError(ErrorInvalidID, "construct health resource")
	}
	snapshot := input.Snapshot
	if snapshot.Schema != "" && snapshot.Schema != HealthSchemaV1 {
		return HealthResource{}, newError(ErrorInvalidObservation, "construct health resource")
	}
	if normalizeTime(snapshot.UpdatedAt).IsZero() || normalizeTime(snapshot.Overall.Since).IsZero() || !stableCodePattern.MatchString(snapshot.Overall.Code) {
		return HealthResource{}, newError(ErrorInvalidObservation, "construct health resource")
	}
	correlationID := input.CorrelationID
	if correlationID == "" {
		correlationID = snapshot.Overall.CorrelationID
	}
	if input.CorrelationID != "" && snapshot.Overall.CorrelationID != "" && input.CorrelationID != snapshot.Overall.CorrelationID {
		return HealthResource{}, newError(ErrorInvalidID, "construct health resource")
	}
	if !validCorrelationID(correlationID) {
		return HealthResource{}, newError(ErrorInvalidID, "construct health resource")
	}
	summary, err := safeBoundedString(snapshot.Overall.Summary, maximumSummaryBytes, true)
	if err != nil {
		return HealthResource{}, err
	}
	repairAction, err := safeBoundedString(snapshot.Overall.RepairAction, maximumRepairBytes, true)
	if err != nil {
		return HealthResource{}, err
	}
	var nextRetryAt *time.Time
	if snapshot.Overall.NextRetryAt != nil {
		value := normalizeTime(*snapshot.Overall.NextRetryAt)
		if value.IsZero() {
			return HealthResource{}, newError(ErrorInvalidRetry, "construct health resource")
		}
		nextRetryAt = &value
	}
	resource := HealthResource{Schema: ContractSchemaV1, Kind: KindHealth, ResourceKind: input.ResourceKind, ResourceID: input.ResourceID, OverallCode: snapshot.Overall.Code, Summary: summary, Since: normalizeTime(snapshot.Overall.Since), Retrying: snapshot.Overall.Retry == RetryScheduled, NextRetryAt: nextRetryAt, RepairAction: repairAction, CorrelationID: correlationID}
	for _, dimension := range dimensionOrder {
		state := snapshot.Dimensions.Get(dimension)
		resource.Dimensions.set(dimension, CanonicalHealthDimension{Status: state.Status, Code: state.Code})
	}
	if err := resource.Validate(); err != nil {
		return HealthResource{}, err
	}
	return resource, nil
}

// ProjectHealthResource is the explicit binding form used by server
// producers. The tracker snapshot and the durable envelope are kept separate
// so an adapter cannot silently invent an identity.
func ProjectHealthResource(snapshot HealthSnapshot, binding HealthResourceBinding) (HealthResource, error) {
	return NewHealthResource(HealthResourceInput{
		ResourceKind:  binding.ResourceKind,
		ResourceID:    binding.ResourceID,
		Snapshot:      snapshot,
		CorrelationID: binding.CorrelationID,
	})
}

// AsResource is a convenience for callers projecting one tracked snapshot.
func (s HealthSnapshot) AsResource(resourceKind, resourceID, correlationID string) (HealthResource, error) {
	return NewHealthResource(HealthResourceInput{ResourceKind: resourceKind, ResourceID: resourceID, Snapshot: s, CorrelationID: correlationID})
}

func (d *CanonicalHealthDimensions) set(dimension Dimension, value CanonicalHealthDimension) {
	switch dimension {
	case DimensionService:
		d.Service = value
	case DimensionEdge:
		d.Edge = value
	case DimensionConfig:
		d.Config = value
	case DimensionRoute:
		d.Route = value
	case DimensionOrigin:
		d.Origin = value
	case DimensionDNS:
		d.DNS = value
	case DimensionCertificate:
		d.Certificate = value
	case DimensionAccess:
		d.Access = value
	case DimensionUpdate:
		d.Update = value
	}
}

func (r HealthResource) Validate() error {
	if r.Schema != ContractSchemaV1 || r.Kind != KindHealth || !validHealthResourceKind(r.ResourceKind) || !validOpaqueID(r.ResourceID) || !stableCodePattern.MatchString(r.OverallCode) || r.Since.IsZero() || !validCorrelationID(r.CorrelationID) || !storedSafeText(r.Summary, maximumSummaryBytes) || !storedSafeText(r.RepairAction, maximumRepairBytes) || r.Retrying != (r.NextRetryAt != nil) || (r.NextRetryAt != nil && r.NextRetryAt.IsZero()) {
		return newError(ErrorInvalidObservation, "validate health resource")
	}
	for _, dimension := range dimensionOrder {
		state := r.Dimensions.Get(dimension)
		if !validHealthStatus(state.Status) || !stableCodePattern.MatchString(state.Code) {
			return newError(ErrorInvalidObservation, "validate health resource")
		}
	}
	return nil
}

func (r HealthResource) JSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

type CanonicalActor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type EventActor = CanonicalActor

type CanonicalEventResource struct {
	Schema        string         `json:"schema"`
	Kind          string         `json:"kind"`
	ID            string         `json:"id"`
	Cursor        string         `json:"cursor"`
	EventType     string         `json:"event_type"`
	ResourceKind  string         `json:"resource_kind"`
	ResourceID    string         `json:"resource_id"`
	OccurredAt    time.Time      `json:"occurred_at"`
	Actor         CanonicalActor `json:"actor"`
	CorrelationID string         `json:"correlation_id"`
	SafeMetadata  map[string]any `json:"safe_metadata"`
}

type CanonicalEventInput struct {
	ID            string
	Cursor        string
	EventType     string
	ResourceKind  string
	ResourceID    string
	OccurredAt    time.Time
	ActorType     string
	ActorID       string
	CorrelationID string
	SafeMetadata  map[string]any
}

type EventResourceBinding struct {
	ID           string
	Cursor       string
	ResourceKind string
	ResourceID   string
	Actor        EventActor
}

func NewCanonicalEvent(input CanonicalEventInput) (CanonicalEventResource, error) {
	if !validOpaqueID(input.ID) || !validOpaqueID(input.Cursor) || !canonicalEventTypePattern.MatchString(input.EventType) || !validEventResourceKind(input.ResourceKind) || !validOpaqueID(input.ResourceID) || normalizeTime(input.OccurredAt).IsZero() || !validActorType(input.ActorType) || !validOpaqueID(input.ActorID) || !validCorrelationID(input.CorrelationID) {
		return CanonicalEventResource{}, newError(ErrorInvalidEvent, "construct canonical event")
	}
	metadata, err := safeMetadata(input.SafeMetadata)
	if err != nil {
		return CanonicalEventResource{}, err
	}
	event := CanonicalEventResource{Schema: ContractSchemaV1, Kind: KindEvent, ID: input.ID, Cursor: input.Cursor, EventType: input.EventType, ResourceKind: input.ResourceKind, ResourceID: input.ResourceID, OccurredAt: normalizeTime(input.OccurredAt), Actor: CanonicalActor{Type: input.ActorType, ID: input.ActorID}, CorrelationID: input.CorrelationID, SafeMetadata: metadata}
	return event, event.Validate()
}

// ProjectEventResource translates an internal event into the canonical v1
// event resource. The human message, severity, and outcome intentionally do
// not cross this boundary; lifecycle metadata remains safe and bounded.
func ProjectEventResource(event Event, binding EventResourceBinding) (CanonicalEventResource, error) {
	if event.Schema != EventSchemaV1 || !stableCodePattern.MatchString(event.Name) || !validOpaqueID(event.CorrelationID) || event.At.IsZero() {
		return CanonicalEventResource{}, newError(ErrorInvalidEvent, "project control-plane event resource")
	}
	if !validEventResourceKind(binding.ResourceKind) || !validOpaqueID(binding.ID) || !validOpaqueID(binding.Cursor) || !validOpaqueID(binding.ResourceID) || !validActorType(binding.Actor.Type) || !validOpaqueID(binding.Actor.ID) {
		return CanonicalEventResource{}, newError(ErrorInvalidID, "project control-plane event resource")
	}
	metadata := make(map[string]any, 24)
	addSafeMetadata(metadata, "account_id", event.IDs.AccountID)
	addSafeMetadata(metadata, "actor_id", event.IDs.ActorID)
	addSafeMetadata(metadata, "tunnel_id", event.IDs.TunnelID)
	addSafeMetadata(metadata, "route_id", event.IDs.RouteID)
	addSafeMetadata(metadata, "connector_id", event.IDs.ConnectorID)
	addSafeMetadata(metadata, "domain_id", event.IDs.DomainID)
	addSafeMetadata(metadata, "certificate_id", event.IDs.CertificateID)
	addSafeMetadata(metadata, "assignment_id", event.IDs.AssignmentID)
	addSafeMetadata(metadata, "host_id", event.IDs.HostID)
	addSafeMetadata(metadata, "device_id", event.IDs.DeviceID)
	addSafeMetadata(metadata, "session_id", event.IDs.SessionID)
	addSafeMetadata(metadata, "operation_id", event.IDs.OperationID)
	addSafeMetadata(metadata, "request_id", event.IDs.RequestID)
	addSafeMetadata(metadata, "edge_node_id", event.IDs.EdgeNodeID)
	addGenerationMetadata(metadata, "config_generation", event.Generations.Config)
	addGenerationMetadata(metadata, "route_generation", event.Generations.Route)
	addGenerationMetadata(metadata, "assignment_generation", event.Generations.Assignment)
	addGenerationMetadata(metadata, "connector_generation", event.Generations.Connector)
	addGenerationMetadata(metadata, "process_generation", event.Generations.Process)
	addGenerationMetadata(metadata, "session_generation", event.Generations.Session)
	addGenerationMetadata(metadata, "installation_generation", event.Generations.Installation)
	addGenerationMetadata(metadata, "credential_generation", event.Generations.Credential)
	addGenerationMetadata(metadata, "certificate_generation", event.Generations.Certificate)
	return NewCanonicalEvent(CanonicalEventInput{
		ID: binding.ID, Cursor: binding.Cursor, EventType: event.Name,
		ResourceKind: binding.ResourceKind, ResourceID: binding.ResourceID,
		OccurredAt: event.At, ActorType: binding.Actor.Type, ActorID: binding.Actor.ID,
		CorrelationID: event.CorrelationID, SafeMetadata: metadata,
	})
}

func (e CanonicalEventResource) Validate() error {
	if e.Schema != ContractSchemaV1 || e.Kind != KindEvent || !validOpaqueID(e.ID) || !validOpaqueID(e.Cursor) || !canonicalEventTypePattern.MatchString(e.EventType) || !validEventResourceKind(e.ResourceKind) || !validOpaqueID(e.ResourceID) || e.OccurredAt.IsZero() || !validActorType(e.Actor.Type) || !validOpaqueID(e.Actor.ID) || !validCorrelationID(e.CorrelationID) {
		return newError(ErrorInvalidEvent, "validate canonical event")
	}
	_, err := safeMetadata(e.SafeMetadata)
	return err
}

func (e CanonicalEventResource) JSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// EventResource is an alias-friendly name for consumers that do not want the
// longer canonical type name.
type EventResource = CanonicalEventResource

func NewEventResource(input CanonicalEventInput) (EventResource, error) {
	return NewCanonicalEvent(input)
}

type LogEntry struct {
	Schema        string         `json:"schema"`
	Kind          string         `json:"kind"`
	ID            string         `json:"id"`
	TunnelID      string         `json:"tunnel_id,omitempty"`
	PreviewID     string         `json:"preview_id,omitempty"`
	RouteID       string         `json:"route_id,omitempty"`
	ConnectorID   string         `json:"connector_id,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	RequestID     string         `json:"request_id,omitempty"`
	OperationID   string         `json:"operation_id,omitempty"`
	ResourceKind  string         `json:"resource_kind,omitempty"`
	ResourceID    string         `json:"resource_id,omitempty"`
	Level         EventSeverity  `json:"level"`
	Component     string         `json:"component"`
	Code          string         `json:"code"`
	Message       string         `json:"message"`
	Metadata      map[string]any `json:"metadata"`
	CorrelationID string         `json:"correlation_id"`
	OccurredAt    time.Time      `json:"occurred_at"`
	Cursor        string         `json:"cursor"`
}

type LogEntryInput struct {
	ID, TunnelID, PreviewID, RouteID, ConnectorID, SessionID string
	RequestID, OperationID, ResourceKind, ResourceID         string
	Level                                                    EventSeverity
	Component, Code, Message, CorrelationID, Cursor          string
	Metadata                                                 map[string]any
	OccurredAt                                               time.Time
}

func NewLogEntry(input LogEntryInput) (LogEntry, error) {
	if !validOpaqueID(input.ID) || !validEventSeverity(input.Level) || !componentPattern.MatchString(input.Component) || !canonicalEventTypePattern.MatchString(input.Code) || !validCorrelationID(input.CorrelationID) || !validOpaqueID(input.Cursor) || normalizeTime(input.OccurredAt).IsZero() || !validOptionalLogIdentity(input.RequestID, "request_", "req_") || !validOptionalLogIdentity(input.OperationID, "operation_", "op_") || (input.ResourceKind != "" && !validEventResourceKind(input.ResourceKind)) || (input.ResourceID != "" && !validOpaqueID(input.ResourceID)) {
		return LogEntry{}, newError(ErrorInvalidEvent, "construct log entry")
	}
	message, err := safeBoundedString(input.Message, 1000, true)
	if err != nil {
		return LogEntry{}, err
	}
	metadata, err := safeMetadata(input.Metadata)
	if err != nil {
		return LogEntry{}, err
	}
	entry := LogEntry{Schema: ContractSchemaV1, Kind: KindLog, ID: input.ID, TunnelID: input.TunnelID, PreviewID: input.PreviewID, RouteID: input.RouteID, ConnectorID: input.ConnectorID, SessionID: input.SessionID, RequestID: input.RequestID, OperationID: input.OperationID, ResourceKind: input.ResourceKind, ResourceID: input.ResourceID, Level: input.Level, Component: input.Component, Code: input.Code, Message: message, Metadata: metadata, CorrelationID: input.CorrelationID, OccurredAt: normalizeTime(input.OccurredAt), Cursor: input.Cursor}
	return entry, entry.Validate()
}

func (e LogEntry) Validate() error {
	if e.Schema != ContractSchemaV1 || e.Kind != KindLog || !validOpaqueID(e.ID) || !validEventSeverity(e.Level) || !componentPattern.MatchString(e.Component) || !canonicalEventTypePattern.MatchString(e.Code) || e.Message == "" || !validCorrelationID(e.CorrelationID) || e.OccurredAt.IsZero() || !validOpaqueID(e.Cursor) || !validOptionalLogIdentity(e.RequestID, "request_", "req_") || !validOptionalLogIdentity(e.OperationID, "operation_", "op_") || (e.ResourceKind != "" && !validEventResourceKind(e.ResourceKind)) || (e.ResourceID != "" && !validOpaqueID(e.ResourceID)) {
		return newError(ErrorInvalidEvent, "validate log entry")
	}
	for _, id := range []string{e.TunnelID, e.PreviewID, e.RouteID, e.ConnectorID, e.SessionID} {
		if id != "" && !validOpaqueID(id) {
			return newError(ErrorInvalidID, "validate log entry")
		}
	}
	_, err := safeMetadata(e.Metadata)
	return err
}

func (e LogEntry) JSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

type ErrorResource struct {
	Schema        string     `json:"schema"`
	Kind          string     `json:"kind"`
	Code          string     `json:"code"`
	Component     Dimension  `json:"component"`
	Message       string     `json:"message"`
	Outcome       string     `json:"outcome"`
	Retryable     bool       `json:"retryable"`
	RetryAt       *time.Time `json:"retry_at"`
	RepairAction  string     `json:"repair_action"`
	RequestID     string     `json:"request_id"`
	CorrelationID string     `json:"correlation_id"`
}

type ErrorResourceInput struct {
	Code          string
	Component     Dimension
	Message       string
	Outcome       string
	Retryable     bool
	RetryAt       time.Time
	RepairAction  string
	RequestID     string
	CorrelationID string
}

func NewErrorResource(input ErrorResourceInput) (ErrorResource, error) {
	message, err := safeBoundedString(input.Message, 1000, true)
	if err != nil {
		return ErrorResource{}, err
	}
	repair, err := safeBoundedString(input.RepairAction, 1000, true)
	if err != nil {
		return ErrorResource{}, err
	}
	if !stableCodePattern.MatchString(input.Code) || !validErrorComponent(input.Component) || (input.Outcome != "unchanged" && input.Outcome != "changed" && input.Outcome != "uncertain") || !validOptionalLogIdentity(input.RequestID, "request_", "req_") || !validOptionalLogIdentity(input.CorrelationID, "cor_", "corr_", "correlation_", "request_", "pb-") || input.RequestID == "" || input.CorrelationID == "" {
		return ErrorResource{}, newError(ErrorInvalidEvent, "construct error resource")
	}
	if input.Retryable != !input.RetryAt.IsZero() {
		return ErrorResource{}, newError(ErrorInvalidRetry, "construct error resource")
	}
	result := ErrorResource{Schema: ContractSchemaV1, Kind: KindError, Code: input.Code, Component: input.Component, Message: message, Outcome: input.Outcome, Retryable: input.Retryable, RepairAction: repair, RequestID: input.RequestID, CorrelationID: input.CorrelationID}
	if !input.RetryAt.IsZero() {
		retryAt := normalizeTime(input.RetryAt)
		result.RetryAt = &retryAt
	}
	return result, result.Validate()
}

func (e ErrorResource) Validate() error {
	if e.Schema != ContractSchemaV1 || e.Kind != KindError || !stableCodePattern.MatchString(e.Code) || !validErrorComponent(e.Component) || (e.Outcome != "unchanged" && e.Outcome != "changed" && e.Outcome != "uncertain") || e.Message == "" || e.RepairAction == "" || !validOptionalLogIdentity(e.RequestID, "request_", "req_") || !validOptionalLogIdentity(e.CorrelationID, "cor_", "corr_", "correlation_", "request_", "pb-") || e.RequestID == "" || e.CorrelationID == "" || e.Retryable != (e.RetryAt != nil) {
		return newError(ErrorInvalidEvent, "validate error resource")
	}
	return nil
}

func (e ErrorResource) JSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

func validHealthResourceKind(value string) bool {
	_, ok := healthResourceKindSet[value]
	return ok
}

func validEventResourceKind(value string) bool {
	return validHealthResourceKind(value) || value == "config_generation" || value == "operation"
}

func validErrorComponent(value Dimension) bool {
	return validDimension(value) || value == DimensionControl
}

func validActorType(value string) bool {
	_, ok := actorTypeSet[value]
	return ok
}

// validOpaqueID is deliberately stricter than the shared JSON schema's broad
// ID syntax. The schema must accept IDs emitted by other implementations, but
// server constructors must not turn a hostname, URL, credential, or control
// string into durable telemetry identity.
func validOpaqueID(value string) bool {
	if !resourceIDPattern.MatchString(value) || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t/\\?#@%") {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"authorization", "password", "passwd", "secret", "token", "credential", "cookie", "private_key", "private-key"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	// Dotted values without a Paperboat ID namespace are almost certainly a
	// hostname. Namespaced opaque IDs may contain a dot because the external
	// contract permits it, although producers should normally avoid one.
	if strings.Contains(value, ".") && !hasKnownOpaqueNamespace(value) {
		return false
	}
	return true
}

func hasKnownOpaqueNamespace(value string) bool {
	for _, prefix := range []string{
		"account_", "actor_", "assignment_", "certificate_", "connector_", "cor_", "corr_", "correlation_", "cur_", "device_", "domain_", "edge_", "err_", "event_", "evt_", "gen_", "host_", "log_", "machine_", "op_", "operation_", "preview_", "prv_", "req_", "request_", "resource_", "route_", "session_", "tunnel_", "tun_",
	} {
		if strings.HasPrefix(strings.ToLower(value), prefix) {
			return true
		}
	}
	return false
}

func validOptionalLogIdentity(value string, prefixes ...string) bool {
	if value == "" {
		return true
	}
	if !validOpaqueID(value) {
		return false
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(strings.ToLower(value), prefix) {
			return true
		}
	}
	return false
}

func safeMetadata(input map[string]any) (map[string]any, error) {
	if len(input) > maximumMetadataItems {
		return nil, newError(ErrorInvalidString, "construct safe metadata")
	}
	result, err := sanitizeMetadataMap(input, 0)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func sanitizeMetadataMap(input map[string]any, depth int) (map[string]any, error) {
	if depth > maximumMetadataDepth || len(input) > maximumMetadataItems {
		return nil, newError(ErrorInvalidString, "construct safe metadata")
	}
	result := make(map[string]any, len(input))
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "" || len(key) > 128 || !utf8.ValidString(key) || strings.TrimSpace(key) != key || strings.ContainsAny(key, "\x00\r\n\t") || metadataKeyPattern.MatchString(key) {
			return nil, newError(ErrorInvalidString, "construct safe metadata")
		}
		value, err := sanitizeMetadataValue(input[key], depth+1, key)
		if err != nil {
			return nil, err
		}
		result[key] = value
	}
	return result, nil
}

func sanitizeMetadataValue(value any, depth int, key string) (any, error) {
	if depth > maximumMetadataDepth {
		return nil, newError(ErrorInvalidString, "construct safe metadata")
	}
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		return safeMetadataString(typed, key)
	case json.Number:
		return safeJSONNumber(typed)
	case bool:
		return typed, nil
	case int:
		return typed, nil
	case int8:
		return typed, nil
	case int16:
		return typed, nil
	case int32:
		return typed, nil
	case int64:
		return typed, nil
	case uint:
		return typed, nil
	case uint8:
		return typed, nil
	case uint16:
		return typed, nil
	case uint32:
		return typed, nil
	case uint64:
		return typed, nil
	case float32:
		if math.IsNaN(float64(typed)) || math.IsInf(float64(typed), 0) {
			return nil, newError(ErrorInvalidString, "construct safe metadata")
		}
		return typed, nil
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, newError(ErrorInvalidString, "construct safe metadata")
		}
		return typed, nil
	case []any:
		if len(typed) > maximumMetadataItems {
			return nil, newError(ErrorInvalidString, "construct safe metadata")
		}
		result := make([]any, len(typed))
		for index, item := range typed {
			clean, err := sanitizeMetadataValue(item, depth+1, "")
			if err != nil {
				return nil, err
			}
			result[index] = clean
		}
		return result, nil
	case map[string]any:
		return sanitizeMetadataMap(typed, depth)
	case []string:
		if len(typed) > maximumMetadataItems {
			return nil, newError(ErrorInvalidString, "construct safe metadata")
		}
		result := make([]any, len(typed))
		for index, item := range typed {
			clean, err := sanitizeMetadataValue(item, depth+1, "")
			if err != nil {
				return nil, err
			}
			result[index] = clean
		}
		return result, nil
	case map[string]string:
		converted := make(map[string]any, len(typed))
		for itemKey, item := range typed {
			converted[itemKey] = item
		}
		return sanitizeMetadataMap(converted, depth)
	default:
		return nil, newError(ErrorUnsupportedValue, "construct safe metadata")
	}
}

func addSafeMetadata(metadata map[string]any, name, value string) {
	if value != "" {
		metadata[name] = value
	}
}

func addGenerationMetadata(metadata map[string]any, name string, value uint64) {
	if value != 0 {
		metadata[name] = value
	}
}
