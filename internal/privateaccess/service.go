package privateaccess

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// AuthorizeInput is the fully verified identity plus the exact route request.
// Proof bytes are verified before this type is constructed and are not kept
// here.  The optional Grant is a short-lived signed grant carried by an edge
// request; when a GrantVerifier is configured it is mandatory.
type AuthorizeInput struct {
	Identity Identity
	Request  Request
	Edge     EdgeIdentity
	Grant    string
}

type cachedDecision struct {
	fingerprint string
	decision    Decision
	expiresAt   time.Time
}

// Config controls only bounded, process-local replay state.  The resource
// resolver remains authoritative on every call so revocation and route changes
// take effect promptly even when a caller retries the same idempotency key.
type Config struct {
	Now           func() time.Time
	DecisionTTL   time.Duration
	MaximumCached int
	GrantVerifier GrantVerifier
	GrantMinter   GrantMinter
	MachineState  MachineStateVerifier
}

// Service is the policy boundary shared by private preview HTTP and private
// tunnel TCP/HTTP.  It never issues or stores a bearer credential.
type Service struct {
	resolver ResourceResolver
	audit    AuditSink
	clock    func() time.Time
	ttl      time.Duration
	maxCache int
	grant    GrantVerifier
	minter   GrantMinter
	machine  MachineStateVerifier

	mu    sync.Mutex
	cache map[string]cachedDecision
}

func NewService(resolver ResourceResolver, audit AuditSink, cfg Config) (*Service, error) {
	if resolver == nil {
		return nil, fmt.Errorf("%w: resource resolver is required", ErrInvalid)
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	ttl := cfg.DecisionTTL
	if ttl == 0 {
		ttl = DefaultDecisionTTL
	}
	if ttl <= 0 || ttl > MaximumDecisionTTL {
		return nil, fmt.Errorf("%w: decision TTL must be positive and at most %s", ErrInvalid, MaximumDecisionTTL)
	}
	maxCache := cfg.MaximumCached
	if maxCache == 0 {
		maxCache = 1024
	}
	if maxCache < 1 || maxCache > 16384 {
		return nil, fmt.Errorf("%w: decision cache bound is invalid", ErrInvalid)
	}
	return &Service{resolver: resolver, audit: audit, clock: now, ttl: ttl, maxCache: maxCache, grant: cfg.GrantVerifier, minter: cfg.GrantMinter, machine: cfg.MachineState, cache: make(map[string]cachedDecision)}, nil
}

// IssueGrant validates the current identity and route before signing one
// short-lived, audience-bound request grant. The caller must supply identity
// fields already derived by IdentityVerifier; this method never accepts an
// account, device, or session override. The signed value is returned once and
// is not persisted by this package.
func (s *Service) IssueGrant(ctx context.Context, identity Identity, edge EdgeIdentity, request Request) (string, error) {
	if s == nil || s.resolver == nil || s.minter == nil || ctx == nil {
		return "", fmt.Errorf("%w: grant issuer is unavailable", ErrIdentityUnavailable)
	}
	now := s.clock().UTC()
	deny := func(reason DenyReason, binding *Binding) (string, error) {
		record := AuditRecord{
			Allowed: false, Reason: reason, AccountID: identity.AccountID, UserID: identity.UserID,
			DeviceID: identity.DeviceID, SessionID: identity.SessionID, ResourceKind: request.ResourceKind,
			RequestID: request.RequestID, CorrelationID: request.CorrelationID, IdempotencyKey: request.IdempotencyKey,
		}
		if binding != nil && binding.ResourceID != "" {
			record.ResourceKind, record.ResourceID, record.RouteID = binding.ResourceKind, binding.ResourceID, binding.RouteID
			record.OperationID, record.ConnectorID, record.CarrierSessionID = binding.OperationID, binding.ConnectorID, binding.CarrierSessionID
			record.Protocol = binding.Protocol
		}
		if auditErr := s.record(ctx, record); auditErr != nil {
			return "", auditErr
		}
		return "", newDenied(reason)
	}
	if err := identity.Validate(now); err != nil {
		if denied, ok := err.(*DeniedError); ok {
			return deny(denied.Reason, nil)
		}
		return deny(ReasonUnauthenticated, nil)
	}
	if err := edge.Validate(); err != nil {
		return deny(ReasonIdentityInvalid, nil)
	}
	if err := request.Validate(); err != nil {
		return "", err
	}
	if request.AccountID != identity.AccountID || request.DeviceID != identity.DeviceID || request.SessionID != identity.SessionID {
		return deny(ReasonIdentityInvalid, nil)
	}
	if request.InstallationGeneration != identity.InstallationGeneration || request.EdgeNodeID != edge.NodeID || request.EdgeProcessEpoch != edge.ProcessEpoch {
		return deny(ReasonIdentityInvalid, nil)
	}
	if !request.ExpiresAt.After(now) || request.ExpiresAt.Sub(now) > MaximumDecisionTTL {
		return deny(ReasonExpired, nil)
	}
	binding, err := s.resolver.ResolvePrivate(ctx, Lookup{AccountID: identity.AccountID, Request: request, Edge: edge, Now: now})
	if err != nil {
		return deny(resolverReason(err), nil)
	}
	if err := binding.Validate(now); err != nil {
		if denied, ok := err.(*DeniedError); ok {
			return deny(denied.Reason, &binding)
		}
		return deny(ReasonInternal, &binding)
	}
	if err := exactBinding(request, binding); err != nil {
		return deny(err.(*DeniedError).Reason, &binding)
	}
	if binding.EdgeNodeID == "" || binding.EdgeProcessEpoch == "" || binding.EdgeNodeID != edge.NodeID || binding.EdgeProcessEpoch != edge.ProcessEpoch {
		return deny(ReasonWrongRoute, &binding)
	}
	if err := routeRequestAllowed(request, binding); err != nil {
		return deny(err.(*DeniedError).Reason, &binding)
	}
	grant, err := s.minter.MintGrant(ctx, request, now)
	if err != nil {
		return "", err
	}
	if err := s.record(ctx, AuditRecord{
		EventType: "private_access.grant_issued", Allowed: true, Reason: DenyReason(DecisionAllowed), AccountID: identity.AccountID,
		UserID: identity.UserID, DeviceID: identity.DeviceID, SessionID: identity.SessionID,
		ResourceKind: binding.ResourceKind, ResourceID: binding.ResourceID, RouteID: binding.RouteID,
		OperationID: binding.OperationID, ConnectorID: binding.ConnectorID, CarrierSessionID: binding.CarrierSessionID,
		Protocol: binding.Protocol, RequestID: request.RequestID, CorrelationID: request.CorrelationID,
		IdempotencyKey: request.IdempotencyKey,
	}); err != nil {
		return "", err
	}
	return grant, nil
}

// Authorize verifies the signed grant (when configured), the current
// server-side resource binding, and the identity's current lifetime/revocation
// status.  A denied decision is returned with a typed *DeniedError.  Its JSON
// projection intentionally contains no resource details.
func (s *Service) Authorize(ctx context.Context, input AuthorizeInput) (Decision, error) {
	if s == nil || s.resolver == nil || ctx == nil {
		return Decision{}, fmt.Errorf("%w: authorization service is unavailable", ErrInvalid)
	}
	now := s.clock().UTC()
	if err := input.Edge.Validate(); err != nil {
		return s.deny(ctx, input, ReasonIdentityInvalid, now, "edge_identity")
	}
	if s.grant == nil || strings.TrimSpace(input.Grant) == "" {
		return s.deny(ctx, input, ReasonUnauthenticated, now, "grant")
	}
	signed, err := s.grant.VerifyGrant(ctx, input.Grant, now)
	if err != nil {
		return s.deny(ctx, input, ReasonUnauthenticated, now, "grant")
	}
	submittedHash, submittedErr := input.Request.Hash()
	signedHash, signedErr := signed.Hash()
	if submittedErr != nil || signedErr != nil || submittedHash != signedHash {
		return s.deny(ctx, input, ReasonIdentityInvalid, now, "grant_request_binding")
	}
	input.Request = signed
	input.Identity = Identity{AccountID: signed.AccountID, UserID: signed.AccountID, DeviceID: signed.DeviceID, SessionID: signed.SessionID, InstallationGeneration: signed.InstallationGeneration, ExpiresAt: signed.ExpiresAt, Method: "machine"}
	if err := input.Request.Validate(); err != nil {
		return Decision{}, err
	}
	if input.Request.EdgeNodeID != input.Edge.NodeID || input.Request.EdgeProcessEpoch != input.Edge.ProcessEpoch {
		return s.deny(ctx, input, ReasonWrongRoute, now, "edge_binding")
	}
	if s.machine == nil {
		return Decision{}, ErrIdentityUnavailable
	}
	if err := s.machine.VerifyCurrentMachine(ctx, input.Identity, now); err != nil {
		var denied *DeniedError
		if errors.As(err, &denied) {
			return s.deny(ctx, input, denied.Reason, now, "machine")
		}
		return Decision{}, ErrIdentityUnavailable
	}
	if err := input.Identity.Validate(now); err != nil {
		if denied, ok := err.(*DeniedError); ok {
			return s.deny(ctx, input, denied.Reason, now, "identity")
		}
		// Missing or malformed authentication is intentionally indistinguishable
		// from a signed-out caller at the HTTP boundary.
		return s.deny(ctx, input, ReasonUnauthenticated, now, "identity")
	}
	if input.Request.AccountID != input.Identity.AccountID {
		return s.deny(ctx, input, ReasonAccountMismatch, now, "account")
	}
	if input.Request.DeviceID != input.Identity.DeviceID || input.Request.SessionID != input.Identity.SessionID {
		return s.deny(ctx, input, ReasonIdentityInvalid, now, "identity")
	}
	if !input.Request.ExpiresAt.After(now) {
		return s.deny(ctx, input, ReasonSessionExpired, now, "grant")
	}
	if input.Request.ExpiresAt.Sub(now) > MaximumDecisionTTL {
		return s.deny(ctx, input, ReasonIdentityInvalid, now, "grant")
	}
	fingerprint, err := requestFingerprint(input)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: fingerprint request", ErrInvalid)
	}
	cacheKey := input.Identity.AccountID + "\x00" + input.Identity.SessionID + "\x00" + input.Request.IdempotencyKey
	if s.cachedConflict(cacheKey, fingerprint, now) {
		return Decision{}, ErrIdempotencyConflict
	}
	binding, err := s.resolver.ResolvePrivate(ctx, Lookup{AccountID: input.Identity.AccountID, Request: input.Request, Edge: input.Edge, Now: now})
	if err != nil {
		return s.deny(ctx, input, resolverReason(err), now, "resource")
	}
	if err := binding.Validate(now); err != nil {
		if denied, ok := err.(*DeniedError); ok {
			return s.denyWithBinding(ctx, input, binding, denied.Reason, now, "binding")
		}
		return s.denyWithBinding(ctx, input, binding, ReasonInternal, now, "binding")
	}
	if err := exactBinding(input.Request, binding); err != nil {
		return s.denyWithBinding(ctx, input, binding, err.(*DeniedError).Reason, now, "binding")
	}
	if binding.EdgeNodeID == "" || binding.EdgeProcessEpoch == "" || binding.EdgeNodeID != input.Edge.NodeID || binding.EdgeProcessEpoch != input.Edge.ProcessEpoch {
		return s.denyWithBinding(ctx, input, binding, ReasonWrongRoute, now, "edge_binding")
	}
	if err := routeRequestAllowed(input.Request, binding); err != nil {
		return s.denyWithBinding(ctx, input, binding, err.(*DeniedError).Reason, now, "route")
	}

	if cached, ok := s.replay(cacheKey, fingerprint, now); ok {
		return cached, nil
	}
	expiresAt := minTime(input.Request.ExpiresAt, binding.ExpiresAt, now.Add(s.ttl))
	decision := Decision{
		Schema: Schema, Kind: Kind, DecisionID: decisionID(fingerprint), Allowed: true,
		Reason: DenyReason(DecisionAllowed), ExpiresAt: expiresAt,
		RequestID: input.Request.RequestID, CorrelationID: input.Request.CorrelationID,
		ResourceKind: binding.ResourceKind, ResourceID: binding.ResourceID, RouteID: binding.RouteID,
		OperationID: binding.OperationID, ConnectorID: binding.ConnectorID,
		CarrierSessionID: binding.CarrierSessionID, RouteGeneration: binding.RouteGeneration,
		SessionGeneration: binding.SessionGeneration, ProcessGeneration: binding.ProcessGeneration, ConfigGeneration: binding.ConfigGeneration,
		AssignmentGeneration: binding.AssignmentGeneration,
		Protocol:             binding.Protocol,
	}
	if err := decision.Validate(now); err != nil {
		return Decision{}, err
	}
	if err := s.record(ctx, AuditRecord{Allowed: true, Reason: DenyReason(DecisionAllowed), AccountID: input.Identity.AccountID, UserID: input.Identity.UserID, DeviceID: input.Identity.DeviceID, SessionID: input.Identity.SessionID, ResourceKind: binding.ResourceKind, ResourceID: binding.ResourceID, RouteID: binding.RouteID, OperationID: binding.OperationID, ConnectorID: binding.ConnectorID, CarrierSessionID: binding.CarrierSessionID, Protocol: binding.Protocol, RequestID: input.Request.RequestID, CorrelationID: input.Request.CorrelationID, IdempotencyKey: input.Request.IdempotencyKey}); err != nil {
		return Decision{}, err
	}
	if err := s.store(cacheKey, cachedDecision{fingerprint: fingerprint, decision: decision, expiresAt: expiresAt}); err != nil {
		return Decision{}, err
	}
	return decision, nil
}

func (s *Service) deny(ctx context.Context, input AuthorizeInput, reason DenyReason, now time.Time, _ string) (Decision, error) {
	return s.denyWithBinding(ctx, input, Binding{}, reason, now, "")
}

func (s *Service) denyWithBinding(ctx context.Context, input AuthorizeInput, binding Binding, reason DenyReason, now time.Time, _ string) (Decision, error) {
	// Do not expose binding identifiers on a denial.  Account mismatch and
	// missing resources therefore have the same safe response shape.
	fingerprint, _ := requestFingerprint(input)
	if len(fingerprint) < 32 {
		fingerprint = "00000000000000000000000000000000"
	}
	expiresAt := now.Add(s.ttl)
	if input.Request.ExpiresAt.After(now) && input.Request.ExpiresAt.Before(expiresAt) {
		expiresAt = input.Request.ExpiresAt
	}
	decision := Decision{Schema: Schema, Kind: Kind, DecisionID: decisionID(fingerprint), Allowed: false, Reason: reason, ExpiresAt: expiresAt, RequestID: input.Request.RequestID, CorrelationID: input.Request.CorrelationID}
	if err := decision.Validate(now); err != nil {
		// A malformed request is reported before this method. This fallback keeps
		// malformed identity errors from turning into a credential-bearing error.
		return Decision{}, err
	}
	record := AuditRecord{Allowed: false, Reason: reason, AccountID: input.Identity.AccountID, UserID: input.Identity.UserID, DeviceID: input.Identity.DeviceID, SessionID: input.Identity.SessionID, ResourceKind: input.Request.ResourceKind, RequestID: input.Request.RequestID, CorrelationID: input.Request.CorrelationID, IdempotencyKey: input.Request.IdempotencyKey}
	if binding.ResourceID != "" {
		record.ResourceKind, record.ResourceID, record.RouteID, record.OperationID = binding.ResourceKind, binding.ResourceID, binding.RouteID, binding.OperationID
	}
	if err := s.record(ctx, record); err != nil {
		return Decision{}, err
	}
	return decision, newDenied(reason)
}

func (s *Service) record(ctx context.Context, record AuditRecord) error {
	if s.audit == nil {
		return nil
	}
	if err := s.audit.Record(ctx, record); err != nil {
		return fmt.Errorf("%w: record authorization event", ErrAuditUnavailable)
	}
	return nil
}

// recordEdgeIdentityDenial records an edge authentication failure without
// copying any request bytes or unverified route identifiers into the audit
// stream. It is deliberately separate from recordIdentityDenial because edge
// verification happens before the request is decoded and before a user
// identity is trusted.
func (s *Service) recordEdgeIdentityDenial(ctx context.Context) error {
	return s.record(ctx, AuditRecord{
		EventType: "private_access.edge_identity_denied",
		Allowed:   false,
		Reason:    ReasonIdentityInvalid,
	})
}

func (s *Service) replay(key, fingerprint string, now time.Time) (Decision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for cacheKey, value := range s.cache {
		if !value.expiresAt.After(now) {
			delete(s.cache, cacheKey)
		}
	}
	value, ok := s.cache[key]
	if !ok || value.fingerprint != fingerprint || !value.expiresAt.After(now) {
		return Decision{}, false
	}
	return value.decision, true
}

func (s *Service) cachedConflict(key, fingerprint string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.cache[key]
	if !ok || !value.expiresAt.After(now) {
		if ok {
			delete(s.cache, key)
		}
		return false
	}
	return value.fingerprint != fingerprint
}

func (s *Service) store(key string, value cachedDecision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.cache[key]; ok && existing.expiresAt.After(s.clock()) && existing.fingerprint != value.fingerprint {
		return ErrIdempotencyConflict
	}
	if len(s.cache) >= s.maxCache {
		for oldKey := range s.cache {
			delete(s.cache, oldKey)
			break
		}
	}
	s.cache[key] = value
	return nil
}

func resolverReason(err error) DenyReason {
	var denied *DeniedError
	if errors.As(err, &denied) && denied.Reason.valid() {
		return denied.Reason
	}
	switch {
	case errors.Is(err, ErrResourceNotFound):
		return ReasonResourceNotFound
	case errors.Is(err, ErrRouteUnavailable):
		return ReasonRoutePaused
	case errors.Is(err, ErrIdentityUnavailable):
		return ReasonIdentityInvalid
	default:
		return ReasonInternal
	}
}

func exactBinding(request Request, binding Binding) error {
	if binding.AccountID != request.AccountID {
		return newDenied(ReasonAccountMismatch)
	}
	if binding.ResourceKind != request.ResourceKind || binding.ResourceID != request.ResourceID || binding.RouteID != request.RouteID || binding.OperationID != request.OperationID || binding.ConnectorID != request.ConnectorID || binding.CarrierSessionID != request.CarrierSessionID || binding.RouteGeneration != request.RouteGeneration || binding.SessionGeneration != request.SessionGeneration || binding.ProcessGeneration != request.ProcessGeneration || binding.ConfigGeneration != request.ConfigGeneration || binding.AssignmentGeneration != request.AssignmentGeneration {
		return newDenied(ReasonWrongRoute)
	}
	if binding.Protocol != request.Protocol {
		return newDenied(ReasonProtocolDenied)
	}
	return nil
}

func routeRequestAllowed(request Request, binding Binding) error {
	switch binding.State {
	case "active", "ready", "edge_ready":
	default:
		return newDenied(ReasonRoutePaused)
	}
	if binding.Protocol == ProtocolHTTP {
		if canonicalHost(request.Host) != canonicalHost(binding.Hostname) {
			return newDenied(ReasonWrongRoute)
		}
		if binding.PathPrefix != "" && !pathPrefixMatches(request.Path, binding.PathPrefix) {
			return newDenied(ReasonWrongRoute)
		}
	}
	return nil
}

func pathPrefixMatches(path, prefix string) bool {
	if prefix == "/" {
		return strings.HasPrefix(path, "/")
	}
	prefix = strings.TrimSuffix(prefix, "/")
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func minTime(values ...time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result.UTC()
}
