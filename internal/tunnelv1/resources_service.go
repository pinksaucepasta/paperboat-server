package tunnelv1

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelcert"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type ResourceService struct {
	repository               ResourceRepository
	cursors                  *resourceCursorCodec
	now                      func() time.Time
	newID                    func(string) (string, error)
	enrollmentTTL            time.Duration
	rotationOverlap          time.Duration
	credentialLifetime       time.Duration
	allowInsecureDevelopment bool
	challengeZone            string
}

type connectorCredentialProofBinding struct {
	Purpose               string `json:"purpose"`
	TunnelID              string `json:"tunnel_id"`
	HostID                string `json:"host_id"`
	EnrollmentTokenSHA256 string `json:"enrollment_token_sha256"`
	CredentialReference   string `json:"credential_reference"`
	CredentialThumbprint  string `json:"credential_thumbprint"`
	IdempotencyKey        string `json:"idempotency_key"`
}

const maxResourceLogMessageBytes = 1000

// ConnectorCredentialProofPayload is the exact host-signed binding used when
// an enrollment installs a connector credential. Only the SHA-256 digest of
// the one-time enrollment token is included in the transcript, so a proof,
// transcript, or diagnostic can never disclose the reusable token itself.
func ConnectorCredentialProofPayload(tunnelID, hostID, enrollmentToken, credentialReference, credentialThumbprint, idempotencyKey string) []byte {
	tokenHash := sha256.Sum256([]byte(enrollmentToken))
	return ConnectorCredentialProofPayloadForTokenHash(tunnelID, hostID, hex.EncodeToString(tokenHash[:]), credentialReference, credentialThumbprint, idempotencyKey)
}

// ConnectorCredentialProofPayloadForTokenHash is the low-level transcript
// constructor for callers that already have the enrollment token digest.
// Hashes are lowercase hexadecimal SHA-256 values to match the durable token
// hash representation used by the enrollment table.
func ConnectorCredentialProofPayloadForTokenHash(tunnelID, hostID, enrollmentTokenSHA256, credentialReference, credentialThumbprint, idempotencyKey string) []byte {
	payload, _ := json.Marshal(connectorCredentialProofBinding{
		Purpose: "paperboat.connector.enrollment.v1", TunnelID: tunnelID, HostID: hostID,
		EnrollmentTokenSHA256: enrollmentTokenSHA256, CredentialReference: credentialReference,
		CredentialThumbprint: credentialThumbprint, IdempotencyKey: idempotencyKey,
	})
	return payload
}

// ConnectorCredentialThumbprint returns the stable public-key thumbprint
// stored with a credential generation. Private key bytes never cross this
// boundary.
func ConnectorCredentialThumbprint(publicKey []byte) string {
	thumbprint, err := connectorprotocol.IdentityThumbprint(ed25519.PublicKey(publicKey))
	if err != nil {
		return ""
	}
	return thumbprint
}

func validateConnectorCredentialVerifier(algorithm string, publicKey, proof []byte, thumbprint string) bool {
	return algorithm == "ed25519" && len(publicKey) == ed25519.PublicKeySize && len(proof) == ed25519.SignatureSize &&
		connectorprotocol.ValidateIdentityKey("ed25519:"+thumbprint, thumbprint) == nil && thumbprint == ConnectorCredentialThumbprint(publicKey)
}

// VerifyConnectorCredentialProof verifies proof-of-possession for a new
// connector key in addition to the enclosing signed machine request.
func VerifyConnectorCredentialProof(algorithm string, publicKey, proof []byte, tunnelID, hostID, enrollmentToken, credentialReference, credentialThumbprint, idempotencyKey string) bool {
	if !validateConnectorCredentialVerifier(algorithm, publicKey, proof, credentialThumbprint) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), ConnectorCredentialProofPayload(tunnelID, hostID, enrollmentToken, credentialReference, credentialThumbprint, idempotencyKey), proof)
}

func NewResourceService(repository ResourceRepository, config ResourceConfig) (*ResourceService, error) {
	if repository == nil {
		return nil, fmt.Errorf("resource repository is required")
	}
	cursors, err := newResourceCursorCodec(config.CursorKey)
	if err != nil {
		return nil, err
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	newID := config.NewID
	if newID == nil {
		newID = randomID
	}
	ttl := config.EnrollmentTTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	if ttl < time.Minute || ttl > 15*time.Minute {
		return nil, fmt.Errorf("enrollment TTL must be between one and fifteen minutes")
	}
	overlap := config.RotationOverlap
	if overlap == 0 {
		overlap = 10 * time.Minute
	}
	if overlap < time.Minute || overlap > 24*time.Hour {
		return nil, fmt.Errorf("rotation overlap must be between one minute and one day")
	}
	lifetime := config.CredentialLifetime
	if lifetime == 0 {
		lifetime = 365 * 24 * time.Hour
	}
	if lifetime < time.Hour || lifetime > connectorprotocol.MaxRotationCredentialLifetime || overlap >= lifetime {
		return nil, fmt.Errorf("credential lifetime is out of bounds")
	}
	challengeZone := strings.TrimSpace(config.ChallengeZone)
	if challengeZone != "" {
		if _, wildcard, zoneErr := tunnelcert.NormalizeChallengeZone(challengeZone); zoneErr != nil || wildcard {
			return nil, fmt.Errorf("challenge zone is invalid")
		}
	}
	return &ResourceService{repository: repository, cursors: cursors, now: now, newID: newID, enrollmentTTL: ttl, rotationOverlap: overlap, credentialLifetime: lifetime, allowInsecureDevelopment: config.AllowInsecureDevelopment, challengeZone: challengeZone}, nil
}

func (s *ResourceService) authorize(request previewtunnelapi.RequestContext, action string, requireHost bool) error {
	return previewtunnelapi.Authorize(request.Actor, previewtunnelapi.AccessRequest{AccountID: request.Actor.AccountID, Resource: "tunnels", Action: action, RequireHost: requireHost})
}

func (s *ResourceService) ListRoutes(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, rawCursor string, limit int) (RoutePage, error) {
	if err := s.authorize(request, "read", false); err != nil {
		return RoutePage{}, err
	}
	if err := validateResourceListLimit(limit); err != nil {
		return RoutePage{}, err
	}
	position, err := s.decodeListCursor(rawCursor, request.Actor.AccountID, tunnelID, "route")
	if err != nil {
		return RoutePage{}, err
	}
	rows, err := s.repository.ListResourceRoutes(ctx, request.Actor.AccountID, tunnelID, position, limit+1)
	if err != nil {
		return RoutePage{}, err
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	page := RoutePage{Items: make([]RouteView, 0, len(rows))}
	for _, row := range rows {
		page.Items = append(page.Items, routeView(row))
	}
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		page.NextCursor, err = s.cursors.EncodeList("route", request.Actor.AccountID, tunnelID, ListPosition{CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			return RoutePage{}, err
		}
	}
	return page, nil
}

func (s *ResourceService) GetRoute(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, routeID string) (RouteView, error) {
	if err := s.authorize(request, "read", false); err != nil {
		return RouteView{}, err
	}
	row, err := s.repository.GetResourceRoute(ctx, request.Actor.AccountID, tunnelID, routeID)
	if err != nil {
		return RouteView{}, err
	}
	return routeView(row), nil
}

func (s *ResourceService) CreateRoute(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID string, input RouteCreateRequest) (RouteMutationResult, error) {
	if err := s.authorize(request, "write", false); err != nil {
		return RouteMutationResult{}, err
	}
	normalized, err := normalizeRouteCreate(input)
	if err != nil {
		return RouteMutationResult{}, err
	}
	if err := s.validateOriginPolicy(normalized.Origin); err != nil {
		return RouteMutationResult{}, err
	}
	request, err = normalizeRequestContext(request, s.newID)
	if err != nil {
		return RouteMutationResult{}, err
	}
	opID, auditID, parentAuditID, err := s.mutationIDs()
	if err != nil {
		return RouteMutationResult{}, err
	}
	routeID, err := s.newID("rte")
	if err != nil {
		return RouteMutationResult{}, err
	}
	record := RouteRecord{OperationID: opID, AuditEventID: auditID, ParentAuditEventID: parentAuditID, AccountID: request.Actor.AccountID, TunnelID: tunnelID,
		RouteID: routeID, Name: normalized.Name, Protocol: dbProtocol(normalized.Protocol), MatchType: normalized.MatchType,
		Hostname: normalized.Hostname, WildcardSuffix: normalized.WildcardSuffix, PathPrefix: normalized.PathPrefix, Origin: normalized.Origin,
		Priority: normalized.Priority, ConnectTimeoutMS: normalized.ConnectTimeoutMS, IdleTimeoutMS: normalized.IdleTimeoutMS, MaxConcurrentStreams: normalized.MaxConcurrentStreams,
		DesiredState: "active", IdempotencyKey: input.Mutation.IdempotencyKey, RequestHash: input.Mutation.RequestHash,
		ActorID: request.Actor.ActorID, AuditActorID: auditActorIDForActor(request.Actor), ActorType: auditActorType(request.Actor), RequestID: request.RequestID,
		CorrelationID: request.CorrelationID, SourceDeviceID: request.Actor.DeviceID, Now: s.now().UTC()}
	if record.RouteID == "" {
		return RouteMutationResult{}, fmt.Errorf("%w: route identity allocation failed", ErrInvalidInput)
	}
	result, err := s.repository.CreateResourceRoute(ctx, record)
	if err != nil {
		return RouteMutationResult{}, err
	}
	return RouteMutationResult{Route: routeView(result.Route), Operation: previewtunnelapi.OperationView(result.Operation, request.RequestID), Replayed: result.Replayed, Changed: result.Changed}, nil
}

func (s *ResourceService) PatchRoute(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, routeID string, input RoutePatchRequest) (RouteMutationResult, error) {
	if err := s.authorize(request, "write", false); err != nil {
		return RouteMutationResult{}, err
	}
	normalized, err := normalizeRoutePatch(input)
	if err != nil {
		return RouteMutationResult{}, err
	}
	if input.Origin != nil {
		if err := s.validateOriginPolicy(normalized.Origin); err != nil {
			return RouteMutationResult{}, err
		}
	}
	request, err = normalizeRequestContext(request, s.newID)
	if err != nil {
		return RouteMutationResult{}, err
	}
	opID, auditID, parentAuditID, err := s.mutationIDs()
	if err != nil {
		return RouteMutationResult{}, err
	}
	record := RouteRecord{OperationID: opID, AuditEventID: auditID, ParentAuditEventID: parentAuditID, AccountID: request.Actor.AccountID, TunnelID: tunnelID, RouteID: routeID,
		Name: normalized.Name, Protocol: dbProtocol(normalized.Protocol), MatchType: normalized.MatchType, Hostname: normalized.Hostname, WildcardSuffix: normalized.WildcardSuffix,
		PathPrefix: normalized.PathPrefix, Origin: normalized.Origin, Priority: normalized.Priority, ConnectTimeoutMS: normalized.ConnectTimeoutMS, IdleTimeoutMS: normalized.IdleTimeoutMS,
		MaxConcurrentStreams: normalized.MaxConcurrentStreams, DesiredState: normalized.DesiredState, ExpectedGeneration: input.Mutation.ExpectedGeneration,
		IdempotencyKey: input.Mutation.IdempotencyKey, RequestHash: input.Mutation.RequestHash, ActorID: request.Actor.ActorID, AuditActorID: auditActorIDForActor(request.Actor), ActorType: auditActorType(request.Actor),
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, SourceDeviceID: request.Actor.DeviceID, Now: s.now().UTC(), NameSet: input.Name != nil, ProtocolSet: input.Protocol != nil,
		MatchTypeSet: input.MatchType != nil, HostnameSet: input.Hostname != nil, WildcardSuffixSet: input.WildcardSuffix != nil, PathPrefixSet: input.PathPrefixSet, OriginSet: input.Origin != nil,
		PrioritySet: input.Priority != nil, ConnectTimeoutSet: input.ConnectTimeoutMS != nil, IdleTimeoutSet: input.IdleTimeoutMS != nil,
		MaxStreamsSet: input.MaxConcurrentStreams != nil, DesiredStateSet: input.DesiredState != nil}
	result, err := s.repository.PatchResourceRoute(ctx, record)
	if err != nil {
		return RouteMutationResult{}, err
	}
	return RouteMutationResult{Route: routeView(result.Route), Operation: previewtunnelapi.OperationView(result.Operation, request.RequestID), Replayed: result.Replayed, Changed: result.Changed}, nil
}

func (s *ResourceService) DeleteRoute(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, routeID string, input ResourceMutationInput) (RouteMutationResult, error) {
	if err := s.authorize(request, "write", false); err != nil {
		return RouteMutationResult{}, err
	}
	request, err := normalizeRequestContext(request, s.newID)
	if err != nil {
		return RouteMutationResult{}, err
	}
	opID, auditID, parentAuditID, err := s.mutationIDs()
	if err != nil {
		return RouteMutationResult{}, err
	}
	record := RouteRecord{OperationID: opID, AuditEventID: auditID, ParentAuditEventID: parentAuditID, AccountID: request.Actor.AccountID, TunnelID: tunnelID, RouteID: routeID,
		ExpectedGeneration: input.ExpectedGeneration, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, ActorID: request.Actor.ActorID, AuditActorID: auditActorIDForActor(request.Actor), ActorType: auditActorType(request.Actor),
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, SourceDeviceID: request.Actor.DeviceID, Now: s.now().UTC()}
	result, err := s.repository.DeleteResourceRoute(ctx, record)
	if err != nil {
		return RouteMutationResult{}, err
	}
	return RouteMutationResult{Route: routeView(result.Route), Operation: previewtunnelapi.OperationView(result.Operation, request.RequestID), Replayed: result.Replayed, Changed: result.Changed}, nil
}

func (s *ResourceService) ListDomains(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, rawCursor string, limit int) (DomainPage, error) {
	if err := s.authorize(request, "read", false); err != nil {
		return DomainPage{}, err
	}
	if err := validateResourceListLimit(limit); err != nil {
		return DomainPage{}, err
	}
	position, err := s.decodeListCursor(rawCursor, request.Actor.AccountID, tunnelID, "domain_binding")
	if err != nil {
		return DomainPage{}, err
	}
	rows, err := s.repository.ListResourceDomains(ctx, request.Actor.AccountID, tunnelID, position, limit+1)
	if err != nil {
		return DomainPage{}, err
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	page := DomainPage{Items: make([]DomainView, 0, len(rows))}
	for _, row := range rows {
		page.Items = append(page.Items, domainView(row))
	}
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		page.NextCursor, err = s.cursors.EncodeList("domain_binding", request.Actor.AccountID, tunnelID, ListPosition{CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			return DomainPage{}, err
		}
	}
	return page, nil
}

func (s *ResourceService) GetDomain(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, domainID string) (DomainView, error) {
	if err := s.authorize(request, "read", false); err != nil {
		return DomainView{}, err
	}
	row, err := s.repository.GetResourceDomain(ctx, request.Actor.AccountID, tunnelID, domainID)
	if err != nil {
		return DomainView{}, err
	}
	return domainView(row), nil
}

func (s *ResourceService) CreateDomain(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID string, input DomainCreateRequest) (DomainMutationResult, error) {
	if err := s.authorize(request, "write", false); err != nil {
		return DomainMutationResult{}, err
	}
	hostname, matchType, err := normalizeBindingHostname(input.Hostname)
	if err != nil {
		return DomainMutationResult{}, err
	}
	if strings.TrimSpace(input.RouteID) == "" {
		return DomainMutationResult{}, fmt.Errorf("%w: route_id is required", ErrInvalidInput)
	}
	provider, err := validateDNSProvider(input.Provider)
	if err != nil {
		return DomainMutationResult{}, err
	}
	certificateStrategy, err := normalizeDomainCertificateStrategy(input.CertificateStrategy, matchType)
	if err != nil {
		return DomainMutationResult{}, err
	}
	request, err = normalizeRequestContext(request, s.newID)
	if err != nil {
		return DomainMutationResult{}, err
	}
	opID, auditID, parentAuditID, err := s.mutationIDs()
	if err != nil {
		return DomainMutationResult{}, err
	}
	domainID, err := s.newID("dom")
	if err != nil {
		return DomainMutationResult{}, err
	}
	challengeID, err := s.newID("dns")
	if err != nil {
		return DomainMutationResult{}, err
	}
	record := DomainRecord{OperationID: opID, AuditEventID: auditID, ParentAuditEventID: parentAuditID, AccountID: request.Actor.AccountID, TunnelID: tunnelID, DomainID: domainID, RouteID: input.RouteID,
		Hostname: hostname, MatchType: matchType, CertificateStrategy: certificateStrategy, ChallengeReference: "dns-challenge://" + challengeID, DNSProvider: provider, IdempotencyKey: input.Mutation.IdempotencyKey, RequestHash: input.Mutation.RequestHash,
		ActorID: request.Actor.ActorID, AuditActorID: auditActorIDForActor(request.Actor), ActorType: auditActorType(request.Actor), RequestID: request.RequestID, CorrelationID: request.CorrelationID,
		SourceDeviceID: request.Actor.DeviceID, Now: s.now().UTC()}
	result, err := s.repository.CreateResourceDomain(ctx, record)
	if err != nil {
		return DomainMutationResult{}, err
	}
	return DomainMutationResult{Domain: domainView(result.Domain), Operation: previewtunnelapi.OperationView(result.Operation, request.RequestID), Replayed: result.Replayed, Changed: result.Changed}, nil
}

func (s *ResourceService) DeleteDomain(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, domainID string, input ResourceMutationInput) (DomainMutationResult, error) {
	return s.mutateDomain(ctx, request, tunnelID, domainID, input, false)
}

func (s *ResourceService) VerifyDomain(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, domainID string, input ResourceMutationInput) (DomainMutationResult, error) {
	return s.mutateDomain(ctx, request, tunnelID, domainID, input, true)
}

func (s *ResourceService) mutateDomain(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, domainID string, input ResourceMutationInput, verify bool) (DomainMutationResult, error) {
	if err := s.authorize(request, "write", false); err != nil {
		return DomainMutationResult{}, err
	}
	request, err := normalizeRequestContext(request, s.newID)
	if err != nil {
		return DomainMutationResult{}, err
	}
	opID, auditID, parentAuditID, err := s.mutationIDs()
	if err != nil {
		return DomainMutationResult{}, err
	}
	record := DomainRecord{OperationID: opID, AuditEventID: auditID, ParentAuditEventID: parentAuditID, AccountID: request.Actor.AccountID, TunnelID: tunnelID, DomainID: domainID,
		ExpectedGeneration: input.ExpectedGeneration, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, ActorID: request.Actor.ActorID, AuditActorID: auditActorIDForActor(request.Actor), ActorType: auditActorType(request.Actor),
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, SourceDeviceID: request.Actor.DeviceID, Now: s.now().UTC()}
	var result ResourceMutationRecord
	if verify {
		result, err = s.repository.BeginResourceDomainVerification(ctx, record)
	} else {
		result, err = s.repository.DeleteResourceDomain(ctx, record)
	}
	if err != nil {
		return DomainMutationResult{}, err
	}
	return DomainMutationResult{Domain: domainView(result.Domain), Operation: previewtunnelapi.OperationView(result.Operation, request.RequestID), Replayed: result.Replayed, Changed: result.Changed}, nil
}

func (s *ResourceService) DomainInstructions(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, domainID string) (DNSInstructions, error) {
	if err := s.authorize(request, "read", false); err != nil {
		return DNSInstructions{}, err
	}
	domain, err := s.repository.GetResourceDomain(ctx, request.Actor.AccountID, tunnelID, domainID)
	if err != nil {
		return DNSInstructions{}, err
	}
	if domain.DeletedAt.Valid {
		return DNSInstructions{}, ErrDomainNotFound
	}
	name := domain.Hostname
	recordName := name
	verificationState := wireDomainState(domain.OwnershipState, domain.ConflictState)
	provider := normalizeDNSProvider(domain.DnsProvider)
	recordType, note := dnsRecordTypeAndNote(name, provider)
	records := []DNSRecordInstruction{{Name: recordName, Type: recordType, Value: domain.DnsTarget, TTL: 300}}
	if s.challengeZone != "" && (domain.CertificateStrategy == "managed" || domain.CertificateStrategy == "on_demand_leaf") {
		challengeTarget, targetErr := tunnelcert.DelegatedChallengeTarget(domain.ID, domain.AccountID, domain.TunnelID, domain.OwnershipChallengeReference, s.challengeZone)
		if targetErr != nil {
			return DNSInstructions{}, ErrDNSInstructionsUnavailable
		}
		base := strings.TrimPrefix(name, "*.")
		records = append(records, DNSRecordInstruction{Name: "_acme-challenge." + base, Type: "CNAME", Value: challengeTarget, TTL: 300})
		note += " For managed TLS, also add the shown _acme-challenge CNAME; Paperboat writes the TXT token only under its authoritative challenge zone."
	}
	return DNSInstructions{Schema: Schema, Kind: "dns_instructions", TunnelID: tunnelID, DomainID: domain.ID, Hostname: name, Provider: provider, Records: records, CertificateStrategy: domain.CertificateStrategy, VerificationState: verificationState, Note: note}, nil
}

func normalizeDNSProvider(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "cloudflare", "route53", "google_cloud_dns", "digitalocean", "namecheap":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "generic"
	}
}

func validateDNSProvider(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "generic", nil
	}
	switch normalized {
	case "generic", "cloudflare", "route53", "google_cloud_dns", "digitalocean", "namecheap":
		return normalized, nil
	default:
		return "", fmt.Errorf("%w: DNS provider is unsupported", ErrInvalidInput)
	}
}

func normalizeDomainCertificateStrategy(value, matchType string) (string, error) {
	strategy := strings.ToLower(strings.TrimSpace(value))
	if strategy == "" {
		strategy = "managed"
	}
	switch strategy {
	case "managed":
		return strategy, nil
	case "on_demand_leaf":
		if matchType != "one_label_wildcard" {
			return "", fmt.Errorf("%w: on_demand_leaf requires a one-label wildcard hostname", ErrInvalidInput)
		}
		return strategy, nil
	default:
		return "", fmt.Errorf("%w: certificate strategy is unsupported", ErrInvalidInput)
	}
}

func dnsRecordTypeAndNote(hostname, provider string) (string, string) {
	registrable, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimPrefix(hostname, "*."))
	apex := err == nil && registrable == strings.TrimPrefix(hostname, "*.") && !strings.HasPrefix(hostname, "*.")
	if !apex {
		return "CNAME", "Add the shown CNAME. Paperboat polls authoritative DNS and starts TLS issuance only after the exact record is observed."
	}
	switch provider {
	case "cloudflare":
		return "CNAME", "Create an apex CNAME with Cloudflare flattening enabled and proxying disabled until verification and TLS are ready."
	case "route53":
		return "ALIAS", "Create a Route 53 apex ALIAS to the stable Paperboat target."
	case "google_cloud_dns", "digitalocean", "namecheap", "generic":
		return "ANAME", "Use your provider's apex ANAME, ALIAS, or CNAME-flattening record. Do not use transient connector addresses."
	default:
		return "ANAME", "Use your provider's apex ANAME, ALIAS, or CNAME-flattening record."
	}
}

func (s *ResourceService) ListConnectors(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, rawCursor string, limit int) (ConnectorPage, error) {
	if err := s.authorize(request, "read", false); err != nil {
		return ConnectorPage{}, err
	}
	if err := validateResourceListLimit(limit); err != nil {
		return ConnectorPage{}, err
	}
	position, err := s.decodeListCursor(rawCursor, request.Actor.AccountID, tunnelID, "connector")
	if err != nil {
		return ConnectorPage{}, err
	}
	rows, err := s.repository.ListResourceConnectors(ctx, request.Actor.AccountID, tunnelID, position, limit+1)
	if err != nil {
		return ConnectorPage{}, err
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	page := ConnectorPage{Items: make([]ConnectorView, 0, len(rows))}
	for _, row := range rows {
		page.Items = append(page.Items, connectorView(row))
	}
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		page.NextCursor, err = s.cursors.EncodeList("connector", request.Actor.AccountID, tunnelID, ListPosition{CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			return ConnectorPage{}, err
		}
	}
	return page, nil
}

func (s *ResourceService) GetConnector(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, connectorID string) (ConnectorView, error) {
	if err := s.authorize(request, "read", false); err != nil {
		return ConnectorView{}, err
	}
	row, err := s.repository.GetResourceConnector(ctx, request.Actor.AccountID, tunnelID, connectorID)
	if err != nil {
		return ConnectorView{}, err
	}
	return connectorView(row), nil
}

func (s *ResourceService) IssueEnrollment(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID string, input EnrollmentRequest) (EnrollmentResult, error) {
	if err := s.authorize(request, "write", false); err != nil {
		return EnrollmentResult{}, err
	}
	hostID := strings.TrimSpace(input.HostID)
	if hostID == "" || len(hostID) > 128 {
		return EnrollmentResult{}, fmt.Errorf("%w: host_id is required", ErrInvalidInput)
	}
	capabilities, err := normalizeCapabilities(input.Capabilities)
	if err != nil {
		return EnrollmentResult{}, err
	}
	ttl := input.TTL
	if ttl == 0 {
		ttl = s.enrollmentTTL
	}
	if ttl < time.Minute || ttl > 15*time.Minute {
		return EnrollmentResult{}, fmt.Errorf("%w: enrollment TTL is bounded to fifteen minutes", ErrInvalidInput)
	}
	request, err = normalizeRequestContext(request, s.newID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	opID, auditID, parentAuditID, err := s.mutationIDs()
	if err != nil {
		return EnrollmentResult{}, err
	}
	enrollmentID, err := s.newID("enr")
	if err != nil {
		return EnrollmentResult{}, err
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return EnrollmentResult{}, err
	}
	token := "pbce_" + base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256([]byte(token))
	record := EnrollmentRecordInput{OperationID: opID, EnrollmentID: enrollmentID, AuditEventID: auditID, ParentAuditEventID: parentAuditID, AccountID: request.Actor.AccountID,
		TunnelID: tunnelID, HostID: hostID, TokenHash: tokenHash[:], Token: token, Capabilities: capabilities, ExpiresAt: s.now().UTC().Add(ttl), IdempotencyKey: input.Mutation.IdempotencyKey,
		RequestHash: input.Mutation.RequestHash, ActorID: request.Actor.ActorID, AuditActorID: auditActorIDForActor(request.Actor), ActorType: auditActorType(request.Actor), RequestID: request.RequestID,
		CorrelationID: request.CorrelationID, SourceDeviceID: request.Actor.DeviceID, Now: s.now().UTC(), CredentialLifetime: s.credentialLifetime}
	result, err := s.repository.IssueConnectorEnrollment(ctx, record)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if result.Replayed && strings.TrimSpace(result.Token) == "" {
		// The enrollment bearer is intentionally write-only. A lost response
		// cannot be reconstructed from the stored token hash, so make the
		// recovery boundary explicit instead of returning a false success with
		// an unusable empty token.
		return EnrollmentResult{}, ErrEnrollmentAlreadyIssued
	}
	view := EnrollmentResult{Schema: Schema, Kind: "connector_enrollment", ID: result.Enrollment.ID, TunnelID: result.Enrollment.TunnelID, HostID: result.Enrollment.HostID,
		Operation: previewtunnelapi.OperationView(result.Operation, request.RequestID), Token: result.Token, ExpiresAt: result.Enrollment.ExpiresAt.UTC(), Capabilities: append([]string(nil), result.Enrollment.Capabilities...), Replayed: result.Replayed}
	return view, nil
}

func (s *ResourceService) ExchangeEnrollment(ctx context.Context, request previewtunnelapi.RequestContext, input EnrollmentExchangeRequest) (ConnectorMutationResult, error) {
	if err := s.authorize(request, "write", true); err != nil {
		return ConnectorMutationResult{}, err
	}
	if strings.TrimSpace(input.Token) == "" || len(input.Token) > 256 {
		return ConnectorMutationResult{}, fmt.Errorf("%w: enrollment token is required", ErrInvalidInput)
	}
	if input.TunnelID == "" || input.HostID == "" || input.HostID != request.Actor.HostID {
		return ConnectorMutationResult{}, ErrHostNotFound
	}
	if !VerifyConnectorCredentialProof(input.CredentialVerifierAlgorithm, input.CredentialVerifierPublicKey, input.CredentialProof,
		input.TunnelID, input.HostID, input.Token, input.CredentialReference, input.CredentialThumbprint, input.Mutation.IdempotencyKey) {
		return ConnectorMutationResult{}, fmt.Errorf("%w: connector credential proof is invalid", ErrInvalidInput)
	}
	protocol := strings.TrimSpace(input.ProtocolVersion)
	if protocol == "" {
		protocol = "1.0"
	}
	if protocol != "1.0" {
		return ConnectorMutationResult{}, fmt.Errorf("%w: unsupported connector protocol", ErrInvalidInput)
	}
	request, err := normalizeRequestContext(request, s.newID)
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	opID, auditID, parentAuditID, err := s.mutationIDs()
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	connectorID, err := s.newID("con")
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	credentialReference := strings.TrimSpace(input.CredentialReference)
	if credentialReference == "" {
		return ConnectorMutationResult{}, fmt.Errorf("%w: host credential reference is required", ErrInvalidInput)
	}
	if err := validateWriteOnlyReference(credentialReference); err != nil {
		return ConnectorMutationResult{}, err
	}
	thumbprint := strings.TrimSpace(input.CredentialThumbprint)
	if thumbprint == "" {
		return ConnectorMutationResult{}, fmt.Errorf("%w: host credential thumbprint is required", ErrInvalidInput)
	}
	if len(thumbprint) > 256 || strings.ContainsAny(thumbprint, "\r\n\t ") {
		return ConnectorMutationResult{}, fmt.Errorf("%w: credential thumbprint is invalid", ErrInvalidInput)
	}
	credentialGenerationID, err := s.newID("crg")
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	tokenHash := sha256.Sum256([]byte(input.Token))
	record := EnrollmentExchangeRecord{OperationID: opID, AuditEventID: auditID, ParentAuditEventID: parentAuditID, AccountID: request.Actor.AccountID, TunnelID: input.TunnelID, HostID: input.HostID,
		TokenHash: tokenHash[:], ProtocolVersion: protocol, SoftwareVersion: nullableStringPtr(input.SoftwareVersion), OperatingSystem: nullableStringPtr(input.OperatingSystem), Architecture: nullableStringPtr(input.Architecture), ConnectorID: connectorID,
		CredentialReference: credentialReference, CredentialThumbprint: thumbprint, CredentialVerifierAlgorithm: input.CredentialVerifierAlgorithm, CredentialVerifierPublicKey: append([]byte(nil), input.CredentialVerifierPublicKey...), CredentialProof: append([]byte(nil), input.CredentialProof...), CredentialGenerationID: credentialGenerationID, IdempotencyKey: input.Mutation.IdempotencyKey, RequestHash: input.Mutation.RequestHash,
		ActorID: request.Actor.ActorID, AuditActorID: auditActorIDForActor(request.Actor), ActorType: auditActorType(request.Actor), RequestID: request.RequestID, CorrelationID: request.CorrelationID,
		SourceDeviceID: request.Actor.DeviceID, Now: s.now().UTC(), CredentialLifetime: s.credentialLifetime, CredentialOverlap: s.rotationOverlap}
	result, err := s.repository.ExchangeConnectorEnrollment(ctx, record)
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	operation := previewtunnelapi.OperationView(result.Operation, request.RequestID)
	if result.ProcessGeneration < 1 || result.Connector.RotationGeneration < 1 {
		return ConnectorMutationResult{}, ErrGenerationConflict
	}
	if err := validateEndpointUUID(result.StableEndpointID); err != nil {
		return ConnectorMutationResult{}, fmt.Errorf("%w: managed endpoint identity is unavailable", ErrInvalidInput)
	}
	activation := &ConnectorActivation{
		Schema: Schema, Kind: "connector_activation", AccountID: request.Actor.AccountID, TunnelID: result.Connector.TunnelID,
		ConnectorID: result.Connector.ID, HostID: result.Connector.HostID,
		StableEndpointID:     result.StableEndpointID,
		CredentialGeneration: result.Connector.RotationGeneration,
		ProcessGeneration:    result.ProcessGeneration, Operation: operation,
	}
	return ConnectorMutationResult{Connector: connectorView(result.Connector), Operation: operation, Activation: activation, Replayed: result.Replayed, Changed: result.Changed}, nil
}

func (s *ResourceService) DrainConnector(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, connectorID string, input ResourceMutationInput) (ConnectorMutationResult, error) {
	return s.mutateConnector(ctx, request, tunnelID, connectorID, input, false)
}

func (s *ResourceService) RevokeConnector(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, connectorID string, input ResourceMutationInput) (ConnectorMutationResult, error) {
	return s.mutateConnector(ctx, request, tunnelID, connectorID, input, true)
}

func (s *ResourceService) mutateConnector(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, connectorID string, input ResourceMutationInput, revoke bool) (ConnectorMutationResult, error) {
	if err := s.authorize(request, "write", false); err != nil {
		return ConnectorMutationResult{}, err
	}
	request, err := normalizeRequestContext(request, s.newID)
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	opID, auditID, parentAuditID, err := s.mutationIDs()
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	record := ConnectorRecord{OperationID: opID, AuditEventID: auditID, ParentAuditEventID: parentAuditID, AccountID: request.Actor.AccountID, TunnelID: tunnelID, ConnectorID: connectorID,
		ExpectedGeneration: input.ExpectedGeneration, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, ActorID: request.Actor.ActorID, AuditActorID: auditActorIDForActor(request.Actor), ActorType: auditActorType(request.Actor),
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, SourceDeviceID: request.Actor.DeviceID, Now: s.now().UTC()}
	var result ResourceMutationRecord
	if revoke {
		result, err = s.repository.RevokeResourceConnector(ctx, record)
	} else {
		result, err = s.repository.DrainResourceConnector(ctx, record)
	}
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	return ConnectorMutationResult{Connector: connectorView(result.Connector), Operation: previewtunnelapi.OperationView(result.Operation, request.RequestID), Replayed: result.Replayed, Changed: result.Changed}, nil
}

func (s *ResourceService) RotateCredentials(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID string, input ResourceMutationInput) (previewtunnelapi.Operation, error) {
	if err := s.authorize(request, "write", false); err != nil {
		return previewtunnelapi.Operation{}, err
	}
	request, err := normalizeRequestContext(request, s.newID)
	if err != nil {
		return previewtunnelapi.Operation{}, err
	}
	opID, auditID, parentAuditID, err := s.mutationIDs()
	if err != nil {
		return previewtunnelapi.Operation{}, err
	}
	record := RotationRecord{OperationID: opID, AuditEventID: auditID, ParentAuditEventID: parentAuditID, AccountID: request.Actor.AccountID, TunnelID: tunnelID,
		ExpectedGeneration: input.ExpectedGeneration, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, ActorID: request.Actor.ActorID, AuditActorID: auditActorIDForActor(request.Actor), ActorType: auditActorType(request.Actor),
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, SourceDeviceID: request.Actor.DeviceID, Now: s.now().UTC(), OverlapUntil: s.now().UTC().Add(s.rotationOverlap), CredentialLifetime: s.credentialLifetime, NewID: s.newID}
	result, err := s.repository.RotateResourceCredentials(ctx, record)
	if err != nil {
		return previewtunnelapi.Operation{}, err
	}
	return previewtunnelapi.OperationView(result, request.RequestID), nil
}

func (s *ResourceService) ListTunnelLogs(ctx context.Context, request previewtunnelapi.RequestContext, tunnelID, rawCursor string, limit int) (LogPage, error) {
	if err := s.authorize(request, "read", false); err != nil {
		return LogPage{}, err
	}
	if err := validateResourceListLimit(limit); err != nil {
		return LogPage{}, err
	}
	after, err := s.cursors.DecodeLog(rawCursor, "tunnel", request.Actor.AccountID, tunnelID)
	if err != nil {
		return LogPage{}, err
	}
	rows, err := s.repository.ListResourceTunnelLogs(ctx, request.Actor.AccountID, tunnelID, after, limit+1)
	if err != nil {
		return LogPage{}, err
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	page := LogPage{Items: make([]LogEntry, 0, len(rows))}
	for _, row := range rows {
		entry, entryErr := logView(row)
		if entryErr != nil {
			return LogPage{}, entryErr
		}
		page.Items = append(page.Items, entry)
	}
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		sequence := last.CursorSequence.Int64
		page.NextCursor, err = s.cursors.EncodeLog("tunnel", request.Actor.AccountID, tunnelID, sequence)
		if err != nil {
			return LogPage{}, err
		}
	}
	return page, nil
}

func (s *ResourceService) ListPreviewLogs(ctx context.Context, request previewtunnelapi.RequestContext, previewID, rawCursor string, limit int) (LogPage, error) {
	if err := previewtunnelapi.Authorize(request.Actor, previewtunnelapi.AccessRequest{AccountID: request.Actor.AccountID, Resource: "previews", Action: "read"}); err != nil {
		return LogPage{}, err
	}
	if err := validateResourceListLimit(limit); err != nil {
		return LogPage{}, err
	}
	after, err := s.cursors.DecodeLog(rawCursor, "preview", request.Actor.AccountID, previewID)
	if err != nil {
		return LogPage{}, err
	}
	rows, err := s.repository.ListResourcePreviewLogs(ctx, request.Actor.AccountID, previewID, after, limit+1)
	if err != nil {
		return LogPage{}, err
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	page := LogPage{Items: make([]LogEntry, 0, len(rows))}
	for _, row := range rows {
		entry, entryErr := logView(row)
		if entryErr != nil {
			return LogPage{}, entryErr
		}
		page.Items = append(page.Items, entry)
	}
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		if !last.CursorSequence.Valid {
			return LogPage{}, fmt.Errorf("invalid log cursor sequence")
		}
		page.NextCursor, err = s.cursors.EncodeLog("preview", request.Actor.AccountID, previewID, last.CursorSequence.Int64)
		if err != nil {
			return LogPage{}, err
		}
	}
	return page, nil
}

func validateResourceListLimit(limit int) error {
	if limit < 1 || limit > previewtunnelapi.MaximumPageLimit {
		return fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidInput, previewtunnelapi.MaximumPageLimit)
	}
	return nil
}

func (s *ResourceService) mutationIDs() (string, string, string, error) {
	op, err := s.newID("op")
	if err != nil {
		return "", "", "", err
	}
	audit, err := s.newID("aud")
	if err != nil {
		return "", "", "", err
	}
	parent, err := s.newID("aud")
	if err != nil {
		return "", "", "", err
	}
	return op, audit, parent, nil
}

func routeView(row dbsqlc.TunnelRoute) RouteView {
	hostMatch := RouteHostMatch{Type: wireMatchType(row.MatchType), Hostname: nullStringValue(row.MatchHostname)}
	if row.MatchType == "one_label_wildcard" {
		hostMatch.Hostname = "*." + nullStringValue(row.WildcardSuffix)
		labels := 1
		hostMatch.WildcardLabels = &labels
	}
	origin := RouteOrigin{Scheme: row.OriginScheme, Address: row.OriginAddress, PreserveHost: row.PreserveHost, HostOverride: nullStringPointer(row.HostOverride)}
	if row.OriginScheme == "https" {
		origin.TLS = &RouteTLS{Verification: row.TlsVerification, ServerName: nullStringPointer(row.TlsServerName), CAReference: nullStringPointer(row.CaReference), ClientCredentialReference: nullStringPointer(row.MtlsCredentialReference)}
	}
	return RouteView{Schema: Schema, Kind: "route", ID: row.ID, TunnelID: row.TunnelID, Name: row.Name, Protocol: wireProtocol(row.Protocol), HostMatch: hostMatch,
		PathPrefix: nullStringPointer(row.PathPrefix), Origin: origin, Priority: row.Priority, ConnectTimeoutMS: row.ConnectTimeoutMs, IdleTimeoutMS: row.IdleTimeoutMs,
		MaxConcurrentStreams: row.MaxConcurrentStreams, DesiredState: row.DesiredState, Generation: row.Generation,
		ETag: previewtunnelapi.ETag("route", row.ID, row.Generation)}
}

func domainView(row dbsqlc.TunnelDomain) DomainView {
	var observed []string
	var raw []any
	if json.Unmarshal(row.ObservedRecords, &raw) == nil {
		for _, value := range raw {
			if text, ok := value.(string); ok {
				observed = append(observed, text)
			}
		}
	}
	dns := DomainDNS{Target: row.DnsTarget, ObservedRecords: observed}
	if row.DnsLastCheckedAt.Valid {
		value := row.DnsLastCheckedAt.Time.UTC()
		dns.LastCheckedAt = &value
	}
	certificate := DomainCertificate{State: wireCertificateState(row.CertificateState)}
	if row.CertificateReference.Valid {
		certificate.Reference = row.CertificateReference.String
	}
	if row.CertificateExpiresAt.Valid {
		value := row.CertificateExpiresAt.Time.UTC()
		certificate.ExpiresAt = &value
	}
	if row.CertificateFailureCode.Valid {
		certificate.Failure = map[string]any{"code": row.CertificateFailureCode.String}
	}
	labels := (*int)(nil)
	if row.MatchType == "one_label_wildcard" {
		value := 1
		labels = &value
	}
	return DomainView{Schema: Schema, Kind: "domain_binding", ID: row.ID, AccountID: row.AccountID, TunnelID: row.TunnelID, RouteID: row.RouteID, Hostname: row.Hostname, MatchType: row.MatchType,
		WildcardLabels: labels, CertificateStrategy: row.CertificateStrategy, State: wireDomainLifecycleState(row), DNS: dns, Certificate: certificate, Generation: row.Generation, ETag: previewtunnelapi.ETag("domain_binding", row.ID, row.Generation)}
}

func wireDomainLifecycleState(row dbsqlc.TunnelDomain) string {
	dnsState := wireDomainState(row.OwnershipState, row.ConflictState)
	if dnsState != "verified" {
		return dnsState
	}
	switch row.CertificateState {
	case "pending", "issuing", "renewing":
		return "issuing_tls"
	case "ready":
		return "ready"
	case "failed", "expired", "revoked":
		return "tls_error"
	default:
		return "verified"
	}
}

func connectorView(row dbsqlc.TunnelConnector) ConnectorView {
	view := ConnectorView{Schema: Schema, Kind: "connector", ID: row.ID, TunnelID: row.TunnelID, HostID: row.HostID, CredentialReference: row.CredentialReference,
		RotationGeneration: row.RotationGeneration, DesiredState: row.DesiredState, ProtocolVersion: row.ProtocolVersion, DrainState: row.DrainState,
		Generation: row.Generation, ETag: previewtunnelapi.ETag("connector", row.ID, row.Generation), LastAppliedConfigGeneration: row.LastAppliedConfigGeneration}
	if row.SoftwareVersion.Valid {
		view.SoftwareVersion = row.SoftwareVersion.String
	}
	if row.OperatingSystem.Valid {
		view.OperatingSystem = row.OperatingSystem.String
	}
	if row.Architecture.Valid {
		view.Architecture = row.Architecture.String
	}
	if row.LastSessionID.Valid {
		view.LastSessionID = row.LastSessionID.String
	}
	if row.LastHeartbeatAt.Valid {
		value := row.LastHeartbeatAt.Time.UTC()
		view.LastHeartbeatAt = &value
	}
	if row.ReadyAt.Valid {
		value := row.ReadyAt.Time.UTC()
		view.ReadyAt = &value
	}
	return view
}

func logView(row any) (LogEntry, error) {
	var entry dbsqlc.TunnelLogEntry
	switch value := row.(type) {
	case dbsqlc.TunnelLogEntry:
		entry = value
	case dbsqlc.ListTunnelLogsV1Row:
		entry = dbsqlc.TunnelLogEntry{ID: value.ID, AccountID: value.AccountID, TunnelID: value.TunnelID, PreviewID: value.PreviewID, RouteID: value.RouteID, ConnectorID: value.ConnectorID, SessionID: value.SessionID,
			Level: value.Level, Component: value.Component, Code: value.Code, Message: value.Message, Metadata: value.Metadata, CorrelationID: value.CorrelationID, OccurredAt: value.OccurredAt, CursorSequence: value.CursorSequence}
	default:
		return LogEntry{}, fmt.Errorf("invalid log row type")
	}
	if !entry.CursorSequence.Valid {
		return LogEntry{}, fmt.Errorf("invalid log cursor sequence")
	}
	if err := validateLogText(entry.Message, maxResourceLogMessageBytes); err != nil {
		return LogEntry{}, fmt.Errorf("unsafe log message: %w", err)
	}
	if err := validateLogCorrelation(entry.CorrelationID); err != nil {
		return LogEntry{}, fmt.Errorf("unsafe log correlation: %w", err)
	}
	var metadata map[string]any
	decoder := json.NewDecoder(bytes.NewReader(entry.Metadata))
	decoder.UseNumber()
	if err := decoder.Decode(&metadata); err != nil {
		return LogEntry{}, fmt.Errorf("decode log metadata: %w", err)
	}
	safe, err := previewtunnelapi.SafeMetadata(metadata)
	if err != nil {
		return LogEntry{}, err
	}
	return LogEntry{Schema: Schema, Kind: "log_entry", ID: entry.ID, TunnelID: nullStringValue(entry.TunnelID), PreviewID: nullStringValue(entry.PreviewID), RouteID: nullStringValue(entry.RouteID), ConnectorID: nullStringValue(entry.ConnectorID), SessionID: nullStringValue(entry.SessionID),
		Level: entry.Level, Component: entry.Component, Code: entry.Code, Message: entry.Message, Metadata: safe, CorrelationID: entry.CorrelationID, OccurredAt: entry.OccurredAt.UTC(), Cursor: strconv.FormatInt(entry.CursorSequence.Int64, 10)}, nil
}

func validateLogText(value string, maxLength int) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxLength || strings.ContainsAny(value, "\r\n\x00") {
		return previewtunnelapi.ErrUnsafeMetadata
	}
	upper := strings.ToUpper(value)
	if strings.Contains(upper, "BEGIN PRIVATE KEY") || strings.Contains(upper, "BEARER ") || strings.Contains(upper, "PASSWORD=") || strings.Contains(upper, "TOKEN=") || strings.Contains(upper, "AUTHORIZATION=") || strings.Contains(upper, "AUTHORIZATION:") {
		return previewtunnelapi.ErrUnsafeMetadata
	}
	for _, token := range strings.Fields(value) {
		candidate := strings.Trim(token, "\"'()[]{}<>,.;")
		if !strings.Contains(candidate, "://") {
			continue
		}
		parsed, err := url.Parse(candidate)
		if err != nil || !parsed.IsAbs() {
			continue
		}
		if parsed.User != nil {
			return previewtunnelapi.ErrUnsafeMetadata
		}
		for key := range parsed.Query() {
			normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
			if strings.Contains(normalized, "token") || strings.Contains(normalized, "secret") || normalized == "password" || normalized == "authorization" {
				return previewtunnelapi.ErrUnsafeMetadata
			}
		}
	}
	return nil
}

func validateLogCorrelation(value string) error {
	if err := validateLogText(value, 256); err != nil {
		return err
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._:-", character)) {
			return previewtunnelapi.ErrUnsafeMetadata
		}
	}
	return nil
}

func nullStringPointer(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	result := value.String
	return &result
}

type normalizedRouteCreate struct {
	Name                 string
	Protocol             string
	MatchType            string
	Hostname             sql.NullString
	WildcardSuffix       sql.NullString
	PathPrefix           sql.NullString
	Origin               RouteOriginRequest
	Priority             int32
	ConnectTimeoutMS     int32
	IdleTimeoutMS        int32
	MaxConcurrentStreams int32
}

type normalizedRoutePatch struct {
	Name                 string
	Protocol             string
	MatchType            string
	Hostname             sql.NullString
	WildcardSuffix       sql.NullString
	PathPrefix           sql.NullString
	Origin               RouteOriginRequest
	Priority             int32
	ConnectTimeoutMS     int32
	IdleTimeoutMS        int32
	MaxConcurrentStreams int32
	DesiredState         string
}

func normalizeRouteCreate(input RouteCreateRequest) (normalizedRouteCreate, error) {
	name, err := validateRouteName(input.Name)
	if err != nil {
		return normalizedRouteCreate{}, err
	}
	protocol, err := normalizeWireProtocol(input.Protocol)
	if err != nil {
		return normalizedRouteCreate{}, err
	}
	matchType, hostname, wildcard, err := normalizeRouteMatch(input.MatchType, input.Hostname, input.WildcardSuffix)
	if err != nil {
		return normalizedRouteCreate{}, err
	}
	origin, err := normalizeRouteOrigin(input.Origin)
	if err != nil {
		return normalizedRouteCreate{}, err
	}
	pathPrefix, err := normalizePathPrefix(input.PathPrefix)
	if err != nil {
		return normalizedRouteCreate{}, err
	}
	if protocol == "tcp_private" && origin.Scheme != "tcp" {
		return normalizedRouteCreate{}, fmt.Errorf("%w: tcp_private requires a tcp origin", ErrInvalidInput)
	}
	if protocol == "tcp_private" && (matchType != "catch_all" || hostname.Valid || wildcard.Valid || pathPrefix.Valid) {
		return normalizedRouteCreate{}, fmt.Errorf("%w: tcp_private requires a catch-all host match without a path prefix", ErrInvalidInput)
	}
	if protocol == "http" && origin.Scheme == "tcp" {
		return normalizedRouteCreate{}, fmt.Errorf("%w: HTTP protocol cannot target a tcp origin", ErrInvalidInput)
	}
	if input.Priority == 0 {
		input.Priority = 100
	}
	if input.Priority < 0 || input.Priority > 1_000_000 {
		return normalizedRouteCreate{}, fmt.Errorf("%w: priority is out of range", ErrInvalidInput)
	}
	connectTimeout, idleTimeout, maxStreams, err := normalizeRouteLimits(input.ConnectTimeoutMS, input.IdleTimeoutMS, input.MaxConcurrentStreams)
	if err != nil {
		return normalizedRouteCreate{}, err
	}
	return normalizedRouteCreate{Name: name, Protocol: protocol, MatchType: matchType, Hostname: hostname, WildcardSuffix: wildcard, PathPrefix: pathPrefix, Origin: origin, Priority: input.Priority,
		ConnectTimeoutMS: connectTimeout, IdleTimeoutMS: idleTimeout, MaxConcurrentStreams: maxStreams}, nil
}

func normalizeRoutePatch(input RoutePatchRequest) (normalizedRoutePatch, error) {
	result := normalizedRoutePatch{}
	if input.Name != nil {
		value, err := validateRouteName(*input.Name)
		if err != nil {
			return result, err
		}
		result.Name = value
	}
	if input.Protocol != nil {
		value, err := normalizeWireProtocol(*input.Protocol)
		if err != nil {
			return result, err
		}
		result.Protocol = value
	}
	if input.MatchType != nil || input.Hostname != nil || input.WildcardSuffix != nil {
		matchType := ""
		if input.MatchType != nil {
			matchType = *input.MatchType
		}
		hostname := ""
		if input.Hostname != nil {
			hostname = *input.Hostname
		}
		wildcard := ""
		if input.WildcardSuffix != nil {
			wildcard = *input.WildcardSuffix
		}
		value, host, suffix, err := normalizeRouteMatch(matchType, hostname, wildcard)
		if err != nil {
			return result, err
		}
		result.MatchType, result.Hostname, result.WildcardSuffix = value, host, suffix
	}
	if input.PathPrefixSet {
		value, err := normalizePathPrefix(input.PathPrefix)
		if err != nil {
			return result, err
		}
		result.PathPrefix = value
	}
	if input.Origin != nil {
		value, err := normalizeRouteOrigin(*input.Origin)
		if err != nil {
			return result, err
		}
		result.Origin = value
	}
	if input.Priority != nil {
		if *input.Priority < 0 || *input.Priority > 1_000_000 {
			return result, fmt.Errorf("%w: priority is out of range", ErrInvalidInput)
		}
		result.Priority = *input.Priority
	}
	if input.ConnectTimeoutMS != nil || input.IdleTimeoutMS != nil || input.MaxConcurrentStreams != nil {
		connectTimeout, idleTimeout, maxStreams, err := normalizeRouteLimits(valueOrZero(input.ConnectTimeoutMS), valueOrZero(input.IdleTimeoutMS), valueOrZero(input.MaxConcurrentStreams))
		if err != nil {
			return result, err
		}
		result.ConnectTimeoutMS, result.IdleTimeoutMS, result.MaxConcurrentStreams = connectTimeout, idleTimeout, maxStreams
	}
	if input.DesiredState != nil {
		switch *input.DesiredState {
		case "active", "disabled":
			result.DesiredState = *input.DesiredState
		default:
			return result, fmt.Errorf("%w: desired_state is invalid", ErrInvalidInput)
		}
	}
	return result, nil
}

func valueOrZero(value *int32) int32 {
	if value == nil {
		return 0
	}
	return *value
}

func normalizeRouteLimits(connectTimeout, idleTimeout, maxStreams int32) (int32, int32, int32, error) {
	if connectTimeout == 0 {
		connectTimeout = 10_000
	}
	if idleTimeout == 0 {
		idleTimeout = 90_000
	}
	if maxStreams == 0 {
		maxStreams = 128
	}
	if connectTimeout < 100 || connectTimeout > 120_000 || idleTimeout < 1_000 || idleTimeout > 3_600_000 || maxStreams < 1 || maxStreams > 10_000 {
		return 0, 0, 0, fmt.Errorf("%w: route timeout or stream limit is out of range", ErrInvalidInput)
	}
	return connectTimeout, idleTimeout, maxStreams, nil
}

func validateRouteName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 1 || len(value) > 80 || !tunnelNamePattern.MatchString(value) {
		return "", fmt.Errorf("%w: route name is invalid", ErrInvalidInput)
	}
	return value, nil
}

func normalizeWireProtocol(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "http":
		return "http", nil
	case "tcp_private":
		return "tcp_private", nil
	default:
		return "", fmt.Errorf("%w: protocol must be http or tcp_private", ErrInvalidInput)
	}
}

func dbProtocol(value string) string {
	if value == "tcp_private" {
		return "private_tcp"
	}
	return value
}
func wireProtocol(value string) string {
	if value == "private_tcp" {
		return "tcp_private"
	}
	return value
}

func normalizeRouteMatch(matchType, hostname, wildcardSuffix string) (string, sql.NullString, sql.NullString, error) {
	matchType = strings.ToLower(strings.TrimSpace(matchType))
	if matchType == "managed_exact" {
		matchType = "managed"
	}
	switch matchType {
	case "managed", "exact":
		if hostname == "" {
			return "", sql.NullString{}, sql.NullString{}, fmt.Errorf("%w: hostname is required", ErrInvalidInput)
		}
		if strings.HasPrefix(hostname, "*.") || wildcardSuffix != "" {
			return "", sql.NullString{}, sql.NullString{}, fmt.Errorf("%w: wildcard is only valid for one_label_wildcard", ErrInvalidInput)
		}
		normalized, err := normalizeIDNAHostname(hostname)
		if err != nil {
			return "", sql.NullString{}, sql.NullString{}, fmt.Errorf("%w: hostname: %v", ErrInvalidInput, err)
		}
		return matchType, nullableString(normalized), sql.NullString{}, nil
	case "one_label_wildcard":
		if wildcardSuffix == "" && strings.HasPrefix(hostname, "*.") {
			wildcardSuffix = strings.TrimPrefix(hostname, "*.")
		}
		if strings.HasPrefix(wildcardSuffix, "*.") || wildcardSuffix == "" {
			return "", sql.NullString{}, sql.NullString{}, fmt.Errorf("%w: one-label wildcard suffix is required", ErrInvalidInput)
		}
		normalized, err := normalizeIDNAHostname(wildcardSuffix)
		if err != nil {
			return "", sql.NullString{}, sql.NullString{}, fmt.Errorf("%w: wildcard suffix: %v", ErrInvalidInput, err)
		}
		if len(strings.Split(normalized, ".")) < 2 {
			return "", sql.NullString{}, sql.NullString{}, fmt.Errorf("%w: wildcard must contain a registrable suffix", ErrInvalidInput)
		}
		return matchType, sql.NullString{}, nullableString(normalized), nil
	case "catch_all":
		if hostname != "" || wildcardSuffix != "" {
			return "", sql.NullString{}, sql.NullString{}, fmt.Errorf("%w: catch-all cannot have a hostname", ErrInvalidInput)
		}
		return matchType, sql.NullString{}, sql.NullString{}, nil
	default:
		return "", sql.NullString{}, sql.NullString{}, fmt.Errorf("%w: host match type is invalid", ErrInvalidInput)
	}
}

func normalizePathPrefix(value *string) (sql.NullString, error) {
	if value == nil {
		return sql.NullString{}, nil
	}
	if *value == "" {
		return sql.NullString{}, nil
	}
	if len(*value) > 2048 || !strings.HasPrefix(*value, "/") || strings.ContainsAny(*value, "\r\n\x00") {
		return sql.NullString{}, fmt.Errorf("%w: path_prefix is invalid", ErrInvalidInput)
	}
	return nullableString(*value), nil
}

func normalizeRouteOrigin(input RouteOriginRequest) (RouteOriginRequest, error) {
	input.Scheme = strings.ToLower(strings.TrimSpace(input.Scheme))
	input.Address = strings.TrimSpace(input.Address)
	if input.HostOverride != nil {
		value := strings.ToLower(strings.TrimSpace(*input.HostOverride))
		input.HostOverride = &value
	}
	if err := validateOriginRequest(OriginRequest{Scheme: input.Scheme, Address: input.Address, PreserveHost: &input.PreserveHost, HostOverride: input.HostOverride}); err != nil {
		return RouteOriginRequest{}, err
	}
	if input.Scheme != "https" && input.TLS != nil {
		return RouteOriginRequest{}, fmt.Errorf("%w: TLS settings require an HTTPS origin", ErrInvalidInput)
	}
	if input.Scheme == "https" {
		if input.TLS == nil {
			input.TLS = &RouteTLSRequest{Verification: "system"}
		}
		if err := validateRouteTLS(*input.TLS); err != nil {
			return RouteOriginRequest{}, err
		}
	} else {
		input.TLS = nil
	}
	return input, nil
}

func validateRouteTLS(tls RouteTLSRequest) error {
	switch tls.Verification {
	case "system", "custom_ca", "insecure_development":
	default:
		return fmt.Errorf("%w: TLS verification is invalid", ErrInvalidInput)
	}
	if tls.Verification == "custom_ca" && (tls.CAReference == nil || strings.TrimSpace(*tls.CAReference) == "") {
		return fmt.Errorf("%w: custom CA reference is required", ErrInvalidInput)
	}
	if tls.Verification != "custom_ca" && tls.CAReference != nil {
		return fmt.Errorf("%w: CA reference requires custom_ca verification", ErrInvalidInput)
	}
	for name, value := range map[string]*string{"server_name": tls.ServerName, "ca_reference": tls.CAReference, "client_credential_reference": tls.ClientCredentialReference} {
		if value != nil {
			if err := validateWriteOnlyReferenceOrHost(name, *value); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *ResourceService) validateOriginPolicy(origin RouteOriginRequest) error {
	if origin.TLS != nil && origin.TLS.Verification == "insecure_development" && !s.allowInsecureDevelopment {
		return fmt.Errorf("%w: insecure_development origin TLS is disabled outside explicit development policy", ErrInvalidInput)
	}
	return nil
}

func validateWriteOnlyReferenceOrHost(name, value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\t") {
		return fmt.Errorf("%w: %s is invalid", ErrInvalidInput, name)
	}
	if name != "server_name" {
		return validateWriteOnlyReference(value)
	}
	if err := validateHostOnly(value); err != nil {
		return fmt.Errorf("%w: TLS server name is invalid", ErrInvalidInput)
	}
	return nil
}

func validateWriteOnlyReference(value string) error {
	value = strings.TrimSpace(value)
	if len(value) < 24 || len(value) > 512 || strings.ContainsAny(value, "\r\n\t ") || strings.Contains(strings.ToLower(value), "bearer") || strings.Contains(strings.ToLower(value), "token=") {
		return fmt.Errorf("%w: write-only reference is invalid", ErrInvalidInput)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Host != "paperboat" || parsed.RawQuery != "" || parsed.Fragment != "" || len(parsed.Path) < 2 {
		return fmt.Errorf("%w: write-only reference must be an opaque Paperboat secret-store reference", ErrInvalidInput)
	}
	switch parsed.Scheme {
	case "keychain", "credential-manager", "secret-service", "protected-file", "tpm":
	default:
		return fmt.Errorf("%w: write-only reference scheme is invalid", ErrInvalidInput)
	}
	for _, character := range strings.TrimPrefix(parsed.Path, "/") {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._~:/@+-", character) {
			continue
		}
		return fmt.Errorf("%w: write-only reference contains invalid characters", ErrInvalidInput)
	}
	return nil
}

func normalizeBindingHostname(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, ".")
	if value == "" || strings.HasSuffix(value, ".") {
		return "", "", fmt.Errorf("%w: hostname is invalid", ErrInvalidInput)
	}
	if strings.HasPrefix(value, "*.") {
		suffix, err := normalizeIDNAHostname(strings.TrimPrefix(value, "*."))
		if err != nil {
			return "", "", fmt.Errorf("%w: hostname: %v", ErrInvalidInput, err)
		}
		if len(strings.Split(suffix, ".")) < 2 {
			return "", "", fmt.Errorf("%w: wildcard must contain a registrable suffix", ErrInvalidInput)
		}
		return "*." + suffix, "one_label_wildcard", nil
	}
	if strings.Contains(value, "*") {
		return "", "", fmt.Errorf("%w: wildcard must cover exactly one label", ErrInvalidInput)
	}
	value, err := normalizeIDNAHostname(value)
	if err != nil {
		return "", "", fmt.Errorf("%w: hostname: %v", ErrInvalidInput, err)
	}
	return value, "exact", nil
}

func normalizeIDNAHostname(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n\t /?#@") {
		return "", errors.New("DNS name is invalid")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", errors.New("DNS name is invalid")
	}
	ascii = strings.ToLower(ascii)
	if err := validateDNSName(ascii); err != nil {
		return "", err
	}
	return ascii, nil
}

func normalizeCapabilities(values []string) ([]string, error) {
	set := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		switch value {
		case "http", "tcp_private", "h2c", "unix":
		default:
			return nil, fmt.Errorf("%w: unsupported connector capability", ErrInvalidInput)
		}
		set[value] = struct{}{}
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("%w: at least one connector capability is required", ErrInvalidInput)
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func wireMatchType(value string) string {
	if value == "managed" {
		return "managed_exact"
	}
	return value
}

func wireDomainState(ownership, conflict string) string {
	if conflict == "quarantined" {
		return "quarantined"
	}
	if conflict == "conflicted" {
		return "conflict"
	}
	switch ownership {
	case "pending":
		return "waiting_dns"
	case "verified":
		return "verified"
	case "failed":
		return "dns_error"
	case "expired":
		return "expired"
	case "revoked":
		return "quarantined"
	default:
		return "requested"
	}
}

func wireCertificateState(value string) string {
	if value == "pending" {
		return "not_requested"
	}
	return value
}

type resourceCursorCodec struct{ key []byte }
type resourceCursorPayload struct {
	Version   int       `json:"version"`
	Kind      string    `json:"kind"`
	AccountID string    `json:"account_id"`
	TunnelID  string    `json:"tunnel_id"`
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}
type logCursorPayload struct {
	Version   int    `json:"version"`
	Kind      string `json:"kind"`
	AccountID string `json:"account_id"`
	ScopeID   string `json:"scope_id"`
	Sequence  int64  `json:"sequence"`
}

func newResourceCursorCodec(key []byte) (*resourceCursorCodec, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("resource cursor signing key must contain at least 32 bytes")
	}
	return &resourceCursorCodec{key: append([]byte(nil), key...)}, nil
}
func (c *resourceCursorCodec) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
func (c *resourceCursorCodec) encode(payload any) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) > 512 {
		return "", previewtunnelapi.ErrInvalidCursor
	}
	signature := c.sign(raw)
	token := base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(token) > 2048 {
		return "", previewtunnelapi.ErrInvalidCursor
	}
	return token, nil
}
func (c *resourceCursorCodec) decode(raw string, target any) error {
	if raw == "" {
		return nil
	}
	if len(raw) > 2048 {
		return previewtunnelapi.ErrInvalidCursor
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return previewtunnelapi.ErrInvalidCursor
	}
	enc := base64.RawURLEncoding.Strict()
	payload, err := enc.DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > 512 {
		return previewtunnelapi.ErrInvalidCursor
	}
	signature, err := enc.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size || !hmac.Equal(signature, c.sign(payload)) {
		return previewtunnelapi.ErrInvalidCursor
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return previewtunnelapi.ErrInvalidCursor
	}
	return nil
}
func (c *resourceCursorCodec) EncodeList(kind, accountID, tunnelID string, position ListPosition) (string, error) {
	if kind == "" || accountID == "" || tunnelID == "" || position.ID == "" || position.CreatedAt.IsZero() {
		return "", previewtunnelapi.ErrInvalidCursor
	}
	return c.encode(resourceCursorPayload{Version: 1, Kind: kind, AccountID: accountID, TunnelID: tunnelID, CreatedAt: position.CreatedAt.UTC(), ID: position.ID})
}
func (c *resourceCursorCodec) DecodeList(raw, kind, accountID, tunnelID string) (*ListPosition, error) {
	if raw == "" {
		return nil, nil
	}
	var value resourceCursorPayload
	if err := c.decode(raw, &value); err != nil || value.Version != 1 || value.Kind != kind || value.AccountID != accountID || value.TunnelID != tunnelID || value.ID == "" || value.CreatedAt.IsZero() {
		return nil, previewtunnelapi.ErrInvalidCursor
	}
	return &ListPosition{ID: value.ID, CreatedAt: value.CreatedAt.UTC()}, nil
}
func (s *ResourceService) decodeListCursor(raw, accountID, tunnelID, kind string) (*ListPosition, error) {
	return s.cursors.DecodeList(raw, kind, accountID, tunnelID)
}
func (c *resourceCursorCodec) EncodeLog(kind, accountID, scopeID string, sequence int64) (string, error) {
	if kind == "" || accountID == "" || scopeID == "" || sequence < 0 {
		return "", previewtunnelapi.ErrInvalidCursor
	}
	return c.encode(logCursorPayload{Version: 1, Kind: kind, AccountID: accountID, ScopeID: scopeID, Sequence: sequence})
}
func (c *resourceCursorCodec) DecodeLog(raw, kind, accountID, scopeID string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	var value logCursorPayload
	if err := c.decode(raw, &value); err != nil || value.Version != 1 || value.Kind != kind || value.AccountID != accountID || value.ScopeID != scopeID || value.Sequence < 0 {
		return 0, previewtunnelapi.ErrInvalidCursor
	}
	return value.Sequence, nil
}
