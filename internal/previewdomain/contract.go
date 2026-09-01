// Package previewdomain owns custom-domain bindings whose target is a
// foreground preview lease.  A preview domain is an alias of an existing
// lease, never a second tunnel or connector.
package previewdomain

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	Schema     = "paperboat.preview-tunnel/v1"
	Kind       = "domain_binding"
	TargetKind = "preview_lease"
	MaxDomains = 8
	Quarantine = 7 * 24 * time.Hour
)

var (
	ErrInvalidInput        = errors.New("invalid preview domain input")
	ErrNotFound            = errors.New("preview domain not found")
	ErrOwnerDenied         = errors.New("preview domain owner denied")
	ErrLeaseNotActive      = errors.New("preview lease is not active")
	ErrDomainConflict      = errors.New("preview domain hostname is already claimed")
	ErrGenerationConflict  = errors.New("preview domain generation conflict")
	ErrIdempotencyConflict = errors.New("preview domain idempotency key conflicts with an earlier operation")
	ErrDNSUnavailable      = errors.New("preview domain DNS instructions are unavailable")
	ErrCertificatePending  = errors.New("preview domain certificate is not ready")
)

// Config contains policy dependencies.  NewID is used only for server-owned
// identifiers and never for a customer hostname or credential.
type Config struct {
	CursorKey       []byte
	ChallengeZone   string
	Now             func() time.Time
	NewID           func(string) (string, error)
	LeaseOwnerGrace time.Duration
}

type MutationInput struct {
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestHash        [sha256.Size]byte
}

type Request struct {
	Hostname            string
	Provider            string
	CertificateStrategy string
	Mutation            MutationInput
}

// BatchCreateRequest is used by a preview create transaction.  IDs are
// intentionally omitted: the server allocates them after validating every
// request, so a failed batch cannot partially publish aliases.
type BatchCreateRequest struct {
	AccountID         string
	PreviewID         string
	PreviewGeneration int64
	StableEndpoint    string
	Domains           []Request
	ActorID           string
	ActorType         string
	RequestID         string
	CorrelationID     string
	Now               time.Time
}

type MutationResult struct {
	Domain    DomainView                 `json:"domain"`
	Operation previewtunnelapi.Operation `json:"operation"`
	Replayed  bool                       `json:"replayed"`
	Changed   bool                       `json:"changed"`
}

type Page struct {
	Items      []DomainView `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

// DomainView is the full domain_binding projection.  It deliberately carries
// only the preview target identity and no route/tunnel identity.
type DomainView struct {
	Schema         string           `json:"schema"`
	Kind           string           `json:"kind"`
	ID             string           `json:"id"`
	AccountID      string           `json:"account_id"`
	TargetKind     string           `json:"target_kind"`
	PreviewID      string           `json:"preview_id"`
	Hostname       string           `json:"hostname"`
	MatchType      string           `json:"match_type"`
	WildcardLabels *int             `json:"wildcard_labels,omitempty"`
	State          string           `json:"state"`
	DNS            DNSState         `json:"dns"`
	Certificate    CertificateState `json:"certificate"`
	Generation     int64            `json:"generation"`
	ETag           string           `json:"etag"`
}

type DNSState struct {
	Target          string     `json:"target"`
	ObservedRecords []string   `json:"observed_records,omitempty"`
	LastCheckedAt   *time.Time `json:"last_checked_at,omitempty"`
}

type CertificateState struct {
	State     string         `json:"state"`
	Reference string         `json:"reference,omitempty"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	Failure   map[string]any `json:"failure"`
}

type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

type DNSInstructions struct {
	Schema              string      `json:"schema"`
	Kind                string      `json:"kind"`
	TargetKind          string      `json:"target_kind"`
	PreviewID           string      `json:"preview_id"`
	DomainID            string      `json:"domain_id"`
	Hostname            string      `json:"hostname"`
	Provider            string      `json:"provider"`
	Records             []DNSRecord `json:"records"`
	CertificateStrategy string      `json:"certificate_strategy"`
	VerificationState   string      `json:"verification_state"`
	Note                string      `json:"note"`
}

// ReadyAlias is intentionally smaller than DomainView and is used by edge
// admission publication.  It is returned only when the lease, DNS ownership,
// certificate, and certificate reference are all current.
type ReadyAlias struct {
	DomainID              string `json:"domain_id"`
	PreviewID             string `json:"preview_id"`
	PreviewGeneration     int64  `json:"preview_generation"`
	Hostname              string `json:"hostname"`
	MatchType             string `json:"match_type"`
	WildcardLabels        *int   `json:"wildcard_labels,omitempty"`
	Generation            int64  `json:"generation"`
	CertificateReference  string `json:"certificate_reference"`
	CertificateGeneration int64  `json:"certificate_generation"`
}

// ReadyAliasRecord joins a preview binding to the independently persisted
// active certificate record. Certificate generation is intentionally not
// inferred from the preview-domain mutation generation.
type ReadyAliasRecord struct {
	Domain                dbsqlc.PreviewDomain
	CertificateReference  string
	CertificateGeneration int64
}

type DNSObservation struct {
	Records     []string
	TTL         time.Duration
	Verified    bool
	FailureCode string
	Now         time.Time
	NextCheck   time.Time
}

type CertificateObservation struct {
	State              string
	Reference          *string
	ExpiresAt          *time.Time
	FailureCode        *string
	CAAState           string
	ExpectedGeneration int64
	Now                time.Time
}

type LeaseContext struct {
	ID              string
	AccountID       string
	Generation      int64
	LeaseDeadline   time.Time
	Endpoint        string
	UserDeadline    sql.NullTime
	AllocationState string
	EdgeState       string
	OriginState     string
	TerminalState   string
	OwnerDeviceID   string
	OwnerSessionID  string
}

type PreviewDomainRepository interface {
	List(context.Context, string, string, *ListPosition, int) ([]dbsqlc.PreviewDomain, error)
	Get(context.Context, string, string, string) (dbsqlc.PreviewDomain, error)
	Lease(context.Context, string, string) (LeaseContext, error)
	Create(context.Context, CreateRecord) (RepositoryMutation, error)
	Verify(context.Context, MutationRecord) (RepositoryMutation, error)
	Delete(context.Context, MutationRecord) (RepositoryMutation, error)
	ApplyDNSObservation(context.Context, DNSObservationRecord) (RepositoryMutation, error)
	ApplyCertificateObservation(context.Context, CertificateObservationRecord) (RepositoryMutation, error)
	ReadyAliases(context.Context, string, string, time.Time) ([]ReadyAliasRecord, error)
}

type ListPosition struct {
	CreatedAt time.Time
	ID        string
}

type CreateRecord struct {
	OperationID         string
	AuditEventID        string
	AccountID           string
	PreviewID           string
	DomainID            string
	PreviewGeneration   int64
	Hostname            string
	MatchType           string
	ChallengeReference  string
	DNSTarget           string
	DNSProvider         string
	ExpectedRecords     []byte
	CertificateStrategy string
	IdempotencyKey      string
	RequestHash         [sha256.Size]byte
	ActorID             string
	ActorType           string
	RequestID           string
	CorrelationID       string
	SourceDeviceID      string
	Now                 time.Time
}

type MutationRecord struct {
	OperationID        string
	AuditEventID       string
	AccountID          string
	PreviewID          string
	DomainID           string
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestHash        [sha256.Size]byte
	ActorID            string
	ActorType          string
	RequestID          string
	CorrelationID      string
	SourceDeviceID     string
	Now                time.Time
}

type DNSObservationRecord struct {
	MutationRecord
	ObservedRecords []byte
	OwnershipState  string
	ConflictState   string
	NextCheckAt     time.Time
	TTLSeconds      *int32
	Verified        bool
}

type CertificateObservationRecord struct {
	MutationRecord
	CertificateState     string
	CertificateReference *string
	CertificateExpiresAt *time.Time
	FailureCode          *string
	CAAState             string
}

type RepositoryMutation struct {
	Domain    dbsqlc.PreviewDomain
	Operation dbsqlc.Operation
	Replayed  bool
	Changed   bool
}

func NormalizeHostname(raw string) (string, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed != raw || trimmed == "" || strings.HasSuffix(trimmed, ".") {
		// A trailing root dot is accepted as input by the shared policy, but a
		// persisted value is always canonical.  Whitespace is never persisted.
		trimmed = strings.TrimSuffix(trimmed, ".")
	}
	host, wildcard, err := normalizeHostname(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("%w: hostname is invalid", ErrInvalidInput)
	}
	if wildcard {
		return host, "one_label_wildcard", nil
	}
	return host, "exact", nil
}

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func normalizeHostname(raw string) (string, bool, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/:@?#\r\n\x00") {
		return "", false, ErrInvalidInput
	}
	wildcard := strings.HasPrefix(host, "*.")
	base := host
	if wildcard {
		base = strings.TrimPrefix(host, "*.")
	}
	ascii, err := idna.Lookup.ToASCII(base)
	if err != nil {
		return "", false, ErrInvalidInput
	}
	base = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if base == "" || net.ParseIP(base) != nil || strings.Contains(base, "*") {
		return "", false, ErrInvalidInput
	}
	parts := strings.Split(base, ".")
	if len(parts) < 2 {
		return "", false, ErrInvalidInput
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 || !dnsLabelPattern.MatchString(part) {
			return "", false, ErrInvalidInput
		}
	}
	if wildcard {
		return "*." + base, true, nil
	}
	return base, false, nil
}

func ValidateCertificateStrategy(raw, matchType string) (string, error) {
	strategy := strings.ToLower(strings.TrimSpace(raw))
	if strategy == "" {
		strategy = "managed"
	}
	switch strategy {
	case "managed", "provided_reference":
		return strategy, nil
	case "on_demand_leaf":
		if matchType != "one_label_wildcard" {
			return "", fmt.Errorf("%w: on_demand_leaf requires one-label wildcard", ErrInvalidInput)
		}
		return strategy, nil
	case "none":
		return strategy, nil
	default:
		return "", fmt.Errorf("%w: unsupported certificate strategy", ErrInvalidInput)
	}
}

func ValidateProvider(raw string) (string, error) {
	provider := strings.ToLower(strings.TrimSpace(raw))
	if provider == "" {
		return "generic", nil
	}
	switch provider {
	case "generic", "cloudflare", "route53", "google_cloud_dns", "digitalocean", "namecheap":
		return provider, nil
	default:
		return "", fmt.Errorf("%w: unsupported DNS provider", ErrInvalidInput)
	}
}

func DNSRecordType(hostname, provider string) string {
	base := strings.TrimPrefix(hostname, "*.")
	registrable, err := publicsuffix.EffectiveTLDPlusOne(base)
	if err == nil && registrable == base && !strings.HasPrefix(hostname, "*.") {
		if provider == "route53" {
			return "ALIAS"
		}
		if provider == "cloudflare" {
			return "CNAME"
		}
		return "ANAME"
	}
	return "CNAME"
}

func DNSInstructionNote(hostname, provider string) string {
	if DNSRecordType(hostname, provider) == "CNAME" {
		return "Add the shown CNAME. Paperboat waits for the exact record before TLS becomes ready."
	}
	return "Create the shown apex alias using your provider's supported ANAME, ALIAS, or CNAME-flattening record. Paperboat waits for DNS before TLS becomes ready."
}

func StableTargetHostname(endpoint string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: preview endpoint is not a safe HTTPS origin", ErrInvalidInput)
	}
	host, _, err := normalizeHostname(parsed.Hostname())
	if err != nil {
		return "", fmt.Errorf("%w: preview endpoint hostname is invalid", ErrInvalidInput)
	}
	return host, nil
}

func delegatedChallengeTarget(domainID, accountID, previewID, challengeReference, zone string) (string, error) {
	zoneHost, wildcard, err := normalizeHostname(zone)
	if err != nil || wildcard {
		return "", ErrDNSUnavailable
	}
	for _, value := range []string{domainID, accountID, previewID, challengeReference} {
		if strings.TrimSpace(value) == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return "", ErrDNSUnavailable
		}
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{domainID, accountID, TargetKind, previewID, challengeReference}, "\x00")))
	return "pb-" + fmt.Sprintf("%x", digest[:16]) + "." + zoneHost, nil
}

func DomainViewFromRow(row dbsqlc.PreviewDomain) DomainView {
	view := DomainView{Schema: Schema, Kind: Kind, ID: row.ID, AccountID: row.AccountID, TargetKind: TargetKind, PreviewID: row.PreviewID,
		Hostname: row.Hostname, MatchType: row.MatchType, State: wireState(row), Generation: row.Generation,
		ETag: previewtunnelapi.ETag(Kind, row.ID, row.Generation), Certificate: CertificateState{State: wireCertificateState(row.CertificateState), Failure: nil}, DNS: DNSState{Target: row.DnsTarget}}
	if row.MatchType == "one_label_wildcard" {
		labels := 1
		view.WildcardLabels = &labels
	}
	if row.DnsLastCheckedAt.Valid {
		value := row.DnsLastCheckedAt.Time.UTC()
		view.DNS.LastCheckedAt = &value
	}
	if len(row.ObservedRecords) > 0 {
		var values []string
		if err := jsonUnmarshalStrings(row.ObservedRecords, &values); err == nil {
			view.DNS.ObservedRecords = values
		}
	}
	if row.CertificateReference.Valid {
		view.Certificate.Reference = row.CertificateReference.String
	}
	if row.CertificateExpiresAt.Valid {
		value := row.CertificateExpiresAt.Time.UTC()
		view.Certificate.ExpiresAt = &value
	}
	if row.CertificateFailureCode.Valid {
		view.Certificate.Failure = map[string]any{"code": row.CertificateFailureCode.String}
	}
	return view
}

func wireCertificateState(value string) string {
	if value == "pending" {
		return "not_requested"
	}
	return value
}

func wireState(row dbsqlc.PreviewDomain) string {
	if row.DeletedAt.Valid {
		if row.ConflictState == "quarantined" {
			return "quarantined"
		}
		return "released"
	}
	switch row.ConflictState {
	case "quarantined":
		return "quarantined"
	case "conflicted":
		return "conflict"
	}
	switch row.OwnershipState {
	case "pending":
		return "waiting_dns"
	case "verified":
		switch row.CertificateState {
		case "pending", "issuing", "renewing":
			return "issuing_tls"
		case "ready":
			return "ready"
		case "failed", "expired", "revoked":
			return "tls_error"
		}
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

// jsonUnmarshalStrings is kept local so malformed persisted observations are
// omitted from the public projection rather than causing an unsafe response.
func jsonUnmarshalStrings(raw []byte, out *[]string) error {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return err
	}
	if len(values) > 64 {
		return errors.New("too many observed DNS records")
	}
	*out = append((*out)[:0], values...)
	return nil
}
