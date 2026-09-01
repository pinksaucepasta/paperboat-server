// Package tunnelcert owns the server-side public TLS lifecycle.  It deliberately
// keeps certificate private keys out of resource views, operation results, audit
// metadata, and logs.  Edge distribution is an authenticated internal boundary;
// callers must use the safe view types for every API-facing projection.
package tunnelcert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

var (
	ErrInvalid                 = errors.New("invalid tunnel certificate request")
	ErrMasterKeyUnavailable    = errors.New("certificate master key is unavailable")
	ErrIssuanceLocked          = errors.New("certificate issuance is already locked")
	ErrCAAUnavailable          = errors.New("certificate authority policy is unavailable")
	ErrCAABlocked              = errors.New("certificate authority policy blocks issuance")
	ErrDNSChallengePending     = errors.New("DNS-01 challenge is pending")
	ErrDNSChallengeUnavailable = errors.New("DNS-01 challenge is unavailable")
	ErrIssuerUnavailable       = errors.New("certificate issuer is unavailable")
	ErrIssuerRateLimited       = errors.New("certificate issuer rate limited")
	ErrCertificateInvalid      = errors.New("issued certificate is invalid")
	ErrCertificateNotReady     = errors.New("certificate distribution is not ready")
	ErrDistributionUnavailable = errors.New("certificate distribution is unavailable")
	ErrGenerationConflict      = errors.New("certificate domain generation is stale")
	ErrCertificateRevoked      = errors.New("certificate is revoked")
)

type Strategy string

const (
	StrategyDelegatedDNS01 Strategy = "delegated_dns01"
	// StrategyPlatformDNS01 is the server-owned Cloudflare DNS-01 path. It is
	// distinct from delegated customer challenges because it writes directly to
	// the platform zone's _acme-challenge record.
	StrategyPlatformDNS01 Strategy = "platform_dns01"
	StrategyProvided      Strategy = "provided_reference"
	StrategyOnDemandLeaf  Strategy = "on_demand_leaf"
	StrategyWildcard      Strategy = "wildcard_fallback"
)

type State string

const (
	StateStaged     State = "staged"
	StateActive     State = "active"
	StateSuperseded State = "superseded"
	StateRevoked    State = "revoked"
	StateExpired    State = "expired"
	StateFailed     State = "failed"
)

// TargetKind identifies the owner of a domain/certificate binding. A
// certificate is always bound to exactly one durable route or one foreground
// preview lease. Keeping this discriminator in the TLS contract prevents a
// preview identifier from being interpreted as a durable tunnel route (or
// vice versa) when a binding is retried or distributed.
type TargetKind string

const (
	TargetDurableRoute TargetKind = "durable_route"
	TargetPreviewLease TargetKind = "preview_lease"
	// TargetPlatformWildcard identifies a server-owned preview/tunnel
	// wildcard. It is distributed to exact edge process targets, but is not
	// owned by a tunnel route or preview lease.
	TargetPlatformWildcard TargetKind = "platform_wildcard"

	// These aliases keep the meaning obvious at call sites that refer to the
	// field rather than the target value.
	TargetKindDurableRoute     = TargetDurableRoute
	TargetKindPreviewLease     = TargetPreviewLease
	TargetKindPlatformWildcard = TargetPlatformWildcard
)

// CertificateTarget is the immutable target identity shared by issuance,
// persistence, distribution, and readiness checks. DomainID is the custom
// domain binding in either target family. Exactly one of RouteID or PreviewID
// is populated according to Kind; preview generations fence lease reuse.
type CertificateTarget struct {
	Kind              TargetKind
	DomainID          string
	AccountID         string
	TunnelID          string
	RouteID           string
	PreviewID         string
	PreviewGeneration uint64
	PreviewState      string
	PreviewExpiresAt  time.Time
}

func (t CertificateTarget) normalizedKind() TargetKind {
	if t.Kind != "" {
		return t.Kind
	}
	if t.PreviewID != "" || t.PreviewGeneration != 0 {
		return TargetPreviewLease
	}
	return TargetDurableRoute
}

func (t CertificateTarget) Validate() error {
	if !validIdentifier(t.DomainID) || !validIdentifier(t.AccountID) {
		return fmt.Errorf("%w: target identity is invalid", ErrInvalid)
	}
	kind := t.normalizedKind()
	switch kind {
	case TargetDurableRoute:
		if !validIdentifier(t.TunnelID) {
			return fmt.Errorf("%w: durable target tunnel is invalid", ErrInvalid)
		}
		// An omitted route ID is accepted only for legacy in-memory fixtures.
		// Persisted/explicit durable targets must identify the route.
		if t.Kind != "" && !validIdentifier(t.RouteID) {
			return fmt.Errorf("%w: durable target route is invalid", ErrInvalid)
		}
		if t.PreviewID != "" || t.PreviewGeneration != 0 || t.PreviewState != "" || !t.PreviewExpiresAt.IsZero() {
			return fmt.Errorf("%w: durable target contains preview-lease fields", ErrInvalid)
		}
	case TargetPreviewLease:
		if t.TunnelID != "" || t.RouteID != "" || !validIdentifier(t.PreviewID) || t.PreviewGeneration == 0 {
			return fmt.Errorf("%w: preview target identity is invalid", ErrInvalid)
		}
	case TargetPlatformWildcard:
		if t.TunnelID != "" || t.RouteID != "" || t.PreviewID != "" || t.PreviewGeneration != 0 || t.PreviewState != "" || !t.PreviewExpiresAt.IsZero() {
			return fmt.Errorf("%w: platform wildcard target contains route or lease identity", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: target kind is invalid", ErrInvalid)
	}
	return nil
}

func (t CertificateTarget) ValidateActive(now time.Time) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if t.normalizedKind() == TargetPreviewLease && (t.PreviewState != "active" || t.PreviewExpiresAt.IsZero() || !t.PreviewExpiresAt.After(now.UTC())) {
		return fmt.Errorf("%w: preview lease is not active", ErrCertificateRevoked)
	}
	return nil
}

func (t CertificateTarget) Key() string {
	return strings.Join([]string{string(t.normalizedKind()), t.DomainID, t.AccountID, t.TunnelID, t.RouteID, t.PreviewID, fmt.Sprint(t.PreviewGeneration)}, "\x00")
}

// Domain is the immutable input fence captured from tunnel_domains.  Edge
// targets are sorted and validated before issuance so a retry cannot silently
// expand to a newly connected edge.
type Domain struct {
	ID        string
	AccountID string
	TunnelID  string
	// TargetKind is explicit for production bindings. An empty value is
	// treated as the durable route target for older in-memory callers.
	TargetKind        TargetKind
	RouteID           string
	PreviewID         string
	PreviewGeneration uint64
	PreviewState      string
	PreviewExpiresAt  time.Time
	Hostname          string
	// ChallengeReference is the immutable, server-issued reference captured
	// when the domain binding is created. It is used only to derive the
	// Paperboat-owned DNS-01 delegation target; it is never sent to an ACME
	// provider or exposed in a certificate view.
	ChallengeReference    string
	Generation            uint64
	Strategy              Strategy
	OwnershipState        string
	CAAState              string
	CertificateReference  string
	CertificateGeneration uint64
	RenewalDue            bool
	AllowOnDemandFallback bool
	// LeafHostname is an ephemeral exact SNI requested under a verified
	// one-label wildcard binding. It is never persisted as the wildcard
	// domain's primary certificate hostname.
	LeafHostname string
	Issuer       string
	EdgeTargets  []EdgeTarget
}

func (d Domain) Target() CertificateTarget {
	return CertificateTarget{
		Kind: d.TargetKind, DomainID: d.ID, AccountID: d.AccountID,
		TunnelID: d.TunnelID, RouteID: d.RouteID, PreviewID: d.PreviewID,
		PreviewGeneration: d.PreviewGeneration, PreviewState: d.PreviewState,
		PreviewExpiresAt: d.PreviewExpiresAt,
	}
}

// DelegatedChallengeTarget returns the stable TXT target for a domain's
// delegated DNS-01 challenge. The target is derived from the immutable domain
// identity and challenge reference, then placed below the server-owned zone.
// It deliberately does not use the customer hostname as a write target.
func DelegatedChallengeTarget(domainID, accountID, tunnelID, challengeReference, challengeZone string) (string, error) {
	for name, value := range map[string]string{"domain_id": domainID, "account_id": accountID, "tunnel_id": tunnelID, "challenge_reference": challengeReference} {
		if !validMetadata(value, 512) {
			return "", fmt.Errorf("%w: %s is invalid", ErrDNSChallengeUnavailable, name)
		}
	}
	zone, wildcard, err := normalizeHostname(challengeZone)
	if err != nil || wildcard {
		return "", fmt.Errorf("%w: challenge zone is invalid", ErrDNSChallengeUnavailable)
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{domainID, accountID, tunnelID, challengeReference}, "\x00")))
	target := "pb-" + hex.EncodeToString(digest[:16]) + "." + zone
	canonicalTarget, targetWildcard, targetErr := normalizeHostname(target)
	if targetErr != nil || targetWildcard || canonicalTarget != target {
		return "", fmt.Errorf("%w: delegated challenge target is invalid", ErrDNSChallengeUnavailable)
	}
	return canonicalTarget, nil
}

// DelegatedChallengeTargetForDomain derives the same server-owned challenge
// name for user-owned target families. Platform wildcards are Cloudflare-owned
// zones and deliberately write the ACME TXT directly at their authorization
// name; they must not depend on a customer-managed CNAME.
func DelegatedChallengeTargetForDomain(domain Domain, challengeZone string) (string, error) {
	kind := domain.Target().normalizedKind()
	targetID := domain.TunnelID
	if kind == TargetPreviewLease {
		targetID = domain.PreviewID
	}
	if kind != TargetDurableRoute && kind != TargetPreviewLease && kind != TargetPlatformWildcard {
		return "", fmt.Errorf("%w: target kind is invalid", ErrDNSChallengeUnavailable)
	}
	if kind == TargetPlatformWildcard {
		return PlatformDNSChallengeTargetForDomain(domain)
	}
	if kind == TargetPreviewLease {
		for name, value := range map[string]string{"domain_id": domain.ID, "account_id": domain.AccountID, "preview_id": targetID, "challenge_reference": domain.ChallengeReference} {
			if !validMetadata(value, 512) {
				return "", fmt.Errorf("%w: %s is invalid", ErrDNSChallengeUnavailable, name)
			}
		}
		zone, wildcard, err := normalizeHostname(challengeZone)
		if err != nil || wildcard {
			return "", fmt.Errorf("%w: challenge zone is invalid", ErrDNSChallengeUnavailable)
		}
		digest := sha256.Sum256([]byte(strings.Join([]string{domain.ID, domain.AccountID, string(kind), targetID, domain.ChallengeReference}, "\x00")))
		target := "pb-" + hex.EncodeToString(digest[:16]) + "." + zone
		canonicalTarget, targetWildcard, targetErr := normalizeHostname(target)
		if targetErr != nil || targetWildcard || canonicalTarget != target {
			return "", fmt.Errorf("%w: delegated challenge target is invalid", ErrDNSChallengeUnavailable)
		}
		return canonicalTarget, nil
	}
	return DelegatedChallengeTarget(domain.ID, domain.AccountID, targetID, domain.ChallengeReference, challengeZone)
}

// PlatformDNSChallengeTargetForDomain returns the direct Cloudflare TXT name
// for a server-owned wildcard. The leading underscore is valid for an ACME
// record name but not for a certificate hostname, so it is validated against
// the already-normalized wildcard base rather than normalizeHostname.
func PlatformDNSChallengeTargetForDomain(domain Domain) (string, error) {
	if domain.Target().normalizedKind() != TargetPlatformWildcard {
		return "", fmt.Errorf("%w: platform wildcard target is required", ErrDNSChallengeUnavailable)
	}
	host, wildcard, err := normalizeHostname(domain.Hostname)
	if err != nil || !wildcard || host != domain.Hostname {
		return "", fmt.Errorf("%w: platform wildcard hostname is invalid", ErrDNSChallengeUnavailable)
	}
	target := "_acme-challenge." + strings.TrimPrefix(host, "*.")
	if !validMetadata(target, 253) || strings.ContainsAny(target, "/:@?#\r\n\x00") {
		return "", fmt.Errorf("%w: platform DNS challenge target is invalid", ErrDNSChallengeUnavailable)
	}
	return target, nil
}

// NormalizeChallengeZone validates and normalizes the server-owned DNS zone
// used for delegated challenge targets. The bool result is always false for
// the accepted non-wildcard zone and is kept to make wildcard rejection
// explicit to callers building DNS instructions.
func NormalizeChallengeZone(raw string) (string, bool, error) {
	return normalizeHostname(raw)
}

// NormalizeHostname returns the canonical DNS wire-form hostname used by
// certificate policy and issuance boundaries. The bool reports a leading
// wildcard and callers handling SNI must reject it.
func NormalizeHostname(raw string) (string, bool, error) {
	return normalizeHostname(raw)
}

type EdgeTarget struct {
	NodeID       string
	ProcessEpoch string
	Generation   uint64
}

func (d Domain) Validate() error {
	// Domain validation is structural. Lease activity is time-dependent and
	// must be checked by the coordinator against its injected clock so retries,
	// tests, and persisted recovery all use one authoritative instant.
	if err := d.Target().Validate(); err != nil {
		return err
	}
	if d.Generation == 0 {
		return fmt.Errorf("%w: domain generation is required", ErrInvalid)
	}
	host, wildcard, err := normalizeHostname(d.Hostname)
	if err != nil {
		return err
	}
	if d.Hostname != host {
		return fmt.Errorf("%w: hostname must be canonical", ErrInvalid)
	}
	if d.Strategy == StrategyOnDemandLeaf && (!wildcard || d.LeafHostname == "") {
		if !(wildcard && d.LeafHostname == "" && d.AllowOnDemandFallback) {
			return fmt.Errorf("%w: on-demand leaf requests require an exact hostname under a wildcard binding", ErrInvalid)
		}
	}
	if d.LeafHostname != "" {
		if d.Strategy != StrategyOnDemandLeaf || !wildcard {
			return fmt.Errorf("%w: exact leaf hostname requires an on-demand wildcard binding", ErrInvalid)
		}
		leaf, leafWildcard, leafErr := normalizeHostname(d.LeafHostname)
		if leafErr != nil || leafWildcard || d.LeafHostname != leaf || !oneLabelUnderWildcard(leaf, host) {
			return fmt.Errorf("%w: exact leaf hostname is outside the wildcard binding", ErrInvalid)
		}
	}
	switch d.Strategy {
	case StrategyDelegatedDNS01, StrategyProvided, StrategyOnDemandLeaf, StrategyWildcard:
	case StrategyPlatformDNS01:
		if d.Target().normalizedKind() != TargetPlatformWildcard {
			return fmt.Errorf("%w: platform DNS-01 strategy requires a platform wildcard target", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: certificate strategy is invalid", ErrInvalid)
	}
	if d.Target().normalizedKind() == TargetPlatformWildcard && d.Strategy != StrategyPlatformDNS01 {
		return fmt.Errorf("%w: platform wildcard target requires platform DNS-01 strategy", ErrInvalid)
	}
	if d.OwnershipState != "verified" {
		return fmt.Errorf("%w: domain ownership is not verified", ErrInvalid)
	}
	if d.CAAState != "" && d.CAAState != "unknown" && d.CAAState != "ready" && d.CAAState != "not_applicable" {
		return fmt.Errorf("%w: CAA state is not ready", ErrCAABlocked)
	}
	seen := make(map[string]struct{}, len(d.EdgeTargets))
	for _, target := range d.EdgeTargets {
		if !validIdentifier(target.NodeID) || !validEpoch(target.ProcessEpoch) || target.Generation == 0 {
			return fmt.Errorf("%w: edge target binding is invalid", ErrInvalid)
		}
		key := target.NodeID + "\x00" + target.ProcessEpoch
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: duplicate edge target", ErrInvalid)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func oneLabelUnderWildcard(leaf, wildcard string) bool {
	if !strings.HasPrefix(wildcard, "*.") || leaf == "" {
		return false
	}
	suffix := strings.TrimPrefix(wildcard, "*.")
	if !strings.HasSuffix(leaf, "."+suffix) {
		return false
	}
	prefix := strings.TrimSuffix(leaf, "."+suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

// OneLabelUnderWildcard reports whether leaf is exactly one DNS label below
// wildcard. It is exported for the authenticated first-SNI path so policy
// containment has one implementation on the server and cannot drift from
// validation used by the coordinator.
func OneLabelUnderWildcard(leaf, wildcard string) bool {
	return oneLabelUnderWildcard(leaf, wildcard)
}

func normalizeHostname(raw string) (string, bool, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/:@?#\r\n\x00") {
		return "", false, fmt.Errorf("%w: hostname is invalid", ErrInvalid)
	}
	wildcard := strings.HasPrefix(host, "*.")
	base := host
	if wildcard {
		base = host[2:]
	}
	// Domains are stored and compared in their DNS wire form.  Convert
	// internationalized input before applying the ASCII label constraints so
	// ownership, certificate SANs, and edge matchers share one representation.
	ascii, err := idna.Lookup.ToASCII(base)
	if err != nil {
		return "", false, fmt.Errorf("%w: hostname is invalid", ErrInvalid)
	}
	base = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if wildcard {
		host = "*." + base
	} else {
		host = base
	}
	if host == "" || len(host) > 253 {
		return "", false, fmt.Errorf("%w: hostname is invalid", ErrInvalid)
	}
	if strings.Contains(base, "*") || net.ParseIP(base) != nil {
		return "", false, fmt.Errorf("%w: hostname is invalid", ErrInvalid)
	}
	if wildcard {
		suffix := strings.TrimPrefix(host, "*.")
		if strings.Count(suffix, ".") < 1 || !dnsNamePattern.MatchString(suffix) {
			return "", false, fmt.Errorf("%w: wildcard hostname is invalid", ErrInvalid)
		}
		return host, true, nil
	}
	if !dnsNamePattern.MatchString(host) {
		return "", false, fmt.Errorf("%w: hostname is invalid", ErrInvalid)
	}
	return host, false, nil
}

var dnsNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func validIdentifier(value string) bool {
	if len(value) < 3 || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func validEpoch(value string) bool {
	return len(value) >= 8 && len(value) <= 128 && strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == ""
}

// CertificateBundle is deliberately not JSON serializable.  It exists only at
// the issuer-to-envelope and envelope-to-authenticated-edge boundaries.
type CertificateBundle struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Issuer         string
	NotBefore      time.Time
	NotAfter       time.Time
}

func (b CertificateBundle) Validate(hostname string, now time.Time, maxLifetime time.Duration) (CertificateIdentity, error) {
	host, wildcard, err := normalizeHostname(hostname)
	if err != nil {
		return CertificateIdentity{}, err
	}
	if len(b.CertificatePEM) == 0 || len(b.CertificatePEM) > 16<<20 || len(b.PrivateKeyPEM) == 0 || len(b.PrivateKeyPEM) > 16<<20 || !validMetadata(b.Issuer, 256) {
		return CertificateIdentity{}, fmt.Errorf("%w: bundle is empty or oversized", ErrCertificateInvalid)
	}
	certBlock, _ := pem.Decode(b.CertificatePEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return CertificateIdentity{}, fmt.Errorf("%w: certificate PEM is invalid", ErrCertificateInvalid)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return CertificateIdentity{}, fmt.Errorf("%w: parse certificate: %v", ErrCertificateInvalid, err)
	}
	key, err := parsePrivateKey(b.PrivateKeyPEM)
	if err != nil {
		return CertificateIdentity{}, fmt.Errorf("%w: parse private key: %v", ErrCertificateInvalid, err)
	}
	if !publicKeysEqual(cert.PublicKey, publicKey(key)) {
		return CertificateIdentity{}, fmt.Errorf("%w: certificate and private key do not match", ErrCertificateInvalid)
	}
	if !cert.NotAfter.After(now) || cert.NotBefore.After(now.Add(10*time.Minute)) || maxLifetime > 0 && cert.NotAfter.Sub(now) > maxLifetime {
		return CertificateIdentity{}, fmt.Errorf("%w: certificate lifetime is outside bounds", ErrCertificateInvalid)
	}
	verifyHost := host
	if wildcard {
		verifyHost = "paperboat." + host[2:]
	}
	if err := cert.VerifyHostname(verifyHost); err != nil {
		return CertificateIdentity{}, fmt.Errorf("%w: certificate does not cover %s", ErrCertificateInvalid, host)
	}
	if !b.NotBefore.IsZero() && !b.NotBefore.Equal(cert.NotBefore) || !b.NotAfter.IsZero() && !b.NotAfter.Equal(cert.NotAfter) {
		return CertificateIdentity{}, fmt.Errorf("%w: issuer timestamps do not match certificate", ErrCertificateInvalid)
	}
	digest := sha256.Sum256(cert.Raw)
	return CertificateIdentity{Fingerprint: digest, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, Hostname: host, Wildcard: wildcard, Issuer: b.Issuer}, nil
}

// validateExactLeafBundle is stricter than ordinary hostname coverage:
// wildcard SANs are intentionally rejected so a fallback cannot silently
// turn one requested SNI into a broadly valid certificate.
func validateExactLeafBundle(bundle CertificateBundle, hostname string, now time.Time, maxLifetime time.Duration) error {
	host, wildcard, err := normalizeHostname(hostname)
	if err != nil || wildcard {
		return fmt.Errorf("%w: exact leaf hostname is invalid", ErrCertificateInvalid)
	}
	identity, err := bundle.Validate(host, now, maxLifetime)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(bundle.CertificatePEM)
	if block == nil {
		return fmt.Errorf("%w: exact leaf certificate is invalid", ErrCertificateInvalid)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: exact leaf certificate is invalid", ErrCertificateInvalid)
	}
	for _, name := range certificate.DNSNames {
		if strings.HasPrefix(strings.ToLower(name), "*.") {
			return fmt.Errorf("%w: exact leaf certificate contains wildcard SAN", ErrCertificateInvalid)
		}
	}
	if identity.Hostname != host || identity.Wildcard {
		return fmt.Errorf("%w: exact leaf certificate is not bound to requested hostname", ErrCertificateInvalid)
	}
	return nil
}

type CertificateIdentity struct {
	Fingerprint [sha256.Size]byte
	NotBefore   time.Time
	NotAfter    time.Time
	Hostname    string
	Wildcard    bool
	Issuer      string
}

func parsePrivateKey(raw []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("private key PEM is invalid")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key")
}

func publicKey(key crypto.PrivateKey) crypto.PublicKey {
	switch value := key.(type) {
	case *rsa.PrivateKey:
		return &value.PublicKey
	case *ecdsa.PrivateKey:
		return &value.PublicKey
	case ed25519.PrivateKey:
		return value.Public()
	default:
		return nil
	}
}

func publicKeysEqual(left, right crypto.PublicKey) bool {
	if left == nil || right == nil {
		return false
	}
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDER, rightDER)
}

// SortEdgeTargets produces a deterministic target-set projection used in the
// distributed issuance lock and edge distribution correlation.
func SortEdgeTargets(targets []EdgeTarget) []EdgeTarget {
	result := append([]EdgeTarget(nil), targets...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].NodeID != result[j].NodeID {
			return result[i].NodeID < result[j].NodeID
		}
		if result[i].ProcessEpoch != result[j].ProcessEpoch {
			return result[i].ProcessEpoch < result[j].ProcessEpoch
		}
		return result[i].Generation < result[j].Generation
	})
	return result
}

type CertificateView struct {
	Reference             string     `json:"reference"`
	Fingerprint           string     `json:"fingerprint"`
	State                 State      `json:"state"`
	TargetKind            TargetKind `json:"target_kind,omitempty"`
	RouteID               string     `json:"route_id,omitempty"`
	PreviewID             string     `json:"preview_id,omitempty"`
	PreviewGeneration     uint64     `json:"preview_generation,omitempty"`
	DomainGeneration      uint64     `json:"domain_generation"`
	CertificateGeneration uint64     `json:"certificate_generation"`
	Issuer                string     `json:"issuer"`
	NotBefore             time.Time  `json:"not_before"`
	ExpiresAt             time.Time  `json:"expires_at"`
	RenewalAt             time.Time  `json:"renewal_at"`
	FailureCode           string     `json:"failure_code,omitempty"`
}

func (v CertificateView) ValidateSafe() error {
	if !validMetadata(v.Reference, 256) || !validMetadata(v.Fingerprint, 128) || !validMetadata(v.Issuer, 256) || !validOptionalMetadata(v.FailureCode, 128) {
		return fmt.Errorf("%w: unsafe certificate view", ErrInvalid)
	}
	return nil
}

func validMetadata(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	return true
}

func validOptionalMetadata(value string, maximum int) bool {
	return value == "" || validMetadata(value, maximum)
}

func validKeyReference(value string) bool {
	if len(value) < 1 || len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':' || r == '/') {
			return false
		}
	}
	return !strings.Contains(strings.ToLower(value), "begin ") && !strings.Contains(strings.ToLower(value), "private key")
}
