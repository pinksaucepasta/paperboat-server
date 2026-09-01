package tunnelcert

// This file contains the server-owned RFC 8555 client.  It intentionally
// stops at the authenticated issuer and DNS-provider boundaries: account
// signing keys and DNS API tokens are resolved by reference for one request,
// kept in memory, and never copied into a database row, wire view, audit event,
// or error string.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	defaultACMETimeout          = 2 * time.Minute
	defaultACMEPropagation      = 2 * time.Minute
	defaultACMECleanup          = 30 * time.Second
	defaultACMEPollInterval     = 2 * time.Second
	defaultACMERetryBase        = 500 * time.Millisecond
	defaultACMERetryMax         = 10 * time.Second
	maxACMEChainCertificates    = 16
	maxACMECertificateDERBytes  = 16 << 20
	maxACMEDNSRecordValueLength = 512
)

// SignerReferenceSource resolves a server-side ACME account key by an
// opaque reference.  Implementations must not persist or expose the returned
// key and should return a fresh in-memory signer when practical.
type SignerReferenceSource interface {
	ResolveSigner(context.Context, string) (crypto.Signer, error)
}

// DNS01Record is the only DNS material passed to a provider. ProviderID is
// opaque provider state and must not contain credentials.
type DNS01Record struct {
	// Domain is the ACME authorization name (the requested customer domain).
	Domain string
	// Name is the provider write/read target. It is the delegated target when
	// TargetName differs from AuthorizationName.
	Name              string
	Value             string
	TTL               time.Duration
	ProviderID        string
	AuthorizationName string
	TargetName        string
}

// DNS01Provider owns the complete DNS-01 record lifecycle. Present and
// Cleanup must be idempotent for the same ProviderID. Wait must not return
// success until the expected TXT value is visible through authoritative or
// configured recursive resolvers.
type DNS01Provider interface {
	Present(context.Context, DNS01Record) (DNS01Record, error)
	Wait(context.Context, DNS01Record) error
	Cleanup(context.Context, DNS01Record) error
}

type ACMEIssuerConfig struct {
	DirectoryURL string
	AccountKID   string
	AccountEmail string

	// AccountKey is an explicitly injected in-memory signer for tests or a
	// process-local secret provider. Production composition should use
	// AccountKeys and AccountKeyReference instead.
	AccountKey          crypto.Signer
	AccountKeys         SignerReferenceSource
	AccountKeyReference string

	DNS                DNS01Provider
	HTTPClient         *http.Client
	Timeout            time.Duration
	PropagationTimeout time.Duration
	CleanupTimeout     time.Duration
	PollInterval       time.Duration
	MaxAttempts        int
	RetryBase          time.Duration
	RetryMax           time.Duration
	Issuer             string
	// ChallengeZone is a Paperboat-owned authoritative DNS zone for user-owned
	// delegated targets. Platform wildcards write directly to their
	// server-owned _acme-challenge name and do not require a CNAME in this zone.
	ChallengeZone string
}

type ACMEIssuer struct {
	directoryURL       string
	accountKID         acme.KeyID
	accountEmail       string
	accountKey         crypto.Signer
	accountKeys        SignerReferenceSource
	accountKeyRef      string
	dns                DNS01Provider
	httpClient         *http.Client
	timeout            time.Duration
	propagationTimeout time.Duration
	cleanupTimeout     time.Duration
	pollInterval       time.Duration
	maxAttempts        int
	retryBase          time.Duration
	retryMax           time.Duration
	issuer             string
	challengeZone      string
	accountMu          sync.Mutex
}

func NewACMEIssuer(config ACMEIssuerConfig) (*ACMEIssuer, error) {
	parsed, err := url.Parse(config.DirectoryURL)
	if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: ACME directory URL is invalid", ErrInvalid)
	}
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("%w: insecure ACME directory must be loopback", ErrInvalid)
		}
	}
	if config.AccountKey == nil {
		if config.AccountKeys == nil || !validKeyReference(config.AccountKeyReference) {
			return nil, fmt.Errorf("%w: exactly one ACME account-key source is required", ErrInvalid)
		}
	} else if config.AccountKeys != nil {
		return nil, fmt.Errorf("%w: exactly one ACME account-key source is required", ErrInvalid)
	}
	if config.AccountKey != nil && !supportedAccountKey(config.AccountKey) {
		return nil, fmt.Errorf("%w: ACME account key algorithm is unsupported", ErrInvalid)
	}
	if config.DNS == nil {
		return nil, fmt.Errorf("%w: DNS-01 provider is required", ErrDNSChallengeUnavailable)
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{}
	} else {
		clone := *client
		client = &clone
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrIssuerUnavailable }
	timeout := config.Timeout
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = defaultACMETimeout
	}
	client.Timeout = timeout
	propagationTimeout := config.PropagationTimeout
	if propagationTimeout <= 0 || propagationTimeout > 10*time.Minute {
		propagationTimeout = defaultACMEPropagation
	}
	cleanupTimeout := config.CleanupTimeout
	if cleanupTimeout <= 0 || cleanupTimeout > 2*time.Minute {
		cleanupTimeout = defaultACMECleanup
	}
	pollInterval := config.PollInterval
	if pollInterval <= 0 || pollInterval > time.Minute {
		pollInterval = defaultACMEPollInterval
	}
	maxAttempts := config.MaxAttempts
	if maxAttempts <= 0 || maxAttempts > 8 {
		maxAttempts = 5
	}
	retryBase := config.RetryBase
	if retryBase <= 0 || retryBase > time.Minute {
		retryBase = defaultACMERetryBase
	}
	retryMax := config.RetryMax
	if retryMax <= 0 || retryMax > 2*time.Minute {
		retryMax = defaultACMERetryMax
	}
	issuer := strings.TrimSpace(config.Issuer)
	if issuer == "" {
		issuer = "letsencrypt"
	}
	if !validMetadata(issuer, 256) {
		return nil, fmt.Errorf("%w: ACME issuer is invalid", ErrInvalid)
	}
	challengeZone := strings.TrimSpace(config.ChallengeZone)
	if challengeZone != "" {
		if _, wildcard, zoneErr := normalizeHostname(challengeZone); zoneErr != nil || wildcard {
			return nil, fmt.Errorf("%w: challenge zone is invalid", ErrInvalid)
		}
	}
	return &ACMEIssuer{directoryURL: strings.TrimRight(config.DirectoryURL, "/"), accountKID: acme.KeyID(strings.TrimSpace(config.AccountKID)), accountEmail: strings.TrimSpace(config.AccountEmail), accountKey: config.AccountKey, accountKeys: config.AccountKeys, accountKeyRef: config.AccountKeyReference, dns: config.DNS, httpClient: client, timeout: timeout, propagationTimeout: propagationTimeout, cleanupTimeout: cleanupTimeout, pollInterval: pollInterval, maxAttempts: maxAttempts, retryBase: retryBase, retryMax: retryMax, issuer: issuer, challengeZone: challengeZone}, nil
}

func (i *ACMEIssuer) Issue(ctx context.Context, request IssueRequest) (CertificateBundle, error) {
	if i == nil {
		return CertificateBundle{}, ErrIssuerUnavailable
	}
	if request.Domain.Strategy != StrategyDelegatedDNS01 && request.Domain.Strategy != StrategyPlatformDNS01 && request.Domain.Strategy != StrategyOnDemandLeaf && request.Domain.Strategy != StrategyWildcard {
		return CertificateBundle{}, fmt.Errorf("%w: ACME issuer only supports DNS-01 strategies", ErrIssuerUnavailable)
	}
	return i.IssueDNS01(ctx, request.Domain)
}

// IssueLeaf is the bounded exact-SNI path used for an on-demand request under
// a verified wildcard binding. The wildcard remains the ownership boundary,
// while the ACME order and returned certificate contain only the requested
// one-label hostname.
func (i *ACMEIssuer) IssueLeaf(ctx context.Context, request IssueRequest) (CertificateBundle, error) {
	if i == nil {
		return CertificateBundle{}, ErrIssuerUnavailable
	}
	if request.Domain.Strategy != StrategyOnDemandLeaf {
		return CertificateBundle{}, fmt.Errorf("%w: exact leaf strategy is invalid", ErrInvalid)
	}
	bound, wildcard, err := normalizeHostname(request.Domain.Hostname)
	if err != nil || !wildcard {
		return CertificateBundle{}, fmt.Errorf("%w: exact leaf requires a wildcard binding", ErrInvalid)
	}
	leaf := request.LeafHostname
	if leaf == "" {
		return CertificateBundle{}, fmt.Errorf("%w: exact leaf hostname is required", ErrInvalid)
	}
	leaf, leafWildcard, err := normalizeHostname(leaf)
	if err != nil || leafWildcard || !oneLabelUnderWildcard(leaf, bound) {
		return CertificateBundle{}, fmt.Errorf("%w: exact leaf hostname is outside the wildcard binding", ErrInvalid)
	}
	domain := request.Domain
	domain.Hostname = leaf
	domain.LeafHostname = ""
	domain.Strategy = StrategyDelegatedDNS01
	domain.AllowOnDemandFallback = false
	return i.IssueDNS01(ctx, domain)
}

// Revoke asks the configured ACME authority to revoke the leaf certificate.
// The PEM is consumed in memory only; callers should remove their own bundle
// immediately after this call returns. The account signer is resolved by
// reference in client and is never included in the returned error.
func (i *ACMEIssuer) Revoke(ctx context.Context, certificatePEM []byte) error {
	ctx = certificateContext(ctx)
	certificate, err := parseACMECertificate(certificatePEM)
	if err != nil {
		return err
	}
	client, err := i.client(ctx)
	if err != nil {
		return err
	}
	if err := client.RevokeCert(ctx, client.Key, certificate.Raw, acme.CRLReasonUnspecified); err != nil {
		return mapACMEError(err)
	}
	return nil
}

// RevokeBundle is the stronger revocation path for authorities that only
// accept the certificate's own key. The account-key attempt remains first so
// the normal RFC 8555 authorization is used whenever supported; the leaf key
// is consumed only in memory as a bounded fallback.
func (i *ACMEIssuer) RevokeBundle(ctx context.Context, bundle CertificateBundle) error {
	ctx = certificateContext(ctx)
	certificate, err := parseACMECertificate(bundle.CertificatePEM)
	if err != nil {
		return err
	}
	if len(bundle.PrivateKeyPEM) == 0 || len(bundle.PrivateKeyPEM) > maxACMECertificateDERBytes {
		return ErrCertificateInvalid
	}
	leafKey, err := parsePrivateKey(bundle.PrivateKeyPEM)
	if err != nil {
		return ErrCertificateInvalid
	}
	leafSigner, ok := leafKey.(crypto.Signer)
	if !ok {
		return ErrCertificateInvalid
	}
	client, err := i.client(ctx)
	if err != nil {
		return err
	}
	accountErr := client.RevokeCert(ctx, client.Key, certificate.Raw, acme.CRLReasonUnspecified)
	if accountErr == nil {
		return nil
	}
	if err := client.RevokeCert(ctx, leafSigner, certificate.Raw, acme.CRLReasonUnspecified); err != nil {
		return mapACMEError(accountErr)
	}
	return nil
}

func parseACMECertificate(certificatePEM []byte) (*x509.Certificate, error) {
	if len(certificatePEM) == 0 || len(certificatePEM) > maxACMECertificateDERBytes {
		return nil, ErrCertificateInvalid
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrCertificateInvalid
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || certificate == nil {
		return nil, ErrCertificateInvalid
	}
	return certificate, nil
}

// IssueDNS01 performs an RFC 8555 order, presents one or more DNS records,
// waits for propagation, accepts each DNS-01 challenge, finalizes the order,
// and returns a validated in-memory bundle. Every presented record is cleaned
// up on success, cancellation, authorization failure, and certificate parse
// failure.
func (i *ACMEIssuer) IssueDNS01(ctx context.Context, domain Domain) (_ CertificateBundle, returnErr error) {
	ctx = certificateContext(ctx)
	if i == nil || i.dns == nil {
		return CertificateBundle{}, ErrDNSChallengeUnavailable
	}
	if err := acmeContextError(ctx); err != nil {
		return CertificateBundle{}, err
	}
	if err := domain.Validate(); err != nil {
		return CertificateBundle{}, err
	}
	hostname, wildcard, err := normalizeHostname(domain.Hostname)
	if err != nil {
		return CertificateBundle{}, err
	}
	if wildcard && domain.Strategy == StrategyOnDemandLeaf && !domain.AllowOnDemandFallback {
		return CertificateBundle{}, fmt.Errorf("%w: wildcard fallback is not enabled", ErrInvalid)
	}
	var challengeTarget string
	if domain.Target().normalizedKind() == TargetPlatformWildcard {
		challengeTarget, err = PlatformDNSChallengeTargetForDomain(domain)
	} else {
		if i.challengeZone == "" {
			return CertificateBundle{}, fmt.Errorf("%w: Paperboat challenge zone is not configured", ErrDNSChallengeUnavailable)
		}
		challengeTarget, err = DelegatedChallengeTargetForDomain(domain, i.challengeZone)
	}
	if err != nil {
		return CertificateBundle{}, err
	}
	client, err := i.client(ctx)
	if err != nil {
		return CertificateBundle{}, err
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(hostname))
	if err != nil {
		return CertificateBundle{}, mapACMEError(err)
	}
	var records []DNS01Record
	defer func() {
		if len(records) == 0 {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), i.cleanupTimeout)
		defer cancel()
		for index := len(records) - 1; index >= 0; index-- {
			if err := i.dns.Cleanup(cleanupCtx, records[index]); err != nil {
				cleanupErr := fmt.Errorf("%w: DNS-01 record cleanup failed", ErrDNSChallengeUnavailable)
				returnErr = errors.Join(returnErr, cleanupErr)
			}
		}
	}()
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			return CertificateBundle{}, mapACMEError(err)
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		challenge := findDNS01Challenge(authorization)
		if challenge == nil || challenge.Token == "" {
			return CertificateBundle{}, ErrDNSChallengeUnavailable
		}
		value, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil || len(value) == 0 || len(value) > maxACMEDNSRecordValueLength {
			return CertificateBundle{}, ErrDNSChallengeUnavailable
		}
		challengeHost := "_acme-challenge." + strings.TrimPrefix(hostname, "*.")
		record := DNS01Record{Domain: hostname, Name: challengeTarget, TargetName: challengeTarget, AuthorizationName: challengeHost, Value: value, TTL: 60 * time.Second}
		record, err = i.dns.Present(ctx, record)
		if err != nil {
			return CertificateBundle{}, mapDNSProviderError(err)
		}
		if record.Name != challengeTarget || record.TargetName != challengeTarget || record.AuthorizationName != challengeHost || record.Value != value || record.ProviderID == "" {
			return CertificateBundle{}, ErrDNSChallengeUnavailable
		}
		records = append(records, record)
		waitCtx, cancel := context.WithTimeout(ctx, i.propagationTimeout)
		err = i.dns.Wait(waitCtx, record)
		cancel()
		if err != nil {
			return CertificateBundle{}, mapDNSProviderError(err)
		}
		if _, err := client.Accept(ctx, challenge); err != nil {
			return CertificateBundle{}, mapACMEError(err)
		}
		completed, err := client.WaitAuthorization(ctx, authorization.URI)
		if err != nil {
			return CertificateBundle{}, mapACMEError(err)
		}
		if completed == nil || completed.Status != acme.StatusValid {
			return CertificateBundle{}, fmt.Errorf("%w: DNS-01 authorization did not become valid", ErrDNSChallengePending)
		}
	}
	readyOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		return CertificateBundle{}, mapACMEError(err)
	}
	if readyOrder == nil || readyOrder.FinalizeURL == "" {
		return CertificateBundle{}, ErrIssuerUnavailable
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CertificateBundle{}, fmt.Errorf("%w: leaf key generation failed", ErrIssuerUnavailable)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}}, key)
	if err != nil {
		return CertificateBundle{}, fmt.Errorf("%w: CSR generation failed", ErrIssuerUnavailable)
	}
	der, _, err := client.CreateOrderCert(ctx, readyOrder.FinalizeURL, csr, true)
	if err != nil {
		// Some RFC 8555 test authorities return a valid order from finalize
		// before populating its certificate URL in that response. Re-fetch the
		// durable order and certificate only when it is already valid; this is
		// bounded and preserves the original error for every other failure.
		latest, refreshErr := client.GetOrder(ctx, order.URI)
		if refreshErr == nil && latest != nil && latest.Status == acme.StatusValid && latest.CertURL != "" {
			der, refreshErr = client.FetchCert(ctx, latest.CertURL, true)
			err = refreshErr
		}
	}
	if err != nil {
		return CertificateBundle{}, mapACMEError(err)
	}
	if len(der) == 0 || len(der) > maxACMEChainCertificates {
		return CertificateBundle{}, fmt.Errorf("%w: ACME returned an invalid chain", ErrCertificateInvalid)
	}
	var leaf *x509.Certificate
	var certificatePEM []byte
	for index, raw := range der {
		if len(raw) == 0 || len(raw) > maxACMECertificateDERBytes {
			return CertificateBundle{}, fmt.Errorf("%w: ACME certificate is oversized", ErrCertificateInvalid)
		}
		parsed, err := x509.ParseCertificate(raw)
		if err != nil {
			return CertificateBundle{}, fmt.Errorf("%w: ACME certificate is invalid", ErrCertificateInvalid)
		}
		if index == 0 {
			leaf = parsed
		}
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})...)
	}
	if leaf == nil {
		return CertificateBundle{}, ErrCertificateInvalid
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return CertificateBundle{}, fmt.Errorf("%w: leaf key encoding failed", ErrCertificateInvalid)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	clear(privateKeyDER)
	return CertificateBundle{CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM, Issuer: i.issuer, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, returnErr
}

func acmeContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (i *ACMEIssuer) client(ctx context.Context) (*acme.Client, error) {
	ctx = certificateContext(ctx)
	i.accountMu.Lock()
	defer i.accountMu.Unlock()
	key := i.accountKey
	if key == nil {
		var err error
		key, err = i.accountKeys.ResolveSigner(ctx, i.accountKeyRef)
		if err != nil || key == nil || !supportedAccountKey(key) {
			return nil, fmt.Errorf("%w: ACME account key resolution failed", ErrMasterKeyUnavailable)
		}
	}
	client := &acme.Client{Key: key, KID: i.accountKID, DirectoryURL: i.directoryURL, HTTPClient: i.httpClient, UserAgent: "paperboat-tunnelcert/1"}
	client.RetryBackoff = func(attempt int, request *http.Request, response *http.Response) time.Duration {
		if attempt >= i.maxAttempts {
			return -1
		}
		if response != nil {
			if retryAfter := parseRetryAfter(response.Header.Get("Retry-After"), time.Now().UTC()); retryAfter > 0 {
				if retryAfter > i.retryMax {
					return i.retryMax
				}
				return retryAfter
			}
		}
		backoff := i.retryBase
		for step := 1; step < attempt && backoff < i.retryMax/2; step++ {
			backoff *= 2
		}
		if backoff > i.retryMax {
			backoff = i.retryMax
		}
		return backoff
	}
	if client.KID == "" {
		contact := []string(nil)
		if i.accountEmail != "" {
			contact = []string{"mailto:" + i.accountEmail}
		}
		if _, err := client.Register(ctx, &acme.Account{Contact: contact}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
			return nil, mapACMEError(err)
		}
		// Register sets KID even when the CA reports that this key already
		// exists. Retain that public account URL in memory for renewal and
		// revocation without persisting or returning key material.
		i.accountKID = client.KID
	}
	return client, nil
}

func findDNS01Challenge(authorization *acme.Authorization) *acme.Challenge {
	if authorization == nil {
		return nil
	}
	for _, challenge := range authorization.Challenges {
		if challenge != nil && challenge.Type == "dns-01" && challenge.Status != acme.StatusInvalid {
			return challenge
		}
	}
	return nil
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil && when.After(now) {
		return when.Sub(now)
	}
	return 0
}

func mapDNSProviderError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrDNSChallengePending) || errors.Is(err, ErrDNSChallengeUnavailable) {
		return err
	}
	return fmt.Errorf("%w: DNS provider operation failed", ErrDNSChallengeUnavailable)
}

func mapACMEError(err error) error {
	if err == nil {
		return nil
	}
	var acmeErr *acme.Error
	if errors.As(err, &acmeErr) && acmeErr != nil {
		code := acmeProblemCode(acmeErr)
		if acmeErr.StatusCode == http.StatusTooManyRequests || strings.Contains(strings.ToLower(acmeErr.ProblemType), "ratelimited") {
			return fmt.Errorf("%w: %s", ErrIssuerRateLimited, code)
		}
		if acmeErr.StatusCode >= 500 || acmeErr.StatusCode == http.StatusRequestTimeout || acmeErr.StatusCode == http.StatusTooEarly {
			return fmt.Errorf("%w: %s", ErrIssuerUnavailable, code)
		}
		if strings.Contains(strings.ToLower(acmeErr.ProblemType), "dns") || strings.Contains(strings.ToLower(acmeErr.Detail), "dns") {
			return fmt.Errorf("%w: %s", ErrDNSChallengeUnavailable, code)
		}
		return fmt.Errorf("%w: %s", ErrIssuerUnavailable, code)
	}
	var orderErr *acme.OrderError
	if errors.As(err, &orderErr) && orderErr != nil && orderErr.Problem != nil {
		return mapACMEError(orderErr.Problem)
	}
	return fmt.Errorf("%w: ACME request failed (%s)", ErrIssuerUnavailable, safeACMECause(err))
}

// acmeProblemCode retains only bounded protocol metadata for diagnostics. In
// particular, never include the ACME problem detail because an issuer may
// echo identifiers or challenge material in that field.
func acmeProblemCode(value *acme.Error) string {
	if value == nil {
		return "acme_error"
	}
	problemType := strings.TrimSpace(value.ProblemType)
	if len(problemType) > 128 || strings.ContainsAny(problemType, "\r\n\x00") {
		problemType = "acme_error"
	}
	if value.StatusCode > 0 {
		return fmt.Sprintf("acme_status_%d:%s", value.StatusCode, problemType)
	}
	return problemType
}

func safeACMECause(err error) string {
	if err == nil {
		return "unknown"
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 256 || strings.ContainsAny(message, "\r\n\x00") {
		return "issuer_error"
	}
	lower := strings.ToLower(message)
	for _, marker := range []string{"private key", "bearer", "authorization", "token="} {
		if strings.Contains(lower, marker) {
			return "issuer_error"
		}
	}
	return message
}

func supportedAccountKey(key crypto.Signer) bool {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		return true
	case interface{ Public() crypto.PublicKey }:
		_, rsaOK := key.Public().(*rsa.PublicKey)
		return rsaOK
	default:
		return false
	}
}
