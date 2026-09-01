package tunnelcert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	defaultLockTTL           = 2 * time.Minute
	defaultRenewBefore       = 30 * 24 * time.Hour
	defaultDistributionLimit = 20 * time.Second
	defaultExpiryAlertWindow = 14 * 24 * time.Hour
)

type CAAResult struct {
	State       string
	Issuer      string
	FailureCode string
}

type CAAInspector interface {
	Check(context.Context, string, string) (CAAResult, error)
}

type DNSChallenge struct {
	// Name is the writable TXT name. For user-owned delegated challenges it is
	// the Paperboat-owned target; platform wildcards write directly to their
	// server-owned _acme-challenge name.
	Name              string
	Type              string
	Value             string
	TTL               time.Duration
	AuthorizationName string
	TargetName        string
}

type DNS01Delegator interface {
	Prepare(context.Context, Domain) (DNSChallenge, error)
}

type IssueRequest struct {
	Domain       Domain
	Strategy     Strategy
	Challenge    DNSChallenge
	LeafHostname string
}

type Issuer interface {
	Issue(context.Context, IssueRequest) (CertificateBundle, error)
}

// CertificateAuthorityRevoker is the authority-side half of revocation. It
// is intentionally separate from Issuer so a deployment cannot accidentally
// treat removal from the local registry as a CA revocation. Implementations
// must consume the bundle only in memory and must not retain either PEM value.
type CertificateAuthorityRevoker interface {
	RevokeBundle(context.Context, CertificateBundle) error
}

// DNS01Issuer owns the complete RFC 8555 DNS-01 exchange.  It is separate
// from DNS01Delegator because an ACME challenge token is minted by the CA
// only after the order is created; a pre-issued DNSChallenge cannot safely
// represent that exchange.  Implementations must keep account and DNS
// credentials in memory only and must remove records on every exit path.
type DNS01Issuer interface {
	IssueDNS01(context.Context, Domain) (CertificateBundle, error)
}

// LeafFallbackIssuer is an open dependency boundary so deployments can
// provide either ExactLeafIssuer or a deliberately constrained test adapter.
// Production composition must provide ExactLeafIssuer; the coordinator
// rejects wildcard material even when an older adapter is supplied.
type LeafFallbackIssuer interface{}

// ExactLeafIssuer is the production on-demand fallback boundary. It must
// issue a leaf for IssueRequest.LeafHostname, never a wildcard replacement;
// the coordinator validates that invariant again before persistence.
type ExactLeafIssuer interface {
	IssueLeaf(context.Context, IssueRequest) (CertificateBundle, error)
}

type IssuanceLock interface {
	Acquire(context.Context, string, string, uint64, time.Time, time.Time) (bool, error)
	Release(context.Context, string, string) error
}

// GenerationIssuanceLock is an optional strengthening implemented by durable
// locks. A retry from an older domain generation must not be able to release a
// newer holder's lease merely because the owner identifier was reused.
type GenerationIssuanceLock interface {
	ReleaseGeneration(context.Context, string, string, uint64) error
}

type StoredCertificate struct {
	ID                string
	DomainID          string
	AccountID         string
	TunnelID          string
	TargetKind        TargetKind
	RouteID           string
	PreviewID         string
	PreviewGeneration uint64
	PreviewState      string
	PreviewExpiresAt  time.Time
	Hostname          string
	// LeafHostname is non-empty only for an exact certificate issued under a
	// verified wildcard binding.  The primary wildcard certificate keeps this
	// field empty and remains the domain's projected certificate.
	LeafHostname          string
	DomainGeneration      uint64
	CertificateGeneration uint64
	Strategy              Strategy
	State                 State
	CertificateReference  string
	MasterKeyReference    string
	Envelope              []byte
	CertificateCiphertext []byte
	PrivateKeyCiphertext  []byte
	Fingerprint           [sha256.Size]byte
	Issuer                string
	NotBefore             time.Time
	ExpiresAt             time.Time
	RenewalAt             time.Time
	FailureCode           string
	RevokedAt             *time.Time
	UpdatedAt             time.Time
}

func (s StoredCertificate) Target() CertificateTarget {
	return CertificateTarget{
		Kind: s.TargetKind, DomainID: s.DomainID, AccountID: s.AccountID,
		TunnelID: s.TunnelID, RouteID: s.RouteID, PreviewID: s.PreviewID,
		PreviewGeneration: s.PreviewGeneration, PreviewState: s.PreviewState,
		PreviewExpiresAt: s.PreviewExpiresAt,
	}
}

func (s StoredCertificate) View() CertificateView {
	return CertificateView{Reference: s.CertificateReference, Fingerprint: hex.EncodeToString(s.Fingerprint[:]), State: s.State, DomainGeneration: s.DomainGeneration, CertificateGeneration: s.CertificateGeneration, Issuer: s.Issuer, NotBefore: s.NotBefore, ExpiresAt: s.ExpiresAt, RenewalAt: s.RenewalAt, FailureCode: s.FailureCode, TargetKind: s.TargetKind, RouteID: s.RouteID, PreviewID: s.PreviewID, PreviewGeneration: s.PreviewGeneration}
}

type CertificateStore interface {
	Current(context.Context, string) (StoredCertificate, bool, error)
	PutStaged(context.Context, StoredCertificate) error
	Activate(context.Context, string, uint64, time.Time) (StoredCertificate, error)
	SupersedeOlder(context.Context, string, uint64, time.Time) error
	MarkFailed(context.Context, string, string, time.Time) error
	Revoke(context.Context, string, string, time.Time) (StoredCertificate, error)
}

// CertificateGenerationSource supplies the next durable certificate sequence
// when an earlier issuance attempt reached the database but failed before it
// became active. Stores that enforce a unique (target, certificate_generation)
// key implement this optional boundary so a retry cannot reuse that sequence.
type CertificateGenerationSource interface {
	NextCertificateGeneration(context.Context, string) (uint64, error)
}

// HostnameCertificateStore is implemented by durable stores that keep the
// wildcard parent and exact on-demand leaves in separate hostname namespaces.
// A coordinator refuses to issue a leaf through a store without this boundary
// rather than risking a parent/sibling replacement.
type HostnameCertificateStore interface {
	CurrentForHostname(context.Context, string, string) (StoredCertificate, bool, error)
	SupersedeOlderForHostname(context.Context, string, string, uint64, time.Time) error
}

// PreviewCertificateLookup is the target-aware read boundary for preview
// leases. A preview lookup must include account and lease identity so a
// reused preview ID or a durable route can never satisfy an SNI request.
type PreviewCertificateLookup interface {
	CurrentPreview(context.Context, string, string, string) (StoredCertificate, bool, error)
	CurrentPreviewForHostname(context.Context, string, string, string, string) (StoredCertificate, bool, error)
}

// PreviewCertificateRebinder is used in the small renewal gap where an active
// certificate still carries the previous lease generation. Rebinding changes
// only the target fence and keeps the certificate material/generation stable.
type PreviewCertificateRebinder interface {
	CurrentPreviewForRebind(context.Context, string, string, string, time.Time) (StoredCertificate, bool, error)
	CurrentPreviewForHostnameRebind(context.Context, string, string, string, string, time.Time) (StoredCertificate, bool, error)
	RebindPreviewCertificateTarget(context.Context, string, string, string, string, uint64, uint64, time.Time, time.Time) (StoredCertificate, error)
}

type DistributionTarget struct {
	NodeID       string
	ProcessEpoch string
	Generation   uint64
}

type DistributionRequest struct {
	Certificate StoredCertificate
	Bundle      CertificateBundle
	Target      DistributionTarget
}

type CertificateDistributor interface {
	Stage(context.Context, DistributionRequest) error
	WaitReady(context.Context, DistributionRequest) error
	Activate(context.Context, DistributionRequest) error
	Retire(context.Context, StoredCertificate, DistributionTarget) error
}

// CertificateRevoker is optional for in-memory/test distributors but is
// required by the production SQL distributor.  Revocation is durable first,
// then removes every previously published edge copy. A failed removal is
// returned so the operation can be retried without pretending the edge is
// safe.
type CertificateRevoker interface {
	RevokeCertificate(context.Context, StoredCertificate) error
}

// CertificateDurableRetirer retires every non-terminal edge distribution row
// that actually received a certificate. It is intentionally separate from
// the request-time target list: an edge process can be replaced between
// certificate generations, and the old process still needs cleanup.
type CertificateDurableRetirer interface {
	RetireCertificate(context.Context, StoredCertificate) error
}

// CertificateDistributionCoverage identifies current edge assignments that
// do not yet hold an already-active certificate. It is used when an edge joins
// or changes process without forcing a new CA issuance.
type CertificateDistributionCoverage interface {
	MissingCertificateTargets(context.Context, StoredCertificate, []DistributionTarget) ([]DistributionTarget, error)
}

// CertificateObsoleteRetirer removes rows for old node/process/assignment
// tuples after a late edge replacement. The durable rows, not a fresh domain
// projection, are the source of truth for cleanup.
type CertificateObsoleteRetirer interface {
	RetireObsoleteCertificateTargets(context.Context, StoredCertificate, []DistributionTarget) error
}

// CertificateDistributionCleanup retries cleanup for certificates that were
// superseded or revoked after a prior edge operation failed. Durable edge rows,
// rather than the current domain target list, are authoritative.
type CertificateDistributionCleanup interface {
	ReconcileCertificateDistributionCleanup(context.Context, int) (int, error)
}

// CertificateRevocationStore is the durable retry ledger for authority-side
// revocation. The certificate row is marked revoked before the authority call;
// a pending marker keeps a crash or unavailable CA from silently losing the
// retry.
type CertificateRevocationStore interface {
	ListPendingCertificateRevocations(context.Context, int) ([]StoredCertificate, error)
	MarkCertificateRevocationResult(context.Context, string, bool, string, time.Time) error
}

var ErrCertificateRevocationUnavailable = errors.New("certificate authority revocation is unavailable")

// CleanupPendingError lets the long-running certificate worker retry a
// transient edge cleanup on its next tick without stopping unrelated issuance.
type CleanupPendingError struct{ Err error }

func (e *CleanupPendingError) Error() string { return "certificate distribution cleanup is pending" }
func (e *CleanupPendingError) Unwrap() error { return e.Err }

// CertificateDistributionRollback removes a newly activated edge copy when
// a later target or durable store step fails. Production transports implement
// this as terminal revocation; test transports may use their equivalent
// bounded removal operation. The old active generation is never retired by
// this path.
type CertificateDistributionRollback interface {
	Revoke(context.Context, StoredCertificate, DistributionTarget) error
}

type ExpiryAlert struct {
	DomainID              string
	Hostname              string
	CertificateRef        string
	CertificateGeneration uint64
	ExpiresAt             time.Time
	Code                  string
}

type ExpiryAlertSink interface {
	Alert(context.Context, ExpiryAlert) error
}

type OperationCompleter interface {
	CompleteDomainCreate(context.Context, string, string, uint64) error
}

// CertificateDomainCommitter is the durable finalization boundary for a
// certificate replacement. Implementations update the domain projection and
// complete the matching domain.create operation in one transaction after the
// certificate has been activated. Keeping this boundary on the store avoids
// exposing a succeeded operation while the domain still says issuing.
type CertificateDomainCommitter interface {
	CommitDomainCertificateReady(context.Context, string, string, uint64, StoredCertificate, time.Time) error
}

// PreviewCertificateDomainCommitter publishes a lease-bound certificate
// without touching the durable tunnel_domains projection.
type PreviewCertificateDomainCommitter interface {
	CommitPreviewDomainCertificateReady(context.Context, string, string, string, uint64, uint64, StoredCertificate, time.Time) error
}

// PreviewCertificateReadiness is the exact edge-admission fence used by the
// preview alias projector. Implementations check the current lease/domain
// generations and the authenticated edge distribution tuple together.
type PreviewCertificateReadiness interface {
	PreviewCertificateReady(context.Context, string, string, string, string, uint64, uint64, uint64, DistributionTarget, time.Time) (bool, error)
}

type Config struct {
	Store                  CertificateStore
	Locks                  IssuanceLock
	Keys                   MasterKeySource
	Issuer                 Issuer
	Fallback               LeafFallbackIssuer
	CAA                    CAAInspector
	Delegated              DNS01Delegator
	Distributor            CertificateDistributor
	Alerts                 ExpiryAlertSink
	Operations             OperationCompleter
	MasterKeyReference     string
	IssuerName             string
	OwnerID                string
	LockTTL                time.Duration
	RenewBefore            time.Duration
	DistributionTimeout    time.Duration
	ExpiryAlertWindow      time.Duration
	MaxCertificateLifetime time.Duration
	Now                    func() time.Time
}

type Coordinator struct {
	config  Config
	alertMu sync.Mutex
	alerted map[string]struct{}
}

// CurrentCertificate exposes the store snapshot needed by the worker's
// atomic domain finalization boundary. It returns a defensive store-owned
// copy and never exposes plaintext certificate material.
func (c *Coordinator) CurrentCertificate(ctx context.Context, domainID string) (StoredCertificate, bool, error) {
	if c == nil || c.config.Store == nil || !validIdentifier(domainID) {
		return StoredCertificate{}, false, ErrInvalid
	}
	return c.config.Store.Current(ctx, domainID)
}

// CurrentCertificateForDomain exposes the target-aware lookup used by the
// certificate worker and preview admission paths. Durable callers retain the
// historical domain-only lookup; preview callers must resolve through the
// lease-bound store interface.
func (c *Coordinator) CurrentCertificateForDomain(ctx context.Context, domain Domain) (StoredCertificate, bool, error) {
	if c == nil || c.config.Store == nil {
		return StoredCertificate{}, false, ErrInvalid
	}
	return c.currentCertificate(ctx, domain)
}

func (c *Coordinator) activeDistributionNeeded(ctx context.Context, certificate StoredCertificate, domain Domain) (bool, error) {
	if len(domain.EdgeTargets) == 0 {
		return false, nil
	}
	coverage, ok := c.config.Distributor.(CertificateDistributionCoverage)
	if !ok {
		return false, nil
	}
	targets := make([]DistributionTarget, 0, len(domain.EdgeTargets))
	for _, edge := range domain.EdgeTargets {
		targets = append(targets, DistributionTarget(edge))
	}
	missing, err := coverage.MissingCertificateTargets(ctx, certificate, targets)
	return len(missing) > 0, err
}

// reconcileActiveDistribution fills only missing current edge assignments for
// an active certificate. It never changes the CA generation or domain state;
// this makes late edge joins and process replacement safe to retry.
func (c *Coordinator) reconcileActiveDistribution(ctx context.Context, certificate StoredCertificate, domain Domain, now time.Time) (Result, error) {
	coverage, ok := c.config.Distributor.(CertificateDistributionCoverage)
	if !ok || len(domain.EdgeTargets) == 0 {
		return Result{Certificate: certificate.View()}, nil
	}
	targets := make([]DistributionTarget, 0, len(domain.EdgeTargets))
	for _, edge := range domain.EdgeTargets {
		targets = append(targets, DistributionTarget(edge))
	}
	missing, err := coverage.MissingCertificateTargets(ctx, certificate, targets)
	if err != nil {
		return Result{}, err
	}
	if len(missing) == 0 {
		return Result{Certificate: certificate.View()}, nil
	}
	opened, err := OpenParts(ctx, c.config.Keys, certificate.MasterKeyReference, certificate.CertificateCiphertext, certificate.PrivateKeyCiphertext)
	if err != nil {
		return Result{}, fmt.Errorf("%w: open active certificate for edge reconciliation: %v", ErrDistributionUnavailable, err)
	}
	bundle := CertificateBundle{CertificatePEM: opened.CertificatePEM, PrivateKeyPEM: opened.PrivateKeyPEM, Issuer: certificate.Issuer, NotBefore: certificate.NotBefore, NotAfter: certificate.ExpiresAt}
	defer wipeCertificateBundle(&bundle)
	if _, err := bundle.Validate(certificate.Hostname, now, c.config.MaxCertificateLifetime); err != nil {
		return Result{}, err
	}
	staged := make([]DistributionRequest, 0, len(missing))
	for _, target := range missing {
		request := DistributionRequest{Certificate: certificate, Bundle: bundle, Target: target}
		if err := c.config.Distributor.Stage(ctx, request); err != nil {
			cause := fmt.Errorf("%w: stage late edge %s: %v", ErrDistributionUnavailable, target.NodeID, err)
			return Result{}, errors.Join(cause, c.rollbackStaged(certificate, staged))
		}
		staged = append(staged, request)
	}
	distributionCtx, cancel := context.WithTimeout(ctx, c.config.DistributionTimeout)
	defer cancel()
	for _, request := range staged {
		if err := c.config.Distributor.WaitReady(distributionCtx, request); err != nil {
			return Result{}, errors.Join(fmt.Errorf("%w: late edge %s is not ready: %v", ErrCertificateNotReady, request.Target.NodeID, err), c.rollbackStaged(certificate, staged))
		}
	}
	for _, request := range staged {
		if err := c.config.Distributor.Activate(ctx, request); err != nil {
			return Result{}, errors.Join(fmt.Errorf("%w: activate late edge %s: %v", ErrDistributionUnavailable, request.Target.NodeID, err), c.rollbackStaged(certificate, staged))
		}
	}
	var cleanupErr error
	if retirer, ok := c.config.Distributor.(CertificateObsoleteRetirer); ok {
		cleanupErr = retirer.RetireObsoleteCertificateTargets(ctx, certificate, targets)
	}
	if cleanupErr != nil {
		return Result{Certificate: certificate.View(), CleanupPending: true, CleanupError: cleanupErr}, nil
	}
	return Result{Certificate: certificate.View()}, nil
}

// CommitDomainCertificateReady delegates the final domain/operation commit to
// the durable store. The fallback is retained only for small in-memory
// adapters used by deterministic tests; production SQL storage always
// implements CertificateDomainCommitter.
func (c *Coordinator) CommitDomainCertificateReady(ctx context.Context, accountID, domainID string, expectedGeneration uint64, certificate StoredCertificate, now time.Time) error {
	if c == nil || c.config.Store == nil || !validIdentifier(accountID) || !validIdentifier(domainID) || expectedGeneration == 0 || certificate.CertificateGeneration == 0 {
		return ErrInvalid
	}
	if committer, ok := c.config.Store.(CertificateDomainCommitter); ok {
		return committer.CommitDomainCertificateReady(ctx, accountID, domainID, expectedGeneration, certificate, now)
	}
	if c.config.Operations != nil {
		return c.config.Operations.CompleteDomainCreate(ctx, accountID, domainID, certificate.CertificateGeneration)
	}
	return fmt.Errorf("%w: atomic domain certificate commit is unavailable", ErrCertificateNotReady)
}

// CommitPreviewDomainCertificateReady delegates the preview projection commit
// to SQLStore. It is intentionally separate from the durable commit boundary:
// an exact leaf or a preview parent must never advance tunnel_domains.
func (c *Coordinator) CommitPreviewDomainCertificateReady(ctx context.Context, accountID, domainID, previewID string, previewGeneration, expectedDomainGeneration uint64, certificate StoredCertificate, now time.Time) error {
	if c == nil || c.config.Store == nil || !validIdentifier(accountID) || !validIdentifier(domainID) || !validIdentifier(previewID) || previewGeneration == 0 || expectedDomainGeneration == 0 || certificate.CertificateGeneration == 0 {
		return ErrInvalid
	}
	committer, ok := c.config.Store.(PreviewCertificateDomainCommitter)
	if !ok {
		return fmt.Errorf("%w: atomic preview certificate commit is unavailable", ErrCertificateNotReady)
	}
	return committer.CommitPreviewDomainCertificateReady(ctx, accountID, domainID, previewID, previewGeneration, expectedDomainGeneration, certificate, now)
}

// PreviewCertificateReady checks the exact preview/edge tuple before an alias
// is published. The store remains authoritative for lease and certificate
// generation fences.
func (c *Coordinator) PreviewCertificateReady(ctx context.Context, accountID, domainID, previewID, hostname string, previewGeneration, domainGeneration, certificateGeneration uint64, edge DistributionTarget, now time.Time) (bool, error) {
	if c == nil || c.config.Store == nil || !validIdentifier(accountID) || !validIdentifier(domainID) || !validIdentifier(previewID) || previewGeneration == 0 || domainGeneration == 0 || certificateGeneration == 0 {
		return false, ErrInvalid
	}
	readiness, ok := c.config.Store.(PreviewCertificateReadiness)
	if !ok {
		return false, fmt.Errorf("%w: preview certificate readiness is unavailable", ErrCertificateNotReady)
	}
	return readiness.PreviewCertificateReady(ctx, accountID, domainID, previewID, hostname, previewGeneration, domainGeneration, certificateGeneration, edge, now)
}

// ReconcileDistributionCleanup performs one bounded durable edge cleanup pass.
func (c *Coordinator) ReconcileDistributionCleanup(ctx context.Context, limit int) (int, error) {
	if c == nil || c.config.Distributor == nil || limit < 1 || limit > 500 {
		return 0, ErrInvalid
	}
	cleaner, ok := c.config.Distributor.(CertificateDistributionCleanup)
	if !ok {
		return 0, nil
	}
	return cleaner.ReconcileCertificateDistributionCleanup(ctx, limit)
}

// ReconcileRevocations performs one bounded authority and edge revocation
// retry pass. It intentionally continues after a per-certificate failure so
// one unavailable authority cannot starve unrelated terminal revocations.
func (c *Coordinator) ReconcileRevocations(ctx context.Context, limit int) (int, error) {
	if c == nil || c.config.Store == nil || limit < 1 || limit > 500 {
		return 0, ErrInvalid
	}
	ledger, ok := c.config.Store.(CertificateRevocationStore)
	if !ok {
		return 0, nil
	}
	certificates, err := ledger.ListPendingCertificateRevocations(ctx, limit)
	if err != nil {
		return 0, err
	}
	completed := 0
	var passErr error
	for _, certificate := range certificates {
		if err := ctx.Err(); err != nil {
			return completed, err
		}
		revokeErr := c.revokeCertificateMaterial(ctx, certificate)
		if revokeErr != nil {
			markErr := ledger.MarkCertificateRevocationResult(ctx, certificate.ID, false, boundedRevocationFailure(revokeErr), c.config.Now().UTC())
			passErr = errors.Join(passErr, errors.Join(revokeErr, markErr))
			continue
		}
		if markErr := ledger.MarkCertificateRevocationResult(ctx, certificate.ID, true, "", c.config.Now().UTC()); markErr != nil {
			passErr = errors.Join(passErr, markErr)
			continue
		}
		completed++
	}
	return completed, passErr
}

// RebindPreviewCertificate reconciles an active preview parent after a lease
// generation advance. It first updates the durable target fence, then uses
// the normal bounded edge distribution path. No issuer is called and the
// certificate generation, ID, fingerprint, and ciphertext remain unchanged.
// A false result means there was no old-generation active certificate to
// rebind; the caller may proceed with ordinary issuance.
func (c *Coordinator) RebindPreviewCertificate(ctx context.Context, domain Domain, now time.Time) (bool, error) {
	if c == nil || c.config.Store == nil || domain.Target().normalizedKind() != TargetPreviewLease || domain.PreviewGeneration == 0 {
		return false, ErrInvalid
	}
	rebinder, ok := c.config.Store.(PreviewCertificateRebinder)
	if !ok {
		return false, nil
	}
	var current StoredCertificate
	var found bool
	var err error
	if domain.LeafHostname == "" {
		current, found, err = rebinder.CurrentPreviewForRebind(ctx, domain.AccountID, domain.ID, domain.PreviewID, now.UTC())
	} else {
		current, found, err = rebinder.CurrentPreviewForHostnameRebind(ctx, domain.AccountID, domain.ID, domain.PreviewID, domain.LeafHostname, now.UTC())
	}
	if err != nil || !found {
		return false, err
	}
	if current.State != StateActive {
		return false, nil
	}
	if current.DomainID != domain.ID || current.AccountID != domain.AccountID || current.PreviewID != domain.PreviewID {
		return false, ErrGenerationConflict
	}
	if current.LeafHostname != domain.LeafHostname {
		return false, ErrGenerationConflict
	}
	// A row already carrying the current lease target is not in the renewal
	// gap. Let Ensure inspect its expiry and either take the healthy fast path or
	// issue a replacement. Returning true here would make every preview renewal
	// look like a successful rebind and suppress due issuance indefinitely.
	if current.Target().Key() == domain.Target().Key() {
		return false, nil
	}
	if current.PreviewGeneration == 0 || current.PreviewGeneration >= domain.PreviewGeneration {
		return false, ErrGenerationConflict
	}
	current, err = rebinder.RebindPreviewCertificateTarget(ctx, current.ID, domain.AccountID, domain.ID, domain.PreviewID, current.PreviewGeneration, domain.PreviewGeneration, domain.PreviewExpiresAt, now.UTC())
	if err != nil {
		return false, err
	}
	if current.Target().Key() != domain.Target().Key() {
		return false, ErrGenerationConflict
	}
	if len(domain.EdgeTargets) == 0 {
		return true, fmt.Errorf("%w: no ready preview edge targets", ErrCertificateNotReady)
	}
	_, err = c.reconcileActiveDistribution(ctx, current, domain, now.UTC())
	return true, err
}

type Result struct {
	Certificate CertificateView
	Fallback    bool
	Issued      bool
	Challenge   *DNSChallenge
	// CleanupPending reports that the new certificate is already authoritative
	// but one or more old edge copies could not be retired. The durable
	// distributor keeps those rows eligible for retry; this is deliberately a
	// warning, not an issuance failure that could trigger another certificate.
	CleanupPending bool
	CleanupError   error
}

func NewCoordinator(config Config) (*Coordinator, error) {
	if config.CAA == nil {
		return nil, fmt.Errorf("%w: CAA preflight is required", ErrCAAUnavailable)
	}
	if config.Store == nil || config.Locks == nil || config.Keys == nil || config.Issuer == nil || config.Distributor == nil || !validKeyReference(config.MasterKeyReference) || !validIdentifier(config.OwnerID) {
		return nil, fmt.Errorf("%w: incomplete coordinator dependencies", ErrInvalid)
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.LockTTL <= 0 || config.LockTTL > 15*time.Minute {
		config.LockTTL = defaultLockTTL
	}
	if config.RenewBefore <= 0 || config.RenewBefore >= 365*24*time.Hour {
		config.RenewBefore = defaultRenewBefore
	}
	if config.DistributionTimeout <= 0 || config.DistributionTimeout > 2*time.Minute {
		config.DistributionTimeout = defaultDistributionLimit
	}
	if config.ExpiryAlertWindow <= 0 || config.ExpiryAlertWindow > 90*24*time.Hour {
		config.ExpiryAlertWindow = defaultExpiryAlertWindow
	}
	if config.MaxCertificateLifetime <= 0 || config.MaxCertificateLifetime > 90*24*time.Hour {
		config.MaxCertificateLifetime = 90 * 24 * time.Hour
	}
	if config.IssuerName == "" {
		config.IssuerName = "letsencrypt"
	}
	return &Coordinator{config: config, alerted: make(map[string]struct{})}, nil
}

func (c *Coordinator) Ensure(ctx context.Context, domain Domain) (result Result, returnErr error) {
	if c == nil {
		return Result{}, ErrInvalid
	}
	// Issuers return transient plaintext PEM buffers. Keep that buffer under a
	// cleanup defer from the moment it is assigned, including issuer errors and
	// fallback failures, so an implementation cannot leave a rejected bundle
	// reachable until the next GC cycle.
	var issuedBundle CertificateBundle
	defer wipeCertificateBundle(&issuedBundle)
	if err := domain.Validate(); err != nil {
		return Result{}, err
	}
	domain.EdgeTargets = SortEdgeTargets(domain.EdgeTargets)
	now := c.config.Now().UTC()
	if err := domain.Target().ValidateActive(now); err != nil {
		return Result{}, err
	}
	current, found, err := c.currentCertificate(ctx, domain)
	if err != nil {
		return Result{}, err
	}
	if found {
		if current.DomainGeneration > domain.Generation {
			return Result{}, ErrGenerationConflict
		}
		if current.DomainGeneration == domain.Generation && current.State == StateRevoked {
			return Result{}, ErrCertificateRevoked
		}
		if current.State == StateActive {
			if domain.LeafHostname == "" && !activeCertificateMatchesDomain(current, domain) {
				// An active row whose reference no longer matches the current
				// verified domain projection is a stale/partial publication. Do
				// not mint another certificate over it or silently repair the
				// projection from an untrusted row.
				return Result{}, ErrGenerationConflict
			}
			// An exact on-demand leaf is a separate SNI product under a
			// wildcard binding. Never reuse the wildcard parent certificate
			// for that request, and never let a parent fast-path suppress the
			// exact-leaf issuance/distribution attempt.
			exactLeafMatches := activeCertificateMatchesDomain(current, domain)
			if err := c.alertExpiry(ctx, domain, current, now); err != nil {
				return Result{}, err
			}
			if exactLeafMatches && !domain.RenewalDue && current.RenewalAt.After(now) && current.ExpiresAt.After(now) {
				needed, err := c.activeDistributionNeeded(ctx, current, domain)
				if err != nil {
					return Result{}, err
				}
				if !needed {
					return Result{Certificate: current.View()}, nil
				}
			}
		}
	}
	if c.config.CAA != nil {
		caa, checkErr := c.config.CAA.Check(ctx, domain.Hostname, c.config.IssuerName)
		if checkErr != nil {
			if errors.Is(checkErr, ErrCAABlocked) || errors.Is(checkErr, ErrCAAUnavailable) {
				return Result{}, checkErr
			}
			return Result{}, fmt.Errorf("%w: %v", ErrCAAUnavailable, checkErr)
		}
		if caa.State != "ready" && caa.State != "not_applicable" {
			code := caa.FailureCode
			if code == "" {
				code = "caa_blocked"
			}
			return Result{}, fmt.Errorf("%w: %s", ErrCAABlocked, code)
		}
	}
	leaseUntil := now.Add(c.config.LockTTL)
	locked, err := c.config.Locks.Acquire(ctx, domain.ID, c.config.OwnerID, domain.Generation, now, leaseUntil)
	if err != nil {
		return Result{}, err
	}
	if !locked {
		return Result{}, ErrIssuanceLocked
	}
	defer func() {
		var releaseErr error
		if generationLock, ok := c.config.Locks.(GenerationIssuanceLock); ok {
			releaseErr = generationLock.ReleaseGeneration(context.Background(), domain.ID, c.config.OwnerID, domain.Generation)
		} else {
			releaseErr = c.config.Locks.Release(context.Background(), domain.ID, c.config.OwnerID)
		}
		if releaseErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("%w: release issuance lock: %v", ErrIssuanceLocked, releaseErr))
		}
	}()
	// Re-read after the distributed lock.  Another replica may have completed
	// issuance between the initial read and lock acquisition.
	current, found, err = c.currentCertificate(ctx, domain)
	if err != nil {
		return Result{}, err
	}
	if found && current.DomainGeneration > domain.Generation {
		return Result{}, ErrGenerationConflict
	}
	exactLeafMatches := activeCertificateMatchesDomain(current, domain)
	if found && current.State == StateActive && current.DomainGeneration <= domain.Generation && exactLeafMatches && !domain.RenewalDue && current.RenewalAt.After(now) && current.ExpiresAt.After(now) {
		needed, err := c.activeDistributionNeeded(ctx, current, domain)
		if err != nil {
			return Result{}, err
		}
		if !needed {
			return Result{Certificate: current.View()}, nil
		}
		return c.reconcileActiveDistribution(ctx, current, domain, now)
	}
	challenge := DNSChallenge{}
	var challengePtr *DNSChallenge
	_, completeDNS01Issuer := c.config.Issuer.(DNS01Issuer)
	if !completeDNS01Issuer && (domain.Strategy == StrategyDelegatedDNS01 || domain.Strategy == StrategyOnDemandLeaf) {
		if domain.Strategy == StrategyDelegatedDNS01 && c.config.Delegated == nil {
			return Result{}, ErrDNSChallengeUnavailable
		}
		if c.config.Delegated != nil {
			challenge, err = c.config.Delegated.Prepare(ctx, domain)
			if err != nil {
				if errors.Is(err, ErrDNSChallengePending) || errors.Is(err, ErrDNSChallengeUnavailable) {
					return Result{}, err
				}
				return Result{}, fmt.Errorf("%w: %v", ErrDNSChallengeUnavailable, err)
			}
			if err := validateChallenge(domain, challenge); err != nil {
				return Result{}, err
			}
			challengePtr = &challenge
		}
	}
	if domain.Strategy == StrategyOnDemandLeaf && domain.LeafHostname != "" {
		leafIssuer, ok := c.config.Issuer.(ExactLeafIssuer)
		if ok {
			issuedBundle, err = leafIssuer.IssueLeaf(ctx, IssueRequest{Domain: domain, Strategy: StrategyOnDemandLeaf, Challenge: challenge, LeafHostname: domain.LeafHostname})
		} else {
			err = fmt.Errorf("%w: exact on-demand leaf issuer is unavailable", ErrIssuerUnavailable)
		}
	} else if completeDNS01Issuer && (domain.Strategy == StrategyDelegatedDNS01 || domain.Strategy == StrategyPlatformDNS01 || domain.Strategy == StrategyOnDemandLeaf || domain.Strategy == StrategyWildcard) {
		issuedBundle, err = c.config.Issuer.(DNS01Issuer).IssueDNS01(ctx, domain)
	} else {
		issuedBundle, err = c.config.Issuer.Issue(ctx, IssueRequest{Domain: domain, Strategy: domain.Strategy, Challenge: challenge})
	}
	fallback := false
	if err != nil && domain.AllowOnDemandFallback && domain.Strategy == StrategyOnDemandLeaf && c.config.Fallback != nil && (errors.Is(err, ErrIssuerRateLimited) || errors.Is(err, ErrIssuerUnavailable)) {
		request := IssueRequest{Domain: domain, Strategy: StrategyOnDemandLeaf, Challenge: challenge, LeafHostname: domain.LeafHostname}
		if leafIssuer, ok := c.config.Fallback.(ExactLeafIssuer); ok {
			issuedBundle, err = leafIssuer.IssueLeaf(ctx, request)
		} else if legacy, ok := c.config.Fallback.(interface {
			IssueWildcardFallback(context.Context, IssueRequest) (CertificateBundle, error)
		}); ok && domain.LeafHostname == "" {
			// This adapter is accepted only for exact-host test deployments. The
			// certificate identity check below rejects wildcard fallback bytes.
			issuedBundle, err = legacy.IssueWildcardFallback(ctx, request)
		} else {
			err = fmt.Errorf("%w: exact on-demand leaf issuer is unavailable", ErrIssuerUnavailable)
		}
		fallback = err == nil
	}
	if err != nil {
		if errors.Is(err, ErrIssuerRateLimited) || errors.Is(err, ErrIssuerUnavailable) {
			return Result{}, err
		}
		return Result{}, fmt.Errorf("%w: %v", ErrIssuerUnavailable, err)
	}
	// Take ownership of a private copy so the coordinator can wipe every
	// plaintext buffer it created without mutating an issuer-owned return
	// value. No result or durable record aliases these PEM slices. Wipe the
	// issuer's original immediately rather than waiting for this call to end.
	bundle := cloneCertificateBundle(issuedBundle)
	wipeCertificateBundle(&issuedBundle)
	defer wipeCertificateBundle(&bundle)
	// An on-demand request is bound to a verified wildcard parent, but the
	// issued certificate must cover the requested exact SNI. Validate against
	// that leaf before persisting it; validating the wildcard parent here would
	// reject a correct leaf and would also blur the parent/leaf identity fence.
	validationHostname := domain.Hostname
	if domain.LeafHostname != "" {
		validationHostname = domain.LeafHostname
	}
	identity, err := bundle.Validate(validationHostname, now, c.config.MaxCertificateLifetime)
	if err != nil {
		return Result{}, err
	}
	if domain.Strategy == StrategyOnDemandLeaf && domain.LeafHostname != "" {
		requested := domain.Hostname
		if domain.LeafHostname != "" {
			requested = domain.LeafHostname
		}
		if err := validateExactLeafBundle(bundle, requested, now, c.config.MaxCertificateLifetime); err != nil {
			return Result{}, err
		}
	}
	certGeneration := uint64(1)
	if generationSource, ok := c.config.Store.(CertificateGenerationSource); ok {
		// A durable source includes failed, staged, superseded, and revoked
		// rows. Always consult it, including renewal, so a retry cannot reuse a
		// generation that reached the database before an earlier attempt failed.
		certGeneration, err = generationSource.NextCertificateGeneration(ctx, domain.ID)
		if err != nil {
			return Result{}, err
		}
		if certGeneration == 0 || (found && certGeneration <= current.CertificateGeneration) {
			return Result{}, ErrGenerationConflict
		}
	} else if found {
		// The in-memory/legacy fallback has no durable history beyond its
		// current projection. Fence the uint64 increment explicitly rather than
		// wrapping back to generation zero.
		if current.CertificateGeneration == ^uint64(0) {
			return Result{}, ErrGenerationConflict
		}
		certGeneration = current.CertificateGeneration + 1
	}
	certificateCiphertext, privateKeyCiphertext, err := SealParts(ctx, c.config.Keys, c.config.MasterKeyReference, bundle)
	if err != nil {
		return Result{}, err
	}
	certID := certificateID(domain, certGeneration, identity.Fingerprint)
	stored := StoredCertificate{ID: certID, DomainID: domain.ID, AccountID: domain.AccountID, TunnelID: domain.TunnelID, TargetKind: domain.TargetKind, RouteID: domain.RouteID, PreviewID: domain.PreviewID, PreviewGeneration: domain.PreviewGeneration, PreviewState: domain.PreviewState, PreviewExpiresAt: domain.PreviewExpiresAt, Hostname: identity.Hostname, LeafHostname: domain.LeafHostname, DomainGeneration: domain.Generation, CertificateGeneration: certGeneration, Strategy: domain.Strategy, State: StateStaged, CertificateReference: "tcert_" + certID, MasterKeyReference: c.config.MasterKeyReference, CertificateCiphertext: certificateCiphertext, PrivateKeyCiphertext: privateKeyCiphertext, Envelope: append([]byte(nil), certificateCiphertext...), Fingerprint: identity.Fingerprint, Issuer: identity.Issuer, NotBefore: identity.NotBefore, ExpiresAt: identity.NotAfter, RenewalAt: identity.NotAfter.Add(-c.config.RenewBefore)}
	stored.UpdatedAt = now
	if err := c.config.Store.PutStaged(ctx, stored); err != nil {
		return Result{}, err
	}
	if len(domain.EdgeTargets) == 0 {
		return Result{}, c.failStaged(ctx, stored.ID, "no_ready_edge_targets", fmt.Errorf("%w: no ready edge targets", ErrCertificateNotReady), now)
	}
	staged := make([]DistributionRequest, 0, len(domain.EdgeTargets))
	for _, target := range domain.EdgeTargets {
		request := DistributionRequest{Certificate: stored, Bundle: bundle, Target: DistributionTarget(target)}
		if err := c.config.Distributor.Stage(ctx, request); err != nil {
			cause := fmt.Errorf("%w: stage edge %s: %v", ErrDistributionUnavailable, target.NodeID, err)
			if rollbackErr := c.rollbackStaged(stored, staged); rollbackErr != nil {
				cause = errors.Join(cause, rollbackErr)
			}
			return Result{}, c.failStaged(ctx, stored.ID, "edge_stage_failed", cause, now)
		}
		staged = append(staged, request)
	}
	distributionCtx, cancel := context.WithTimeout(ctx, c.config.DistributionTimeout)
	defer cancel()
	for _, request := range staged {
		if err := c.config.Distributor.WaitReady(distributionCtx, request); err != nil {
			cause := fmt.Errorf("%w: edge %s: %v", ErrCertificateNotReady, request.Target.NodeID, err)
			if rollbackErr := c.rollbackStaged(stored, staged); rollbackErr != nil {
				cause = errors.Join(cause, rollbackErr)
			}
			return Result{}, c.failStaged(ctx, stored.ID, "edge_not_ready", cause, now)
		}
	}
	for _, request := range staged {
		if err := c.config.Distributor.Activate(ctx, request); err != nil {
			cause := fmt.Errorf("%w: activate edge %s: %v", ErrDistributionUnavailable, request.Target.NodeID, err)
			if rollbackErr := c.rollbackStaged(stored, staged); rollbackErr != nil {
				cause = errors.Join(cause, rollbackErr)
			}
			return Result{}, c.failStaged(ctx, stored.ID, "edge_activate_failed", cause, now)
		}
	}
	active, err := c.config.Store.Activate(ctx, stored.ID, domain.Generation, now)
	if err != nil {
		cause := fmt.Errorf("%w: activate durable certificate: %v", ErrDistributionUnavailable, err)
		if rollbackErr := c.rollbackStaged(stored, staged); rollbackErr != nil {
			cause = errors.Join(cause, rollbackErr)
		}
		return Result{}, c.failStaged(ctx, stored.ID, "certificate_activate_failed", cause, now)
	}
	if domain.Target().normalizedKind() == TargetPreviewLease {
		// Preview renewal may briefly leave an active row on the previous
		// generation when an older server is still finishing the transaction.
		// Surface that row as a stale generation rather than minting a second
		// certificate. The worker rebinds it before retrying Ensure.
	} else if domain.LeafHostname != "" {
		leafStore, ok := c.config.Store.(HostnameCertificateStore)
		if !ok {
			return Result{}, fmt.Errorf("%w: exact leaf store is unavailable", ErrDistributionUnavailable)
		}
		if err := leafStore.SupersedeOlderForHostname(ctx, domain.ID, domain.LeafHostname, active.CertificateGeneration, now); err != nil {
			return Result{}, err
		}
	} else if err := c.config.Store.SupersedeOlder(ctx, domain.ID, active.CertificateGeneration, now); err != nil {
		return Result{}, err
	}
	var cleanupErr error
	if found && current.State == StateActive {
		if durableRetirer, ok := c.config.Distributor.(CertificateDurableRetirer); ok {
			if err := durableRetirer.RetireCertificate(ctx, current); err != nil {
				cleanupErr = fmt.Errorf("%w: retire prior edge distributions: %v", ErrDistributionUnavailable, err)
			}
		} else {
			for _, target := range domain.EdgeTargets {
				if err := c.config.Distributor.Retire(ctx, current, DistributionTarget(target)); err != nil {
					cleanupErr = errors.Join(cleanupErr, fmt.Errorf("%w: retire edge %s: %v", ErrDistributionUnavailable, target.NodeID, err))
				}
			}
		}
	}
	// SQLStore performs the domain projection and domain.create completion in a
	// single serializable worker/store transaction. Only the deliberately
	// minimal in-memory adapter uses the legacy operation callback here.
	// Exact leaves are children of the wildcard domain. They never mutate the
	// wildcard domain projection or complete its domain.create operation.
	if domain.LeafHostname == "" {
		if _, atomicCommitter := c.config.Store.(CertificateDomainCommitter); !atomicCommitter && c.config.Operations != nil {
			if err := c.config.Operations.CompleteDomainCreate(ctx, domain.AccountID, domain.ID, active.CertificateGeneration); err != nil {
				return Result{}, err
			}
		}
	}
	return Result{Certificate: active.View(), Fallback: fallback, Issued: true, Challenge: challengePtr, CleanupPending: cleanupErr != nil, CleanupError: cleanupErr}, nil
}

func (c *Coordinator) currentCertificate(ctx context.Context, domain Domain) (StoredCertificate, bool, error) {
	if domain.Target().normalizedKind() == TargetPreviewLease {
		previewStore, ok := c.config.Store.(PreviewCertificateLookup)
		if !ok {
			return StoredCertificate{}, false, fmt.Errorf("%w: preview certificate store is unavailable", ErrDistributionUnavailable)
		}
		if domain.LeafHostname == "" {
			current, found, err := previewStore.CurrentPreview(ctx, domain.AccountID, domain.ID, domain.PreviewID)
			if err != nil || found {
				return current, found, err
			}
			if rebinder, ok := c.config.Store.(PreviewCertificateRebinder); ok {
				return rebinder.CurrentPreviewForRebind(ctx, domain.AccountID, domain.ID, domain.PreviewID, c.config.Now().UTC())
			}
			return current, false, nil
		}
		current, found, err := previewStore.CurrentPreviewForHostname(ctx, domain.AccountID, domain.ID, domain.PreviewID, domain.LeafHostname)
		if err != nil || found {
			return current, found, err
		}
		if rebinder, ok := c.config.Store.(PreviewCertificateRebinder); ok {
			return rebinder.CurrentPreviewForHostnameRebind(ctx, domain.AccountID, domain.ID, domain.PreviewID, domain.LeafHostname, c.config.Now().UTC())
		}
		return current, false, nil
	}
	if domain.LeafHostname == "" {
		return c.config.Store.Current(ctx, domain.ID)
	}
	store, ok := c.config.Store.(HostnameCertificateStore)
	if !ok {
		return StoredCertificate{}, false, fmt.Errorf("%w: exact leaf store is unavailable", ErrDistributionUnavailable)
	}
	return store.CurrentForHostname(ctx, domain.ID, domain.LeafHostname)
}

func activeCertificateMatchesDomain(certificate StoredCertificate, domain Domain) bool {
	if certificate.CertificateReference == "" || certificate.Target().Key() != domain.Target().Key() {
		return false
	}
	if domain.LeafHostname != "" {
		return certificate.LeafHostname == domain.LeafHostname && certificate.Hostname == domain.LeafHostname
	}
	return certificate.LeafHostname == "" && certificate.Hostname == domain.Hostname && certificate.CertificateReference == domain.CertificateReference
}

func (c *Coordinator) rollbackStaged(certificate StoredCertificate, staged []DistributionRequest) error {
	if len(staged) == 0 {
		return nil
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), c.config.DistributionTimeout)
	defer cancel()
	var rollbackErr error
	for _, request := range staged {
		var err error
		if rollback, ok := c.config.Distributor.(CertificateDistributionRollback); ok {
			err = rollback.Revoke(rollbackCtx, certificate, request.Target)
		} else {
			err = c.config.Distributor.Retire(rollbackCtx, certificate, request.Target)
		}
		if err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("%w: rollback edge %s: %v", ErrDistributionUnavailable, request.Target.NodeID, err))
		}
	}
	return rollbackErr
}

func (c *Coordinator) failStaged(ctx context.Context, id, reason string, cause error, now time.Time) error {
	if err := c.config.Store.MarkFailed(ctx, id, reason, now); err != nil {
		return fmt.Errorf("%w: persist staged failure: %w", cause, err)
	}
	return cause
}

func (c *Coordinator) Revoke(ctx context.Context, domainID, reason string) (CertificateView, error) {
	if c == nil || !validIdentifier(domainID) {
		return CertificateView{}, ErrInvalid
	}
	current, found, err := c.config.Store.Current(ctx, domainID)
	if err != nil {
		return CertificateView{}, err
	}
	if !found {
		return CertificateView{}, ErrCertificateNotReady
	}
	return c.revokeCurrent(ctx, current, reason)
}

// RevokeHostname revokes one exact leaf in the hostname namespace of a
// wildcard binding. It deliberately resolves the leaf before revocation, so
// the wildcard parent's current projection and generation are never cleared
// by an exact-leaf operation.
func (c *Coordinator) RevokeHostname(ctx context.Context, domainID, hostname, reason string) (CertificateView, error) {
	if c == nil || !validIdentifier(domainID) {
		return CertificateView{}, ErrInvalid
	}
	host, wildcard, err := normalizeHostname(hostname)
	if err != nil || wildcard || host != hostname {
		return CertificateView{}, ErrInvalid
	}
	store, ok := c.config.Store.(HostnameCertificateStore)
	if !ok {
		return CertificateView{}, fmt.Errorf("%w: exact leaf store is unavailable", ErrDistributionUnavailable)
	}
	current, found, err := store.CurrentForHostname(ctx, domainID, host)
	if err != nil {
		return CertificateView{}, err
	}
	if !found || current.LeafHostname != host {
		return CertificateView{}, ErrCertificateNotReady
	}
	return c.revokeCurrent(ctx, current, reason)
}

func (c *Coordinator) revokeCurrent(ctx context.Context, current StoredCertificate, reason string) (CertificateView, error) {
	now := c.config.Now().UTC()
	revoked, err := c.config.Store.Revoke(ctx, current.ID, reason, now)
	if err != nil {
		return CertificateView{}, err
	}
	var revokeErr error
	if revoker, ok := c.config.Distributor.(CertificateRevoker); ok {
		if err := revoker.RevokeCertificate(ctx, revoked); err != nil {
			revokeErr = errors.Join(revokeErr, fmt.Errorf("%w: revoke edge distribution: %v", ErrDistributionUnavailable, err))
		}
	} else {
		revokeErr = errors.Join(revokeErr, fmt.Errorf("%w: edge transport does not support terminal revocation", ErrDistributionUnavailable))
	}
	if err := c.revokeCertificateMaterial(ctx, revoked); err != nil {
		revokeErr = errors.Join(revokeErr, err)
	}
	if ledger, ok := c.config.Store.(CertificateRevocationStore); ok {
		confirmed := revokeErr == nil
		markErr := ledger.MarkCertificateRevocationResult(ctx, revoked.ID, confirmed, boundedRevocationFailure(revokeErr), now)
		if markErr != nil {
			revokeErr = errors.Join(revokeErr, markErr)
		}
	} else if revokeErr == nil {
		// Production SQL storage always implements the ledger. Refuse to claim
		// terminal authority revocation when a custom store cannot retry it.
		revokeErr = fmt.Errorf("%w: durable revocation ledger is unavailable", ErrCertificateRevocationUnavailable)
	}
	if revokeErr != nil {
		return revoked.View(), revokeErr
	}
	return revoked.View(), nil
}

func (c *Coordinator) revokeCertificateMaterial(ctx context.Context, certificate StoredCertificate) error {
	caRevoker, ok := c.config.Issuer.(CertificateAuthorityRevoker)
	if !ok {
		return fmt.Errorf("%w: configured issuer cannot revoke certificates", ErrCertificateRevocationUnavailable)
	}
	bundle, err := OpenParts(ctx, c.config.Keys, certificate.MasterKeyReference, certificate.CertificateCiphertext, certificate.PrivateKeyCiphertext)
	if err != nil {
		return fmt.Errorf("%w: open certificate bundle: %v", ErrCertificateRevocationUnavailable, err)
	}
	defer wipeCertificateBundle(&bundle)
	if err := caRevoker.RevokeBundle(ctx, bundle); err != nil {
		return fmt.Errorf("%w: authority rejected certificate revocation: %v", ErrCertificateRevocationUnavailable, err)
	}
	return nil
}

func wipeCertificateBundle(bundle *CertificateBundle) {
	if bundle == nil {
		return
	}
	clear(bundle.CertificatePEM)
	clear(bundle.PrivateKeyPEM)
	bundle.CertificatePEM = nil
	bundle.PrivateKeyPEM = nil
}

func cloneCertificateBundle(bundle CertificateBundle) CertificateBundle {
	return CertificateBundle{
		CertificatePEM: append([]byte(nil), bundle.CertificatePEM...),
		PrivateKeyPEM:  append([]byte(nil), bundle.PrivateKeyPEM...),
		Issuer:         bundle.Issuer,
		NotBefore:      bundle.NotBefore,
		NotAfter:       bundle.NotAfter,
	}
}

func boundedRevocationFailure(err error) string {
	if err == nil {
		return "ca_revoked"
	}
	const prefix = "ca_revocation_pending"
	return prefix
}

func (c *Coordinator) alertExpiry(ctx context.Context, domain Domain, current StoredCertificate, now time.Time) error {
	if c.config.Alerts == nil || current.State != StateActive {
		return nil
	}
	remaining := current.ExpiresAt.Sub(now)
	if remaining <= 0 {
		return c.emitExpiryAlert(ctx, ExpiryAlert{DomainID: domain.ID, Hostname: domain.Hostname, CertificateRef: current.CertificateReference, CertificateGeneration: current.CertificateGeneration, ExpiresAt: current.ExpiresAt, Code: "certificate_expired"})
	}
	if remaining <= c.config.ExpiryAlertWindow {
		return c.emitExpiryAlert(ctx, ExpiryAlert{DomainID: domain.ID, Hostname: domain.Hostname, CertificateRef: current.CertificateReference, CertificateGeneration: current.CertificateGeneration, ExpiresAt: current.ExpiresAt, Code: "certificate_expiring"})
	}
	return nil
}

func (c *Coordinator) emitExpiryAlert(ctx context.Context, alert ExpiryAlert) error {
	key := fmt.Sprintf("%s:%d:%s", alert.DomainID, alert.CertificateGeneration, alert.Code)
	c.alertMu.Lock()
	if _, exists := c.alerted[key]; exists {
		c.alertMu.Unlock()
		return nil
	}
	// Reserve before calling the sink so concurrent reconciles cannot emit the
	// same alert twice.  A failed sink releases the reservation and allows a
	// later reconciliation to retry delivery.
	c.alerted[key] = struct{}{}
	c.alertMu.Unlock()
	if err := c.config.Alerts.Alert(ctx, alert); err != nil {
		c.alertMu.Lock()
		delete(c.alerted, key)
		c.alertMu.Unlock()
		return err
	}
	return nil
}

func validateChallenge(domain Domain, challenge DNSChallenge) error {
	host, wildcard, err := normalizeHostname(domain.Hostname)
	if err != nil {
		return err
	}
	if challenge.Type != "TXT" || challenge.Name == "" || challenge.Value == "" || len(challenge.Value) > 512 || challenge.TTL < 30*time.Second || challenge.TTL > 24*time.Hour {
		return fmt.Errorf("%w: delegated DNS challenge is invalid", ErrDNSChallengeUnavailable)
	}
	base := host
	if wildcard {
		base = host[2:]
	}
	authorizationName := challenge.AuthorizationName
	if authorizationName == "" {
		authorizationName = "_acme-challenge." + base
	}
	wantAuthorization := "_acme-challenge." + base
	if !strings.EqualFold(strings.TrimSuffix(authorizationName, "."), wantAuthorization) {
		return fmt.Errorf("%w: challenge authorization name is not bound to hostname", ErrDNSChallengeUnavailable)
	}
	targetName := challenge.TargetName
	if targetName == "" {
		targetName = challenge.Name
	}
	if !strings.EqualFold(strings.TrimSuffix(challenge.Name, "."), strings.TrimSuffix(targetName, ".")) {
		return fmt.Errorf("%w: challenge write target mismatch", ErrDNSChallengeUnavailable)
	}
	if domain.ChallengeReference != "" && domain.Target().normalizedKind() != TargetPlatformWildcard {
		// The coordinator cannot know the configured challenge zone, but it can
		// still reject the unsafe legacy direct-customer target whenever the
		// issuer supplied a distinct authorization name.
		if strings.EqualFold(strings.TrimSuffix(targetName, "."), wantAuthorization) && !strings.EqualFold(strings.TrimSuffix(challenge.Name, "."), wantAuthorization) {
			return fmt.Errorf("%w: challenge target is not delegated", ErrDNSChallengeUnavailable)
		}
	}
	return nil
}

func certificateID(domain Domain, generation uint64, fingerprint [sha256.Size]byte) string {
	hash := sha256.New()
	for _, value := range []string{
		string(domain.Target().normalizedKind()), domain.ID, domain.AccountID,
		domain.TunnelID, domain.RouteID, domain.PreviewID,
		fmt.Sprint(domain.PreviewGeneration), fmt.Sprint(generation), domain.Hostname,
		domain.LeafHostname,
	} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	hash.Write(fingerprint[:])
	return hex.EncodeToString(hash.Sum(nil)[:16])
}

// MemoryStore is deterministic storage for unit tests and for callers that
// need an explicit state machine without a database.  Production uses the SQL
// implementation in sql_store.go.
type MemoryStore struct {
	mu                 sync.Mutex
	current            map[string]StoredCertificate
	leafCurrent        map[string]StoredCertificate
	previewCurrent     map[string]StoredCertificate
	previewLeafCurrent map[string]StoredCertificate
	all                map[string]StoredCertificate
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		current: make(map[string]StoredCertificate), leafCurrent: make(map[string]StoredCertificate),
		previewCurrent: make(map[string]StoredCertificate), previewLeafCurrent: make(map[string]StoredCertificate),
		all: make(map[string]StoredCertificate),
	}
}

func (s *MemoryStore) Current(_ context.Context, domainID string) (StoredCertificate, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.current[domainID]
	value.Envelope = append([]byte(nil), value.Envelope...)
	value.CertificateCiphertext = append([]byte(nil), value.CertificateCiphertext...)
	value.PrivateKeyCiphertext = append([]byte(nil), value.PrivateKeyCiphertext...)
	return value, ok, nil
}

// NextCertificateGeneration mirrors the durable store's no-reuse rule for
// tests and in-memory callers. Scan every row in this domain namespace, not
// only the active projection, because a staged or failed row already consumed
// its sequence.
func (s *MemoryStore) NextCertificateGeneration(_ context.Context, domainID string) (uint64, error) {
	if s == nil || !validIdentifier(domainID) {
		return 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var maximum uint64
	for _, value := range s.all {
		if value.DomainID != domainID {
			continue
		}
		if value.CertificateGeneration > maximum {
			maximum = value.CertificateGeneration
		}
	}
	if maximum == ^uint64(0) {
		return 0, ErrGenerationConflict
	}
	return maximum + 1, nil
}

func (s *MemoryStore) CurrentForHostname(_ context.Context, domainID, hostname string) (StoredCertificate, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.leafCurrent[domainHostnameKey(domainID, hostname)]
	value.Envelope = append([]byte(nil), value.Envelope...)
	value.CertificateCiphertext = append([]byte(nil), value.CertificateCiphertext...)
	value.PrivateKeyCiphertext = append([]byte(nil), value.PrivateKeyCiphertext...)
	return value, ok, nil
}

func (s *MemoryStore) CurrentPreview(_ context.Context, accountID, domainID, previewID string) (StoredCertificate, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.previewCurrent[previewTargetKey(accountID, domainID, previewID)]
	value.Envelope = append([]byte(nil), value.Envelope...)
	value.CertificateCiphertext = append([]byte(nil), value.CertificateCiphertext...)
	value.PrivateKeyCiphertext = append([]byte(nil), value.PrivateKeyCiphertext...)
	return value, ok, nil
}

func (s *MemoryStore) CurrentPreviewForHostname(_ context.Context, accountID, domainID, previewID, hostname string) (StoredCertificate, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.previewLeafCurrent[previewTargetHostnameKey(accountID, domainID, previewID, hostname)]
	value.Envelope = append([]byte(nil), value.Envelope...)
	value.CertificateCiphertext = append([]byte(nil), value.CertificateCiphertext...)
	value.PrivateKeyCiphertext = append([]byte(nil), value.PrivateKeyCiphertext...)
	return value, ok, nil
}

func (s *MemoryStore) CurrentPreviewForRebind(_ context.Context, accountID, domainID, previewID string, _ time.Time) (StoredCertificate, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var selected StoredCertificate
	found := false
	for _, value := range s.all {
		if value.AccountID != accountID || value.DomainID != domainID || value.PreviewID != previewID || value.Target().normalizedKind() != TargetPreviewLease || value.LeafHostname != "" || value.State != StateActive {
			continue
		}
		if !found || value.PreviewGeneration > selected.PreviewGeneration || value.CertificateGeneration > selected.CertificateGeneration {
			selected, found = value, true
		}
	}
	selected.Envelope = append([]byte(nil), selected.Envelope...)
	selected.CertificateCiphertext = append([]byte(nil), selected.CertificateCiphertext...)
	selected.PrivateKeyCiphertext = append([]byte(nil), selected.PrivateKeyCiphertext...)
	return selected, found, nil
}

func (s *MemoryStore) CurrentPreviewForHostnameRebind(_ context.Context, accountID, domainID, previewID, hostname string, _ time.Time) (StoredCertificate, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var selected StoredCertificate
	found := false
	for _, value := range s.all {
		if value.AccountID != accountID || value.DomainID != domainID || value.PreviewID != previewID || value.Target().normalizedKind() != TargetPreviewLease || value.LeafHostname != hostname || value.State != StateActive {
			continue
		}
		if !found || value.PreviewGeneration > selected.PreviewGeneration || value.CertificateGeneration > selected.CertificateGeneration {
			selected, found = value, true
		}
	}
	selected.Envelope = append([]byte(nil), selected.Envelope...)
	selected.CertificateCiphertext = append([]byte(nil), selected.CertificateCiphertext...)
	selected.PrivateKeyCiphertext = append([]byte(nil), selected.PrivateKeyCiphertext...)
	return selected, found, nil
}

func (s *MemoryStore) PutStaged(_ context.Context, value StoredCertificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := value.Target().ValidateActive(value.UpdatedAt); err != nil {
		return err
	}
	if existing, exists := s.all[value.ID]; exists {
		if existing.DomainID != value.DomainID || existing.AccountID != value.AccountID || existing.TunnelID != value.TunnelID || existing.Target().Key() != value.Target().Key() || existing.Hostname != value.Hostname || existing.LeafHostname != value.LeafHostname || existing.DomainGeneration != value.DomainGeneration || existing.CertificateGeneration != value.CertificateGeneration || existing.Fingerprint != value.Fingerprint || existing.State != StateStaged && existing.State != StateFailed {
			return ErrGenerationConflict
		}
		if existing.State == StateFailed {
			existing.State = StateStaged
			existing.FailureCode = ""
			existing.UpdatedAt = value.UpdatedAt
			s.all[value.ID] = existing
		}
		return nil
	}
	value.Envelope = append([]byte(nil), value.Envelope...)
	value.CertificateCiphertext = append([]byte(nil), value.CertificateCiphertext...)
	value.PrivateKeyCiphertext = append([]byte(nil), value.PrivateKeyCiphertext...)
	s.all[value.ID] = value
	return nil
}

func (s *MemoryStore) Activate(_ context.Context, id string, domainGeneration uint64, now time.Time) (StoredCertificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.all[id]
	if !ok || value.DomainGeneration != domainGeneration || value.State != StateStaged {
		return StoredCertificate{}, ErrGenerationConflict
	}
	for otherID, other := range s.all {
		if otherID != id && other.DomainID == value.DomainID && other.Target().Key() == value.Target().Key() && other.LeafHostname == value.LeafHostname && other.State == StateActive && other.CertificateGeneration < value.CertificateGeneration {
			other.State = StateSuperseded
			other.UpdatedAt = now
			s.all[otherID] = other
		}
	}
	value.State = StateActive
	value.UpdatedAt = now
	s.all[id] = value
	if value.Target().normalizedKind() == TargetPreviewLease {
		key := previewTargetKey(value.AccountID, value.DomainID, value.PreviewID)
		if value.LeafHostname == "" {
			s.previewCurrent[key] = value
		} else {
			s.previewLeafCurrent[previewTargetHostnameKey(value.AccountID, value.DomainID, value.PreviewID, value.LeafHostname)] = value
		}
	} else if value.LeafHostname == "" {
		s.current[value.DomainID] = value
	} else {
		s.leafCurrent[domainHostnameKey(value.DomainID, value.LeafHostname)] = value
	}
	return value, nil
}

func (s *MemoryStore) SupersedeOlder(_ context.Context, domainID string, generation uint64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, value := range s.all {
		kind := value.Target().normalizedKind()
		if value.DomainID == domainID && (kind == TargetDurableRoute || kind == TargetPlatformWildcard) && value.LeafHostname == "" && value.CertificateGeneration < generation && value.State == StateActive {
			value.State = StateSuperseded
			value.UpdatedAt = now
			s.all[id] = value
		}
	}
	return nil
}

func (s *MemoryStore) SupersedeOlderForHostname(_ context.Context, domainID, hostname string, generation uint64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, value := range s.all {
		if value.DomainID == domainID && value.Target().normalizedKind() == TargetDurableRoute && value.LeafHostname == hostname && value.CertificateGeneration < generation && value.State == StateActive {
			value.State = StateSuperseded
			value.UpdatedAt = now
			s.all[id] = value
		}
	}
	return nil
}

func (s *MemoryStore) RebindPreviewCertificateTarget(_ context.Context, certificateID, accountID, domainID, previewID string, previousGeneration, previewGeneration uint64, expiresAt, now time.Time) (StoredCertificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.all[certificateID]
	if !ok || value.AccountID != accountID || value.DomainID != domainID || value.PreviewID != previewID || value.Target().normalizedKind() != TargetPreviewLease || value.PreviewGeneration != previousGeneration || value.State != StateActive && value.State != StateStaged {
		return StoredCertificate{}, ErrGenerationConflict
	}
	if previousGeneration == 0 || previewGeneration == 0 || previousGeneration == previewGeneration || expiresAt.IsZero() || !expiresAt.After(now.UTC()) {
		return StoredCertificate{}, ErrInvalid
	}
	oldParentKey := previewTargetKey(value.AccountID, value.DomainID, value.PreviewID)
	oldLeafKey := previewTargetHostnameKey(value.AccountID, value.DomainID, value.PreviewID, value.LeafHostname)
	value.PreviewGeneration = previewGeneration
	value.PreviewState = "active"
	value.PreviewExpiresAt = expiresAt.UTC()
	value.UpdatedAt = now.UTC()
	s.all[certificateID] = value
	if value.LeafHostname == "" {
		if current, exists := s.previewCurrent[oldParentKey]; exists && current.ID == certificateID {
			delete(s.previewCurrent, oldParentKey)
		}
		s.previewCurrent[oldParentKey] = value
	} else {
		if current, exists := s.previewLeafCurrent[oldLeafKey]; exists && current.ID == certificateID {
			delete(s.previewLeafCurrent, oldLeafKey)
		}
		s.previewLeafCurrent[previewTargetHostnameKey(value.AccountID, value.DomainID, value.PreviewID, value.LeafHostname)] = value
	}
	return value, nil
}

func (s *MemoryStore) MarkFailed(_ context.Context, id, reason string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.all[id]
	if !ok {
		return ErrCertificateNotReady
	}
	value.State, value.FailureCode, value.UpdatedAt = StateFailed, reason, now
	s.all[id] = value
	return nil
}

func (s *MemoryStore) Revoke(_ context.Context, id, reason string, now time.Time) (StoredCertificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.all[id]
	if !ok {
		return StoredCertificate{}, ErrCertificateNotReady
	}
	value.State, value.FailureCode, value.RevokedAt, value.UpdatedAt = StateRevoked, reason, &now, now
	s.all[id] = value
	if value.Target().normalizedKind() == TargetPreviewLease {
		if value.LeafHostname == "" {
			if current, ok := s.previewCurrent[previewTargetKey(value.AccountID, value.DomainID, value.PreviewID)]; ok && current.ID == value.ID {
				delete(s.previewCurrent, previewTargetKey(value.AccountID, value.DomainID, value.PreviewID))
			}
		} else {
			key := previewTargetHostnameKey(value.AccountID, value.DomainID, value.PreviewID, value.LeafHostname)
			if current, ok := s.previewLeafCurrent[key]; ok && current.ID == value.ID {
				delete(s.previewLeafCurrent, key)
			}
		}
	} else if value.LeafHostname == "" {
		if current, ok := s.current[value.DomainID]; ok && current.ID == value.ID {
			delete(s.current, value.DomainID)
		}
	} else {
		key := domainHostnameKey(value.DomainID, value.LeafHostname)
		if current, ok := s.leafCurrent[key]; ok && current.ID == value.ID {
			delete(s.leafCurrent, key)
		}
	}
	return value, nil
}

func domainHostnameKey(domainID, hostname string) string {
	return domainID + "\x00" + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
}

func previewTargetKey(accountID, domainID, previewID string) string {
	return strings.Join([]string{accountID, domainID, previewID}, "\x00")
}

func previewTargetHostnameKey(accountID, domainID, previewID, hostname string) string {
	return previewTargetKey(accountID, domainID, previewID) + "\x00" + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
}

type MemoryLock struct {
	mu     sync.Mutex
	leases map[string]memoryLease
}

type memoryLease struct {
	owner      string
	until      time.Time
	generation uint64
}

func NewMemoryLock() *MemoryLock { return &MemoryLock{leases: make(map[string]memoryLease)} }

func (l *MemoryLock) Acquire(_ context.Context, domainID, owner string, generation uint64, now, until time.Time) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	lease, ok := l.leases[domainID]
	if ok {
		// Once a higher domain generation has been observed, an older retry
		// remains fenced even if the previous lease expired. The same owner
		// may renew or advance its own generation, but never move backward.
		if generation < lease.generation {
			return false, nil
		}
		if lease.until.After(now) && lease.owner != owner {
			return false, nil
		}
	}
	l.leases[domainID] = memoryLease{owner: owner, until: until, generation: generation}
	return true, nil
}
func (l *MemoryLock) Release(_ context.Context, domainID, owner string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lease, ok := l.leases[domainID]; ok && lease.owner == owner {
		delete(l.leases, domainID)
	}
	return nil
}

func (l *MemoryLock) ReleaseGeneration(_ context.Context, domainID, owner string, generation uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lease, ok := l.leases[domainID]; ok && lease.owner == owner && lease.generation == generation {
		delete(l.leases, domainID)
	}
	return nil
}

// MemoryDistributor records the state transitions and enforces the intended
// ordering.  It is also useful as a deterministic test oracle.
type MemoryDistributor struct {
	mu      sync.Mutex
	Targets map[string]bool
	Active  map[string]bool
	Events  []string
	FailAt  string
}

func NewMemoryDistributor() *MemoryDistributor {
	return &MemoryDistributor{Targets: make(map[string]bool), Active: make(map[string]bool)}
}
func (d *MemoryDistributor) Stage(_ context.Context, request DistributionRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Events = append(d.Events, "stage:"+request.Target.NodeID)
	if d.FailAt == "stage" {
		return ErrDistributionUnavailable
	}
	return nil
}
func (d *MemoryDistributor) WaitReady(_ context.Context, request DistributionRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Events = append(d.Events, "ready:"+request.Target.NodeID)
	if d.FailAt == "ready" {
		return ErrCertificateNotReady
	}
	d.Targets[request.Target.NodeID] = true
	return nil
}
func (d *MemoryDistributor) Activate(_ context.Context, request DistributionRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Events = append(d.Events, "activate:"+request.Target.NodeID)
	if d.FailAt == "activate" {
		return ErrDistributionUnavailable
	}
	if !d.Targets[request.Target.NodeID] {
		return ErrCertificateNotReady
	}
	d.Active[distributionTargetKey(request.Target)] = true
	return nil
}
func (d *MemoryDistributor) Retire(_ context.Context, certificate StoredCertificate, target DistributionTarget) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Events = append(d.Events, "retire:"+certificate.CertificateReference+":"+target.NodeID)
	if d.FailAt == "retire" {
		return ErrDistributionUnavailable
	}
	return nil
}

func (d *MemoryDistributor) Revoke(_ context.Context, certificate StoredCertificate, target DistributionTarget) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Events = append(d.Events, "rollback:"+certificate.CertificateReference+":"+target.NodeID)
	if d.FailAt == "rollback" {
		return ErrDistributionUnavailable
	}
	return nil
}

func (d *MemoryDistributor) RevokeCertificate(_ context.Context, certificate StoredCertificate) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Events = append(d.Events, "revoke:"+certificate.CertificateReference)
	if d.FailAt == "revoke" {
		return ErrDistributionUnavailable
	}
	return nil
}

func (d *MemoryDistributor) MissingCertificateTargets(_ context.Context, certificate StoredCertificate, targets []DistributionTarget) ([]DistributionTarget, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	missing := make([]DistributionTarget, 0, len(targets))
	for _, target := range targets {
		if err := target.Validate(); err != nil {
			return nil, err
		}
		if !d.Active[distributionTargetKey(target)] {
			missing = append(missing, target)
		}
	}
	return missing, nil
}

type MemoryCAA struct {
	Result CAAResult
	Err    error
}

func (c MemoryCAA) Check(context.Context, string, string) (CAAResult, error) { return c.Result, c.Err }

type MemoryDelegator struct {
	Challenge DNSChallenge
	Err       error
}

func (d MemoryDelegator) Prepare(context.Context, Domain) (DNSChallenge, error) {
	return d.Challenge, d.Err
}

type MemoryAlerts struct {
	mu     sync.Mutex
	Alerts []ExpiryAlert
}

func (a *MemoryAlerts) Alert(_ context.Context, alert ExpiryAlert) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Alerts = append(a.Alerts, alert)
	return nil
}

type MemoryOperations struct {
	mu        sync.Mutex
	Completed []string
}

func (o *MemoryOperations) CompleteDomainCreate(_ context.Context, accountID, domainID string, generation uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.Completed = append(o.Completed, fmt.Sprintf("%s:%s:%d", accountID, domainID, generation))
	return nil
}

// EnsureTargetOrder is exposed for integration tests and diagnostic snapshots.
func EnsureTargetOrder(targets []EdgeTarget) []EdgeTarget { return SortEdgeTargets(targets) }
