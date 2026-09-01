package previewdomain

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

type API interface {
	List(context.Context, previewtunnelapi.RequestContext, string, string, int) (Page, error)
	Get(context.Context, previewtunnelapi.RequestContext, string, string) (DomainView, error)
	Create(context.Context, previewtunnelapi.RequestContext, string, Request) (MutationResult, error)
	Verify(context.Context, previewtunnelapi.RequestContext, string, string, MutationInput) (MutationResult, error)
	Delete(context.Context, previewtunnelapi.RequestContext, string, string, MutationInput) (MutationResult, error)
	Instructions(context.Context, previewtunnelapi.RequestContext, string, string) (DNSInstructions, error)
	ReadyAliases(context.Context, previewtunnelapi.RequestContext, string) ([]ReadyAlias, error)
}

type BatchCreator interface {
	CreateForPreviewTx(context.Context, *db.Tx, BatchCreateRequest) ([]dbsqlc.PreviewDomain, error)
}

type Service struct {
	repository    PreviewDomainRepository
	cursors       *cursorCodec
	challengeZone string
	now           func() time.Time
	newID         func(string) (string, error)
}

func NewService(repository PreviewDomainRepository, config Config) (*Service, error) {
	if repository == nil {
		return nil, fmt.Errorf("%w: repository is required", ErrInvalidInput)
	}
	cursors, err := newCursorCodec(config.CursorKey)
	if err != nil {
		return nil, err
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	newID := config.NewID
	if newID == nil {
		newID = defaultID
	}
	zone := strings.TrimSpace(config.ChallengeZone)
	if zone != "" {
		if normalized, wildcard, zoneErr := normalizeHostname(zone); zoneErr != nil || wildcard {
			return nil, fmt.Errorf("%w: challenge zone is invalid", ErrInvalidInput)
		} else {
			zone = normalized
		}
	}
	return &Service{repository: repository, cursors: cursors, challengeZone: zone, now: now, newID: newID}, nil
}

func (s *Service) List(ctx context.Context, request previewtunnelapi.RequestContext, previewID, rawCursor string, limit int) (Page, error) {
	if err := authorize(request, "read"); err != nil {
		return Page{}, err
	}
	if limit < 1 || limit > previewtunnelapi.MaximumPageLimit {
		return Page{}, fmt.Errorf("%w: list limit is invalid", ErrInvalidInput)
	}
	lease, err := s.repository.Lease(ctx, request.Actor.AccountID, previewID)
	if err != nil {
		return Page{}, err
	}
	if err := requireActiveLease(lease, s.now()); err != nil {
		return Page{}, err
	}
	position, err := s.cursors.Decode(rawCursor, request.Actor.AccountID, previewID)
	if err != nil {
		return Page{}, err
	}
	rows, err := s.repository.List(ctx, request.Actor.AccountID, previewID, position, limit+1)
	if err != nil {
		return Page{}, err
	}
	page := Page{Items: make([]DomainView, 0, minInt(len(rows), limit))}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	for _, row := range rows {
		if row.PreviewGeneration != lease.Generation {
			continue
		}
		page.Items = append(page.Items, DomainViewFromRow(row))
	}
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		page.NextCursor, err = s.cursors.Encode(request.Actor.AccountID, previewID, last.CreatedAt, last.ID)
		if err != nil {
			return Page{}, err
		}
	}
	return page, nil
}

func (s *Service) Get(ctx context.Context, request previewtunnelapi.RequestContext, previewID, domainID string) (DomainView, error) {
	if err := authorize(request, "read"); err != nil {
		return DomainView{}, err
	}
	lease, err := s.repository.Lease(ctx, request.Actor.AccountID, previewID)
	if err != nil {
		return DomainView{}, err
	}
	if err := requireActiveLease(lease, s.now()); err != nil {
		return DomainView{}, err
	}
	domain, err := s.repository.Get(ctx, request.Actor.AccountID, previewID, domainID)
	if err != nil {
		return DomainView{}, err
	}
	if domain.PreviewGeneration != lease.Generation {
		return DomainView{}, ErrGenerationConflict
	}
	return DomainViewFromRow(domain), nil
}

func (s *Service) Create(ctx context.Context, request previewtunnelapi.RequestContext, previewID string, input Request) (MutationResult, error) {
	if err := authorize(request, "write"); err != nil {
		return MutationResult{}, err
	}
	lease, err := s.repository.Lease(ctx, request.Actor.AccountID, previewID)
	if err != nil {
		return MutationResult{}, err
	}
	now := s.now().UTC()
	if err := requireActiveLease(lease, now); err != nil {
		return MutationResult{}, err
	}
	if err := authorizeOwner(request, lease); err != nil {
		return MutationResult{}, err
	}
	hostname, matchType, err := NormalizeHostname(input.Hostname)
	if err != nil {
		return MutationResult{}, err
	}
	provider, err := ValidateProvider(input.Provider)
	if err != nil {
		return MutationResult{}, err
	}
	strategy, err := ValidateCertificateStrategy(input.CertificateStrategy, matchType)
	if err != nil {
		return MutationResult{}, err
	}
	if err := validateMutation(input.Mutation, false); err != nil {
		return MutationResult{}, err
	}
	operationID, err := s.newID("op")
	if err != nil {
		return MutationResult{}, err
	}
	auditID, err := s.newID("aud")
	if err != nil {
		return MutationResult{}, err
	}
	domainID, err := s.newID("pdom")
	if err != nil {
		return MutationResult{}, err
	}
	challengeID, err := s.newID("dns")
	if err != nil {
		return MutationResult{}, err
	}
	target, err := StableTargetHostname(lease.Endpoint)
	if err != nil {
		return MutationResult{}, err
	}
	recordType := DNSRecordType(hostname, provider)
	expected, err := json.Marshal([]DNSRecord{{Name: hostname, Type: recordType, Value: target, TTL: 300}})
	if err != nil {
		return MutationResult{}, err
	}
	result, err := s.repository.Create(ctx, CreateRecord{OperationID: operationID, AuditEventID: auditID, AccountID: request.Actor.AccountID, PreviewID: previewID, DomainID: domainID, PreviewGeneration: lease.Generation, Hostname: hostname, MatchType: matchType, ChallengeReference: "dns-challenge://" + challengeID, DNSTarget: target, DNSProvider: provider, ExpectedRecords: expected, CertificateStrategy: strategy, IdempotencyKey: input.Mutation.IdempotencyKey, RequestHash: input.Mutation.RequestHash, ActorID: request.Actor.ActorID, ActorType: actorType(request.Actor), RequestID: request.RequestID, CorrelationID: request.CorrelationID, SourceDeviceID: request.Actor.DeviceID, Now: now})
	if err != nil {
		return MutationResult{}, err
	}
	return mutationResult(result, request.RequestID), nil
}

func (s *Service) Verify(ctx context.Context, request previewtunnelapi.RequestContext, previewID, domainID string, input MutationInput) (MutationResult, error) {
	return s.mutate(ctx, request, previewID, domainID, input, true)
}

func (s *Service) Delete(ctx context.Context, request previewtunnelapi.RequestContext, previewID, domainID string, input MutationInput) (MutationResult, error) {
	return s.mutate(ctx, request, previewID, domainID, input, false)
}

func (s *Service) mutate(ctx context.Context, request previewtunnelapi.RequestContext, previewID, domainID string, input MutationInput, verify bool) (MutationResult, error) {
	if err := authorize(request, "write"); err != nil {
		return MutationResult{}, err
	}
	now := s.now().UTC()
	lease, err := s.repository.Lease(ctx, request.Actor.AccountID, previewID)
	if err != nil {
		return MutationResult{}, err
	}
	if err := requireActiveLease(lease, now); err != nil {
		return MutationResult{}, err
	}
	if err := authorizeOwner(request, lease); err != nil {
		return MutationResult{}, err
	}
	if err := validateMutation(input, true); err != nil {
		return MutationResult{}, err
	}
	operationID, err := s.newID("op")
	if err != nil {
		return MutationResult{}, err
	}
	auditID, err := s.newID("aud")
	if err != nil {
		return MutationResult{}, err
	}
	record := MutationRecord{OperationID: operationID, AuditEventID: auditID, AccountID: request.Actor.AccountID, PreviewID: previewID, DomainID: domainID, ExpectedGeneration: input.ExpectedGeneration, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, ActorID: request.Actor.ActorID, ActorType: actorType(request.Actor), RequestID: request.RequestID, CorrelationID: request.CorrelationID, SourceDeviceID: request.Actor.DeviceID, Now: now}
	var result RepositoryMutation
	if verify {
		result, err = s.repository.Verify(ctx, record)
	} else {
		result, err = s.repository.Delete(ctx, record)
	}
	if err != nil {
		return MutationResult{}, err
	}
	return mutationResult(result, request.RequestID), nil
}

func (s *Service) Instructions(ctx context.Context, request previewtunnelapi.RequestContext, previewID, domainID string) (DNSInstructions, error) {
	if err := authorize(request, "read"); err != nil {
		return DNSInstructions{}, err
	}
	lease, err := s.repository.Lease(ctx, request.Actor.AccountID, previewID)
	if err != nil {
		return DNSInstructions{}, err
	}
	if err := requireActiveLease(lease, s.now()); err != nil {
		return DNSInstructions{}, err
	}
	domain, err := s.repository.Get(ctx, request.Actor.AccountID, previewID, domainID)
	if err != nil {
		return DNSInstructions{}, err
	}
	if domain.PreviewGeneration != lease.Generation {
		return DNSInstructions{}, ErrGenerationConflict
	}
	if domain.DeletedAt.Valid {
		return DNSInstructions{}, ErrNotFound
	}
	provider := domain.DnsProvider
	records := []DNSRecord{{Name: domain.Hostname, Type: DNSRecordType(domain.Hostname, provider), Value: domain.DnsTarget, TTL: 300}}
	note := DNSInstructionNote(domain.Hostname, provider)
	if s.challengeZone != "" && (domain.CertificateStrategy == "managed" || domain.CertificateStrategy == "on_demand_leaf") {
		challengeTarget, targetErr := delegatedChallengeTarget(domain.ID, domain.AccountID, domain.PreviewID, domain.OwnershipChallengeReference, s.challengeZone)
		if targetErr != nil {
			return DNSInstructions{}, ErrDNSUnavailable
		}
		base := strings.TrimPrefix(domain.Hostname, "*.")
		records = append(records, DNSRecord{Name: "_acme-challenge." + base, Type: "CNAME", Value: challengeTarget, TTL: 300})
		note += " Paperboat writes ACME TXT values only below its authoritative challenge zone; TLS becomes ready after DNS propagation and certificate distribution."
	}
	return DNSInstructions{Schema: Schema, Kind: "dns_instructions", TargetKind: TargetKind, PreviewID: previewID, DomainID: domain.ID, Hostname: domain.Hostname, Provider: provider, Records: records, CertificateStrategy: domain.CertificateStrategy, VerificationState: wireState(domain), Note: note}, nil
}

func (s *Service) ReadyAliases(ctx context.Context, request previewtunnelapi.RequestContext, previewID string) ([]ReadyAlias, error) {
	if err := authorize(request, "read"); err != nil {
		return nil, err
	}
	lease, err := s.repository.Lease(ctx, request.Actor.AccountID, previewID)
	if err != nil {
		return nil, err
	}
	if err := requireActiveLease(lease, s.now()); err != nil {
		return nil, err
	}
	rows, err := s.repository.ReadyAliases(ctx, request.Actor.AccountID, previewID, s.now().UTC())
	if err != nil {
		return nil, err
	}
	aliases := make([]ReadyAlias, 0, len(rows))
	for _, record := range rows {
		row := record.Domain
		if row.AccountID != request.Actor.AccountID || row.PreviewID != previewID || row.PreviewGeneration != lease.Generation || row.DeletedAt.Valid || row.OwnershipState != "verified" || row.ConflictState != "clear" || row.CertificateState != "ready" || record.CertificateReference == "" || record.CertificateGeneration < 1 {
			continue
		}
		var wildcardLabels *int
		if row.MatchType == "one_label_wildcard" {
			labels := 1
			wildcardLabels = &labels
		}
		aliases = append(aliases, ReadyAlias{DomainID: row.ID, PreviewID: row.PreviewID, PreviewGeneration: row.PreviewGeneration, Hostname: row.Hostname, MatchType: row.MatchType, WildcardLabels: wildcardLabels, Generation: row.Generation, CertificateReference: record.CertificateReference, CertificateGeneration: record.CertificateGeneration})
	}
	return aliases, nil
}

// CreateForPreviewTx is the service-level batch seam used by the preview
// lease creator. It requires a concrete SQL repository because the caller
// owns the transaction; no operation or commit is emitted here.
func (s *Service) CreateForPreviewTx(ctx context.Context, tx *db.Tx, input BatchCreateRequest) ([]DomainView, error) {
	creator, ok := s.repository.(BatchCreator)
	if !ok {
		return nil, fmt.Errorf("%w: repository does not support transactional preview creation", ErrInvalidInput)
	}
	if input.ActorID != "" && input.AccountID == "" {
		return nil, ErrInvalidInput
	}
	rows, err := creator.CreateForPreviewTx(ctx, tx, input)
	if err != nil {
		return nil, err
	}
	views := make([]DomainView, 0, len(rows))
	for _, row := range rows {
		views = append(views, DomainViewFromRow(row))
	}
	return views, nil
}

func authorize(request previewtunnelapi.RequestContext, action string) error {
	return previewtunnelapi.Authorize(request.Actor, previewtunnelapi.AccessRequest{AccountID: request.Actor.AccountID, Resource: "previews", Action: action})
}

func authorizeOwner(request previewtunnelapi.RequestContext, lease LeaseContext) error {
	if request.Actor.DeviceID != "" && request.Actor.DeviceID != lease.OwnerDeviceID {
		return ErrOwnerDenied
	}
	if request.Actor.HostID != "" && request.Actor.HostID != lease.OwnerDeviceID {
		return ErrOwnerDenied
	}
	return nil
}

func validateMutation(input MutationInput, generation bool) error {
	if strings.TrimSpace(input.IdempotencyKey) == "" || input.RequestHash == ([sha256.Size]byte{}) || (generation && input.ExpectedGeneration < 1) {
		return ErrInvalidInput
	}
	return nil
}

func mutationResult(result RepositoryMutation, requestID string) MutationResult {
	return MutationResult{Domain: DomainViewFromRow(result.Domain), Operation: operationView(result.Operation, requestID), Replayed: result.Replayed, Changed: result.Changed}
}

func operationView(row dbsqlc.Operation, requestID string) previewtunnelapi.Operation {
	var operationError *previewtunnelapi.APIError
	if row.ErrorCode.Valid {
		operationError = &previewtunnelapi.APIError{Schema: Schema, Kind: "error", Code: row.ErrorCode.String, Component: "preview_domain", Message: "The preview domain operation needs attention.", Outcome: "uncertain", Retryable: true, RequestID: requestID, CorrelationID: row.CorrelationID}
	}
	return previewtunnelapi.Operation{Schema: Schema, Kind: "operation", ID: row.ID, ResourceKind: row.ResourceKind, ResourceID: nullableStringValue(row.ResourceID), Phase: row.Phase, State: row.State, Progress: int(row.Progress), Retrying: row.Retrying, NextRetryAt: nullableTimeValue(row.NextRetryAt), Error: operationError, CorrelationID: row.CorrelationID, CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC()}
}

func actorType(actor previewtunnelapi.Actor) string {
	if actor.Role == "system_worker" {
		return "system"
	}
	if actor.HostID != "" {
		return "host"
	}
	return "user"
}

func nullableStringValue(value sql.NullString) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func nullableTimeValue(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time.UTC()
	return &t
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

type cursorCodec struct{ key []byte }

type cursorPayload struct {
	Version   int       `json:"version"`
	AccountID string    `json:"account_id"`
	PreviewID string    `json:"preview_id"`
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

func newCursorCodec(key []byte) (*cursorCodec, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("preview domain cursor key must contain at least 32 bytes")
	}
	return &cursorCodec{key: append([]byte(nil), key...)}, nil
}

func (c *cursorCodec) Encode(accountID, previewID string, createdAt time.Time, id string) (string, error) {
	payload, err := json.Marshal(cursorPayload{Version: 1, AccountID: accountID, PreviewID: previewID, CreatedAt: createdAt.UTC(), ID: id})
	if err != nil || len(payload) > 768 {
		return "", previewtunnelapi.ErrInvalidCursor
	}
	signature := c.sign(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (c *cursorCodec) Decode(raw, accountID, previewID string) (*ListPosition, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || len(raw) > 2048 {
		return nil, previewtunnelapi.ErrInvalidCursor
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > 768 {
		return nil, previewtunnelapi.ErrInvalidCursor
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size || !hmac.Equal(signature, c.sign(payload)) {
		return nil, previewtunnelapi.ErrInvalidCursor
	}
	var value cursorPayload
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value.Version != 1 || value.AccountID != accountID || value.PreviewID != previewID || value.ID == "" || value.CreatedAt.IsZero() {
		return nil, previewtunnelapi.ErrInvalidCursor
	}
	return &ListPosition{CreatedAt: value.CreatedAt.UTC(), ID: value.ID}, nil
}

func (c *cursorCodec) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
