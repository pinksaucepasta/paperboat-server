package tunnelcert

// This file contains the server-owned platform certificate target store. The
// platform targets intentionally do not use tunnel_domains, preview_domains,
// users, or any other user-owned row. Certificate records use the explicit
// platform-wildcard wire target so the existing authenticated edge protocol
// and distributor can be reused without granting an edge DNS credential.

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

const (
	PlatformPreviewTargetID = "platform_cert_preview_v1"
	PlatformTunnelTargetID  = "platform_cert_tunnel_v1"
	PlatformRuntimeTargetID = "platform_cert_runtime_v1"

	// PostgreSQL generations are BIGINTs. Keep the public uint64 contract
	// explicit at the boundary so casts into sqlc's int64 parameters cannot
	// silently wrap a value above MaxInt64.
	maxPlatformGeneration = uint64(1<<63 - 1)

	// This ID is deliberately stable and is used only as the platform edge
	// account namespace. It is not a users row or a custom-domain owner.
	PlatformAccountID = "platform_system_v1"

	PlatformPreviewChallengeReference = "platform_preview_dns01_v1"
	PlatformTunnelChallengeReference  = "platform_tunnel_dns01_v1"
	PlatformRuntimeChallengeReference = "platform_runtime_dns01_v1"
)

type PlatformCertificateTargetKind string

const (
	PlatformPreviewWildcardTarget PlatformCertificateTargetKind = "preview_wildcard"
	PlatformTunnelWildcardTarget  PlatformCertificateTargetKind = "tunnel_wildcard"
	PlatformRuntimeWildcardTarget PlatformCertificateTargetKind = "runtime_wildcard"
)

// PlatformCertificateBases are the three public, server-owned DNS bases. The
// values are expected to be the already configured bases (for example
// preview.pprbt.dev, tunnels.pprbt.dev, and runtime.pprbt.dev), not a root
// domain to which labels should be appended.
type PlatformCertificateBases struct {
	PreviewBaseDomain string
	TunnelBaseDomain  string
	RuntimeBaseDomain string
}

// PlatformCertificateTargetDefinition is the immutable identity used by the
// certificate coordinator. IDs are deterministic so every server replica
// acquires the same issuance lock and certificate namespace.
type PlatformCertificateTargetDefinition struct {
	ID                 string
	Kind               PlatformCertificateTargetKind
	Hostname           string
	AccountID          string
	ChallengeReference string
	Generation         uint64
}

func (d PlatformCertificateTargetDefinition) Validate() error {
	if !validIdentifier(d.ID) || d.AccountID != PlatformAccountID || !validMetadata(d.ChallengeReference, 256) || !platformGenerationFitsSQL(d.Generation) {
		return fmt.Errorf("%w: platform certificate target identity is invalid", ErrInvalid)
	}
	host, wildcard, err := normalizeHostname(d.Hostname)
	if err != nil || !wildcard || host != d.Hostname {
		return fmt.Errorf("%w: platform certificate target hostname is invalid", ErrInvalid)
	}
	switch {
	case d.ID == PlatformPreviewTargetID && d.Kind == PlatformPreviewWildcardTarget && d.ChallengeReference == PlatformPreviewChallengeReference:
	case d.ID == PlatformTunnelTargetID && d.Kind == PlatformTunnelWildcardTarget && d.ChallengeReference == PlatformTunnelChallengeReference:
	case d.ID == PlatformRuntimeTargetID && d.Kind == PlatformRuntimeWildcardTarget && d.ChallengeReference == PlatformRuntimeChallengeReference:
	default:
		return fmt.Errorf("%w: platform certificate target kind is invalid", ErrInvalid)
	}
	return nil
}

func platformGenerationFitsSQL(value uint64) bool {
	return value > 0 && value <= maxPlatformGeneration
}

// PlatformCertificateTarget is a durable target projection plus the retry
// state needed by a background worker. Certificate private material never
// appears in this projection.
type PlatformCertificateTarget struct {
	PlatformCertificateTargetDefinition
	DesiredState                  string
	CertificateState              string
	CertificateReference          string
	CertificateExpiresAt          time.Time
	CertificateRenewalAttemptedAt time.Time
	CertificateFailureCode        string
	RetryCount                    int
	NextRetryAt                   time.Time
	CreatedAt                     time.Time
	UpdatedAt                     time.Time
}

func (t PlatformCertificateTarget) Validate() error {
	if err := t.PlatformCertificateTargetDefinition.Validate(); err != nil {
		return err
	}
	if t.DesiredState != "active" && t.DesiredState != "revoked" {
		return fmt.Errorf("%w: platform target desired state is invalid", ErrInvalid)
	}
	switch t.CertificateState {
	case "pending", "failed", "ready", "revoked":
	default:
		return fmt.Errorf("%w: platform target certificate state is invalid", ErrInvalid)
	}
	if t.RetryCount < 0 || t.RetryCount > 30 {
		return fmt.Errorf("%w: platform target retry count is invalid", ErrInvalid)
	}
	if (t.DesiredState == "revoked") != (t.CertificateState == "revoked") {
		return fmt.Errorf("%w: platform target revocation state is inconsistent", ErrInvalid)
	}
	return nil
}

// PlatformCertificateTargetDefinitions returns exactly the three built-in
// wildcard targets. It is safe to call on every worker start; the store
// upsert preserves a previously revoked target instead of silently reviving
// it. The returned order is fixed so every worker replica reconciles targets
// deterministically.
func PlatformCertificateTargetDefinitions(bases PlatformCertificateBases) ([]PlatformCertificateTargetDefinition, error) {
	previewBase, previewWildcard, err := normalizeHostname(bases.PreviewBaseDomain)
	if err != nil || previewWildcard {
		return nil, fmt.Errorf("%w: preview base domain is invalid", ErrInvalid)
	}
	tunnelBase, tunnelWildcard, err := normalizeHostname(bases.TunnelBaseDomain)
	if err != nil || tunnelWildcard {
		return nil, fmt.Errorf("%w: tunnel base domain is invalid", ErrInvalid)
	}
	runtimeBase, runtimeWildcard, err := normalizeHostname(bases.RuntimeBaseDomain)
	if err != nil || runtimeWildcard {
		return nil, fmt.Errorf("%w: runtime base domain is invalid", ErrInvalid)
	}
	if previewBase == tunnelBase || previewBase == runtimeBase || tunnelBase == runtimeBase {
		return nil, fmt.Errorf("%w: preview, tunnel, and runtime base domains must differ", ErrInvalid)
	}
	definitions := []PlatformCertificateTargetDefinition{
		{ID: PlatformPreviewTargetID, Kind: PlatformPreviewWildcardTarget, Hostname: "*." + previewBase, AccountID: PlatformAccountID, ChallengeReference: PlatformPreviewChallengeReference, Generation: 1},
		{ID: PlatformTunnelTargetID, Kind: PlatformTunnelWildcardTarget, Hostname: "*." + tunnelBase, AccountID: PlatformAccountID, ChallengeReference: PlatformTunnelChallengeReference, Generation: 1},
		{ID: PlatformRuntimeTargetID, Kind: PlatformRuntimeWildcardTarget, Hostname: "*." + runtimeBase, AccountID: PlatformAccountID, ChallengeReference: PlatformRuntimeChallengeReference, Generation: 1},
	}
	for _, definition := range definitions {
		if err := definition.Validate(); err != nil {
			return nil, err
		}
	}
	return definitions, nil
}

// PlatformCertificateTargetStore is the target projection used by the
// platform worker. The SQL implementation below also implements
// CertificateStore and CertificateRevocationStore so Coordinator remains the
// only issuer/distribution state machine.
type PlatformCertificateTargetStore interface {
	EnsurePlatformTargets(context.Context, []PlatformCertificateTargetDefinition, time.Time) error
	ListPlatformTargets(context.Context, int) ([]PlatformCertificateTarget, error)
	MarkPlatformCertificateReady(context.Context, string, string, time.Time, time.Time) error
	MarkPlatformCertificateFailure(context.Context, string, string, time.Time, time.Time) error
	MarkPlatformTargetRevoked(context.Context, string, string, time.Time) error
}

type PlatformCertificateStore struct {
	db *db.DB
}

func NewPlatformCertificateStore(database *db.DB) (*PlatformCertificateStore, error) {
	if database == nil || database.Queries() == nil {
		return nil, fmt.Errorf("%w: database is required", ErrInvalid)
	}
	return &PlatformCertificateStore{db: database}, nil
}

func (s *PlatformCertificateStore) EnsurePlatformTargets(ctx context.Context, definitions []PlatformCertificateTargetDefinition, now time.Time) error {
	if s == nil || s.db == nil || len(definitions) != 3 || now.IsZero() {
		return ErrInvalid
	}
	now = now.UTC()
	seen := make(map[string]struct{}, len(definitions))
	seenHosts := make(map[string]struct{}, len(definitions))
	for _, definition := range definitions {
		if err := definition.Validate(); err != nil {
			return err
		}
		if _, ok := seen[definition.ID]; ok {
			return fmt.Errorf("%w: duplicate platform target", ErrInvalid)
		}
		if _, ok := seenHosts[definition.Hostname]; ok {
			return fmt.Errorf("%w: duplicate platform hostname", ErrInvalid)
		}
		seen[definition.ID] = struct{}{}
		seenHosts[definition.Hostname] = struct{}{}
	}
	return s.db.InTx(ctx, func(txCtx context.Context, tx *db.Tx) error {
		for _, definition := range definitions {
			_, err := tx.Queries().UpsertTunnelPlatformCertificateTargetV1(txCtx, dbsqlc.UpsertTunnelPlatformCertificateTargetV1Params{
				ID: definition.ID, Kind: string(definition.Kind), Hostname: definition.Hostname,
				AccountID: definition.AccountID, ChallengeReference: definition.ChallengeReference,
				Generation: int64(definition.Generation), Now: now,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: platform target %s conflicts with persisted identity", ErrGenerationConflict, definition.ID)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *PlatformCertificateStore) ListPlatformTargets(ctx context.Context, limit int) ([]PlatformCertificateTarget, error) {
	if s == nil || s.db == nil || limit < 1 || limit > 500 {
		return nil, ErrInvalid
	}
	rows, err := s.db.Queries().ListTunnelPlatformCertificateTargetsV1(ctx, int32(limit))
	if err != nil {
		return nil, err
	}
	result := make([]PlatformCertificateTarget, 0, limit)
	for _, row := range rows {
		var target PlatformCertificateTarget
		if row.Generation <= 0 || uint64(row.Generation) > maxPlatformGeneration {
			return nil, fmt.Errorf("%w: platform target generation is invalid", ErrGenerationConflict)
		}
		target.ID = row.ID
		target.Kind = PlatformCertificateTargetKind(row.Kind)
		target.Hostname = row.Hostname
		target.AccountID = row.AccountID
		target.ChallengeReference = row.ChallengeReference
		target.Generation = uint64(row.Generation)
		target.DesiredState = row.DesiredState
		target.CertificateState = row.CertificateState
		target.CertificateReference = row.CertificateReference.String
		target.CertificateExpiresAt = row.CertificateExpiresAt.Time
		target.CertificateRenewalAttemptedAt = row.CertificateRenewalAttemptedAt.Time
		target.CertificateFailureCode = row.CertificateFailureCode.String
		target.RetryCount = int(row.RetryCount)
		target.NextRetryAt = row.NextRetryAt.Time
		target.CreatedAt = row.CreatedAt
		target.UpdatedAt = row.UpdatedAt
		if err := target.Validate(); err != nil {
			return nil, err
		}
		result = append(result, target)
	}
	return result, nil
}

func (s *PlatformCertificateStore) MarkPlatformCertificateReady(ctx context.Context, targetID, certificateReference string, expiresAt, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(targetID) || !validMetadata(certificateReference, 256) || expiresAt.IsZero() || now.IsZero() || !expiresAt.After(now) {
		return ErrInvalid
	}
	result, err := s.db.Queries().MarkTunnelPlatformCertificateReadyV1(ctx, dbsqlc.MarkTunnelPlatformCertificateReadyV1Params{
		CertificateReference: sql.NullString{String: certificateReference, Valid: true},
		CertificateExpiresAt: sql.NullTime{Time: expiresAt.UTC(), Valid: true},
		Now:                  sql.NullTime{Time: now.UTC(), Valid: true},
		ID:                   targetID,
	})
	if err != nil {
		return err
	}
	if result != 1 {
		return ErrGenerationConflict
	}
	return nil
}

func (s *PlatformCertificateStore) MarkPlatformCertificateFailure(ctx context.Context, targetID, reason string, nextRetryAt, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(targetID) || !validMetadata(reason, 128) || nextRetryAt.IsZero() || now.IsZero() || !nextRetryAt.After(now) {
		return ErrInvalid
	}
	result, err := s.db.Queries().MarkTunnelPlatformCertificateFailureV1(ctx, dbsqlc.MarkTunnelPlatformCertificateFailureV1Params{
		FailureCode: sql.NullString{String: reason, Valid: true},
		Now:         sql.NullTime{Time: now.UTC(), Valid: true},
		NextRetryAt: sql.NullTime{Time: nextRetryAt.UTC(), Valid: true}, ID: targetID,
	})
	if err != nil {
		return err
	}
	if result != 1 {
		return ErrGenerationConflict
	}
	return nil
}

func (s *PlatformCertificateStore) MarkPlatformTargetRevoked(ctx context.Context, targetID, reason string, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(targetID) || !validMetadata(reason, 128) || now.IsZero() {
		return ErrInvalid
	}
	result, err := s.db.Queries().MarkTunnelPlatformCertificateTargetRevokedV1(ctx, dbsqlc.MarkTunnelPlatformCertificateTargetRevokedV1Params{
		FailureCode: sql.NullString{String: reason, Valid: true}, Now: now.UTC(), ID: targetID,
	})
	if err != nil {
		return err
	}
	if result != 1 {
		return ErrCertificateNotReady
	}
	return nil
}

func platformStoredCertificateValid(value StoredCertificate) error {
	if !validIdentifier(value.ID) || !validIdentifier(value.DomainID) || value.AccountID != PlatformAccountID || !validKeyReference(value.MasterKeyReference) || !platformGenerationFitsSQL(value.DomainGeneration) || !platformGenerationFitsSQL(value.CertificateGeneration) || len(value.CertificateCiphertext) < 29 || len(value.CertificateCiphertext) > 16<<20 || len(value.PrivateKeyCiphertext) < 29 || len(value.PrivateKeyCiphertext) > 16<<20 || value.Fingerprint == [32]byte{} || value.Hostname == "" || value.LeafHostname != "" || !validMetadata(value.CertificateReference, 256) || !validMetadata(value.Issuer, 256) || value.NotBefore.IsZero() || value.ExpiresAt.IsZero() || value.RenewalAt.IsZero() || !value.ExpiresAt.After(value.NotBefore) || !value.RenewalAt.Before(value.ExpiresAt) {
		return ErrInvalid
	}
	if bytes.Contains(value.CertificateCiphertext, []byte("-----BEGIN ")) || bytes.Contains(value.PrivateKeyCiphertext, []byte("-----BEGIN ")) {
		return fmt.Errorf("%w: platform certificate material must remain encrypted", ErrInvalid)
	}
	if value.TargetKind != TargetPlatformWildcard {
		return fmt.Errorf("%w: platform certificate must use platform wildcard edge target", ErrInvalid)
	}
	if !validPlatformCertificateTargetID(value.DomainID) {
		return fmt.Errorf("%w: platform certificate target identity is invalid", ErrInvalid)
	}
	if err := value.Target().Validate(); err != nil {
		return err
	}
	host, wildcard, err := normalizeHostname(value.Hostname)
	if err != nil || !wildcard || host != value.Hostname {
		return ErrInvalid
	}
	if value.Strategy != StrategyPlatformDNS01 {
		return fmt.Errorf("%w: platform certificate strategy is invalid", ErrInvalid)
	}
	return nil
}

func validPlatformCertificateTargetID(id string) bool {
	return id == PlatformPreviewTargetID || id == PlatformTunnelTargetID || id == PlatformRuntimeTargetID
}

func (s *PlatformCertificateStore) Current(ctx context.Context, domainID string) (StoredCertificate, bool, error) {
	if s == nil || s.db == nil || !validIdentifier(domainID) {
		return StoredCertificate{}, false, ErrInvalid
	}
	row, err := s.db.Queries().GetActiveTunnelPlatformCertificateV1(ctx, sql.NullString{String: domainID, Valid: true})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCertificate{}, false, nil
	}
	if err != nil {
		return StoredCertificate{}, false, err
	}
	value := storedFromSQL(row)
	if err := platformStoredCertificateValid(value); err != nil {
		return StoredCertificate{}, false, err
	}
	return value, true, nil
}

// NextCertificateGeneration reserves no state itself. The caller holds the
// per-target issuance lock while using this snapshot, and the unique database
// constraint remains the final race fence. Failed rows are included so a retry
// cannot reuse a certificate generation that already has persisted material.
func (s *PlatformCertificateStore) NextCertificateGeneration(ctx context.Context, domainID string) (uint64, error) {
	if s == nil || s.db == nil || !validIdentifier(domainID) {
		return 0, ErrInvalid
	}
	row, err := s.db.Queries().NextTunnelPlatformCertificateGenerationV1(ctx, sql.NullString{String: domainID, Valid: true})
	if err != nil {
		// The aggregate query increments BIGINT in PostgreSQL before sqlc scans
		// it. Once the persisted maximum is reached PostgreSQL reports numeric
		// overflow rather than returning a row we can range-check below. Treat
		// that condition as the same durable generation fence and never expose a
		// driver-specific error that could invite a wrapped/reused generation.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "22003" {
			return 0, ErrGenerationConflict
		}
		return 0, err
	}
	if row <= 0 || uint64(row) > maxPlatformGeneration {
		return 0, ErrGenerationConflict
	}
	return uint64(row), nil
}

func (s *PlatformCertificateStore) PutStaged(ctx context.Context, value StoredCertificate) error {
	if s == nil || s.db == nil {
		return ErrInvalid
	}
	if err := platformStoredCertificateValid(value); err != nil {
		return err
	}
	now := value.UpdatedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	created, err := s.db.Queries().CreateTunnelPlatformCertificateRecordV1(ctx, dbsqlc.CreateTunnelPlatformCertificateRecordV1Params{
		ID: value.ID, DomainID: sql.NullString{String: value.DomainID, Valid: true}, AccountID: value.AccountID,
		Hostname: value.Hostname, DomainGeneration: int64(value.DomainGeneration), CertificateGeneration: int64(value.CertificateGeneration),
		Strategy: string(value.Strategy), CertificateReference: value.CertificateReference, MasterKeyReference: value.MasterKeyReference,
		CertificateCiphertext: append([]byte(nil), value.CertificateCiphertext...), PrivateKeyCiphertext: append([]byte(nil), value.PrivateKeyCiphertext...),
		Fingerprint: append([]byte(nil), value.Fingerprint[:]...), Issuer: value.Issuer, NotBefore: value.NotBefore.UTC(),
		ExpiresAt: value.ExpiresAt.UTC(), RenewalAt: value.RenewalAt.UTC(), Now: now,
	})
	if err == nil && !platformCertificateReplayMatches(storedFromSQL(created), value) {
		// The SQL upsert can return an existing staged/failed row when its
		// immutable identity matches. It must also match every encrypted payload
		// and certificate metadata field; otherwise a same-ID retry could clear a
		// failure while leaving different material in the durable row.
		return ErrGenerationConflict
	}
	if errors.Is(err, pgx.ErrNoRows) {
		// An active row with the same immutable identity is a safe replay of a
		// request that already committed. A mismatched replay remains a hard
		// generation conflict and cannot replace encrypted material in place.
		existing, lookupErr := s.db.Queries().GetTunnelCertificateV1(ctx, value.ID)
		if lookupErr != nil {
			if errors.Is(lookupErr, pgx.ErrNoRows) {
				return ErrGenerationConflict
			}
			return lookupErr
		}
		if existing.State == string(StateActive) && platformCertificateReplayMatches(storedFromSQL(existing), value) {
			return nil
		}
		return ErrGenerationConflict
	}
	if err != nil {
		return err
	}
	return nil
}

func platformCertificateReplayMatches(existing, candidate StoredCertificate) bool {
	return existing.ID == candidate.ID && existing.DomainID == candidate.DomainID &&
		existing.AccountID == candidate.AccountID && existing.TargetKind == candidate.TargetKind &&
		existing.Hostname == candidate.Hostname && existing.DomainGeneration == candidate.DomainGeneration &&
		existing.CertificateGeneration == candidate.CertificateGeneration && existing.Strategy == candidate.Strategy &&
		existing.CertificateReference == candidate.CertificateReference && existing.MasterKeyReference == candidate.MasterKeyReference &&
		existing.Issuer == candidate.Issuer && existing.NotBefore.Equal(candidate.NotBefore) &&
		existing.ExpiresAt.Equal(candidate.ExpiresAt) && existing.RenewalAt.Equal(candidate.RenewalAt) &&
		bytes.Equal(existing.CertificateCiphertext, candidate.CertificateCiphertext) &&
		bytes.Equal(existing.PrivateKeyCiphertext, candidate.PrivateKeyCiphertext) &&
		existing.Fingerprint == candidate.Fingerprint
}

func (s *PlatformCertificateStore) Activate(ctx context.Context, id string, domainGeneration uint64, now time.Time) (StoredCertificate, error) {
	if s == nil || s.db == nil || !validIdentifier(id) || !platformGenerationFitsSQL(domainGeneration) || now.IsZero() {
		return StoredCertificate{}, ErrInvalid
	}
	var row dbsqlc.TunnelCertificateRecord
	err := s.db.InTx(ctx, func(txCtx context.Context, tx *db.Tx) error {
		candidate, err := tx.Queries().GetTunnelPlatformCertificateForUpdateV1(txCtx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGenerationConflict
		}
		if err != nil {
			return err
		}
		if candidate.State != string(StateStaged) || candidate.DomainGeneration != int64(domainGeneration) || !candidate.DomainID.Valid {
			return ErrGenerationConflict
		}
		candidateValue := storedFromSQL(candidate)
		if err := platformStoredCertificateValid(candidateValue); err != nil {
			return err
		}
		if _, err := tx.Queries().SupersedeOlderTunnelPlatformCertificatesV1(txCtx, dbsqlc.SupersedeOlderTunnelPlatformCertificatesV1Params{
			Now: now.UTC(), DomainID: candidate.DomainID, CertificateGeneration: candidate.CertificateGeneration,
		}); err != nil {
			return err
		}
		updated, err := tx.Queries().ActivateTunnelPlatformCertificateV1(txCtx, dbsqlc.ActivateTunnelPlatformCertificateV1Params{
			Now: now.UTC(), ID: id, DomainGeneration: int64(domainGeneration),
		})
		if err != nil {
			return err
		}
		if updated != 1 {
			return ErrGenerationConflict
		}
		row, err = tx.Queries().GetTunnelCertificateV1(txCtx, id)
		if err != nil {
			return err
		}
		return platformStoredCertificateValid(storedFromSQL(row))
	})
	if err != nil {
		return StoredCertificate{}, err
	}
	return storedFromSQL(row), nil
}

func (s *PlatformCertificateStore) SupersedeOlder(ctx context.Context, domainID string, generation uint64, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(domainID) || !platformGenerationFitsSQL(generation) || now.IsZero() {
		return ErrInvalid
	}
	_, err := s.db.Queries().SupersedeOlderTunnelPlatformCertificatesV1(ctx, dbsqlc.SupersedeOlderTunnelPlatformCertificatesV1Params{
		Now: now.UTC(), DomainID: sql.NullString{String: domainID, Valid: true}, CertificateGeneration: int64(generation),
	})
	return err
}

func (s *PlatformCertificateStore) MarkFailed(ctx context.Context, id, reason string, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(id) || !validMetadata(reason, 128) || now.IsZero() {
		return ErrInvalid
	}
	result, err := s.db.Queries().MarkTunnelPlatformCertificateFailedV1(ctx, dbsqlc.MarkTunnelPlatformCertificateFailedV1Params{
		FailureCode: sql.NullString{String: reason, Valid: true}, Now: now.UTC(), ID: id,
	})
	if err != nil {
		return err
	}
	if result != 1 {
		return ErrGenerationConflict
	}
	return nil
}

func (s *PlatformCertificateStore) Revoke(ctx context.Context, id, reason string, now time.Time) (StoredCertificate, error) {
	if s == nil || s.db == nil || !validIdentifier(id) || now.IsZero() {
		return StoredCertificate{}, ErrInvalid
	}
	if reason == "" {
		reason = "certificate_revoked"
	}
	if !validMetadata(reason, 128) {
		return StoredCertificate{}, ErrInvalid
	}
	var row dbsqlc.TunnelCertificateRecord
	err := s.db.InTx(ctx, func(txCtx context.Context, tx *db.Tx) error {
		candidate, err := tx.Queries().GetTunnelPlatformCertificateForUpdateV1(txCtx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrCertificateNotReady
		}
		if err != nil {
			return err
		}
		if candidate.State != string(StateRevoked) {
			updated, err := tx.Queries().RevokeTunnelPlatformCertificateV1(txCtx, dbsqlc.RevokeTunnelPlatformCertificateV1Params{
				Now: sql.NullTime{Time: now.UTC(), Valid: true}, FailureCode: sql.NullString{String: reason, Valid: true}, ID: id,
			})
			if err != nil {
				return err
			}
			if updated != 1 {
				return ErrGenerationConflict
			}
		}
		row, err = tx.Queries().GetTunnelCertificateV1(txCtx, id)
		return err
	})
	if err != nil {
		return StoredCertificate{}, err
	}
	return storedFromSQL(row), nil
}

func (s *PlatformCertificateStore) ListPendingCertificateRevocations(ctx context.Context, limit int) ([]StoredCertificate, error) {
	if s == nil || s.db == nil || limit < 1 || limit > 500 {
		return nil, ErrInvalid
	}
	ids, err := s.db.Queries().ListPendingTunnelPlatformCertificateRevocationIDsV1(ctx, int32(limit))
	if err != nil {
		return nil, err
	}
	result := make([]StoredCertificate, 0, limit)
	for _, id := range ids {
		row, err := s.db.Queries().GetTunnelCertificateV1(ctx, id)
		if err != nil {
			return nil, err
		}
		value := storedFromSQL(row)
		if err := platformStoredCertificateValid(value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func (s *PlatformCertificateStore) MarkCertificateRevocationResult(ctx context.Context, id string, confirmed bool, _ string, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(id) || now.IsZero() {
		return ErrInvalid
	}
	code := "ca_revocation_pending"
	if confirmed {
		code = "ca_revoked"
	}
	result, err := s.db.Queries().MarkTunnelPlatformCertificateRevocationResultV1(ctx, dbsqlc.MarkTunnelPlatformCertificateRevocationResultV1Params{
		FailureCode: sql.NullString{String: code, Valid: true}, Now: now.UTC(), ID: id,
	})
	if err != nil {
		return err
	}
	if result != 1 {
		return ErrGenerationConflict
	}
	return nil
}

// Ensure the compile-time interfaces remain explicit. SQLDistributor and the
// coordinator use the same encrypted certificate/distribution row as normal
// durable routes.
var _ CertificateStore = (*PlatformCertificateStore)(nil)
var _ CertificateRevocationStore = (*PlatformCertificateStore)(nil)
var _ PlatformCertificateTargetStore = (*PlatformCertificateStore)(nil)
var _ CertificateGenerationSource = (*PlatformCertificateStore)(nil)
