package tunnelcert

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

// SQLStore is the durable certificate store.  It persists only envelope
// ciphertext and certificate metadata; decryption is intentionally separate
// from the database adapter.
type SQLStore struct{ db *db.DB }

func NewSQLStore(database *db.DB) (*SQLStore, error) {
	if database == nil || database.Queries() == nil {
		return nil, fmt.Errorf("%w: database is required", ErrInvalid)
	}
	return &SQLStore{db: database}, nil
}

func (s *SQLStore) Current(ctx context.Context, domainID string) (StoredCertificate, bool, error) {
	if s == nil || s.db == nil || !validIdentifier(domainID) {
		return StoredCertificate{}, false, ErrInvalid
	}
	row, err := s.db.Queries().GetActiveTunnelCertificateV1(ctx, sql.NullString{String: domainID, Valid: true})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCertificate{}, false, nil
	}
	if err != nil {
		return StoredCertificate{}, false, err
	}
	return storedFromSQL(row), true, nil
}

func (s *SQLStore) CurrentForHostname(ctx context.Context, domainID, hostname string) (StoredCertificate, bool, error) {
	if s == nil || s.db == nil || !validIdentifier(domainID) {
		return StoredCertificate{}, false, ErrInvalid
	}
	host, wildcard, err := normalizeHostname(hostname)
	if err != nil || wildcard {
		return StoredCertificate{}, false, ErrInvalid
	}
	row, err := s.db.Queries().GetActiveTunnelCertificateByHostnameV1(ctx, dbsqlc.GetActiveTunnelCertificateByHostnameV1Params{DomainID: sql.NullString{String: domainID, Valid: true}, Hostname: host})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCertificate{}, false, nil
	}
	if err != nil {
		return StoredCertificate{}, false, err
	}
	return storedFromSQL(row), true, nil
}

// CurrentPreview resolves the active wildcard parent for one verified preview
// domain. Preview-lease identity is part of the lookup fence; a durable route or a
// different lease can never satisfy this read.
func (s *SQLStore) CurrentPreview(ctx context.Context, accountID, domainID, previewID string) (StoredCertificate, bool, error) {
	if s == nil || s.db == nil || !validIdentifier(accountID) || !validIdentifier(domainID) || !validIdentifier(previewID) {
		return StoredCertificate{}, false, ErrInvalid
	}
	row, err := s.db.Queries().GetActivePreviewTunnelCertificateV1(ctx, dbsqlc.GetActivePreviewTunnelCertificateV1Params{
		DomainID: sql.NullString{String: domainID, Valid: true}, AccountID: accountID,
		PreviewID: sql.NullString{String: previewID, Valid: true}, Now: time.Now().UTC(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCertificate{}, false, nil
	}
	if err != nil {
		return StoredCertificate{}, false, err
	}
	return storedFromSQL(row), true, nil
}

// CurrentPreviewForHostname resolves an exact leaf in a preview lease's
// hostname namespace. It deliberately cannot return the wildcard parent.
func (s *SQLStore) CurrentPreviewForHostname(ctx context.Context, accountID, domainID, previewID, hostname string) (StoredCertificate, bool, error) {
	if s == nil || s.db == nil || !validIdentifier(accountID) || !validIdentifier(domainID) || !validIdentifier(previewID) {
		return StoredCertificate{}, false, ErrInvalid
	}
	host, wildcard, err := normalizeHostname(hostname)
	if err != nil || wildcard || host != hostname {
		return StoredCertificate{}, false, ErrInvalid
	}
	row, err := s.db.Queries().GetActivePreviewTunnelCertificateByHostnameV1(ctx, dbsqlc.GetActivePreviewTunnelCertificateByHostnameV1Params{
		DomainID: sql.NullString{String: domainID, Valid: true}, AccountID: accountID,
		PreviewID: sql.NullString{String: previewID, Valid: true}, Hostname: host, Now: time.Now().UTC(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCertificate{}, false, nil
	}
	if err != nil {
		return StoredCertificate{}, false, err
	}
	return storedFromSQL(row), true, nil
}

// CurrentPreviewForHostnameRebind is the exact-leaf counterpart to
// CurrentPreviewForRebind. It closes the renewal gap without projecting a
// second leaf when a first-SNI request races a lease generation advance.
func (s *SQLStore) CurrentPreviewForHostnameRebind(ctx context.Context, accountID, domainID, previewID, hostname string, now time.Time) (StoredCertificate, bool, error) {
	if s == nil || s.db == nil || !validIdentifier(accountID) || !validIdentifier(domainID) || !validIdentifier(previewID) {
		return StoredCertificate{}, false, ErrInvalid
	}
	host, wildcard, err := normalizeHostname(hostname)
	if err != nil || wildcard || host != hostname {
		return StoredCertificate{}, false, ErrInvalid
	}
	row, err := s.db.Queries().GetActivePreviewTunnelCertificateByDomainHostnameForRebindV1(ctx, dbsqlc.GetActivePreviewTunnelCertificateByDomainHostnameForRebindV1Params{
		DomainID: sql.NullString{String: domainID, Valid: true}, AccountID: accountID,
		PreviewID: sql.NullString{String: previewID, Valid: true}, Hostname: host, Now: now.UTC(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCertificate{}, false, nil
	}
	if err != nil {
		return StoredCertificate{}, false, err
	}
	return storedFromSQL(row), true, nil
}

// CurrentPreviewForRebind is the renewal-gap lookup. It returns an active
// preview parent carrying either the old or current lease generation so the
// caller can fence it to the current generation before alias admission.
func (s *SQLStore) CurrentPreviewForRebind(ctx context.Context, accountID, domainID, previewID string, now time.Time) (StoredCertificate, bool, error) {
	if s == nil || s.db == nil || !validIdentifier(accountID) || !validIdentifier(domainID) || !validIdentifier(previewID) {
		return StoredCertificate{}, false, ErrInvalid
	}
	row, err := s.db.Queries().GetActivePreviewTunnelCertificateForRebindV1(ctx, dbsqlc.GetActivePreviewTunnelCertificateForRebindV1Params{
		DomainID: sql.NullString{String: domainID, Valid: true}, AccountID: accountID,
		PreviewID: sql.NullString{String: previewID, Valid: true}, Now: now.UTC(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCertificate{}, false, nil
	}
	if err != nil {
		return StoredCertificate{}, false, err
	}
	return storedFromSQL(row), true, nil
}

// RebindPreviewCertificateTarget moves one active/staged certificate to the
// current lease generation. Certificate generation, ID, fingerprint, and
// encrypted material remain unchanged.
func (s *SQLStore) RebindPreviewCertificateTarget(ctx context.Context, certificateID, accountID, domainID, previewID string, previousGeneration, previewGeneration uint64, expiresAt, now time.Time) (StoredCertificate, error) {
	if s == nil || s.db == nil || !validIdentifier(certificateID) || !validIdentifier(accountID) || !validIdentifier(domainID) || !validIdentifier(previewID) || previousGeneration == 0 || previewGeneration == 0 || previousGeneration == previewGeneration || expiresAt.IsZero() || !expiresAt.After(now.UTC()) {
		return StoredCertificate{}, ErrInvalid
	}
	row, err := s.db.Queries().RebindPreviewCertificateTargetV1(ctx, dbsqlc.RebindPreviewCertificateTargetV1Params{
		PreviewGeneration: sql.NullInt64{Int64: int64(previewGeneration), Valid: true},
		PreviewExpiresAt:  sql.NullTime{Time: expiresAt.UTC(), Valid: true}, Now: now.UTC(),
		CertificateID: certificateID, PreviousPreviewGeneration: sql.NullInt64{Int64: int64(previousGeneration), Valid: true},
		DomainID: domainID, AccountID: accountID, PreviewID: previewID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCertificate{}, ErrGenerationConflict
	}
	if err != nil {
		return StoredCertificate{}, err
	}
	return storedFromSQL(row), nil
}

// RebindPreviewCertificatesTx updates all active/staged preview target
// rows in the same transaction as a lease generation advance. The helper is
// exported so preview lease persistence can keep certificate and alias fences
// atomic without importing SQL internals or issuing a second transaction.
func RebindPreviewCertificatesTx(ctx context.Context, tx *db.Tx, accountID, previewID string, previousGeneration, previewGeneration uint64, expiresAt, now time.Time) (int64, error) {
	if tx == nil || !validIdentifier(accountID) || !validIdentifier(previewID) || previousGeneration == 0 || previewGeneration == 0 || previousGeneration == previewGeneration || expiresAt.IsZero() || !expiresAt.After(now.UTC()) {
		return 0, ErrInvalid
	}
	return tx.Queries().RebindPreviewCertificatesForLeaseV1(ctx, dbsqlc.RebindPreviewCertificatesForLeaseV1Params{
		PreviewGeneration: sql.NullInt64{Int64: int64(previewGeneration), Valid: true},
		PreviewExpiresAt:  sql.NullTime{Time: expiresAt.UTC(), Valid: true}, Now: now.UTC(),
		PreviousPreviewGeneration: sql.NullInt64{Int64: int64(previousGeneration), Valid: true},
		AccountID:                 accountID, PreviewID: previewID,
	})
}

// RevokePreviewCertificatesTx terminally withdraws every live preview target
// for a lease. It is intended to run in the same transaction as the lease and
// preview-domain terminal transition. Edge distribution cleanup then follows
// the revoked certificate rows without exposing a stale active target.
func RevokePreviewCertificatesTx(ctx context.Context, tx *db.Tx, accountID, previewID, reason string, now time.Time) (int64, error) {
	if tx == nil || !validIdentifier(accountID) || !validIdentifier(previewID) || reason == "" || now.IsZero() {
		return 0, ErrInvalid
	}
	return tx.Queries().RevokePreviewCertificatesForLeaseV1(ctx, dbsqlc.RevokePreviewCertificatesForLeaseV1Params{
		Now: sql.NullTime{Time: now.UTC(), Valid: true}, FailureCode: sql.NullString{String: reason, Valid: true},
		AccountID: accountID, PreviewID: sql.NullString{String: previewID, Valid: true},
	})
}

// RebindPreviewCertificatesForLease is the non-transactional convenience
// wrapper for worker/reconciliation callers. Lease renewal should use the Tx
// form above so no alias can observe an unmatched generation.
func (s *SQLStore) RebindPreviewCertificatesForLease(ctx context.Context, accountID, previewID string, previousGeneration, previewGeneration uint64, expiresAt, now time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, ErrInvalid
	}
	var rebound int64
	err := s.db.InTx(ctx, func(txCtx context.Context, tx *db.Tx) error {
		var err error
		rebound, err = RebindPreviewCertificatesTx(txCtx, tx, accountID, previewID, previousGeneration, previewGeneration, expiresAt, now)
		return err
	})
	return rebound, err
}

func (s *SQLStore) PutStaged(ctx context.Context, value StoredCertificate) error {
	if s == nil || s.db == nil || !validIdentifier(value.ID) || !validIdentifier(value.DomainID) || !validIdentifier(value.AccountID) || !validKeyReference(value.MasterKeyReference) || value.DomainGeneration == 0 || value.CertificateGeneration == 0 || len(value.Envelope) < 29 || len(value.Fingerprint) != 32 {
		return ErrInvalid
	}
	if err := value.Target().ValidateActive(value.UpdatedAt); err != nil {
		return err
	}
	host, wildcard, err := normalizeHostname(value.Hostname)
	if err != nil || wildcard || host != value.Hostname {
		return ErrInvalid
	}
	if value.LeafHostname != "" {
		host, wildcard, err := normalizeHostname(value.LeafHostname)
		if err != nil || wildcard || host != value.LeafHostname || value.Hostname != value.LeafHostname {
			return ErrInvalid
		}
	}
	certificateCiphertext := value.CertificateCiphertext
	privateKeyCiphertext := value.PrivateKeyCiphertext
	if len(certificateCiphertext) == 0 {
		certificateCiphertext = value.Envelope
	}
	if len(privateKeyCiphertext) == 0 {
		privateKeyCiphertext = value.Envelope
	}
	var createErr error
	if value.Target().normalizedKind() == TargetPreviewLease {
		_, createErr = s.db.Queries().CreatePreviewTunnelCertificateRecordV1(ctx, dbsqlc.CreatePreviewTunnelCertificateRecordV1Params{
			ID: value.ID, DomainID: sql.NullString{String: value.DomainID, Valid: true}, AccountID: value.AccountID,
			PreviewID: sql.NullString{String: value.PreviewID, Valid: true}, PreviewGeneration: sql.NullInt64{Int64: int64(value.PreviewGeneration), Valid: true}, PreviewExpiresAt: sql.NullTime{Time: value.PreviewExpiresAt, Valid: true},
			Hostname: value.Hostname, LeafHostname: sql.NullString{String: value.LeafHostname, Valid: value.LeafHostname != ""}, DomainGeneration: int64(value.DomainGeneration), CertificateGeneration: int64(value.CertificateGeneration), Strategy: string(value.Strategy),
			CertificateReference: value.CertificateReference, MasterKeyReference: value.MasterKeyReference, CertificateCiphertext: append([]byte(nil), certificateCiphertext...), PrivateKeyCiphertext: append([]byte(nil), privateKeyCiphertext...), Fingerprint: append([]byte(nil), value.Fingerprint[:]...), Issuer: value.Issuer,
			NotBefore: value.NotBefore, ExpiresAt: value.ExpiresAt, RenewalAt: value.RenewalAt, Now: value.UpdatedAt,
		})
	} else {
		_, createErr = s.db.Queries().CreateTunnelCertificateRecordV1(ctx, dbsqlc.CreateTunnelCertificateRecordV1Params{
			ID: value.ID, DomainID: sql.NullString{String: value.DomainID, Valid: true}, AccountID: value.AccountID, TunnelID: sql.NullString{String: value.TunnelID, Valid: true}, RouteID: sql.NullString{String: value.RouteID, Valid: value.RouteID != ""}, Hostname: value.Hostname,
			DomainGeneration: int64(value.DomainGeneration), CertificateGeneration: int64(value.CertificateGeneration), Strategy: string(value.Strategy), CertificateReference: value.CertificateReference, MasterKeyReference: value.MasterKeyReference,
			LeafHostname: sql.NullString{String: value.LeafHostname, Valid: value.LeafHostname != ""}, CertificateCiphertext: append([]byte(nil), certificateCiphertext...), PrivateKeyCiphertext: append([]byte(nil), privateKeyCiphertext...), Fingerprint: append([]byte(nil), value.Fingerprint[:]...), Issuer: value.Issuer,
			NotBefore: value.NotBefore, ExpiresAt: value.ExpiresAt, RenewalAt: value.RenewalAt, Now: value.UpdatedAt,
		})
	}
	if errors.Is(createErr, pgx.ErrNoRows) {
		return ErrGenerationConflict
	}
	return createErr
}

func (s *SQLStore) Activate(ctx context.Context, id string, domainGeneration uint64, now time.Time) (StoredCertificate, error) {
	if s == nil || s.db == nil || !validIdentifier(id) || domainGeneration == 0 {
		return StoredCertificate{}, ErrInvalid
	}
	// Supersede only the prior certificate for this exact hostname namespace and
	// activate the new row in one serializable transaction. Wildcard parents and
	// exact leaves may share a domain and certificate generation safely.
	var row dbsqlc.TunnelCertificateRecord
	err := s.db.InTx(ctx, func(txCtx context.Context, tx *db.Tx) error {
		activation, err := tx.Queries().GetTunnelCertificateActivationContextV1(txCtx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrGenerationConflict
			}
			return err
		}
		if !activation.DomainID.Valid || activation.DomainID.String == "" || activation.AccountID == "" || activation.CertificateGeneration <= 0 || activation.Hostname == "" {
			return ErrGenerationConflict
		}
		domainID := activation.DomainID
		certificateGeneration := activation.CertificateGeneration
		if activation.TargetKind == string(TargetPreviewLease) {
			if !activation.PreviewID.Valid || !activation.PreviewGeneration.Valid || activation.PreviewGeneration.Int64 <= 0 {
				return ErrGenerationConflict
			}
			if activation.LeafHostname == "" {
				if _, err := tx.Queries().SupersedeOlderPreviewTunnelCertificatesV1(txCtx, dbsqlc.SupersedeOlderPreviewTunnelCertificatesV1Params{
					Now: now, DomainID: domainID, PreviewID: activation.PreviewID,
					PreviewGeneration: activation.PreviewGeneration, Hostname: activation.Hostname,
					CertificateGeneration: certificateGeneration,
				}); err != nil {
					return err
				}
			} else {
				if _, err := tx.Queries().SupersedeOlderPreviewTunnelCertificatesByHostnameV1(txCtx, dbsqlc.SupersedeOlderPreviewTunnelCertificatesByHostnameV1Params{
					Now: now, DomainID: domainID, PreviewID: activation.PreviewID,
					PreviewGeneration: activation.PreviewGeneration, Hostname: activation.LeafHostname,
					CertificateGeneration: certificateGeneration,
				}); err != nil {
					return err
				}
			}
		} else if activation.TargetKind == string(TargetDurableRoute) || activation.TargetKind == "" {
			if activation.LeafHostname == "" {
				if _, err := tx.Queries().SupersedeOlderTunnelCertificatesV1(txCtx, dbsqlc.SupersedeOlderTunnelCertificatesV1Params{Now: now, DomainID: domainID, CertificateGeneration: certificateGeneration}); err != nil {
					return err
				}
			} else if _, err := tx.Queries().SupersedeOlderTunnelCertificatesByHostnameV1(txCtx, dbsqlc.SupersedeOlderTunnelCertificatesByHostnameV1Params{Now: now, DomainID: domainID, Hostname: activation.LeafHostname, CertificateGeneration: certificateGeneration}); err != nil {
				return err
			}
		} else {
			return ErrGenerationConflict
		}
		candidate, err := tx.Queries().ActivateTunnelCertificateV1(txCtx, dbsqlc.ActivateTunnelCertificateV1Params{Now: now, ID: id, DomainGeneration: int64(domainGeneration)})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGenerationConflict
		}
		if err != nil {
			return err
		}
		row = candidate
		return nil
	})
	if err != nil {
		return StoredCertificate{}, err
	}
	return storedFromSQL(row), nil
}

// CommitDomainCertificateReady is the final certificate lifecycle commit. It
// locks and validates the exact domain generation and active certificate, then
// updates the domain projection and completes its domain.create operation in
// the same SERIALIZABLE transaction. A stale worker therefore commits neither
// side of the externally visible ready state.
func (s *SQLStore) CommitDomainCertificateReady(ctx context.Context, accountID, domainID string, expectedGeneration uint64, certificate StoredCertificate, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(accountID) || !validIdentifier(domainID) || expectedGeneration == 0 || certificate.DomainID != domainID || certificate.AccountID != accountID || certificate.DomainGeneration != expectedGeneration || certificate.State != StateActive || certificate.CertificateGeneration == 0 || certificate.CertificateReference == "" || certificate.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	now = now.UTC()
	return s.db.InTx(ctx, func(txCtx context.Context, tx *db.Tx) error {
		domainContext, err := tx.Queries().GetTunnelDomainCertificateCommitContextV1(txCtx, domainID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrGenerationConflict
			}
			return err
		}
		if domainContext.AccountID != accountID || domainContext.Generation <= 0 || uint64(domainContext.Generation) != expectedGeneration {
			return ErrGenerationConflict
		}
		certificateContext, err := tx.Queries().GetTunnelCertificateCommitContextV1(txCtx, certificate.ID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrGenerationConflict
			}
			return err
		}
		if !certificateContext.DomainID.Valid || certificateContext.DomainID.String != domainID || certificateContext.AccountID != accountID || certificateContext.DomainGeneration <= 0 || uint64(certificateContext.DomainGeneration) != expectedGeneration || certificateContext.CertificateGeneration <= 0 || uint64(certificateContext.CertificateGeneration) != certificate.CertificateGeneration || certificateContext.State != string(StateActive) || certificateContext.CertificateReference != certificate.CertificateReference || certificateContext.LeafHostname.Valid {
			return ErrGenerationConflict
		}
		full, err := tx.Queries().GetTunnelCertificateV1(txCtx, certificate.ID)
		if err != nil {
			return err
		}
		if full.TargetKind != string(TargetDurableRoute) {
			return ErrGenerationConflict
		}
		rows, err := tx.Queries().MarkTunnelDomainCertificateProjectionReadyV1(txCtx, dbsqlc.MarkTunnelDomainCertificateProjectionReadyV1Params{
			CertificateReference: sql.NullString{String: certificate.CertificateReference, Valid: true},
			CertificateExpiresAt: sql.NullTime{Time: certificate.ExpiresAt, Valid: true},
			Now:                  sql.NullTime{Time: now, Valid: true}, DomainID: domainID, AccountID: accountID,
			ExpectedGeneration: int64(expectedGeneration),
		})
		if err != nil {
			return err
		}
		if rows != 1 {
			return ErrGenerationConflict
		}
		// Complete only the exact domain.create aggregate. If another request is
		// still pending for this resource, refusing the commit is safer than
		// exposing a ready domain with an unresolved create operation.
		completed, err := tx.Queries().CompleteTunnelDomainCreateOperationV1(txCtx, dbsqlc.CompleteTunnelDomainCreateOperationV1Params{
			Now: sql.NullTime{Time: now, Valid: true}, AccountID: accountID, DomainID: sql.NullString{String: domainID, Valid: true},
		})
		if err != nil {
			return err
		}
		if completed > 1 {
			return ErrGenerationConflict
		}
		if completed == 0 {
			pending, err := tx.Queries().HasPendingTunnelDomainCreateOperationV1(txCtx, dbsqlc.HasPendingTunnelDomainCreateOperationV1Params{
				AccountID: accountID, DomainID: sql.NullString{String: domainID, Valid: true},
			})
			if err != nil {
				return err
			}
			if pending {
				return ErrGenerationConflict
			}
			// The first certificate for an issuing/non-ready domain must be
			// tied to exactly one create operation. A ready domain may be
			// renewed by the certificate worker without a domain.create row,
			// but an issuing projection with no operation is an unsafe partial
			// commit and must roll back both updates.
			if domainContext.CertificateState != "ready" || domainContext.CertificateReference == "" {
				return ErrGenerationConflict
			}
		}
		return nil
	})
}

// CommitPreviewDomainCertificateReady publishes a preview certificate only
// when both the preview-domain generation and lease generation still match
// the certificate target. Unlike a durable route commit, this never mutates
// tunnel_domains or a durable domain.create operation.
func (s *SQLStore) CommitPreviewDomainCertificateReady(ctx context.Context, accountID, domainID, previewID string, previewGeneration, expectedDomainGeneration uint64, certificate StoredCertificate, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(accountID) || !validIdentifier(domainID) || !validIdentifier(previewID) || previewGeneration == 0 || expectedDomainGeneration == 0 || certificate.DomainID != domainID || certificate.AccountID != accountID || certificate.TargetKind != TargetPreviewLease || certificate.PreviewID != previewID || certificate.PreviewGeneration != previewGeneration || certificate.DomainGeneration != expectedDomainGeneration || certificate.LeafHostname != "" || certificate.State != StateActive || certificate.CertificateGeneration == 0 || certificate.CertificateReference == "" || certificate.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	now = now.UTC()
	rows, err := s.db.Queries().CommitPreviewDomainCertificateReadyV1(ctx, dbsqlc.CommitPreviewDomainCertificateReadyV1Params{
		CertificateReference: sql.NullString{String: certificate.CertificateReference, Valid: true},
		CertificateExpiresAt: sql.NullTime{Time: certificate.ExpiresAt, Valid: true},
		Now:                  sql.NullTime{Time: now, Valid: true}, DomainID: domainID, AccountID: accountID, PreviewID: previewID,
		PreviewGeneration: int64(previewGeneration), ExpectedDomainGeneration: int64(expectedDomainGeneration),
		CertificateID: certificate.ID, CertificateGeneration: int64(certificate.CertificateGeneration),
	})
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrGenerationConflict
	}
	return nil
}

// PreviewCertificateReady is the edge-admission readiness fence. It checks
// the preview lease, current domain/certificate generations, and the exact
// active edge distribution row in one generated query.
func (s *SQLStore) PreviewCertificateReady(ctx context.Context, accountID, domainID, previewID, hostname string, previewGeneration, domainGeneration, certificateGeneration uint64, edge DistributionTarget, now time.Time) (bool, error) {
	if s == nil || s.db == nil || !validIdentifier(accountID) || !validIdentifier(domainID) || !validIdentifier(previewID) || previewGeneration == 0 || domainGeneration == 0 || certificateGeneration == 0 {
		return false, ErrInvalid
	}
	host, _, err := normalizeHostname(hostname)
	if err != nil || host != hostname {
		return false, ErrInvalid
	}
	if err := edge.Validate(); err != nil {
		return false, err
	}
	ready, err := s.db.Queries().GetPreviewCertificateReadinessV1(ctx, dbsqlc.GetPreviewCertificateReadinessV1Params{
		DomainID: domainID, AccountID: accountID, PreviewID: previewID, PreviewGeneration: int64(previewGeneration), DomainGeneration: int64(domainGeneration), Hostname: host,
		CertificateGeneration: int64(certificateGeneration), EdgeNodeID: edge.NodeID, EdgeProcessEpoch: edge.ProcessEpoch, EdgeAssignmentGeneration: int64(edge.Generation), Now: now.UTC(),
	})
	return ready, err
}

func (s *SQLStore) SupersedeOlder(ctx context.Context, domainID string, generation uint64, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(domainID) || generation == 0 {
		return ErrInvalid
	}
	_, err := s.db.Queries().SupersedeOlderTunnelCertificatesV1(ctx, dbsqlc.SupersedeOlderTunnelCertificatesV1Params{Now: now, DomainID: sql.NullString{String: domainID, Valid: true}, CertificateGeneration: int64(generation)})
	return err
}

func (s *SQLStore) SupersedeOlderForHostname(ctx context.Context, domainID, hostname string, generation uint64, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(domainID) || generation == 0 {
		return ErrInvalid
	}
	host, wildcard, err := normalizeHostname(hostname)
	if err != nil || wildcard {
		return ErrInvalid
	}
	_, err = s.db.Queries().SupersedeOlderTunnelCertificatesByHostnameV1(ctx, dbsqlc.SupersedeOlderTunnelCertificatesByHostnameV1Params{Now: now, DomainID: sql.NullString{String: domainID, Valid: true}, Hostname: host, CertificateGeneration: int64(generation)})
	return err
}

func (s *SQLStore) MarkFailed(ctx context.Context, id, reason string, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(id) || reason == "" {
		return ErrInvalid
	}
	rows, err := s.db.Queries().MarkTunnelCertificateFailedV1(ctx, dbsqlc.MarkTunnelCertificateFailedV1Params{FailureCode: sql.NullString{String: reason, Valid: true}, Now: now, ID: id})
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrGenerationConflict
	}
	return nil
}

func (s *SQLStore) Revoke(ctx context.Context, id, reason string, now time.Time) (StoredCertificate, error) {
	if s == nil || s.db == nil || !validIdentifier(id) {
		return StoredCertificate{}, ErrInvalid
	}
	var row dbsqlc.TunnelCertificateRecord
	err := s.db.InTx(ctx, func(txCtx context.Context, tx *db.Tx) error {
		revokeContext, err := tx.Queries().GetTunnelCertificateRevokeContextV1(txCtx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrCertificateNotReady
			}
			return err
		}
		candidate, err := tx.Queries().RevokeTunnelCertificateV1(txCtx, dbsqlc.RevokeTunnelCertificateV1Params{Now: sql.NullTime{Time: now, Valid: true}, Reason: sql.NullString{String: reason, Valid: reason != ""}, ID: id})
		if errors.Is(err, pgx.ErrNoRows) {
			candidate, getErr := tx.Queries().GetTunnelCertificateV1(txCtx, id)
			if getErr != nil {
				return getErr
			}
			if candidate.State != string(StateRevoked) {
				return ErrGenerationConflict
			}
			row = candidate
			return nil
		}
		if err != nil {
			return err
		}
		row = candidate
		// Exact leaves, preview targets, and a durable certificate whose
		// projection was already replaced must never mutate tunnel_domains.
		if revokeContext.TargetKind != string(TargetDurableRoute) || !revokeContext.DomainID.Valid || revokeContext.LeafHostname != "" {
			return nil
		}
		failureCode := reason
		if failureCode == "" {
			failureCode = "certificate_revoked"
		}
		// The certificate row is authoritative. Only clear the domain's current
		// reference when it still points at this exact certificate; a newer
		// replacement must never be overwritten by a late revoke.
		_, err = tx.Queries().ClearTunnelDomainCertificateOnRevokeV1(txCtx, dbsqlc.ClearTunnelDomainCertificateOnRevokeV1Params{
			FailureCode: sql.NullString{String: failureCode, Valid: true}, Now: now,
			DomainID: revokeContext.DomainID.String, AccountID: revokeContext.AccountID,
			CertificateReference: sql.NullString{String: revokeContext.CertificateReference, Valid: true}, LeafHostname: revokeContext.LeafHostname,
		})
		return err
	})
	if err != nil {
		return StoredCertificate{}, err
	}
	return storedFromSQL(row), nil
}

// ListPendingCertificateRevocations returns only certificates which were
// durably marked revoked locally but whose CA revocation has not yet been
// confirmed. It uses IDs for the bounded work-list and lets sqlc perform the
// complete metadata/ciphertext projection, keeping this retry query stable as
// the certificate record grows.
func (s *SQLStore) ListPendingCertificateRevocations(ctx context.Context, limit int) ([]StoredCertificate, error) {
	if s == nil || s.db == nil || limit < 1 || limit > 500 {
		return nil, ErrInvalid
	}
	ids, err := s.db.Queries().ListPendingTunnelCertificateRevocationIDsV1(ctx, int32(limit))
	if err != nil {
		return nil, err
	}
	result := make([]StoredCertificate, 0, limit)
	for _, id := range ids {
		row, err := s.db.Queries().GetTunnelCertificateV1(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, storedFromSQL(row))
	}
	return result, nil
}

// MarkCertificateRevocationResult records the authority-side terminal state
// without changing the already-revoked local certificate state. The pending
// marker is deliberately a stable, non-secret code so retries survive process
// restarts and do not expose provider error text.
func (s *SQLStore) MarkCertificateRevocationResult(ctx context.Context, id string, confirmed bool, _ string, now time.Time) error {
	if s == nil || s.db == nil || !validIdentifier(id) {
		return ErrInvalid
	}
	code := "ca_revocation_pending"
	if confirmed {
		code = "ca_revoked"
	}
	rows, err := s.db.Queries().MarkTunnelCertificateRevocationResultV1(ctx, dbsqlc.MarkTunnelCertificateRevocationResultV1Params{FailureCode: sql.NullString{String: code, Valid: true}, Now: now, ID: id})
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrGenerationConflict
	}
	return nil
}

func storedFromSQL(row dbsqlc.TunnelCertificateRecord) StoredCertificate {
	var fingerprint [32]byte
	copy(fingerprint[:], row.Fingerprint)
	domainID := row.DomainID.String
	if !row.DomainID.Valid {
		domainID = ""
	}
	tunnelID := row.TunnelID.String
	if !row.TunnelID.Valid {
		tunnelID = ""
	}
	routeID := row.RouteID.String
	if !row.RouteID.Valid {
		routeID = ""
	}
	previewID := row.PreviewID.String
	if !row.PreviewID.Valid {
		previewID = ""
	}
	previewGeneration := uint64(0)
	if row.PreviewGeneration.Valid && row.PreviewGeneration.Int64 > 0 {
		previewGeneration = uint64(row.PreviewGeneration.Int64)
	}
	previewState := row.PreviewState.String
	if !row.PreviewState.Valid {
		previewState = ""
	}
	var revokedAt *time.Time
	if row.RevokedAt.Valid {
		value := row.RevokedAt.Time
		revokedAt = &value
	}
	return StoredCertificate{ID: row.ID, DomainID: domainID, AccountID: row.AccountID, TunnelID: tunnelID, TargetKind: TargetKind(row.TargetKind), RouteID: routeID, PreviewID: previewID, PreviewGeneration: previewGeneration, PreviewState: previewState, PreviewExpiresAt: row.PreviewExpiresAt.Time, Hostname: row.Hostname, LeafHostname: row.LeafHostname.String, DomainGeneration: uint64(row.DomainGeneration), CertificateGeneration: uint64(row.CertificateGeneration), Strategy: Strategy(row.Strategy), State: State(row.State), CertificateReference: row.CertificateReference, MasterKeyReference: row.MasterKeyReference, Envelope: append([]byte(nil), row.CertificateCiphertext...), CertificateCiphertext: append([]byte(nil), row.CertificateCiphertext...), PrivateKeyCiphertext: append([]byte(nil), row.PrivateKeyCiphertext...), Fingerprint: fingerprint, Issuer: row.Issuer, NotBefore: row.NotBefore, ExpiresAt: row.ExpiresAt, RenewalAt: row.RenewalAt, FailureCode: row.FailureCode.String, RevokedAt: revokedAt, UpdatedAt: row.UpdatedAt}
}

type SQLIssuanceLock struct{ db *db.DB }

func NewSQLIssuanceLock(database *db.DB) (*SQLIssuanceLock, error) {
	if database == nil || database.Queries() == nil {
		return nil, fmt.Errorf("%w: database is required", ErrInvalid)
	}
	return &SQLIssuanceLock{db: database}, nil
}

func (l *SQLIssuanceLock) Acquire(ctx context.Context, domainID, owner string, generation uint64, now, until time.Time) (bool, error) {
	if l == nil || l.db == nil || !validIdentifier(domainID) || !validIdentifier(owner) || generation == 0 || !until.After(now) {
		return false, ErrInvalid
	}
	_, err := l.db.Queries().AcquireTunnelCertificateIssuanceLockV1(ctx, dbsqlc.AcquireTunnelCertificateIssuanceLockV1Params{DomainID: domainID, OwnerID: owner, DomainGeneration: int64(generation), LeaseUntil: until, Now: now})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (l *SQLIssuanceLock) Release(ctx context.Context, domainID, owner string) error {
	if l == nil || l.db == nil || !validIdentifier(domainID) || !validIdentifier(owner) {
		return ErrInvalid
	}
	_, err := l.db.Queries().ReleaseTunnelCertificateIssuanceLockV1(ctx, dbsqlc.ReleaseTunnelCertificateIssuanceLockV1Params{DomainID: domainID, OwnerID: owner})
	return err
}

// ReleaseGeneration is the fenced release used by the coordinator when the
// lock implementation is durable. Keep this operation keyed by the exact
// generation so an older retry cannot release a newer lease held by the same
// owner identifier after a restart.
func (l *SQLIssuanceLock) ReleaseGeneration(ctx context.Context, domainID, owner string, generation uint64) error {
	if l == nil || l.db == nil || !validIdentifier(domainID) || !validIdentifier(owner) || generation == 0 {
		return ErrInvalid
	}
	_, err := l.db.Queries().ReleaseTunnelCertificateIssuanceLockGenerationV1(certificateContext(ctx), dbsqlc.ReleaseTunnelCertificateIssuanceLockGenerationV1Params{DomainID: domainID, OwnerID: owner, DomainGeneration: int64(generation)})
	return err
}

type SQLOperationCompleter struct{ db *db.DB }

func NewSQLOperationCompleter(database *db.DB) (*SQLOperationCompleter, error) {
	if database == nil || database.Queries() == nil {
		return nil, fmt.Errorf("%w: database is required", ErrInvalid)
	}
	return &SQLOperationCompleter{db: database}, nil
}

func (o *SQLOperationCompleter) CompleteDomainCreate(ctx context.Context, accountID, domainID string, generation uint64) error {
	if o == nil || o.db == nil || !validIdentifier(accountID) || !validIdentifier(domainID) || generation == 0 {
		return ErrInvalid
	}
	rows, err := o.db.Queries().CompleteTunnelDomainCreateAfterCertificateV1(ctx, dbsqlc.CompleteTunnelDomainCreateAfterCertificateV1Params{Now: sql.NullTime{Time: time.Now().UTC(), Valid: true}, AccountID: accountID, DomainID: sql.NullString{String: domainID, Valid: true}, CertificateGeneration: int64(generation)})
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrCertificateNotReady
	}
	return nil
}

// EdgeCertificateTransport is implemented by the authenticated control
// client.  The transport receives the bundle only after the server has
// resolved the encrypted envelope; it must not log or expose the key bytes.
type EdgeCertificateTransport interface {
	Stage(context.Context, DistributionRequest) error
	WaitReady(context.Context, DistributionRequest) error
	Activate(context.Context, DistributionRequest) error
	Retire(context.Context, StoredCertificate, DistributionTarget) error
}

// EdgeCertificateRevocationTransport is implemented by transports that can
// distinguish revocation from ordinary retirement.  Keeping this optional
// preserves the small distributor interface used by deterministic tests while
// ensuring production edges remove a revoked certificate with terminal
// semantics instead of merely marking it retired.
type EdgeCertificateRevocationTransport interface {
	Revoke(context.Context, StoredCertificate, DistributionTarget) error
}

type SQLDistributor struct {
	db        *db.DB
	transport EdgeCertificateTransport
}

func NewSQLDistributor(database *db.DB, transport EdgeCertificateTransport) (*SQLDistributor, error) {
	if database == nil || database.Queries() == nil || transport == nil {
		return nil, fmt.Errorf("%w: database and edge transport are required", ErrDistributionUnavailable)
	}
	return &SQLDistributor{db: database, transport: transport}, nil
}

func (d *SQLDistributor) Stage(ctx context.Context, request DistributionRequest) error {
	if err := request.Validate(); err != nil {
		return distributionError(err)
	}
	if _, err := d.db.Queries().StageTunnelCertificateEdgeV1(ctx, dbsqlc.StageTunnelCertificateEdgeV1Params{CertificateID: request.Certificate.ID, EdgeNodeID: request.Target.NodeID, EdgeProcessEpoch: request.Target.ProcessEpoch, EdgeAssignmentGeneration: int64(request.Target.Generation), CertificateGeneration: int64(request.Certificate.CertificateGeneration), Now: time.Now().UTC()}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGenerationConflict
		}
		return err
	}
	if err := d.transport.Stage(ctx, request); err != nil {
		return d.markFailed(ctx, request, "edge_stage_failed", err)
	}
	return nil
}

func (d *SQLDistributor) WaitReady(ctx context.Context, request DistributionRequest) error {
	if err := request.Validate(); err != nil {
		return distributionError(err)
	}
	if err := d.transport.WaitReady(ctx, request); err != nil {
		return d.markFailed(ctx, request, "edge_not_ready", err)
	}
	_, err := d.db.Queries().MarkTunnelCertificateEdgeStateV1(ctx, dbsqlc.MarkTunnelCertificateEdgeStateV1Params{State: "ready", ObservedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}, Now: time.Now().UTC(), CertificateID: request.Certificate.ID, EdgeNodeID: request.Target.NodeID, EdgeProcessEpoch: request.Target.ProcessEpoch, EdgeAssignmentGeneration: int64(request.Target.Generation), CertificateGeneration: int64(request.Certificate.CertificateGeneration)})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGenerationConflict
	}
	return err
}

func (d *SQLDistributor) Activate(ctx context.Context, request DistributionRequest) error {
	if err := request.Validate(); err != nil {
		return distributionError(err)
	}
	if err := d.transport.Activate(ctx, request); err != nil {
		return d.markFailed(ctx, request, "edge_activate_failed", err)
	}
	_, err := d.db.Queries().MarkTunnelCertificateEdgeStateV1(ctx, dbsqlc.MarkTunnelCertificateEdgeStateV1Params{State: "active", ObservedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}, Now: time.Now().UTC(), CertificateID: request.Certificate.ID, EdgeNodeID: request.Target.NodeID, EdgeProcessEpoch: request.Target.ProcessEpoch, EdgeAssignmentGeneration: int64(request.Target.Generation), CertificateGeneration: int64(request.Certificate.CertificateGeneration)})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGenerationConflict
	}
	return err
}

func (d *SQLDistributor) Retire(ctx context.Context, certificate StoredCertificate, target DistributionTarget) error {
	if err := certificate.validateDistributionMetadata(); err != nil {
		return distributionError(err)
	}
	if err := target.Validate(); err != nil {
		return distributionError(err)
	}
	if err := d.transport.Retire(ctx, certificate, target); err != nil {
		return err
	}
	_, err := d.db.Queries().MarkTunnelCertificateEdgeStateV1(ctx, dbsqlc.MarkTunnelCertificateEdgeStateV1Params{State: "retired", ObservedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}, Now: time.Now().UTC(), CertificateID: certificate.ID, EdgeNodeID: target.NodeID, EdgeProcessEpoch: target.ProcessEpoch, EdgeAssignmentGeneration: int64(target.Generation), CertificateGeneration: int64(certificate.CertificateGeneration)})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGenerationConflict
	}
	return err
}

// RetireCertificate uses the durable edge target rows captured for the old
// certificate. The current domain target list is not authoritative after an
// edge process replacement, so cleanup must follow every non-terminal row
// that actually received this certificate.
func (d *SQLDistributor) RetireCertificate(ctx context.Context, certificate StoredCertificate) error {
	if d == nil || d.db == nil {
		return ErrInvalid
	}
	if err := certificate.validateDistributionMetadata(); err != nil {
		return distributionError(err)
	}
	rows, err := d.db.Queries().ListTunnelCertificateEdgesV1(ctx, certificate.ID)
	if err != nil {
		return err
	}
	for _, row := range rows {
		switch row.State {
		case "staged", "ready", "active", "failed":
		default:
			continue
		}
		target := DistributionTarget{NodeID: row.EdgeNodeID, ProcessEpoch: row.EdgeProcessEpoch, Generation: uint64(row.EdgeAssignmentGeneration)}
		current, err := d.targetUsesCurrentProcess(ctx, target)
		if err != nil {
			return err
		}
		if !current {
			// The old process can no longer acknowledge this row. Retire the
			// exact durable tuple locally, without sending an action to a
			// replacement process or waiting for an impossible ACK.
			if err := d.markEdgeState(ctx, certificate, target, "retired"); err != nil {
				return err
			}
			continue
		}
		if err := d.Retire(ctx, certificate, target); err != nil {
			return err
		}
	}
	return nil
}

// MissingCertificateTargets returns only exact current node/process/
// assignment tuples that are not active for this certificate. A ready row
// from a prior process epoch never satisfies a replacement target.
func (d *SQLDistributor) MissingCertificateTargets(ctx context.Context, certificate StoredCertificate, targets []DistributionTarget) ([]DistributionTarget, error) {
	if d == nil || d.db == nil || certificate.ID == "" {
		return nil, ErrInvalid
	}
	rows, err := d.db.Queries().ListTunnelCertificateEdgesV1(ctx, certificate.ID)
	if err != nil {
		return nil, err
	}
	active := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		// Rebinding a preview target updates the certificate row without
		// changing its generation or ID. An older edge row therefore must be
		// treated as missing until the same bundle is staged/activated with the
		// new target tuple.
		if row.State != "active" || uint64(row.ObservedCertificateGeneration) != certificate.CertificateGeneration || row.UpdatedAt.Before(certificate.UpdatedAt) {
			continue
		}
		active[distributionTargetKey(DistributionTarget{NodeID: row.EdgeNodeID, ProcessEpoch: row.EdgeProcessEpoch, Generation: uint64(row.EdgeAssignmentGeneration)})] = struct{}{}
	}
	missing := make([]DistributionTarget, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if err := target.Validate(); err != nil {
			return nil, distributionError(err)
		}
		key := distributionTargetKey(target)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		if _, ok := active[key]; !ok {
			missing = append(missing, target)
		}
	}
	return missing, nil
}

// RetireObsoleteCertificateTargets removes non-terminal rows whose exact
// assignment tuple is no longer current. This catches old processes after a
// node restart even when the new domain projection has already replaced them.
func (d *SQLDistributor) RetireObsoleteCertificateTargets(ctx context.Context, certificate StoredCertificate, current []DistributionTarget) error {
	if d == nil || d.db == nil || certificate.ID == "" {
		return ErrInvalid
	}
	rows, err := d.db.Queries().ListTunnelCertificateEdgesV1(ctx, certificate.ID)
	if err != nil {
		return err
	}
	keep := make(map[string]struct{}, len(current))
	for _, target := range current {
		if err := target.Validate(); err != nil {
			return distributionError(err)
		}
		keep[distributionTargetKey(target)] = struct{}{}
	}
	for _, row := range rows {
		if row.State != "staged" && row.State != "ready" && row.State != "active" && row.State != "failed" {
			continue
		}
		target := DistributionTarget{NodeID: row.EdgeNodeID, ProcessEpoch: row.EdgeProcessEpoch, Generation: uint64(row.EdgeAssignmentGeneration)}
		if _, ok := keep[distributionTargetKey(target)]; ok {
			continue
		}
		currentProcess, err := d.targetUsesCurrentProcess(ctx, target)
		if err != nil {
			return err
		}
		if !currentProcess {
			if err := d.markEdgeState(ctx, certificate, target, "retired"); err != nil {
				return err
			}
			continue
		}
		if err := d.Retire(ctx, certificate, target); err != nil {
			return err
		}
	}
	return nil
}

func distributionTargetKey(target DistributionTarget) string {
	return target.NodeID + "\x00" + target.ProcessEpoch + "\x00" + fmt.Sprint(target.Generation)
}

type certificateCleanupDisposition struct {
	action        string
	terminalState string
}

func certificateCleanupDispositionFor(state State) (certificateCleanupDisposition, bool) {
	switch state {
	case StateSuperseded:
		return certificateCleanupDisposition{action: "retire", terminalState: "retired"}, true
	case StateRevoked, StateFailed:
		// A failed certificate is never activated during cleanup. It is
		// always removed with the terminal revoke action.
		return certificateCleanupDisposition{action: "revoke", terminalState: "revoked"}, true
	default:
		return certificateCleanupDisposition{}, false
	}
}

// targetUsesCurrentProcess compares a durable edge row's process epoch with
// the current authoritative node registration. A missing node is also stale:
// there is no process left that could ever acknowledge the row. Database
// errors other than no-rows are returned so cleanup remains retryable.
func (d *SQLDistributor) targetUsesCurrentProcess(ctx context.Context, target DistributionTarget) (bool, error) {
	if d == nil || d.db == nil {
		return false, ErrInvalid
	}
	identity, err := d.db.Queries().GetDistributionNodeIdentityV1(ctx, target.NodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return identity.ProcessEpoch == target.ProcessEpoch, nil
}

// Revoke removes one edge copy with terminal revocation semantics. It is also
// used as the compensation path when a replacement edge activated before a
// later target or durable store step failed.
func (d *SQLDistributor) Revoke(ctx context.Context, certificate StoredCertificate, target DistributionTarget) error {
	if err := certificate.validateDistributionMetadata(); err != nil {
		return distributionError(err)
	}
	if err := target.Validate(); err != nil {
		return distributionError(err)
	}
	revoker, ok := d.transport.(EdgeCertificateRevocationTransport)
	if !ok {
		return fmt.Errorf("%w: edge transport does not support terminal revocation", ErrDistributionUnavailable)
	}
	if err := revoker.Revoke(ctx, certificate, target); err != nil {
		return err
	}
	return d.markEdgeState(ctx, certificate, target, "revoked")
}

func (d *SQLDistributor) RevokeCertificate(ctx context.Context, certificate StoredCertificate) error {
	if d == nil || d.db == nil {
		return ErrInvalid
	}
	rows, err := d.db.Queries().ListTunnelCertificateEdgesV1(ctx, certificate.ID)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.State == "revoked" || row.State == "retired" {
			continue
		}
		target := DistributionTarget{NodeID: row.EdgeNodeID, ProcessEpoch: row.EdgeProcessEpoch, Generation: uint64(row.EdgeAssignmentGeneration)}
		current, err := d.targetUsesCurrentProcess(ctx, target)
		if err != nil {
			return err
		}
		if !current {
			// A replaced or removed process cannot receive a valid authenticated
			// revoke action. The durable row is still fenced by its complete
			// tuple, so terminalize it locally.
			if err := d.markEdgeState(ctx, certificate, target, "revoked"); err != nil {
				return err
			}
			continue
		}
		revoker, ok := d.transport.(EdgeCertificateRevocationTransport)
		if !ok {
			return fmt.Errorf("%w: edge transport does not support terminal revocation", ErrDistributionUnavailable)
		}
		// Durable revocation happens before this transport call. The row is
		// therefore already terminal, but the internal message still carries
		// the complete certificate metadata required by the edge verifier. A
		// revoked store state is not an instruction to reject that message.
		transportCertificate := certificate
		if transportCertificate.State == StateRevoked || transportCertificate.State == StateFailed {
			transportCertificate.State = StateActive
		}
		if err := revoker.Revoke(ctx, transportCertificate, target); err != nil {
			return err
		}
		if err := d.markEdgeState(ctx, certificate, target, "revoked"); err != nil {
			return err
		}
	}
	return nil
}

// ReconcileCertificateDistributionCleanup retries terminal cleanup for every
// durable edge row belonging to a superseded, revoked, or failed certificate. It
// snapshots IDs under a short transaction and performs edge calls outside it,
// so a slow or unavailable edge never holds database locks.
func (d *SQLDistributor) ReconcileCertificateDistributionCleanup(ctx context.Context, limit int) (int, error) {
	if d == nil || d.db == nil || limit < 1 || limit > 500 {
		return 0, ErrInvalid
	}
	ids := make([]string, 0, limit)
	err := d.db.InReadCommittedTx(ctx, func(txCtx context.Context, tx *db.Tx) error {
		pending, err := tx.Queries().ListPendingTunnelCertificateCleanupIDsV1(txCtx, int32(limit))
		if err != nil {
			return err
		}
		ids = append(ids, pending...)
		return nil
	})
	if err != nil {
		return 0, err
	}
	cleaned := 0
	var cleanupErr error
	for _, id := range ids {
		row, getErr := d.db.Queries().GetTunnelCertificateV1(ctx, id)
		if getErr != nil {
			cleanupErr = errors.Join(cleanupErr, getErr)
			continue
		}
		certificate := storedFromSQL(row)
		disposition, ok := certificateCleanupDispositionFor(certificate.State)
		if !ok {
			continue
		}
		var reconcileErr error
		switch disposition.action {
		case "retire":
			reconcileErr = d.RetireCertificate(ctx, certificate)
		case "revoke":
			reconcileErr = d.RevokeCertificate(ctx, certificate)
		}
		if reconcileErr != nil {
			cleanupErr = errors.Join(cleanupErr, reconcileErr)
			continue
		}
		cleaned++
	}
	return cleaned, cleanupErr
}

func (d *SQLDistributor) markEdgeState(ctx context.Context, certificate StoredCertificate, target DistributionTarget, state string) error {
	now := time.Now().UTC()
	_, err := d.db.Queries().MarkTunnelCertificateEdgeStateV1(ctx, dbsqlc.MarkTunnelCertificateEdgeStateV1Params{State: state, ObservedAt: sql.NullTime{Time: now, Valid: true}, Now: now, CertificateID: certificate.ID, EdgeNodeID: target.NodeID, EdgeProcessEpoch: target.ProcessEpoch, EdgeAssignmentGeneration: int64(target.Generation), CertificateGeneration: int64(certificate.CertificateGeneration)})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGenerationConflict
	}
	return err
}

func (d *SQLDistributor) markFailed(ctx context.Context, request DistributionRequest, reason string, cause error) error {
	_, markErr := d.db.Queries().MarkTunnelCertificateEdgeStateV1(ctx, dbsqlc.MarkTunnelCertificateEdgeStateV1Params{State: "failed", FailureCode: sql.NullString{String: reason, Valid: true}, Now: time.Now().UTC(), CertificateID: request.Certificate.ID, EdgeNodeID: request.Target.NodeID, EdgeProcessEpoch: request.Target.ProcessEpoch, EdgeAssignmentGeneration: int64(request.Target.Generation), CertificateGeneration: int64(request.Certificate.CertificateGeneration)})
	if errors.Is(markErr, pgx.ErrNoRows) {
		markErr = ErrGenerationConflict
	}
	if markErr != nil {
		return fmt.Errorf("%w: distribution=%v; persist failure=%w", ErrDistributionUnavailable, cause, markErr)
	}
	return fmt.Errorf("%w: %v", ErrDistributionUnavailable, cause)
}
