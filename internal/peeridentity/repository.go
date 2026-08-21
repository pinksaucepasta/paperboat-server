package peeridentity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

type SQLRepository struct {
	store *db.DB
	audit *audit.Writer
}

func (r *SQLRepository) Bootstrap(ctx context.Context, operationID, userID string, rootPublic ed25519.PublicKey, proposed Certificate) (Certificate, error) {
	if r == nil || ctx == nil || len(operationID) < 16 || len(operationID) > 256 || !identifierExpr.MatchString(userID) || len(rootPublic) != ed25519.PublicKeySize || proposed.Role != RoleCLI || proposed.EndpointID == "" || proposed.AccountID != userID {
		return Certificate{}, ErrInvalid
	}
	rootFingerprint := sha256.Sum256(rootPublic)
	if proposed.RootFingerprint != rootFingerprint {
		return Certificate{}, ErrIdentity
	}
	var result Certificate
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		root, err := q.CreateAccountE2EERoot(ctx, dbsqlc.CreateAccountE2EERootParams{UserID: userID, PublicKey: rootPublic, Fingerprint: rootFingerprint[:]})
		created := err == nil
		if errors.Is(err, sql.ErrNoRows) {
			root, err = q.GetAccountE2EERootForUpdate(ctx, userID)
		}
		if err != nil {
			return err
		}
		if root.RevokedAt.Valid || !bytes.Equal(root.PublicKey, rootPublic) || !bytes.Equal(root.Fingerprint, rootFingerprint[:]) || root.Generation != 1 {
			return ErrConflict
		}
		result, err = r.registerTx(ctx, tx, operationID, userID, proposed, root, false)
		if err != nil {
			return err
		}
		if created {
			rootOperation := sha256.Sum256([]byte("account-e2ee-root\x00" + operationID))
			return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "account_e2ee.root_created", ResourceType: "account_e2ee_root", ResourceID: hex.EncodeToString(rootFingerprint[:]), IdempotencyKey: "root_" + hex.EncodeToString(rootOperation[:]), Metadata: map[string]any{"generation": 1}})
		}
		return nil
	})
	return result, err
}

func NewSQLRepository(store *db.DB, writer *audit.Writer) (*SQLRepository, error) {
	if store == nil || writer == nil {
		return nil, ErrInvalid
	}
	return &SQLRepository{store: store, audit: writer}, nil
}

func (r *SQLRepository) ResolveAccountRoot(ctx context.Context, userID string) (AccountRoot, error) {
	if r == nil || ctx == nil || !identifierExpr.MatchString(userID) {
		return AccountRoot{}, ErrInvalid
	}
	row, err := r.store.Queries().GetActiveAccountE2EERoot(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return AccountRoot{}, ErrUnavailable
	}
	if err != nil || len(row.PublicKey) != ed25519.PublicKeySize || len(row.Fingerprint) != sha256.Size || row.Generation <= 0 {
		if err != nil {
			return AccountRoot{}, err
		}
		return AccountRoot{}, ErrUnavailable
	}
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], row.Fingerprint)
	return AccountRoot{PublicKey: append(ed25519.PublicKey(nil), row.PublicKey...), Fingerprint: fingerprint, Generation: uint64(row.Generation)}, nil
}

func (r *SQLRepository) RequestMachineEndpoint(ctx context.Context, request MachineEndpointRequest, id string, hash [sha256.Size]byte, expiresAt time.Time) (EndpointEnrollmentRequest, error) {
	if r == nil || ctx == nil || !identifierExpr.MatchString(id) || !expiresAt.After(request.Now) {
		return EndpointEnrollmentRequest{}, ErrInvalid
	}
	var result EndpointEnrollmentRequest
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if _, err := q.ExpirePeerEndpointEnrollmentRequests(ctx, request.Now.UTC()); err != nil {
			return err
		}
		existing, err := q.GetPeerEndpointEnrollmentRequestByOperation(ctx, request.OperationID)
		if err == nil {
			matches := bytes.Equal(existing.RequestHash, hash[:]) && existing.UserID == request.UserID && existing.EndpointID == request.EndpointID && existing.Generation == int64(request.Generation)
			if matches && existing.State == "expired" {
				renewed, renewErr := q.RenewExpiredPeerEndpointEnrollmentRequest(ctx, dbsqlc.RenewExpiredPeerEndpointEnrollmentRequestParams{
					CreatedAt: request.Now.UTC(), ExpiresAt: expiresAt.UTC(), OperationKey: request.OperationID,
					RequestHash: hash[:], UserID: request.UserID, EndpointID: request.EndpointID, Generation: int64(request.Generation),
				})
				if errors.Is(renewErr, sql.ErrNoRows) {
					return ErrUnavailable
				}
				if renewErr != nil {
					return renewErr
				}
				result, renewErr = endpointRequestFromRow(renewed)
				if renewErr != nil {
					return renewErr
				}
				return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: request.UserID, ActorType: audit.ActorSystem, EventType: "peer_endpoint.enrollment_renewed", ResourceType: "peer_endpoint_enrollment", ResourceID: renewed.ID, IdempotencyKey: request.OperationID + ":renew:" + request.Now.UTC().Format(time.RFC3339Nano), Metadata: map[string]any{"endpoint_id": request.EndpointID, "generation": request.Generation}})
			}
			if matches && existing.State == "fulfilled" {
				// The certificate is already durably registered. Return only the
				// same bound enrollment record so a client that failed before
				// saving it locally can poll and recover; never create another
				// request or certificate for this operation.
				result, err = endpointRequestFromRow(existing)
				return err
			}
			if !matches || existing.State != "pending" || !existing.ExpiresAt.After(request.Now) {
				return ErrConflict
			}
			result, err = endpointRequestFromRow(existing)
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		row, err := q.CreatePeerEndpointEnrollmentRequest(ctx, dbsqlc.CreatePeerEndpointEnrollmentRequestParams{ID: id, OperationKey: request.OperationID, RequestHash: hash[:], UserID: request.UserID, EndpointID: request.EndpointID, Generation: int64(request.Generation), NoisePublicKey: request.NoisePublicKey[:], QuicPublicKey: request.QUICPublicKey[:], CreatedAt: request.Now.UTC(), ExpiresAt: expiresAt.UTC()})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		result, err = endpointRequestFromRow(row)
		if err != nil {
			return err
		}
		return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: request.UserID, ActorType: audit.ActorSystem, EventType: "peer_endpoint.enrollment_requested", ResourceType: "peer_endpoint_enrollment", ResourceID: row.ID, IdempotencyKey: request.OperationID, Metadata: map[string]any{"endpoint_id": request.EndpointID, "generation": request.Generation}})
	})
	return result, err
}

func (r *SQLRepository) RequestCLIEndpoint(ctx context.Context, request CLIEndpointRequest, id string, hash [sha256.Size]byte, expiresAt time.Time) (EndpointEnrollmentRequest, error) {
	if r == nil || ctx == nil || !identifierExpr.MatchString(id) || !expiresAt.After(request.Now) {
		return EndpointEnrollmentRequest{}, ErrInvalid
	}
	var result EndpointEnrollmentRequest
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if _, err := q.ExpirePeerEndpointEnrollmentRequests(ctx, request.Now.UTC()); err != nil {
			return err
		}
		existing, err := q.GetPeerEndpointEnrollmentRequestByOperation(ctx, request.OperationID)
		if err == nil {
			matches := bytes.Equal(existing.RequestHash, hash[:]) && existing.UserID == request.UserID && existing.EndpointID == request.EndpointID && existing.Generation == int64(request.Generation) && existing.Role == "cli"
			if matches && existing.State == "expired" {
				renewed, renewErr := q.RenewExpiredCLIPeerEndpointEnrollmentRequest(ctx, dbsqlc.RenewExpiredCLIPeerEndpointEnrollmentRequestParams{CreatedAt: request.Now.UTC(), ExpiresAt: expiresAt.UTC(), OperationKey: request.OperationID, RequestHash: hash[:], UserID: request.UserID, EndpointID: request.EndpointID, Generation: int64(request.Generation)})
				if errors.Is(renewErr, sql.ErrNoRows) {
					return ErrUnavailable
				}
				if renewErr != nil {
					return renewErr
				}
				result, renewErr = endpointRequestFromRow(renewed)
				if renewErr != nil {
					return renewErr
				}
				return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: request.UserID, ActorType: audit.ActorSystem, EventType: "peer_endpoint.cli_enrollment_renewed", ResourceType: "peer_endpoint_enrollment", ResourceID: renewed.ID, IdempotencyKey: request.OperationID + ":renew", Metadata: map[string]any{"endpoint_id": request.EndpointID, "generation": request.Generation, "role": "cli"}})
			}
			if !matches || existing.State != "pending" || !existing.ExpiresAt.After(request.Now) {
				return ErrConflict
			}
			result, err = endpointRequestFromRow(existing)
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		row, err := q.CreateCLIPeerEndpointEnrollmentRequest(ctx, dbsqlc.CreateCLIPeerEndpointEnrollmentRequestParams{ID: id, OperationKey: request.OperationID, RequestHash: hash[:], UserID: request.UserID, EndpointID: request.EndpointID, Generation: int64(request.Generation), NoisePublicKey: request.NoisePublicKey[:], QuicPublicKey: request.QUICPublicKey[:], CreatedAt: request.Now.UTC(), ExpiresAt: expiresAt.UTC()})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		result, err = endpointRequestFromRow(row)
		if err != nil {
			return err
		}
		return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: request.UserID, ActorType: audit.ActorSystem, EventType: "peer_endpoint.cli_enrollment_requested", ResourceType: "peer_endpoint_enrollment", ResourceID: row.ID, IdempotencyKey: request.OperationID, Metadata: map[string]any{"endpoint_id": request.EndpointID, "generation": request.Generation, "role": "cli"}})
	})
	return result, err
}

func (r *SQLRepository) ListPendingEndpoints(ctx context.Context, userID string, now time.Time, limit int32) ([]EndpointEnrollmentRequest, error) {
	if r == nil || ctx == nil || !identifierExpr.MatchString(userID) || now.IsZero() || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := r.store.Queries().ListPendingPeerEndpointEnrollmentRequests(ctx, dbsqlc.ListPendingPeerEndpointEnrollmentRequestsParams{UserID: userID, Now: now.UTC(), RowLimit: limit})
	if err != nil {
		return nil, err
	}
	result := make([]EndpointEnrollmentRequest, 0, len(rows))
	for _, row := range rows {
		value, err := endpointRequestFromRow(row)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func (r *SQLRepository) Register(ctx context.Context, operationID, userID string, proposed Certificate) (Certificate, error) {
	if r == nil || ctx == nil || len(operationID) < 16 || len(operationID) > 256 ||
		!identifierExpr.MatchString(userID) || proposed.AccountID != userID || len(proposed.Raw) == 0 {
		return Certificate{}, ErrInvalid
	}
	var result Certificate
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		root, err := q.GetAccountE2EERootForUpdate(ctx, userID)
		if errors.Is(err, sql.ErrNoRows) || err == nil && root.RevokedAt.Valid {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(root.Fingerprint, proposed.RootFingerprint[:]) || len(root.PublicKey) != ed25519.PublicKeySize {
			return ErrConflict
		}
		result, err = r.registerTx(ctx, tx, operationID, userID, proposed, root, true)
		return err
	})
	return result, err
}

func (r *SQLRepository) registerTx(ctx context.Context, tx *db.Tx, operationID, userID string, proposed Certificate, root dbsqlc.AccountE2eeRoot, requireEnrollment bool) (Certificate, error) {
	q := tx.Queries()
	requestHash := sha256.Sum256(proposed.Raw)
	var result Certificate
	existingOperation, err := q.GetPeerEndpointCertificateOperationForUpdate(ctx, operationID)
	if err == nil {
		if existingOperation.UserID != userID || !bytes.Equal(existingOperation.RequestHash, requestHash[:]) || !bytes.Equal(existingOperation.CertificateFingerprint, proposed.Fingerprint[:]) {
			return Certificate{}, ErrConflict
		}
		row, getErr := q.GetPeerEndpointCertificateByFingerprint(ctx, existingOperation.CertificateFingerprint)
		if getErr != nil {
			return Certificate{}, getErr
		}
		return certificateFromRow(row, root.PublicKey, proposed.RootFingerprint, proposed.IssuedAt)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, err
	}
	var enrollment dbsqlc.PeerEndpointEnrollmentRequest
	if requireEnrollment && (proposed.Role == RoleMachine || proposed.Role == RoleCLI) {
		enrollment, err = q.GetMatchingPeerEndpointEnrollmentRequestForUpdate(ctx, dbsqlc.GetMatchingPeerEndpointEnrollmentRequestForUpdateParams{UserID: userID, EndpointID: proposed.EndpointID, Generation: int64(proposed.Generation), Now: proposed.IssuedAt})
		if errors.Is(err, sql.ErrNoRows) {
			return Certificate{}, ErrUnavailable
		}
		if err != nil {
			return Certificate{}, err
		}
		if roleFromString(enrollment.Role) != proposed.Role || !bytes.Equal(enrollment.NoisePublicKey, proposed.NoisePublicKey[:]) || !bytes.Equal(enrollment.QuicPublicKey, proposed.QUICPublicKey[:]) || proposed.IssuedAt.Before(enrollment.CreatedAt) {
			return Certificate{}, ErrConflict
		}
	}
	if _, err := q.RevokeSupersededPeerEndpointCertificates(ctx, dbsqlc.RevokeSupersededPeerEndpointCertificatesParams{Now: sql.NullTime{Time: proposed.IssuedAt, Valid: true}, UserID: userID, EndpointID: proposed.EndpointID, Generation: int64(proposed.Generation)}); err != nil {
		return Certificate{}, err
	}
	row, err := q.CreatePeerEndpointCertificate(ctx, dbsqlc.CreatePeerEndpointCertificateParams{
		Fingerprint: proposed.Fingerprint[:], UserID: userID, EndpointID: proposed.EndpointID,
		Role: proposed.Role.String(), Generation: int64(proposed.Generation), Serial: int64(proposed.Serial),
		Certificate: proposed.Raw, NoisePublicKey: proposed.NoisePublicKey[:], QuicPublicKey: proposed.QUICPublicKey[:],
		IssuedAt: proposed.IssuedAt, ExpiresAt: proposed.ExpiresAt,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, ErrConflict
	}
	if err != nil {
		return Certificate{}, err
	}
	if _, err := q.CreatePeerEndpointCertificateOperation(ctx, dbsqlc.CreatePeerEndpointCertificateOperationParams{OperationID: operationID, UserID: userID, RequestHash: requestHash[:], CertificateFingerprint: proposed.Fingerprint[:], CreatedAt: proposed.IssuedAt}); err != nil {
		return Certificate{}, err
	}
	if requireEnrollment && (proposed.Role == RoleMachine || proposed.Role == RoleCLI) {
		if _, err := q.FulfillPeerEndpointEnrollmentRequest(ctx, dbsqlc.FulfillPeerEndpointEnrollmentRequestParams{CertificateFingerprint: proposed.Fingerprint[:], Now: sql.NullTime{Time: proposed.IssuedAt, Valid: true}, ID: enrollment.ID}); err != nil {
			return Certificate{}, err
		}
	}
	result, err = certificateFromRow(row, root.PublicKey, proposed.RootFingerprint, proposed.IssuedAt)
	if err != nil {
		return Certificate{}, err
	}
	if err := r.audit.WriteTx(ctx, tx, audit.Event{
		ActorUserID: userID, ActorType: audit.ActorUser, EventType: "peer_endpoint.certificate_registered",
		ResourceType: "peer_endpoint_certificate", ResourceID: hex.EncodeToString(proposed.Fingerprint[:]),
		IdempotencyKey: operationID, Metadata: map[string]any{"endpoint_id": proposed.EndpointID, "role": proposed.Role.String(), "generation": proposed.Generation, "serial": proposed.Serial},
	}); err != nil {
		return Certificate{}, err
	}
	return result, nil
}

func endpointRequestFromRow(row dbsqlc.PeerEndpointEnrollmentRequest) (EndpointEnrollmentRequest, error) {
	if len(row.NoisePublicKey) != 32 || len(row.QuicPublicKey) != 32 || row.Generation < 1 || !row.ExpiresAt.After(row.CreatedAt) {
		return EndpointEnrollmentRequest{}, ErrUnavailable
	}
	result := EndpointEnrollmentRequest{ID: row.ID, UserID: row.UserID, EndpointID: row.EndpointID, Generation: uint64(row.Generation), Role: roleFromString(row.Role), State: row.State, CreatedAt: row.CreatedAt.UTC(), ExpiresAt: row.ExpiresAt.UTC()}
	if result.Role == 0 || (result.State != "pending" && result.State != "fulfilled" && result.State != "expired" && result.State != "revoked") {
		return EndpointEnrollmentRequest{}, ErrUnavailable
	}
	// CLI identities are intentionally single-generation. Reject malformed or
	// legacy rows rather than exposing a request that could not produce the
	// certificate contract enforced by Bootstrap (role=cli, generation=1).
	if result.Role == RoleCLI && result.Generation != 1 {
		return EndpointEnrollmentRequest{}, ErrUnavailable
	}
	copy(result.NoisePublicKey[:], row.NoisePublicKey)
	copy(result.QUICPublicKey[:], row.QuicPublicKey)
	return result, nil
}

func (r *SQLRepository) Get(ctx context.Context, userID, endpointID string, generation uint64, now time.Time) (Certificate, error) {
	if r == nil || ctx == nil || !identifierExpr.MatchString(userID) || !identifierExpr.MatchString(endpointID) || generation == 0 || generation > maximumInteger || now.IsZero() {
		return Certificate{}, ErrInvalid
	}
	root, err := r.ResolveAccountRoot(ctx, userID)
	if err != nil {
		return Certificate{}, err
	}
	row, err := r.store.Queries().GetPeerEndpointCertificateByIdentity(ctx, dbsqlc.GetPeerEndpointCertificateByIdentityParams{UserID: userID, EndpointID: endpointID, Generation: int64(generation)})
	if errors.Is(err, sql.ErrNoRows) || err == nil && row.RevokedAt.Valid {
		return Certificate{}, ErrUnavailable
	}
	if err != nil {
		return Certificate{}, err
	}
	return certificateFromRow(row, root.PublicKey, root.Fingerprint, now)
}

func (r *SQLRepository) Revoke(ctx context.Context, operationID, userID, endpointID string, generation, serial uint64, reason string, now time.Time) (Certificate, error) {
	if r == nil || ctx == nil {
		return Certificate{}, ErrInvalid
	}
	var result Certificate
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		root, err := q.GetAccountE2EERootForUpdate(ctx, userID)
		if errors.Is(err, sql.ErrNoRows) || err == nil && root.RevokedAt.Valid {
			return ErrUnavailable
		}
		if err != nil || len(root.PublicKey) != ed25519.PublicKeySize || len(root.Fingerprint) != sha256.Size {
			if err != nil {
				return err
			}
			return ErrUnavailable
		}
		var rootFingerprint [sha256.Size]byte
		copy(rootFingerprint[:], root.Fingerprint)
		replay, err := q.GetPeerEndpointCertificateRevocationForUpdate(ctx, operationID)
		if err == nil {
			if replay.UserID != userID || replay.Serial != int64(serial) || replay.Reason != reason {
				return ErrConflict
			}
			row, getErr := q.GetPeerEndpointCertificateByFingerprint(ctx, replay.CertificateFingerprint)
			if getErr != nil || row.EndpointID != endpointID || row.Generation != int64(generation) {
				return ErrConflict
			}
			result, err = certificateFromRow(row, root.PublicKey, rootFingerprint, row.IssuedAt)
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		row, err := q.GetPeerEndpointCertificateByIdentity(ctx, dbsqlc.GetPeerEndpointCertificateByIdentityParams{UserID: userID, EndpointID: endpointID, Generation: int64(generation)})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		if err != nil || row.Serial != int64(serial) || row.RevokedAt.Valid {
			if err != nil {
				return err
			}
			return ErrConflict
		}
		if _, err := q.CreatePeerEndpointCertificateRevocation(ctx, dbsqlc.CreatePeerEndpointCertificateRevocationParams{OperationID: operationID, UserID: userID, CertificateFingerprint: row.Fingerprint, Serial: int64(serial), Reason: reason, CreatedAt: now}); err != nil {
			return err
		}
		row, err = q.RevokePeerEndpointCertificate(ctx, dbsqlc.RevokePeerEndpointCertificateParams{Now: sql.NullTime{Time: now, Valid: true}, Reason: sql.NullString{String: reason, Valid: true}, Fingerprint: row.Fingerprint})
		if err != nil {
			return err
		}
		result, err = certificateFromRow(row, root.PublicKey, rootFingerprint, row.IssuedAt)
		if err != nil {
			return err
		}
		return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "peer_endpoint.certificate_revoked", ResourceType: "peer_endpoint_certificate", ResourceID: hex.EncodeToString(row.Fingerprint), IdempotencyKey: operationID, Metadata: map[string]any{"endpoint_id": endpointID, "generation": generation, "serial": serial, "reason": reason}})
	})
	return result, err
}

func certificateFromRow(row dbsqlc.PeerEndpointCertificate, rootPublic ed25519.PublicKey, rootFingerprint [sha256.Size]byte, now time.Time) (Certificate, error) {
	certificate, err := Verify(row.Certificate, rootPublic, Expected{AccountID: row.UserID, EndpointID: row.EndpointID, Role: roleFromString(row.Role), Generation: uint64(row.Generation), Serial: uint64(row.Serial)}, now)
	if err != nil {
		return Certificate{}, err
	}
	if !bytes.Equal(row.Fingerprint, certificate.Fingerprint[:]) || !bytes.Equal(row.NoisePublicKey, certificate.NoisePublicKey[:]) || !bytes.Equal(row.QuicPublicKey, certificate.QUICPublicKey[:]) || !row.IssuedAt.Equal(certificate.IssuedAt) || !row.ExpiresAt.Equal(certificate.ExpiresAt) {
		return Certificate{}, ErrConflict
	}
	certificate.RootFingerprint = rootFingerprint
	return certificate, nil
}

func roleFromString(value string) Role {
	switch value {
	case "cli":
		return RoleCLI
	case "machine":
		return RoleMachine
	default:
		return 0
	}
}
