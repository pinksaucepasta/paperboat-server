package previewattachment

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// SQLRepository persists only the short-lived binding metadata. It does not
// restore a host carrier after restart; a new machine-proof request must
// resolve a fresh preview-ephemeral session and route generation.
type SQLRepository struct {
	db  *db.DB
	now func() time.Time
}

func NewSQLRepository(database *db.DB) (*SQLRepository, error) {
	if database == nil || database.Pool() == nil {
		return nil, fmt.Errorf("%w: database is not open", ErrInvalid)
	}
	return &SQLRepository{db: database, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *SQLRepository) SetClock(now func() time.Time) error {
	if now == nil {
		return fmt.Errorf("%w: nil clock", ErrInvalid)
	}
	s.now = now
	return nil
}

func (s *SQLRepository) Get(ctx context.Context, accountID, operationID string) (Attachment, error) {
	if s == nil || s.db == nil || ctx == nil || !validID(accountID) || !validID(operationID) {
		return Attachment{}, fmt.Errorf("%w: invalid attachment lookup", ErrInvalid)
	}
	return scanAttachmentWithRepositoryError(s.db.Pool().QueryRow(ctx, selectAttachmentSQL, accountID, operationID))
}

// CreatePending inserts one server-authoritative allocation. ON CONFLICT is
// deliberately followed by an account-scoped read so a retry returns the
// exact previous decision, while a changed request hash is rejected.
func (s *SQLRepository) CreatePending(ctx context.Context, attachment Attachment) (Attachment, error) {
	if s == nil || s.db == nil || ctx == nil {
		return Attachment{}, fmt.Errorf("%w: repository is not available", ErrInvalid)
	}
	if attachment.State != StatePending || attachment.AttachmentGeneration != 1 || attachment.EdgeReady || attachment.OriginReady {
		return Attachment{}, fmt.Errorf("%w: only a pending generation-one attachment can be inserted", ErrInvalid)
	}
	if err := attachment.Validate(time.Time{}); err != nil {
		return Attachment{}, err
	}
	hash, err := hex.DecodeString(attachment.RequestHash)
	if err != nil || len(hash) != 32 {
		return Attachment{}, fmt.Errorf("%w: invalid request hash", ErrInvalid)
	}
	now := s.clock()
	var result Attachment
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		command, err := tx.Exec(ctx, insertAttachmentSQL,
			attachment.AccountID, attachment.PreviewID, attachment.OperationID,
			attachment.IdempotencyKey, attachment.RequestID, attachment.CorrelationID, hash,
			attachment.OwnerDeviceID, attachment.OwnerSessionID, attachment.HostID,
			attachment.EdgeNodeID, attachment.MachineIdentityPublicKey, attachment.MachineIdentityThumbprint,
			attachment.LeaseGeneration, attachment.TunnelID, attachment.ConnectorID,
			attachment.SessionID, attachment.ProcessGeneration, attachment.ConfigGeneration,
			attachment.ConfigContentHash, attachment.RouteID, attachment.RouteGeneration,
			attachment.EdgeEndpoints, attachment.EdgeProcessEpoch, attachment.EdgeCarrierServerSPKISHA256, attachment.EdgeCarrierServerCertificateChainPEM, attachment.IssuedAt.UTC(), attachment.ExpiresAt.UTC(), now, now,
		)
		if err != nil {
			return fmt.Errorf("%w: insert attachment: %v", ErrConflict, err)
		}
		if command.RowsAffected() == 0 {
			existing, getErr := scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, attachment.AccountID, attachment.OperationID))
			if errors.Is(getErr, pgx.ErrNoRows) {
				return fmt.Errorf("%w: preview already has another live attachment", ErrConflict)
			}
			if getErr != nil {
				return getErr
			}
			if existing.RequestHash != attachment.RequestHash {
				return ErrIdempotencyConflict
			}
			result = existing
			if result.State == StatePending {
				return prepareAdmissionTx(ctx, tx, result, now)
			}
			return nil
		}
		result, err = scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, attachment.AccountID, attachment.OperationID))
		if err != nil {
			return err
		}
		if result.State == StatePending {
			return prepareAdmissionTx(ctx, tx, result, now)
		}
		return nil
	})
	return result, err
}

// PreparePreviewCarrierAdmission durably records the exact safe edge intent
// before an external publisher is called. It is idempotent for the same
// operation/generation and carries no credential material.
func (s *SQLRepository) PreparePreviewCarrierAdmission(ctx context.Context, attachment Attachment, now time.Time) error {
	if s == nil || s.db == nil || ctx == nil {
		return fmt.Errorf("%w: repository is not available", ErrInvalid)
	}
	if attachment.State != StatePending {
		return fmt.Errorf("%w: admission must be prepared from pending state", ErrConflict)
	}
	if err := attachment.Validate(time.Time{}); err != nil {
		return err
	}
	if now.IsZero() {
		now = s.clock()
	}
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return prepareAdmissionTx(ctx, tx, attachment, now)
	})
}

func prepareAdmissionTx(ctx context.Context, tx *db.Tx, attachment Attachment, now time.Time) error {
	binding, err := json.Marshal(attachment.Binding)
	if err != nil {
		return fmt.Errorf("%w: encode admission binding: %v", ErrInvalid, err)
	}
	_, err = tx.Exec(ctx, prepareAdmissionOutboxSQL,
		attachment.AccountID, attachment.OperationID, attachment.AttachmentGeneration,
		binding, attachment.ConfigContentHash, attachment.EdgeEndpoints,
		attachment.Endpoint, attachment.AccessMode, attachment.ExpiresAt.UTC(), now.UTC(),
	)
	return err
}

// Admit records only that the edge publisher accepted the write-only
// admission. It intentionally does not set edge_ready; that flag is reserved
// for a later authenticated edge observation.
func (s *SQLRepository) Admit(ctx context.Context, attachment Attachment, now time.Time) (Attachment, error) {
	if err := validateRepositoryAttachment(attachment); err != nil {
		return Attachment{}, err
	}
	if now.IsZero() {
		now = s.clock()
	}
	var result Attachment
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		command, err := tx.Exec(ctx, admitAttachmentSQL,
			attachment.AccountID, attachment.OperationID, attachment.AttachmentGeneration,
			attachment.PreviewID, attachment.OwnerDeviceID, attachment.OwnerSessionID,
			attachment.HostID, attachment.EdgeNodeID, attachment.MachineIdentityPublicKey,
			attachment.MachineIdentityThumbprint, attachment.LeaseGeneration, attachment.TunnelID,
			attachment.ConnectorID, attachment.SessionID, attachment.ProcessGeneration,
			attachment.ConfigGeneration, attachment.RouteID, attachment.RouteGeneration, now.UTC(), attachment.EdgeProcessEpoch,
			attachment.EdgeCarrierServerSPKISHA256, attachment.EdgeCarrierServerCertificateChainPEM,
		)
		if err != nil {
			return err
		}
		if command.RowsAffected() == 0 {
			current, getErr := scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, attachment.AccountID, attachment.OperationID))
			if getErr != nil {
				return translateRepositoryRowError(getErr)
			}
			if current.AttachmentGeneration == attachment.AttachmentGeneration+1 && current.Binding == attachment.Binding && current.State == StateAdmitted {
				result = current
				return nil
			}
			return ErrStaleBinding
		}
		result, err = scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, attachment.AccountID, attachment.OperationID))
		return err
	})
	return result, err
}

// ObserveEdge is called only by the authenticated edge transport after the
// publisher has installed the admission. A host cannot call this method via
// the machine-proof HTTP surface.
func (s *SQLRepository) ObserveEdge(ctx context.Context, attachment Attachment, now time.Time) (Attachment, error) {
	if err := validateRepositoryAttachment(attachment); err != nil {
		return Attachment{}, err
	}
	if now.IsZero() {
		now = s.clock()
	}
	var result Attachment
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		command, err := tx.Exec(ctx, observeEdgeAttachmentSQL,
			attachment.AccountID, attachment.OperationID, attachment.AttachmentGeneration,
			attachment.PreviewID, attachment.OwnerDeviceID, attachment.OwnerSessionID,
			attachment.HostID, attachment.EdgeNodeID, attachment.MachineIdentityPublicKey,
			attachment.MachineIdentityThumbprint, attachment.LeaseGeneration, attachment.TunnelID,
			attachment.ConnectorID, attachment.SessionID, attachment.ProcessGeneration,
			attachment.ConfigGeneration, attachment.RouteID, attachment.RouteGeneration, now.UTC(), attachment.EdgeProcessEpoch,
			attachment.EdgeCarrierServerSPKISHA256, attachment.EdgeCarrierServerCertificateChainPEM,
		)
		if err != nil {
			return err
		}
		if command.RowsAffected() == 0 {
			current, getErr := scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, attachment.AccountID, attachment.OperationID))
			if getErr != nil {
				return translateRepositoryRowError(getErr)
			}
			if current.AttachmentGeneration == attachment.AttachmentGeneration+1 && current.Binding == attachment.Binding && current.State == StateEdgeReady && current.EdgeReady && !current.OriginReady {
				result = current
				return nil
			}
			if current.AttachmentGeneration == attachment.AttachmentGeneration && current.Binding == attachment.Binding && current.EdgeReady {
				result = current
				return nil
			}
			return ErrStaleBinding
		}
		result, err = scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, attachment.AccountID, attachment.OperationID))
		return err
	})
	return result, err
}

// ObserveOrigin is the machine-proof path. Edge readiness is an invariant of
// the stored publisher/edge transition and is never accepted from this call.
func (s *SQLRepository) ObserveOrigin(ctx context.Context, attachment Attachment, originReady bool, now time.Time) (Attachment, error) {
	if err := validateRepositoryAttachment(attachment); err != nil {
		return Attachment{}, err
	}
	if now.IsZero() {
		now = s.clock()
	}
	var result Attachment
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		command, err := tx.Exec(ctx, observeOriginAttachmentSQL,
			attachment.AccountID, attachment.OperationID, attachment.AttachmentGeneration,
			attachment.PreviewID, attachment.OwnerDeviceID, attachment.OwnerSessionID,
			attachment.HostID, attachment.EdgeNodeID, attachment.MachineIdentityPublicKey,
			attachment.MachineIdentityThumbprint, attachment.LeaseGeneration, attachment.TunnelID,
			attachment.ConnectorID, attachment.SessionID, attachment.ProcessGeneration,
			attachment.ConfigGeneration, attachment.RouteID, attachment.RouteGeneration,
			originReady, now.UTC(), attachment.EdgeProcessEpoch,
			attachment.EdgeCarrierServerSPKISHA256, attachment.EdgeCarrierServerCertificateChainPEM,
		)
		if err != nil {
			return err
		}
		if command.RowsAffected() == 0 {
			current, getErr := scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, attachment.AccountID, attachment.OperationID))
			if getErr != nil {
				return translateRepositoryRowError(getErr)
			}
			postState := StateEdgeReady
			if originReady {
				postState = StateReady
			}
			if current.AttachmentGeneration == attachment.AttachmentGeneration+1 && current.Binding == attachment.Binding && current.State == postState && current.EdgeReady && current.OriginReady == originReady {
				result = current
				return nil
			}
			if current.AttachmentGeneration == attachment.AttachmentGeneration && current.Binding == attachment.Binding && current.EdgeReady && current.OriginReady == originReady {
				result = current
				return nil
			}
			return ErrStaleBinding
		}
		result, err = scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, attachment.AccountID, attachment.OperationID))
		return err
	})
	return result, err
}

// Renew updates the current lease/carrier lifetime. It keeps route identity
// immutable and allows only a newer connector session/process/config or lease
// generation for the same preview operation.
func (s *SQLRepository) Renew(ctx context.Context, current, next Attachment, now time.Time) (Attachment, error) {
	if err := validateRepositoryAttachment(current); err != nil {
		return Attachment{}, err
	}
	if err := validateRepositoryAttachment(next); err != nil {
		return Attachment{}, err
	}
	if !logicalBindingEqual(current.Binding, next.Binding) || current.OperationID != next.OperationID || current.AccountID != next.AccountID || current.RequestHash != next.RequestHash || next.ExpiresAt.IsZero() || next.RouteGeneration != current.RouteGeneration || next.LeaseGeneration < current.LeaseGeneration || next.ProcessGeneration < current.ProcessGeneration || next.ConfigGeneration < current.ConfigGeneration || next.ConfigGeneration == current.ConfigGeneration && next.ConfigContentHash != current.ConfigContentHash || next.SessionID != current.SessionID && next.ProcessGeneration <= current.ProcessGeneration || next.SessionID == current.SessionID && next.ProcessGeneration != current.ProcessGeneration {
		return Attachment{}, fmt.Errorf("%w: renew cannot change preview, operation, owner, or route", ErrConflict)
	}
	if now.IsZero() {
		now = s.clock()
	}
	if !next.ExpiresAt.After(now) {
		return Attachment{}, ErrExpired
	}
	var result Attachment
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		command, err := tx.Exec(ctx, renewAttachmentSQL,
			current.AccountID, current.OperationID, current.AttachmentGeneration,
			current.PreviewID, current.OwnerDeviceID, current.OwnerSessionID, current.HostID,
			current.EdgeNodeID, current.MachineIdentityPublicKey, current.MachineIdentityThumbprint,
			current.TunnelID, current.ConnectorID, current.RouteID, current.RouteGeneration,
			current.LeaseGeneration, current.SessionID, current.ProcessGeneration, current.ConfigGeneration,
			next.LeaseGeneration, next.SessionID, next.ProcessGeneration, next.ConfigGeneration,
			next.ConfigContentHash, next.EdgeEndpoints, next.EdgeNodeID,
			next.MachineIdentityPublicKey, next.MachineIdentityThumbprint, next.ExpiresAt.UTC(), now.UTC(),
			next.EdgeProcessEpoch, current.EdgeProcessEpoch,
			next.EdgeCarrierServerSPKISHA256, next.EdgeCarrierServerCertificateChainPEM,
			current.EdgeCarrierServerSPKISHA256, current.EdgeCarrierServerCertificateChainPEM,
		)
		if err != nil {
			return err
		}
		if command.RowsAffected() == 0 {
			persisted, getErr := scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, current.AccountID, current.OperationID))
			if errors.Is(getErr, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if getErr != nil {
				return getErr
			}
			if persisted.AttachmentGeneration == current.AttachmentGeneration+1 && persisted.Binding == next.Binding && persisted.ExpiresAt.Equal(next.ExpiresAt) {
				result = persisted
				return nil
			}
			return ErrStaleBinding
		}
		result, err = scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, current.AccountID, current.OperationID))
		if err != nil {
			return err
		}
		// A reconnect or carrier generation change resets admission readiness to
		// pending. Keep the exact desired admission durable in the same
		// transaction as the CAS update so a crash cannot strand the new route.
		if result.State == StatePending {
			if err := prepareAdmissionTx(ctx, tx, result, now.UTC()); err != nil {
				return err
			}
		}
		return nil
	})
	return result, err
}

func (s *SQLRepository) Release(ctx context.Context, attachment Attachment, now time.Time) (Attachment, error) {
	if attachment.State != StateReleased && attachment.State != StateFailed {
		if err := validateRepositoryAttachment(attachment); err != nil {
			return Attachment{}, err
		}
	} else if err := attachment.Validate(time.Time{}); err != nil {
		return Attachment{}, err
	}
	if now.IsZero() {
		now = s.clock()
	}
	var result Attachment
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		command, err := tx.Exec(ctx, releaseAttachmentSQL,
			attachment.AccountID, attachment.OperationID, attachment.AttachmentGeneration,
			attachment.PreviewID, attachment.OwnerDeviceID, attachment.OwnerSessionID,
			attachment.HostID, attachment.EdgeNodeID, attachment.MachineIdentityPublicKey,
			attachment.MachineIdentityThumbprint, attachment.LeaseGeneration, attachment.TunnelID,
			attachment.ConnectorID, attachment.SessionID, attachment.ProcessGeneration,
			attachment.ConfigGeneration, attachment.RouteID, attachment.RouteGeneration, now.UTC(), attachment.EdgeProcessEpoch,
			attachment.EdgeCarrierServerSPKISHA256, attachment.EdgeCarrierServerCertificateChainPEM,
		)
		if err != nil {
			return err
		}
		if command.RowsAffected() == 0 {
			current, getErr := scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, attachment.AccountID, attachment.OperationID))
			if getErr != nil {
				return translateRepositoryRowError(getErr)
			}
			if current.State == StateReleased && current.Binding == attachment.Binding && current.AttachmentGeneration == attachment.AttachmentGeneration+1 {
				result = current
				return nil
			}
			if current.State == StateReleased && current.Binding == attachment.Binding && current.AttachmentGeneration == attachment.AttachmentGeneration {
				result = current
				return nil
			}
			if current.State == StateFailed && current.Binding == attachment.Binding && current.AttachmentGeneration == attachment.AttachmentGeneration {
				result = current
				return nil
			}
			return ErrStaleBinding
		}
		if err := enqueueDetachTx(ctx, tx, attachment, now.UTC()); err != nil {
			return err
		}
		result, err = scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, attachment.AccountID, attachment.OperationID))
		return err
	})
	return result, err
}

func scanAttachmentWithRepositoryError(row rowScanner) (Attachment, error) {
	attachment, err := scanAttachment(row)
	if err != nil {
		return Attachment{}, translateRepositoryRowError(err)
	}
	return attachment, nil
}

func (s *SQLRepository) Expire(ctx context.Context, now time.Time) error {
	if s == nil || s.db == nil || ctx == nil {
		return fmt.Errorf("%w: repository is not available", ErrInvalid)
	}
	if now.IsZero() {
		now = s.clock()
	}
	_, err := s.db.Pool().Exec(ctx, expireAttachmentSQL, now.UTC())
	return err
}

func (s *SQLRepository) clock() time.Time {
	if s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}

func validateRepositoryAttachment(attachment Attachment) error {
	if attachment.State == StateReleased || attachment.State == StateFailed {
		return fmt.Errorf("%w: terminal attachment cannot be mutated", ErrTerminal)
	}
	return attachment.Validate(time.Time{})
}

func translateRepositoryRowError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func enqueueDetachTx(ctx context.Context, tx *db.Tx, attachment Attachment, now time.Time) error {
	binding, err := json.Marshal(attachment.Binding)
	if err != nil {
		return fmt.Errorf("%w: encode detach binding: %v", ErrInvalid, err)
	}
	_, err = tx.Exec(ctx, enqueueDetachOutboxSQL,
		attachment.AccountID, attachment.OperationID, attachment.AttachmentGeneration+1,
		binding, attachment.ConfigContentHash, attachment.EdgeEndpoints,
		attachment.Endpoint, attachment.AccessMode, now, now,
	)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAttachment(row rowScanner) (Attachment, error) {
	var (
		accountID, previewID, operationID, idempotencyKey, requestID, correlationID                                                            string
		requestHash                                                                                                                            []byte
		ownerDeviceID, ownerSessionID, hostID, edgeNodeID, edgeProcessEpoch, edgeCarrierServerSPKISHA256, edgeCarrierServerCertificateChainPEM string
		machineIdentityPublicKey, machineIdentityThumbprint, carrierKind                                                                       string
		leaseGeneration, processGeneration, configGeneration, routeGeneration                                                                  int64
		tunnelID, connectorID, connectorSessionID, configContentHash, routeID                                                                  string
		edgeEndpoints                                                                                                                          []string
		attachmentGeneration                                                                                                                   int64
		state                                                                                                                                  string
		edgeReady, originReady                                                                                                                 bool
		issuedAt, expiresAt, createdAt, updatedAt                                                                                              time.Time
		readyAt, releasedAt                                                                                                                    sql.NullTime
		endpoint, targetScheme, targetAddress, accessMode                                                                                      string
	)
	err := row.Scan(
		&accountID, &previewID, &operationID, &idempotencyKey, &requestID, &correlationID, &requestHash,
		&ownerDeviceID, &ownerSessionID, &hostID, &edgeNodeID,
		&machineIdentityPublicKey, &machineIdentityThumbprint, &carrierKind, &leaseGeneration,
		&tunnelID, &connectorID, &connectorSessionID, &processGeneration,
		&configGeneration, &configContentHash, &routeID, &routeGeneration,
		&edgeEndpoints, &edgeProcessEpoch, &edgeCarrierServerSPKISHA256, &edgeCarrierServerCertificateChainPEM, &attachmentGeneration, &state, &edgeReady, &originReady,
		&issuedAt, &expiresAt, &readyAt, &releasedAt, &createdAt, &updatedAt,
		&endpoint, &targetScheme, &targetAddress, &accessMode,
	)
	if err != nil {
		return Attachment{}, err
	}
	if carrierKind != "preview_ephemeral" {
		return Attachment{}, fmt.Errorf("%w: persisted attachment is not preview-ephemeral", ErrConflict)
	}
	if leaseGeneration <= 0 || processGeneration <= 0 || configGeneration <= 0 || routeGeneration <= 0 || attachmentGeneration <= 0 {
		return Attachment{}, fmt.Errorf("%w: persisted attachment has invalid generation", ErrConflict)
	}
	a := Attachment{
		Schema: Schema, Kind: Kind,
		Binding: Binding{
			AccountID: accountID, PreviewID: previewID, OperationID: operationID,
			OwnerDeviceID: ownerDeviceID, OwnerSessionID: ownerSessionID, HostID: hostID,
			LeaseGeneration: uint64(leaseGeneration), TunnelID: tunnelID, ConnectorID: connectorID,
			SessionID: connectorSessionID, ProcessGeneration: uint64(processGeneration),
			ConfigGeneration: uint64(configGeneration), RouteID: routeID, RouteGeneration: uint64(routeGeneration),
			EdgeNodeID: edgeNodeID, EdgeProcessEpoch: edgeProcessEpoch, EdgeCarrierServerSPKISHA256: edgeCarrierServerSPKISHA256, EdgeCarrierServerCertificateChainPEM: edgeCarrierServerCertificateChainPEM, MachineIdentityPublicKey: machineIdentityPublicKey,
			MachineIdentityThumbprint: machineIdentityThumbprint,
		},
		IdempotencyKey: idempotencyKey, RequestID: requestID, CorrelationID: correlationID, RequestHash: hex.EncodeToString(requestHash),
		Endpoint: endpoint, Target: Target{Scheme: targetScheme, Address: targetAddress}, AccessMode: accessMode,
		ConfigContentHash: configContentHash, EdgeEndpoints: append([]string(nil), edgeEndpoints...),
		AttachmentGeneration: uint64(attachmentGeneration), IssuedAt: issuedAt, ExpiresAt: expiresAt,
		State: state, EdgeReady: edgeReady, OriginReady: originReady,
	}
	if readyAt.Valid {
		value := readyAt.Time.UTC()
		a.ReadyAt = &value
	}
	if releasedAt.Valid {
		value := releasedAt.Time.UTC()
		a.ReleasedAt = &value
	}
	if err := a.Validate(time.Time{}); err != nil {
		return Attachment{}, err
	}
	_ = createdAt
	_ = updatedAt
	return a, nil
}

const selectAttachmentSQL = `
SELECT a.account_id, a.preview_id, a.operation_id, a.idempotency_key,
       a.request_id, a.correlation_id, a.request_hash, a.owner_device_id, a.owner_session_id, a.host_id,
       a.edge_node_id, a.machine_identity_public_key, a.machine_identity_thumbprint,
       a.carrier_kind, a.lease_generation, a.tunnel_id, a.connector_id,
       a.connector_session_id, a.process_generation, a.config_generation,
       a.config_content_hash, a.route_id, a.route_generation,
	       a.edge_endpoints, a.edge_process_epoch, a.edge_carrier_server_spki_sha256, a.edge_carrier_server_certificate_chain_pem, a.attachment_generation, a.state, a.edge_ready,
       a.origin_ready, a.issued_at, a.expires_at, a.ready_at, a.released_at,
       a.created_at, a.updated_at,
       p.endpoint, p.target_scheme, p.target_address, p.access_mode
FROM preview_lease_carrier_attachments AS a
JOIN preview_leases AS p ON p.id = a.preview_id AND p.account_id = a.account_id
WHERE a.account_id = $1 AND a.operation_id = $2`

const insertAttachmentSQL = `
INSERT INTO preview_lease_carrier_attachments (
  account_id, preview_id, operation_id, idempotency_key, request_id, correlation_id, request_hash,
  owner_device_id, owner_session_id, host_id, edge_node_id, machine_identity_public_key, machine_identity_thumbprint,
  carrier_kind, lease_generation,
  tunnel_id, connector_id, connector_session_id, process_generation,
  config_generation, config_content_hash, route_id, route_generation,
	  edge_endpoints, edge_process_epoch, edge_carrier_server_spki_sha256, edge_carrier_server_certificate_chain_pem, attachment_generation, state, edge_ready, origin_ready,
	  issued_at, expires_at, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'preview_ephemeral',$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,1,'pending',false,false,$27,$28,$29,$30)
ON CONFLICT DO NOTHING`

const admitAttachmentSQL = `
UPDATE preview_lease_carrier_attachments
SET state = 'admitted', edge_ready = false, attachment_generation = attachment_generation + 1,
    ready_at = NULL, updated_at = $19
WHERE account_id = $1 AND operation_id = $2 AND state = 'pending'
  AND attachment_generation = $3 AND preview_id = $4 AND owner_device_id = $5
  AND owner_session_id = $6 AND host_id = $7 AND edge_node_id = $8
  AND machine_identity_public_key = $9 AND machine_identity_thumbprint = $10
  AND lease_generation = $11 AND tunnel_id = $12 AND connector_id = $13
  AND connector_session_id = $14 AND process_generation = $15
  AND config_generation = $16 AND route_id = $17
  AND route_generation = $18 AND expires_at > $19
  AND edge_process_epoch = $20
  AND edge_carrier_server_spki_sha256 = $21
  AND edge_carrier_server_certificate_chain_pem = $22`

const observeEdgeAttachmentSQL = `
UPDATE preview_lease_carrier_attachments
SET edge_ready = true, origin_ready = false, state = 'edge_ready',
    ready_at = NULL, attachment_generation = attachment_generation + 1, updated_at = $19
WHERE account_id = $1 AND operation_id = $2 AND state = 'admitted'
  AND attachment_generation = $3 AND preview_id = $4 AND owner_device_id = $5
  AND owner_session_id = $6 AND host_id = $7 AND edge_node_id = $8
  AND machine_identity_public_key = $9 AND machine_identity_thumbprint = $10
  AND lease_generation = $11 AND tunnel_id = $12 AND connector_id = $13
  AND connector_session_id = $14 AND process_generation = $15
  AND config_generation = $16 AND route_id = $17
  AND route_generation = $18 AND expires_at > $19
  AND edge_process_epoch = $20
  AND edge_carrier_server_spki_sha256 = $21
  AND edge_carrier_server_certificate_chain_pem = $22`

const observeOriginAttachmentSQL = `
UPDATE preview_lease_carrier_attachments
SET origin_ready = $19,
    state = CASE WHEN $19 THEN 'ready' ELSE 'edge_ready' END,
    ready_at = CASE WHEN $19 THEN $20 ELSE NULL END,
    attachment_generation = attachment_generation + 1, updated_at = $20
WHERE account_id = $1 AND operation_id = $2 AND state IN ('edge_ready','ready')
  AND edge_ready AND attachment_generation = $3 AND preview_id = $4
  AND owner_device_id = $5 AND owner_session_id = $6 AND host_id = $7
  AND edge_node_id = $8 AND machine_identity_public_key = $9
  AND machine_identity_thumbprint = $10 AND lease_generation = $11
  AND tunnel_id = $12 AND connector_id = $13 AND connector_session_id = $14
  AND process_generation = $15 AND config_generation = $16
  AND route_id = $17 AND route_generation = $18
  AND expires_at > $20 AND edge_process_epoch = $21
  AND edge_carrier_server_spki_sha256 = $22
  AND edge_carrier_server_certificate_chain_pem = $23`

const renewAttachmentSQL = `
UPDATE preview_lease_carrier_attachments
SET lease_generation = $19, connector_session_id = $20, process_generation = $21,
    config_generation = $22, config_content_hash = $23, edge_endpoints = $24,
    edge_node_id = $25, machine_identity_public_key = $26, machine_identity_thumbprint = $27,
	    edge_process_epoch = $30, attachment_generation = attachment_generation + 1,
	    edge_carrier_server_spki_sha256 = $32, edge_carrier_server_certificate_chain_pem = $33,
	    edge_ready = CASE WHEN connector_session_id = $20 AND process_generation = $21 AND config_generation = $22 AND config_content_hash = $23 AND edge_node_id = $25 AND edge_process_epoch = $30 AND edge_carrier_server_spki_sha256 = $32 AND edge_carrier_server_certificate_chain_pem = $33 AND machine_identity_public_key = $26 AND machine_identity_thumbprint = $27 THEN edge_ready ELSE false END,
	    origin_ready = CASE WHEN connector_session_id = $20 AND process_generation = $21 AND config_generation = $22 AND config_content_hash = $23 AND edge_node_id = $25 AND edge_process_epoch = $30 AND edge_carrier_server_spki_sha256 = $32 AND edge_carrier_server_certificate_chain_pem = $33 AND machine_identity_public_key = $26 AND machine_identity_thumbprint = $27 THEN origin_ready ELSE false END,
	    state = CASE WHEN connector_session_id = $20 AND process_generation = $21 AND config_generation = $22 AND config_content_hash = $23 AND edge_node_id = $25 AND edge_process_epoch = $30 AND edge_carrier_server_spki_sha256 = $32 AND edge_carrier_server_certificate_chain_pem = $33 AND machine_identity_public_key = $26 AND machine_identity_thumbprint = $27 THEN state ELSE 'pending' END,
	    ready_at = CASE WHEN connector_session_id = $20 AND process_generation = $21 AND config_generation = $22 AND config_content_hash = $23 AND edge_node_id = $25 AND edge_process_epoch = $30 AND edge_carrier_server_spki_sha256 = $32 AND edge_carrier_server_certificate_chain_pem = $33 AND machine_identity_public_key = $26 AND machine_identity_thumbprint = $27 THEN ready_at ELSE NULL END,
    expires_at = $28, updated_at = $29
WHERE account_id = $1 AND operation_id = $2 AND state NOT IN ('failed','released')
  AND attachment_generation = $3 AND preview_id = $4 AND owner_device_id = $5
  AND owner_session_id = $6 AND host_id = $7
  AND edge_node_id = $8 AND machine_identity_public_key = $9
  AND machine_identity_thumbprint = $10 AND tunnel_id = $11 AND connector_id = $12
  AND route_id = $13 AND route_generation = $14
  AND lease_generation = $15 AND connector_session_id = $16
	AND process_generation = $17 AND config_generation = $18
	AND expires_at > $29 AND edge_process_epoch = $31
	AND edge_carrier_server_spki_sha256 = $34
	AND edge_carrier_server_certificate_chain_pem = $35`

const releaseAttachmentSQL = `
UPDATE preview_lease_carrier_attachments
SET state = 'released', edge_ready = false, origin_ready = false,
    ready_at = NULL, released_at = $19, expires_at = $19,
    attachment_generation = attachment_generation + 1, updated_at = $19
WHERE account_id = $1 AND operation_id = $2 AND state NOT IN ('failed','released')
  AND attachment_generation = $3 AND preview_id = $4 AND owner_device_id = $5
  AND owner_session_id = $6 AND host_id = $7 AND edge_node_id = $8
  AND machine_identity_public_key = $9 AND machine_identity_thumbprint = $10
  AND lease_generation = $11 AND tunnel_id = $12 AND connector_id = $13
	AND connector_session_id = $14 AND process_generation = $15
	AND config_generation = $16 AND route_id = $17 AND route_generation = $18
	AND edge_process_epoch = $20
	AND edge_carrier_server_spki_sha256 = $21
	AND edge_carrier_server_certificate_chain_pem = $22`

const enqueueDetachOutboxSQL = `
INSERT INTO preview_carrier_attachment_outbox (
  account_id, operation_id, attachment_generation, action, binding,
  config_content_hash, edge_endpoints, endpoint, access_mode, expires_at, created_at, updated_at
) VALUES ($1,$2,$3,'detach',$4::jsonb,$5,$6,$7,$8,$9,$10,$10)
ON CONFLICT (account_id, operation_id, attachment_generation, action) DO NOTHING`

const expireAttachmentSQL = `
WITH changed AS (
  UPDATE preview_lease_carrier_attachments
  SET state = 'failed', edge_ready = false, origin_ready = false, ready_at = NULL,
      attachment_generation = attachment_generation + 1, updated_at = $1
  WHERE state NOT IN ('failed','released') AND expires_at <= $1
	  RETURNING account_id, preview_id, operation_id, attachment_generation, config_content_hash,
	            edge_endpoints, edge_node_id, edge_process_epoch, edge_carrier_server_spki_sha256, edge_carrier_server_certificate_chain_pem, tunnel_id, connector_id,
	            connector_session_id, process_generation, config_generation, route_id,
	            route_generation, machine_identity_public_key, machine_identity_thumbprint,
            owner_device_id, owner_session_id, lease_generation
)
INSERT INTO preview_carrier_attachment_outbox (
  account_id, operation_id, attachment_generation, action, binding,
  config_content_hash, edge_endpoints, endpoint, access_mode, expires_at, created_at, updated_at
)
SELECT changed.account_id, changed.operation_id, changed.attachment_generation, 'detach',
       jsonb_build_object(
		 'account_id', changed.account_id, 'preview_id', changed.preview_id,
         'operation_id', changed.operation_id, 'owner_device_id', changed.owner_device_id,
         'owner_session_id', changed.owner_session_id, 'host_id', changed.owner_device_id,
	         'lease_generation', changed.lease_generation, 'tunnel_id', changed.tunnel_id,
         'connector_id', changed.connector_id, 'session_id', changed.connector_session_id,
         'process_generation', changed.process_generation, 'config_generation', changed.config_generation,
	         'route_id', changed.route_id, 'route_generation', changed.route_generation,
	         'edge_node_id', changed.edge_node_id,
	         'edge_process_epoch', changed.edge_process_epoch,
	         'edge_carrier_server_spki_sha256', changed.edge_carrier_server_spki_sha256,
	         'edge_carrier_server_certificate_chain_pem', changed.edge_carrier_server_certificate_chain_pem,
         'machine_identity_public_key', changed.machine_identity_public_key,
         'machine_identity_thumbprint', changed.machine_identity_thumbprint
       ), changed.config_content_hash, changed.edge_endpoints, lease.endpoint,
       lease.access_mode, lease.lease_deadline, $1, $1
FROM changed
JOIN preview_leases AS lease
  ON lease.id = changed.preview_id
 AND lease.account_id = changed.account_id
ON CONFLICT DO NOTHING`

const prepareAdmissionOutboxSQL = `
INSERT INTO preview_carrier_attachment_outbox (
  account_id, operation_id, attachment_generation, action, binding,
  config_content_hash, edge_endpoints, endpoint, access_mode, expires_at, created_at, updated_at
) VALUES ($1,$2,$3,'admit',$4::jsonb,$5,$6,$7,$8,$9,$10,$10)
ON CONFLICT (account_id, operation_id, attachment_generation, action) DO NOTHING`
