package previewattachment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// PreviewCarrierOutboxItem is the safe, replayable edge work item. It is
// intentionally a metadata-only projection. The edge obtains machine mTLS
// identity through its existing endpoint identity flow, never from this row.
type PreviewCarrierOutboxItem struct {
	AccountID            string    `json:"account_id"`
	OperationID          string    `json:"operation_id"`
	AttachmentGeneration uint64    `json:"attachment_generation"`
	Action               string    `json:"action"`
	Binding              Binding   `json:"binding"`
	AccessMode           string    `json:"access_mode"`
	ConfigContentHash    string    `json:"config_content_hash"`
	EdgeEndpoints        []string  `json:"edge_endpoints"`
	Endpoint             string    `json:"endpoint"`
	ExpiresAt            time.Time `json:"expires_at"`
	State                string    `json:"state"`
	Attempts             int       `json:"attempts"`
	NextAttemptAt        time.Time `json:"next_attempt_at"`
}

func (i PreviewCarrierOutboxItem) validate(now time.Time, nodeID string, processEpochs ...string) error {
	if !validID(i.AccountID) || !validID(i.OperationID) || i.AttachmentGeneration == 0 || i.Action != "admit" && i.Action != "detach" {
		return fmt.Errorf("%w: invalid preview carrier outbox item", ErrInvalid)
	}
	if i.Binding.AccountID != i.AccountID || i.Binding.OperationID != i.OperationID || i.Binding.EdgeNodeID != nodeID {
		return fmt.Errorf("%w: outbox item is scoped to another edge node", ErrUnauthorized)
	}
	if len(processEpochs) > 0 && (connectorprotocol.ValidateOpaqueEpoch(processEpochs[0]) != nil || i.Binding.EdgeProcessEpoch != processEpochs[0]) {
		return fmt.Errorf("%w: outbox item is scoped to another edge process", ErrUnauthorized)
	}
	if err := i.Binding.validate(); err != nil {
		return err
	}
	if err := validateAccessModeAndRoute(i.AccessMode, ""); err != nil {
		return err
	}
	if !validContentHash(i.ConfigContentHash) {
		return fmt.Errorf("%w: invalid outbox config hash", ErrInvalid)
	}
	if err := validateEdgeEndpoints(i.EdgeEndpoints); err != nil {
		return err
	}
	if err := validateEndpoint(i.Endpoint); err != nil {
		return err
	}
	if i.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: outbox expiry is required", ErrInvalid)
	}
	if i.Action == "admit" && !now.IsZero() && !i.ExpiresAt.After(now) {
		return ErrExpired
	}
	return nil
}

// PreviewCarrierOutbox is the edge delivery boundary. Pull claims work for a
// short lease and acknowledgement is idempotent. A lost response leaves the
// item in-flight until maintenance requeues it.
type PreviewCarrierOutbox interface {
	// PullPreviewCarrierSnapshot is a complete desired-state read.  It has no
	// caller supplied page size: returning a partial set would make an edge
	// reconcile remove unrelated last-known-good routes.
	PullPreviewCarrierSnapshot(context.Context, string, string) ([]PreviewCarrierOutboxItem, error)
	PullPreviewCarrierDetachOutbox(context.Context, string, string) ([]PreviewCarrierOutboxItem, error)
	AcknowledgePreviewCarrierOutbox(context.Context, string, string, string, string, uint64, string) error
}

// OutboxAdmissionPublisher is the default server publisher. It records the
// desired admission before returning and reports retryable until the edge has
// actually pulled, installed, and acknowledged it. This deliberately keeps
// the attachment pending and prevents a durable queue write from being
// mistaken for edge readiness or even edge admission.
type OutboxAdmissionPublisher struct {
	repository *SQLRepository
}

func NewOutboxAdmissionPublisher(repository *SQLRepository) (*OutboxAdmissionPublisher, error) {
	if repository == nil {
		return nil, fmt.Errorf("%w: nil preview carrier repository", ErrInvalid)
	}
	return &OutboxAdmissionPublisher{repository: repository}, nil
}

func (p *OutboxAdmissionPublisher) PublishPreviewCarrierAdmission(ctx context.Context, request AdmissionRequest) (AdmissionDelivery, error) {
	if p == nil || p.repository == nil || ctx == nil {
		return AdmissionDelivery{}, fmt.Errorf("%w: outbox publisher is not available", ErrInvalid)
	}
	if err := request.Validate(p.repository.clock()); err != nil {
		return AdmissionDelivery{}, err
	}
	var state string
	err := p.repository.db.Pool().QueryRow(ctx, previewCarrierOutboxStateSQL,
		request.Binding.AccountID, request.OperationID, request.AttachmentGeneration).Scan(&state)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AdmissionDelivery{Status: AdmissionRetry, Code: "admission_not_queued"}, nil
		}
		return AdmissionDelivery{}, err
	}
	if state == "delivered" {
		return AdmissionDelivery{Status: AdmissionAlready, Code: "edge_acknowledged"}, nil
	}
	return AdmissionDelivery{Status: AdmissionRetry, Code: "queued_waiting_for_edge_ack"}, nil
}

// PullPreviewCarrierSnapshot returns the complete desired admission set for a
// node. It is read from live attachment rows rather than outbox rows so an
// edge restart can recover an already-admitted route even after its ACK was
// lost. The method rejects a partial bounded result instead of allowing an
// edge to clear routes based on an incomplete snapshot.
const maxPreviewCarrierAdmissions = 4096

func (s *SQLRepository) PullPreviewCarrierSnapshot(ctx context.Context, nodeID, processEpoch string) ([]PreviewCarrierOutboxItem, error) {
	if s == nil || s.db == nil || ctx == nil || !validID(nodeID) || connectorprotocol.ValidateOpaqueEpoch(processEpoch) != nil {
		return nil, fmt.Errorf("%w: invalid preview carrier snapshot pull", ErrInvalid)
	}
	now := s.clock()
	type snapshotKey struct {
		accountID, operationID string
		commandGeneration      uint64
	}
	var keys []snapshotKey
	var items []PreviewCarrierOutboxItem
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := assertPreviewEdgeProcessEpochTx(ctx, tx, nodeID, processEpoch, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, pullPreviewCarrierSnapshotSQL, nodeID, now.UTC(), maxPreviewCarrierAdmissions+1, processEpoch)
		if err != nil {
			return err
		}
		for rows.Next() {
			var key snapshotKey
			if err := rows.Scan(&key.accountID, &key.operationID, &key.commandGeneration); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, key)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(keys) > maxPreviewCarrierAdmissions {
			return fmt.Errorf("%w: preview carrier snapshot exceeds maximum", ErrConflict)
		}
		snapshot := make([]PreviewCarrierOutboxItem, 0, len(keys))
		for _, key := range keys {
			attachment, err := scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, key.accountID, key.operationID))
			if err != nil {
				return translateRepositoryRowError(err)
			}
			item := PreviewCarrierOutboxItem{
				AccountID: attachment.AccountID, OperationID: attachment.OperationID,
				AttachmentGeneration: key.commandGeneration, Action: "admit",
				Binding: attachment.Binding, AccessMode: attachment.AccessMode, ConfigContentHash: attachment.ConfigContentHash,
				EdgeEndpoints: append([]string(nil), attachment.EdgeEndpoints...), Endpoint: attachment.Endpoint,
				ExpiresAt: attachment.ExpiresAt, State: attachment.State,
			}
			if err := item.validate(now, nodeID, processEpoch); err != nil {
				return err
			}
			snapshot = append(snapshot, item)
		}
		// Assign only after all rows have validated, keeping the transaction's
		// result atomic from the caller's perspective.
		items = snapshot
		return nil
	})
	if err != nil {
		return nil, err
	}
	if items == nil {
		items = []PreviewCarrierOutboxItem{}
	}
	return items, nil
}

// PullPreviewCarrierDetachOutbox claims only detach commands. Admission
// snapshots are intentionally sourced from live rows; this method exists so
// an edge can process explicit cleanup while preserving the durable outbox.
func (s *SQLRepository) PullPreviewCarrierDetachOutbox(ctx context.Context, nodeID, processEpoch string) ([]PreviewCarrierOutboxItem, error) {
	if s == nil || s.db == nil || ctx == nil || !validID(nodeID) || connectorprotocol.ValidateOpaqueEpoch(processEpoch) != nil {
		return nil, fmt.Errorf("%w: invalid preview carrier detach pull", ErrInvalid)
	}
	now := s.clock()
	var items []PreviewCarrierOutboxItem
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := assertPreviewEdgeProcessEpochTx(ctx, tx, nodeID, processEpoch, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, pullPreviewCarrierDetachOutboxSQL, nodeID, now.UTC(), maxPreviewCarrierAdmissions+1, processEpoch)
		if err != nil {
			return err
		}
		pending := make([]PreviewCarrierOutboxItem, 0, maxPreviewCarrierAdmissions)
		for rows.Next() {
			item, err := scanPreviewCarrierOutbox(rows)
			if err != nil {
				rows.Close()
				return err
			}
			if err := item.validate(now, nodeID, processEpoch); err != nil {
				rows.Close()
				return err
			}
			pending = append(pending, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(pending) > maxPreviewCarrierAdmissions {
			return fmt.Errorf("%w: preview carrier detachments exceed maximum", ErrConflict)
		}
		for _, item := range pending {
			command, err := tx.Exec(ctx, claimPreviewCarrierOutboxSQL,
				nodeID, item.AccountID, item.OperationID, item.AttachmentGeneration, item.Action, now.UTC(), processEpoch)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return fmt.Errorf("%w: detach outbox claim raced", ErrStaleBinding)
			}
			item.State = "in_flight"
			item.Attempts++
			items = append(items, item)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if items == nil {
		items = []PreviewCarrierOutboxItem{}
	}
	return items, nil
}

// AcknowledgePreviewCarrierOutbox completes a claimed edge admission or
// detach. It accepts an already-delivered row so an edge retry after a lost
// response is a successful no-op.
func (s *SQLRepository) AcknowledgePreviewCarrierOutbox(ctx context.Context, nodeID, processEpoch, accountID, operationID string, generation uint64, action string) error {
	if s == nil || s.db == nil || ctx == nil || !validID(nodeID) || connectorprotocol.ValidateOpaqueEpoch(processEpoch) != nil || !validID(accountID) || !validID(operationID) || generation == 0 || action != "admit" && action != "detach" {
		return fmt.Errorf("%w: invalid preview carrier outbox acknowledgement", ErrInvalid)
	}
	now := s.clock()
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := assertPreviewEdgeProcessEpochTx(ctx, tx, nodeID, processEpoch, now); err != nil {
			return err
		}
		if action == "admit" {
			return s.acknowledgeAdmissionTx(ctx, tx, nodeID, processEpoch, accountID, operationID, generation, now)
		}
		command, err := tx.Exec(ctx, acknowledgePreviewCarrierOutboxSQL,
			nodeID, accountID, operationID, generation, action, now.UTC(), processEpoch)
		if err != nil {
			return err
		}
		if command.RowsAffected() == 1 {
			return nil
		}
		var delivered bool
		if err := tx.QueryRow(ctx, deliveredPreviewCarrierOutboxSQL,
			nodeID, accountID, operationID, generation, action, processEpoch).Scan(&delivered); err != nil {
			return err
		}
		if delivered {
			return nil
		}
		return ErrNotFound
	})
}

func (s *SQLRepository) acknowledgeAdmissionTx(ctx context.Context, tx *db.Tx, nodeID, processEpoch, requestedAccountID, operationID string, generation uint64, now time.Time) error {
	var (
		storedAccountID, storedOperationID, action, state string
		storedGeneration                                  uint64
		bindingJSON                                       []byte
		configHash                                        string
		accessMode                                        string
		endpoints                                         []string
		endpoint                                          string
		expiresAt                                         time.Time
	)
	err := tx.QueryRow(ctx, previewCarrierOutboxForUpdateSQL, nodeID, requestedAccountID, operationID, generation, "admit", processEpoch).Scan(
		&storedAccountID, &storedOperationID, &storedGeneration, &action, &bindingJSON,
		&configHash, &endpoints, &endpoint, &accessMode, &expiresAt, &state,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		var delivered bool
		if scanErr := tx.QueryRow(ctx, deliveredPreviewCarrierOutboxSQL, nodeID, requestedAccountID, operationID, generation, "admit", processEpoch).Scan(&delivered); scanErr != nil {
			return scanErr
		}
		if delivered {
			return nil
		}
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if state == "delivered" {
		return nil
	}
	var binding Binding
	if err := json.Unmarshal(bindingJSON, &binding); err != nil {
		return fmt.Errorf("%w: decode admission binding: %v", ErrInvalid, err)
	}
	item := PreviewCarrierOutboxItem{
		AccountID: storedAccountID, OperationID: storedOperationID, AttachmentGeneration: storedGeneration,
		Action: action, Binding: binding, AccessMode: accessMode, ConfigContentHash: configHash,
		EdgeEndpoints: endpoints, Endpoint: endpoint, ExpiresAt: expiresAt, State: state,
	}
	if err := item.validate(now, nodeID, processEpoch); err != nil && !(state == "delivered" && errors.Is(err, ErrExpired)) {
		return err
	}
	current, err := scanAttachment(tx.QueryRow(ctx, selectAttachmentSQL, storedAccountID, operationID))
	if err != nil {
		return translateRepositoryRowError(err)
	}
	if current.Binding != binding {
		return ErrStaleBinding
	}
	// The edge may retry an ACK after the server has already advanced through
	// edge_ready or ready and the first response was lost. Once the exact
	// binding is still current, any non-pending admission state is a safe
	// idempotent replay. A changed binding or a pending row is rejected below.
	if current.AttachmentGeneration >= generation+1 && (current.State == StateAdmitted || current.State == StateEdgeReady || current.State == StateReady) {
		return markPreviewCarrierOutboxDeliveredTx(ctx, tx, nodeID, processEpoch, storedAccountID, operationID, generation, "admit", now)
	}
	if current.State != StatePending || current.AttachmentGeneration != generation {
		return ErrStaleBinding
	}
	command, err := tx.Exec(ctx, admitAttachmentSQL,
		current.AccountID, current.OperationID, current.AttachmentGeneration,
		current.PreviewID, current.OwnerDeviceID, current.OwnerSessionID,
		current.HostID, current.EdgeNodeID, current.MachineIdentityPublicKey,
		current.MachineIdentityThumbprint, current.LeaseGeneration, current.TunnelID,
		current.ConnectorID, current.SessionID, current.ProcessGeneration,
		current.ConfigGeneration, current.RouteID, current.RouteGeneration, now.UTC(),
		current.EdgeProcessEpoch,
		current.EdgeCarrierServerSPKISHA256, current.EdgeCarrierServerCertificateChainPEM,
	)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrStaleBinding
	}
	return markPreviewCarrierOutboxDeliveredTx(ctx, tx, nodeID, processEpoch, storedAccountID, operationID, generation, "admit", now)
}

func markPreviewCarrierOutboxDeliveredTx(ctx context.Context, tx *db.Tx, nodeID, processEpoch, accountID, operationID string, generation uint64, action string, now time.Time) error {
	command, err := tx.Exec(ctx, acknowledgePreviewCarrierOutboxSQL,
		nodeID, accountID, operationID, generation, action, now.UTC(), processEpoch)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 1 {
		return nil
	}
	var delivered bool
	if err := tx.QueryRow(ctx, deliveredPreviewCarrierOutboxSQL, nodeID, accountID, operationID, generation, action, processEpoch).Scan(&delivered); err != nil {
		return err
	}
	if delivered {
		return nil
	}
	return ErrNotFound
}

// RequeuePreviewCarrierOutbox releases claims whose edge response was lost.
// It is safe to run concurrently with pulls because the update is scoped to
// the in-flight claim timeout.
func (s *SQLRepository) RequeuePreviewCarrierOutbox(ctx context.Context, now time.Time) error {
	if s == nil || s.db == nil || ctx == nil {
		return fmt.Errorf("%w: repository is not available", ErrInvalid)
	}
	if now.IsZero() {
		now = s.clock()
	}
	_, err := s.db.Pool().Exec(ctx, requeuePreviewCarrierOutboxSQL, now.UTC())
	return err
}

// OutboxWorker performs only durable maintenance. Edge delivery remains
// pull-based and authenticated by EdgeHTTPHandler, so a server worker never
// marks an admission delivered without an edge acknowledgement.
func (s *SQLRepository) OutboxWorker(interval time.Duration) func(context.Context) error {
	if interval <= 0 {
		interval = time.Second
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			now := s.clock()
			if err := s.Expire(ctx, now); err != nil {
				return fmt.Errorf("expire preview carrier attachments: %w", err)
			}
			if err := s.RequeuePreviewCarrierOutbox(ctx, now); err != nil {
				return fmt.Errorf("requeue preview carrier outbox: %w", err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func scanPreviewCarrierOutbox(row interface{ Scan(...any) error }) (PreviewCarrierOutboxItem, error) {
	var (
		item                              PreviewCarrierOutboxItem
		bindingJSON                       []byte
		state                             string
		attempts                          int
		nextAttempt, createdAt, updatedAt time.Time
		deliveredAt                       sql.NullTime
	)
	if err := row.Scan(&item.AccountID, &item.OperationID, &item.AttachmentGeneration, &item.Action,
		&bindingJSON, &item.ConfigContentHash, &item.EdgeEndpoints, &item.Endpoint, &item.AccessMode, &item.ExpiresAt,
		&state, &attempts, &nextAttempt, &createdAt, &updatedAt, &deliveredAt); err != nil {
		return PreviewCarrierOutboxItem{}, err
	}
	item.State = state
	item.Attempts = attempts
	item.NextAttemptAt = nextAttempt
	if err := json.Unmarshal(bindingJSON, &item.Binding); err != nil {
		return PreviewCarrierOutboxItem{}, fmt.Errorf("%w: decode outbox binding: %v", ErrInvalid, err)
	}
	_ = createdAt
	_ = updatedAt
	_ = deliveredAt
	return item, nil
}

// assertPreviewEdgeProcessEpochTx locks the registered edge row for the
// duration of each pull/ack operation. This closes the race where an old edge
// process keeps the shared credential while registration replaces the node's
// process epoch.
func assertPreviewEdgeProcessEpochTx(ctx context.Context, tx *db.Tx, nodeID, processEpoch string, now time.Time) error {
	var currentEpoch string
	var available bool
	if err := tx.QueryRow(ctx, previewEdgeProcessEpochForUpdateSQL, nodeID, now.UTC()).Scan(&currentEpoch, &available); errors.Is(err, pgx.ErrNoRows) {
		return ErrUnauthorized
	} else if err != nil {
		return err
	} else if currentEpoch != processEpoch || !available {
		return ErrUnauthorized
	}
	return nil
}

// pullPreviewCarrierSnapshotSQL deliberately reads live attachment rows. The
// lateral lookup preserves the original admit command generation, which is
// the generation the edge must ACK. Readiness observations may advance the
// attachment generation without changing the route admission; a later
// reconnect/renew that changes the carrier binding creates a new admit row.
// The final LIMIT is only an internal hard safety bound and is always queried
// as maxPreviewCarrierAdmissions+1 so callers never receive a silent prefix.
const pullPreviewCarrierSnapshotSQL = `
SELECT a.account_id, a.operation_id,
       COALESCE(admit.attachment_generation, a.attachment_generation)
FROM preview_lease_carrier_attachments AS a
JOIN preview_leases AS lease
  ON lease.id = a.preview_id AND lease.account_id = a.account_id
LEFT JOIN LATERAL (
  SELECT o.attachment_generation
  FROM preview_carrier_attachment_outbox AS o
  WHERE o.account_id = a.account_id
    AND o.operation_id = a.operation_id
    AND o.action = 'admit'
    AND o.binding->>'account_id' = a.account_id
    AND o.binding->>'preview_id' = a.preview_id
    AND o.binding->>'operation_id' = a.operation_id
    AND o.binding->>'owner_device_id' = a.owner_device_id
    AND o.binding->>'owner_session_id' = a.owner_session_id
    AND o.binding->>'host_id' = a.host_id
    AND o.binding->>'lease_generation' = a.lease_generation::text
    AND o.binding->>'tunnel_id' = a.tunnel_id
    AND o.binding->>'connector_id' = a.connector_id
    AND o.binding->>'session_id' = a.connector_session_id
    AND o.binding->>'process_generation' = a.process_generation::text
    AND o.binding->>'config_generation' = a.config_generation::text
    AND o.binding->>'route_id' = a.route_id
    AND o.binding->>'route_generation' = a.route_generation::text
    AND o.binding->>'edge_node_id' = a.edge_node_id
    AND o.binding->>'edge_process_epoch' = a.edge_process_epoch
    AND o.binding->>'machine_identity_public_key' = a.machine_identity_public_key
    AND o.binding->>'machine_identity_thumbprint' = a.machine_identity_thumbprint
  ORDER BY o.attachment_generation DESC
  LIMIT 1
) AS admit ON true
WHERE a.edge_node_id = $1
  AND a.edge_process_epoch = $4
  AND a.state IN ('pending','admitted','edge_ready','ready')
  AND a.expires_at > $2
  AND lease.terminal_state = 'active'
ORDER BY a.account_id, a.operation_id
LIMIT $3`

const pullPreviewCarrierDetachOutboxSQL = `
SELECT account_id, operation_id, attachment_generation, action, binding,
       config_content_hash, edge_endpoints, endpoint, access_mode, expires_at, state,
       attempts, next_attempt_at, created_at, updated_at, delivered_at
FROM preview_carrier_attachment_outbox
WHERE binding->>'edge_node_id' = $1
  AND binding->>'edge_process_epoch' = $4
  AND action = 'detach'
  AND state IN ('pending','failed')
  AND next_attempt_at <= $2
ORDER BY created_at, account_id, operation_id, attachment_generation
LIMIT $3
FOR UPDATE SKIP LOCKED`

const claimPreviewCarrierOutboxSQL = `
UPDATE preview_carrier_attachment_outbox
SET state = 'in_flight', attempts = attempts + 1,
    next_attempt_at = $6 + interval '30 seconds', updated_at = $6
WHERE binding->>'edge_node_id' = $1
  AND binding->>'edge_process_epoch' = $7
  AND account_id = $2 AND operation_id = $3
  AND attachment_generation = $4 AND action = $5
  AND state IN ('pending','failed')`

const acknowledgePreviewCarrierOutboxSQL = `
UPDATE preview_carrier_attachment_outbox
SET state = 'delivered', delivered_at = $6, updated_at = $6
WHERE binding->>'edge_node_id' = $1
  AND binding->>'edge_process_epoch' = $7
  AND account_id = $2 AND operation_id = $3 AND attachment_generation = $4
  AND action = $5 AND state <> 'delivered'`

const previewCarrierOutboxStateSQL = `
SELECT state
FROM preview_carrier_attachment_outbox
WHERE account_id = $1 AND operation_id = $2
  AND attachment_generation = $3 AND action = 'admit'`

const previewCarrierOutboxForUpdateSQL = `
SELECT account_id, operation_id, attachment_generation, action, binding,
       config_content_hash, edge_endpoints, endpoint, access_mode, expires_at, state
FROM preview_carrier_attachment_outbox
WHERE binding->>'edge_node_id' = $1
  AND binding->>'edge_process_epoch' = $6
  AND account_id = $2 AND operation_id = $3 AND attachment_generation = $4
  AND action = $5
FOR UPDATE`

const deliveredPreviewCarrierOutboxSQL = `
SELECT EXISTS (
  SELECT 1 FROM preview_carrier_attachment_outbox
  WHERE binding->>'edge_node_id' = $1
    AND binding->>'edge_process_epoch' = $6
    AND account_id = $2 AND operation_id = $3 AND attachment_generation = $4
    AND action = $5 AND state = 'delivered'
)`

const requeuePreviewCarrierOutboxSQL = `
UPDATE preview_carrier_attachment_outbox
SET state = 'pending', next_attempt_at = $1::timestamptz, updated_at = $1::timestamptz
WHERE state = 'in_flight' AND updated_at <= $1::timestamptz - interval '30 seconds'`

const previewEdgeProcessEpochForUpdateSQL = `
SELECT process_epoch,
       (((state = 'ready' AND ready) OR state = 'draining')
        AND (last_heartbeat_at IS NULL OR last_heartbeat_at > $2::timestamptz - interval '2 minutes')
        AND (drain_deadline IS NULL OR drain_deadline > $2::timestamptz)) AS available
FROM control_tunnel_nodes
WHERE id = $1
FOR UPDATE`
