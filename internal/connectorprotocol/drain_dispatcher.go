package connectorprotocol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

const (
	defaultDrainReconcileInterval = 5 * time.Second
	defaultDrainDeadline          = 30 * time.Second
	defaultRevokeDeadline         = 10 * time.Second
	defaultDrainSendTimeout       = 5 * time.Second
	defaultDrainOperationLimit    = 64
)

// DrainOperation is the durable, secret-free target of one connector drain or
// revoke. Every field is read from the current connector session and active
// config generation in the same database snapshot as the operation.
type DrainOperation struct {
	OperationID       string
	OperationType     string
	AccountID         string
	TunnelID          string
	ConnectorID       string
	HostID            string
	SessionID         string
	ProcessGeneration uint64
	ConfigGeneration  uint64
	ConfigContentHash string
}

func (o DrainOperation) validate() error {
	if ValidateIdentifier(o.OperationID) != nil || ValidateIdentifier(o.AccountID) != nil || ValidateIdentifier(o.TunnelID) != nil || ValidateIdentifier(o.ConnectorID) != nil || ValidateIdentifier(o.HostID) != nil || ValidateIdentifier(o.SessionID) != nil || o.ProcessGeneration == 0 || o.ConfigGeneration == 0 || !hashPattern.MatchString(o.ConfigContentHash) {
		return ErrInvalidInput
	}
	if o.OperationType != "connector.drain" && o.OperationType != "connector.revoke" {
		return ErrInvalidInput
	}
	return nil
}

// DrainOperationSource is the bounded durable recovery boundary used by the
// dispatcher. SQLControlStore implements it without exposing database models.
type DrainOperationSource interface {
	ListConnectorDrainOperations(context.Context, int) ([]DrainOperation, error)
}

// ListConnectorDrainOperations returns only operations bound to the exact
// current, live connector session and its applied immutable config generation.
// Disconnected operations remain uncertain until a replacement session is
// ready, at which point this query safely rebinds delivery to that session.
func (s *SQLControlStore) ListConnectorDrainOperations(ctx context.Context, limit int) ([]DrainOperation, error) {
	if ctx == nil || s.valid() != nil || limit < 1 || limit > defaultDrainOperationLimit {
		return nil, ErrInvalidInput
	}
	now := s.now()
	result := make([]DrainOperation, 0, limit)
	err := s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT o.id, o.operation_type, o.account_id,
       c.tunnel_id, c.id, c.host_id,
       session.id, session.process_generation,
       session.applied_config_generation, generation.content_hash
FROM operations AS o
JOIN tunnel_connectors AS c
  ON c.id = o.resource_id
JOIN tunnels AS tunnel
  ON tunnel.id = c.tunnel_id AND tunnel.account_id = o.account_id
JOIN tunnel_connector_sessions AS session
  ON session.id = c.last_session_id AND session.connector_id = c.id
JOIN tunnel_config_generations AS generation
  ON generation.tunnel_id = c.tunnel_id
 AND generation.generation = session.applied_config_generation
WHERE o.resource_kind = 'connector'
  AND o.operation_type IN ('connector.drain', 'connector.revoke')
  AND o.state IN ('pending', 'running', 'uncertain')
  AND (o.next_retry_at IS NULL OR o.next_retry_at <= $1)
  AND tunnel.deleted_at IS NULL
  AND session.state IN ('ready', 'draining')
  AND session.lease_deadline > $1
  AND session.applied_config_generation > 0
ORDER BY o.created_at, o.id
LIMIT $2`, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item DrainOperation
			var processGeneration, configGeneration int64
			var contentHash []byte
			if err := rows.Scan(&item.OperationID, &item.OperationType, &item.AccountID, &item.TunnelID, &item.ConnectorID, &item.HostID, &item.SessionID, &processGeneration, &configGeneration, &contentHash); err != nil {
				return err
			}
			if processGeneration <= 0 || configGeneration <= 0 {
				return ErrInvalidInput
			}
			item.ProcessGeneration = uint64(processGeneration)
			item.ConfigGeneration = uint64(configGeneration)
			item.ConfigContentHash, err = drainHash(contentHash)
			if err != nil {
				return err
			}
			if err := item.validate(); err != nil {
				return err
			}
			result = append(result, item)
		}
		return rows.Err()
	})
	return result, err
}

// DrainLiveSession is registered by the control transport after authentication
// and Welcome. The sender must be the transport's bounded serialized writer.
type DrainLiveSession struct {
	Projection             ActiveControlSession
	Session                *PersistentSession
	NegotiatedCapabilities []string
	Send                   RotationFrameSender
}

func (s DrainLiveSession) validate() error {
	if s.Projection.validate() != nil || s.Session == nil || s.Send == nil || s.Session.Reference() != (SessionRef{TunnelID: s.Projection.TunnelID, ConnectorID: s.Projection.ConnectorID, SessionID: s.Projection.SessionID, ProcessGeneration: s.Projection.ProcessGeneration}) {
		return ErrInvalidInput
	}
	return nil
}

type DrainDispatcherConfig struct {
	Store             DrainOperationSource
	Clock             Clock
	ReconcileInterval time.Duration
	DrainDeadline     time.Duration
	RevokeDeadline    time.Duration
	SendTimeout       time.Duration
	OperationLimit    int
	ReportError       func(error)
}

// DrainDispatcher reconciles durable drain/revoke operations onto exact live
// control sessions. It owns no connector or operation state itself.
type DrainDispatcher struct {
	store             DrainOperationSource
	clock             Clock
	reconcileInterval time.Duration
	drainDeadline     time.Duration
	revokeDeadline    time.Duration
	sendTimeout       time.Duration
	operationLimit    int
	reportError       func(error)

	mu       sync.RWMutex
	sessions map[string]DrainLiveSession
}

func NewDrainDispatcher(config DrainDispatcherConfig) (*DrainDispatcher, error) {
	if config.Store == nil || config.ReportError == nil {
		return nil, ErrInvalidInput
	}
	if config.Clock == nil {
		config.Clock = realClock{}
	}
	if config.ReconcileInterval == 0 {
		config.ReconcileInterval = defaultDrainReconcileInterval
	}
	if config.DrainDeadline == 0 {
		config.DrainDeadline = defaultDrainDeadline
	}
	if config.RevokeDeadline == 0 {
		config.RevokeDeadline = defaultRevokeDeadline
	}
	if config.SendTimeout == 0 {
		config.SendTimeout = defaultDrainSendTimeout
	}
	if config.OperationLimit == 0 {
		config.OperationLimit = defaultDrainOperationLimit
	}
	if config.ReconcileInterval <= 0 || config.ReconcileInterval > time.Minute || config.DrainDeadline <= 0 || config.DrainDeadline > MaxLease || config.RevokeDeadline <= 0 || config.RevokeDeadline > config.DrainDeadline || config.SendTimeout <= 0 || config.SendTimeout > time.Minute || config.OperationLimit < 1 || config.OperationLimit > defaultDrainOperationLimit {
		return nil, ErrInvalidInput
	}
	return &DrainDispatcher{
		store: config.Store, clock: config.Clock, reconcileInterval: config.ReconcileInterval,
		drainDeadline: config.DrainDeadline, revokeDeadline: config.RevokeDeadline,
		sendTimeout: config.SendTimeout, operationLimit: config.OperationLimit,
		reportError: config.ReportError, sessions: make(map[string]DrainLiveSession),
	}, nil
}

// RegisterSession replaces only an older process generation. Equal exact
// registration is an idempotent sender refresh; an equal different session or
// a lower process generation is rejected.
func (d *DrainDispatcher) RegisterSession(ctx context.Context, session DrainLiveSession) error {
	if d == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := session.validate(); err != nil {
		return err
	}
	session.NegotiatedCapabilities = append([]string(nil), session.NegotiatedCapabilities...)
	d.mu.Lock()
	defer d.mu.Unlock()
	key := controlSessionKey(session.Projection.TunnelID, session.Projection.ConnectorID)
	if current, ok := d.sessions[key]; ok {
		if current.Projection.AccountID != session.Projection.AccountID || current.Projection.HostID != session.Projection.HostID {
			return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
		}
		if session.Projection.ProcessGeneration < current.Projection.ProcessGeneration || session.Projection.ProcessGeneration == current.Projection.ProcessGeneration && session.Projection.SessionID != current.Projection.SessionID {
			return codeError(ErrSessionConflict, ReasonStaleGeneration, false, nil)
		}
	}
	d.sessions[key] = session
	return nil
}

// DetachSession is exact-match and cannot remove a replacement process.
func (d *DrainDispatcher) DetachSession(ref SessionRef) {
	if d == nil || ref.Validate() != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key := controlSessionKey(ref.TunnelID, ref.ConnectorID)
	current, ok := d.sessions[key]
	if ok && current.Session.Reference() == ref {
		delete(d.sessions, key)
	}
}

func (d *DrainDispatcher) session(operation DrainOperation) (DrainLiveSession, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	current, ok := d.sessions[controlSessionKey(operation.TunnelID, operation.ConnectorID)]
	if !ok || current.Projection.AccountID != operation.AccountID || current.Projection.HostID != operation.HostID || current.Session.Reference() != (SessionRef{TunnelID: operation.TunnelID, ConnectorID: operation.ConnectorID, SessionID: operation.SessionID, ProcessGeneration: operation.ProcessGeneration}) {
		return DrainLiveSession{}, false
	}
	return current, true
}

func (d *DrainDispatcher) ReconcileOnce(ctx context.Context) error {
	if d == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	operations, err := d.store.ListConnectorDrainOperations(ctx, d.operationLimit)
	if err != nil {
		return err
	}
	var joined error
	for _, operation := range operations {
		if err := operation.validate(); err != nil {
			joined = errors.Join(joined, err)
			continue
		}
		live, ok := d.session(operation)
		if !ok || !hasCapability(live.NegotiatedCapabilities, CapabilityDrain) {
			continue
		}
		force := operation.OperationType == "connector.revoke"
		drain, _, _ := live.Session.session.Drain()
		if drain.DrainID == "" {
			current, ready, generation := live.Session.Current()
			if !ready || generation != operation.ConfigGeneration || current.Generation != operation.ConfigGeneration || current.ContentHash != operation.ConfigContentHash {
				continue
			}
			deadline := d.clock.Now().UTC().Add(d.drainDeadline)
			if force {
				deadline = d.clock.Now().UTC().Add(d.revokeDeadline)
			}
			var beginErr error
			drain, beginErr = live.Session.BeginDrain(ctx, operation.OperationID, deadline, force)
			if beginErr != nil {
				joined = errors.Join(joined, beginErr)
				continue
			}
		}
		if drain.AccountID != operation.AccountID || drain.TunnelID != operation.TunnelID || drain.ConnectorID != operation.ConnectorID || drain.SessionID != operation.SessionID || drain.ProcessGeneration != operation.ProcessGeneration || drain.DrainID != operation.OperationID || drain.Generation != operation.ConfigGeneration || drain.ContentHash != operation.ConfigContentHash || drain.ForceAfterDeadline != force {
			joined = errors.Join(joined, codeError(ErrSessionConflict, ReasonStaleGeneration, false, nil))
			continue
		}
		frame, frameErr := NewFrame(MessageDrain, operation.OperationID, drain)
		if frameErr != nil {
			joined = errors.Join(joined, frameErr)
			continue
		}
		sendCtx, cancel := context.WithTimeout(ctx, d.sendTimeout)
		sendErr := live.Send(sendCtx, frame)
		cancel()
		if sendErr != nil {
			joined = errors.Join(joined, sendErr)
		}
	}
	return joined
}

func (d *DrainDispatcher) Run(ctx context.Context) error {
	if d == nil || ctx == nil {
		return ErrInvalidInput
	}
	attempt := 0
	for {
		err := d.ReconcileOnce(ctx)
		delay := d.reconcileInterval
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			d.reportError(err)
			attempt++
			delay = drainRetryDelay(delay, attempt)
		} else {
			attempt = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func drainRetryDelay(base time.Duration, attempt int) time.Duration {
	capDelay := base
	for index := 1; index < attempt && capDelay < time.Minute; index++ {
		capDelay *= 2
		if capDelay > time.Minute {
			capDelay = time.Minute
		}
	}
	if capDelay <= 1 {
		return capDelay
	}
	return time.Duration(rand.Int64N(int64(capDelay) + 1))
}

func drainHash(raw []byte) (string, error) {
	if len(raw) != sha256.Size {
		return "", ErrConfigHashCorrupt
	}
	return "sha256:" + hex.EncodeToString(raw), nil
}
