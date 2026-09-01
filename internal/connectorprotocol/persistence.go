package connectorprotocol

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	servertelemetry "github.com/pinksaucepasta/paperboat-server/internal/telemetry"
)

// PersistentControlStore is the server adapter boundary for migration 122's
// connector, connector-session, and config-generation records. Implementations
// own database transactions and secret custody. The protocol passes only
// metadata and detached proofs, never bearer or private credential bytes.
//
// AuthenticateConnector and RenewConnector must perform durable nonce replay
// protection in the same transaction as the authorization decision. A process
// local replay cache is deliberately not part of this contract: it cannot
// protect a second server replica or a process restart.
type PersistentControlStore interface {
	AuthenticateConnector(context.Context, AuthRequest) (AuthResult, error)
	RenewConnector(context.Context, RenewalRequest) (AuthResult, error)
	Snapshot(context.Context, string) (Snapshot, error)
	CreateConnectorSession(context.Context, SessionRef, Lease, uint64) error
	RecordApplied(context.Context, SessionRef, Ack) error
	RecordReady(context.Context, SessionRef, Readiness) error
	RecordHeartbeat(context.Context, SessionRef, Heartbeat, HeartbeatAck) error
	RecordRenewal(context.Context, SessionRef, AuthResult) error
	RecordDisconnected(context.Context, SessionRef, Disconnect) error
}

// PersistentDrainStore is required by NewPersistentServer. Drain transitions
// change admission eligibility and therefore cannot silently fall back to
// process-local state. Keeping the lifecycle separate lets TRK-07's operation
// repository add its own operation/audit event in the same transaction without
// widening the wire package's core store contract.
type PersistentDrainStore interface {
	RecordDrain(context.Context, SessionRef, Drain, DrainStatus, uint32, Code) error
}

// PersistentSessionMetadataStore lets the SQL adapter persist the negotiated
// version and capabilities without putting those fields into the smaller
// legacy-shaped CreateConnectorSession method.
type PersistentSessionMetadataStore interface {
	CreateConnectorSessionV1(context.Context, SessionRef, Welcome, uint64) error
}

// RotationPlanSource is the restart/reconciliation boundary. Implementations
// return plans reconstructed from immutable target rows, not from a fresh
// connector listing.
type RotationPlanSource interface {
	ListCredentialRotationPlans(context.Context, int) ([]RotationPlan, error)
}

// IdentityProofVerifier resolves the enrolled public key using the request's
// account/tunnel/connector/host/key identity and verifies the exact transcript
// supplied by this package. A verifier must do its lookup against durable
// enrollment state; a single global callback is unsafe for a multi-host server.
type IdentityProofVerifier interface {
	VerifyAuthProof(context.Context, AuthRequest, []byte, []byte) error
	VerifyRenewalProof(context.Context, RenewalRequest, []byte, []byte) error
}

// IdentityProofVerifierFuncs is convenient for tests and for an adapter that
// delegates key lookup to an existing identity service.
type IdentityProofVerifierFuncs struct {
	AuthFunc    func(context.Context, AuthRequest, []byte, []byte) error
	RenewalFunc func(context.Context, RenewalRequest, []byte, []byte) error
}

func (f IdentityProofVerifierFuncs) VerifyAuthProof(ctx context.Context, request AuthRequest, payload, signature []byte) error {
	if f.AuthFunc == nil {
		return errors.New("authentication proof verifier is not configured")
	}
	return f.AuthFunc(ctx, request, payload, signature)
}

func (f IdentityProofVerifierFuncs) VerifyRenewalProof(ctx context.Context, request RenewalRequest, payload, signature []byte) error {
	if f.RenewalFunc == nil {
		return errors.New("renewal proof verifier is not configured")
	}
	return f.RenewalFunc(ctx, request, payload, signature)
}

type PersistentAuthenticator struct {
	Store    PersistentControlStore
	Verifier IdentityProofVerifier
	Clock    Clock
}

func (a PersistentAuthenticator) now() time.Time {
	if a.Clock == nil {
		return time.Now().UTC()
	}
	return a.Clock.Now().UTC()
}

func (a PersistentAuthenticator) Authenticate(ctx context.Context, request AuthRequest) (AuthResult, error) {
	if ctx == nil || a.Store == nil || a.Verifier == nil {
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, errors.New("persistent authenticator is incomplete"))
	}
	now := a.now()
	if err := request.Validate(now); err != nil {
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	payload, err := AuthProofPayload(request)
	if err != nil {
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	signature, err := DecodeProof(request.SignedProof)
	if err != nil {
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	if err := a.Verifier.VerifyAuthProof(ctx, request, payload, signature); err != nil {
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	// The store performs the durable nonce reservation atomically with its
	// connector/credential authorization. It must reject a replay even after a
	// process restart or on another server replica.
	result, err := a.Store.AuthenticateConnector(ctx, request)
	if err != nil {
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	if err := result.Validate(now); err != nil || !sameAuthIdentity(request, result) {
		if err == nil {
			err = ErrIdentityMismatch
		}
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	return result, nil
}

func (a PersistentAuthenticator) Renew(ctx context.Context, request RenewalRequest) (AuthResult, error) {
	if ctx == nil || a.Store == nil || a.Verifier == nil {
		return AuthResult{}, codeError(ErrCredentialExpired, ReasonCredentialExpired, true, errors.New("persistent authenticator is incomplete"))
	}
	now := a.now()
	// Freshness is part of the server-side acceptance rule. Validate() alone is
	// insufficient because a signed renewal can otherwise be replayed after a
	// process restart when the in-memory nonce map is gone.
	if err := request.ValidateAt(now); err != nil {
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	payload, err := RenewalProofPayload(request)
	if err != nil {
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	signature, err := DecodeProof(request.SignedProof)
	if err != nil {
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	if err := a.Verifier.VerifyRenewalProof(ctx, request, payload, signature); err != nil {
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	result, err := a.Store.RenewConnector(ctx, request)
	if err != nil {
		return AuthResult{}, codeError(ErrCredentialExpired, ReasonCredentialExpired, true, err)
	}
	if err := result.Validate(now); err != nil || result.AccountID != request.AccountID || result.TunnelID != request.TunnelID || result.ConnectorID != request.ConnectorID || result.HostID != request.HostID || result.IdentityKeyID != request.IdentityKeyID || result.IdentityKeyThumbprint != request.IdentityKeyThumbprint || result.ProcessGeneration != request.ProcessGeneration || result.CredentialGeneration < request.CredentialGeneration {
		if err == nil {
			err = ErrIdentityMismatch
		}
		return AuthResult{}, codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
	}
	return result, nil
}

func sameAuthIdentity(request AuthRequest, result AuthResult) bool {
	return request.AccountID == result.AccountID && request.TunnelID == result.TunnelID && request.ConnectorID == result.ConnectorID && request.HostID == result.HostID && request.IdentityKeyID == result.IdentityKeyID && request.IdentityKeyThumbprint == result.IdentityKeyThumbprint && request.ProcessGeneration == result.ProcessGeneration && result.CredentialGeneration >= request.CredentialGeneration
}

type PersistentSnapshotSource struct {
	Store PersistentControlStore
}

func (s PersistentSnapshotSource) Snapshot(ctx context.Context, tunnelID string) (Snapshot, error) {
	if ctx == nil || s.Store == nil {
		return Snapshot{}, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, true, errors.New("persistent snapshot store is not configured"))
	}
	snapshot, err := s.Store.Snapshot(ctx, tunnelID)
	if err != nil {
		return Snapshot{}, err
	}
	if err := snapshot.Validate(); err != nil || snapshot.TunnelID != tunnelID {
		if err == nil {
			err = ErrIdentityMismatch
		}
		return Snapshot{}, codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, err)
	}
	return snapshot, nil
}

type PersistentServer struct {
	server      *Server
	store       PersistentControlStore
	telemetryMu sync.RWMutex
	telemetry   *ConnectorTelemetry
}

func NewPersistentServer(store PersistentControlStore, verifier IdentityProofVerifier, config ServerConfig) (*PersistentServer, error) {
	if store == nil || verifier == nil {
		return nil, ErrInvalidInput
	}
	if _, ok := store.(PersistentDrainStore); !ok {
		return nil, ErrInvalidInput
	}
	if _, ok := store.(PersistentSessionMetadataStore); !ok {
		return nil, ErrInvalidInput
	}
	config.Authenticator = PersistentAuthenticator{Store: store, Verifier: verifier, Clock: config.Clock}
	config.Snapshots = PersistentSnapshotSource{Store: store}
	server, err := NewServer(config)
	if err != nil {
		return nil, err
	}
	return &PersistentServer{server: server, store: store}, nil
}

// NewRotationCoordinator creates the production rotation adapter only when
// the store exposes every durable boundary required by connector-v1. In
// particular, the old-key verifier is resolved by connector/account/host and
// generation inside SQL, and restart recovery is loaded from the immutable
// target rows. There is intentionally no in-memory-only fallback here.
func (s *PersistentServer) NewRotationCoordinator(plan RotationPlan) (*RotationCoordinator, error) {
	if s == nil || s.server == nil || s.store == nil || plan.Validate() != nil {
		return nil, ErrInvalidInput
	}
	store, ok := s.store.(RotationPersistence)
	if !ok {
		return nil, codeError(ErrUnsupportedMessage, ReasonCredentialRotation, false, errors.New("rotation persistence is not configured"))
	}
	if _, ok := s.store.(RotationRecoveryStore); !ok {
		return nil, codeError(ErrUnsupportedMessage, ReasonCredentialRotation, false, errors.New("rotation recovery is not configured"))
	}
	if _, ok := s.store.(RotationSessionAuthorizer); !ok {
		return nil, codeError(ErrUnsupportedMessage, ReasonCredentialRotation, false, errors.New("rotation session authorization is not configured"))
	}
	verifier, ok := s.store.(interface {
		VerifyRotationOldProof(context.Context, CredentialRotationProof, []byte, []byte) error
	})
	if !ok {
		return nil, codeError(ErrUnsupportedMessage, ReasonCredentialRotation, false, errors.New("rotation proof verifier is not configured"))
	}
	return NewRotationCoordinator(plan, RotationConfig{
		Store: store,
		Clock: s.server.config.Clock,
		VerifyOldProof: func(ctx context.Context, proof CredentialRotationProof, payload, signature []byte) error {
			return verifier.VerifyRotationOldProof(ctx, proof, payload, signature)
		},
	})
}

// ResumeRotation reconstructs one durable aggregate without issuing a new
// challenge. Workers use this after loading the immutable plan from their
// operation queue; all target phases and credential generations are checked by
// the coordinator and SQL recovery store.
func (s *PersistentServer) ResumeRotation(ctx context.Context, plan RotationPlan) (*RotationCoordinator, error) {
	coordinator, err := s.NewRotationCoordinator(plan)
	if err != nil {
		return nil, err
	}
	if err := coordinator.Resume(ctx); err != nil {
		return nil, err
	}
	return coordinator, nil
}

func (s *PersistentServer) ListRotationPlans(ctx context.Context, limit int) ([]RotationPlan, error) {
	if s == nil || s.store == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	source, ok := s.store.(RotationPlanSource)
	if !ok {
		return nil, codeError(ErrUnsupportedMessage, ReasonCredentialRotation, false, errors.New("rotation plan source is not configured"))
	}
	return source.ListCredentialRotationPlans(ctx, limit)
}

func (s *PersistentServer) Accept(ctx context.Context, hello Hello) (*PersistentSession, Welcome, Snapshot, error) {
	if s == nil || s.server == nil || s.store == nil || ctx == nil {
		return nil, Welcome{}, Snapshot{}, ErrInvalidInput
	}
	startedAt := time.Now()
	wasReconnect := false
	if s.server.config.Registry != nil {
		_, wasReconnect = s.server.config.Registry.Active(hello.ConnectorID)
	}
	observer := s.connectorTelemetry()
	attempt := connectorTelemetryIdentity{
		AccountID:            hello.AccountID,
		Reference:            SessionRef{TunnelID: hello.TunnelID, ConnectorID: hello.ConnectorID, ProcessGeneration: hello.ProcessGeneration},
		CredentialGeneration: hello.Auth.CredentialGeneration,
	}
	recordAcceptFailure := func(ref SessionRef) {
		if observer == nil {
			return
		}
		if ref.TunnelID == "" {
			ref = attempt.Reference
		}
		failure := connectorTelemetryIdentity{AccountID: hello.AccountID, Reference: ref, CredentialGeneration: hello.Auth.CredentialGeneration}
		observer.handshake(failure, hello.HostID, servertelemetry.ConnectorHandshakeFailed, time.Since(startedAt))
		observer.connection(failure, hello.HostID, servertelemetry.ConnectorConnectionFailed)
		if wasReconnect {
			observer.reconnect(failure, hello.HostID, servertelemetry.ConnectorReconnectFailed)
		}
	}
	session, welcome, snapshot, err := s.server.Accept(ctx, hello)
	if err != nil {
		recordAcceptFailure(attempt.Reference)
		return nil, Welcome{}, Snapshot{}, err
	}
	metadataStore := s.store.(PersistentSessionMetadataStore)
	persistErr := metadataStore.CreateConnectorSessionV1(ctx, session.Reference(), welcome, session.auth.CredentialGeneration)
	if persistErr != nil {
		recordAcceptFailure(session.Reference())
		closeErr := session.Close(ReasonProtocolClosed)
		(&PersistentSession{session: session, store: s.store, parent: s}).recordClosedTelemetry()
		return nil, Welcome{}, Snapshot{}, fmt.Errorf("create connector session: %w", errors.Join(persistErr, closeErr))
	}
	if observer != nil {
		accepted := connectorTelemetryIdentity{AccountID: hello.AccountID, Reference: session.Reference(), CredentialGeneration: session.auth.CredentialGeneration, ConfigGeneration: snapshot.Generation}
		observer.handshake(accepted, hello.HostID, servertelemetry.ConnectorHandshakeSucceeded, time.Since(startedAt))
		observer.connection(accepted, hello.HostID, servertelemetry.ConnectorConnectionOpened)
		observer.config(accepted, hello.HostID, servertelemetry.ConfigGenerationDesired, snapshot.Generation, servertelemetry.RetryNone, time.Time{})
		if wasReconnect {
			observer.reconnect(accepted, hello.HostID, servertelemetry.ConnectorReconnectSucceeded)
		}
	}
	return &PersistentSession{session: session, store: s.store, parent: s}, welcome, snapshot, nil
}

type PersistentSession struct {
	session            *ServerSession
	store              PersistentControlStore
	parent             *PersistentServer
	telemetryCloseOnce sync.Once
}

func (s *PersistentSession) Reference() SessionRef {
	if s == nil || s.session == nil {
		return SessionRef{}
	}
	return s.session.Reference()
}

// failClosed withdraws readiness whenever durable state cannot confirm the
// in-memory transition. Returning a typed conflict while closing is safer than
// leaving a process eligible with a lease/config state the database did not
// record.
func (s *PersistentSession) failClosed(ctx context.Context, primary error) error {
	if s == nil || s.session == nil || s.store == nil {
		return primary
	}
	closeErr := s.session.Close(ReasonProtocolClosed)
	// Durable cleanup must not inherit a canceled request context. Closing the
	// in-memory session is immediate; the database record gets its own short,
	// bounded context so a failed write cannot leave a stale live row forever.
	disconnectErr := s.recordDisconnectedBounded()
	s.recordClosedTelemetry()
	return codeError(ErrSessionConflict, ReasonProtocolClosed, false, errors.Join(primary, closeErr, disconnectErr))
}

func (s *PersistentSession) recordDisconnectedBounded() error {
	if s == nil || s.session == nil || s.store == nil {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), DefaultAbortTimeout)
	defer cancel()
	err := s.store.RecordDisconnected(cleanupCtx, s.session.Reference(), s.session.Disconnect())
	s.recordClosedTelemetry()
	return err
}

func (s *PersistentSession) HandleAck(ctx context.Context, ack Ack) error {
	if s == nil || s.session == nil || s.store == nil || ctx == nil {
		return ErrInvalidInput
	}
	persistNegative := s.session.CanPersistNegativeAck(ack)
	if err := s.session.HandleAck(ctx, ack); err != nil {
		if persistNegative {
			if persistErr := s.store.RecordApplied(ctx, s.session.Reference(), ack); persistErr != nil {
				s.recordClosedTelemetry()
				return s.failClosed(ctx, errors.Join(err, persistErr))
			}
		}
		s.recordClosedTelemetry()
		return err
	}
	if err := s.store.RecordApplied(ctx, s.session.Reference(), ack); err != nil {
		s.recordClosedTelemetry()
		return s.failClosed(ctx, err)
	}
	if ack.Status == AckApplied {
		s.recordConfigTelemetry(ack, servertelemetry.RetryNone, time.Time{})
	} else if ack.Status == AckRejected {
		s.recordDesiredTelemetry(s.currentSnapshotForTelemetry(ack.Generation), servertelemetry.RetryScheduled, time.Now().UTC().Add(time.Minute))
	} else if ack.Status == AckSnapshotRequired {
		s.recordDesiredTelemetry(s.currentSnapshotForTelemetry(ack.Generation), servertelemetry.RetryWaitForChange, time.Time{})
	}
	return nil
}

func (s *PersistentSession) OfferSnapshot(ctx context.Context, snapshot Snapshot) error {
	if s == nil || s.session == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := s.session.OfferSnapshot(ctx, snapshot); err != nil {
		s.recordClosedTelemetry()
		return err
	}
	s.recordDesiredTelemetry(snapshot, servertelemetry.RetryNone, time.Time{})
	return nil
}

func (s *PersistentSession) OfferDelta(ctx context.Context, delta Delta) error {
	if s == nil || s.session == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := s.session.OfferDelta(ctx, delta); err != nil {
		s.recordClosedTelemetry()
		return err
	}
	snapshot := Snapshot{TunnelID: delta.TunnelID, Generation: delta.Generation, ContentHash: delta.ContentHash}
	s.recordDesiredTelemetry(snapshot, servertelemetry.RetryNone, time.Time{})
	return nil
}

func (s *PersistentSession) HandleReadiness(ctx context.Context, readiness Readiness) (Ack, error) {
	if s == nil || s.session == nil || s.store == nil || ctx == nil {
		return Ack{}, ErrInvalidInput
	}
	ack, err := s.session.HandleReadiness(ctx, readiness)
	if err != nil {
		s.recordClosedTelemetry()
		return Ack{}, err
	}
	if err := s.store.RecordReady(ctx, s.session.Reference(), readiness); err != nil {
		s.recordClosedTelemetry()
		return Ack{}, s.failClosed(ctx, err)
	}
	s.recordReadyTelemetry(readiness)
	return ack, nil
}

func (s *PersistentSession) HandleHeartbeat(ctx context.Context, heartbeat Heartbeat) (HeartbeatAck, error) {
	if s == nil || s.session == nil || s.store == nil || ctx == nil {
		return HeartbeatAck{}, ErrInvalidInput
	}
	ack, err := s.session.HandleHeartbeat(ctx, heartbeat)
	if err != nil {
		s.recordClosedTelemetry()
		return HeartbeatAck{}, err
	}
	if err := s.store.RecordHeartbeat(ctx, s.session.Reference(), heartbeat, ack); err != nil {
		s.recordClosedTelemetry()
		return HeartbeatAck{}, s.failClosed(ctx, err)
	}
	return ack, nil
}

func (s *PersistentSession) Renew(ctx context.Context, request RenewalRequest) (AuthResult, error) {
	if s == nil || s.session == nil || s.store == nil || ctx == nil {
		return AuthResult{}, ErrInvalidInput
	}
	result, err := s.session.Renew(ctx, request)
	if err != nil {
		s.recordClosedTelemetry()
		return AuthResult{}, err
	}
	if err := s.store.RecordRenewal(ctx, s.session.Reference(), result); err != nil {
		s.recordClosedTelemetry()
		return AuthResult{}, s.failClosed(ctx, err)
	}
	return result, nil
}

func (s *PersistentSession) BeginDrain(ctx context.Context, drainID string, deadline time.Time, forceAfterDeadline bool) (Drain, error) {
	if s == nil || s.session == nil || s.store == nil || ctx == nil {
		return Drain{}, ErrInvalidInput
	}
	drain, err := s.session.BeginDrain(ctx, drainID, deadline, forceAfterDeadline)
	if err != nil {
		s.recordClosedTelemetry()
		return Drain{}, err
	}
	store := s.store.(PersistentDrainStore)
	if err := store.RecordDrain(ctx, s.session.Reference(), drain, DrainAccepted, 0, ""); err != nil {
		s.recordClosedTelemetry()
		return Drain{}, s.failClosed(ctx, err)
	}
	accountID, hostID, ref, credentialGeneration, configGeneration := s.session.telemetrySnapshot()
	if observer := s.connectorTelemetry(); observer != nil {
		observer.session(connectorTelemetryIdentity{AccountID: accountID, Reference: ref, CredentialGeneration: credentialGeneration, ConfigGeneration: configGeneration}, hostID, servertelemetry.ConnectorSessionDraining, configGeneration)
	}
	return drain, nil
}

func (s *PersistentSession) HandleDrainAck(ctx context.Context, ack DrainAck) error {
	if s == nil || s.session == nil || s.store == nil || ctx == nil {
		return ErrInvalidInput
	}
	persistNegative := s.session.CanPersistNegativeDrainAck(ack)
	if err := s.session.HandleDrainAck(ctx, ack); err != nil {
		if persistNegative {
			request, _, _ := s.session.Drain()
			if persistErr := s.store.(PersistentDrainStore).RecordDrain(ctx, s.session.Reference(), request, ack.Status, ack.ActiveStreams, ack.Code); persistErr != nil {
				s.recordClosedTelemetry()
				return s.failClosed(ctx, errors.Join(err, persistErr))
			}
		}
		s.recordClosedTelemetry()
		return err
	}
	store := s.store.(PersistentDrainStore)
	request, _, _ := s.session.Drain()
	if err := store.RecordDrain(ctx, s.session.Reference(), request, ack.Status, ack.ActiveStreams, ack.Code); err != nil {
		s.recordClosedTelemetry()
		return s.failClosed(ctx, err)
	}
	return nil
}

func (s *PersistentSession) Close(ctx context.Context, reason DisconnectReason) error {
	if s == nil || s.session == nil || s.store == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := s.session.Close(reason); err != nil {
		s.recordClosedTelemetry()
		return err
	}
	// Use a detached bounded cleanup context. A canceled RPC or shutdown
	// context must not strand the durable session as live.
	if err := s.recordDisconnectedBounded(); err != nil {
		s.recordClosedTelemetry()
		return codeError(ErrSessionConflict, ReasonProtocolClosed, false, err)
	}
	s.recordClosedTelemetry()
	return nil
}

func (s *PersistentSession) CheckLease(ctx context.Context, now time.Time) error {
	if s == nil || s.session == nil || s.store == nil || ctx == nil {
		return ErrInvalidInput
	}
	err := s.session.CheckLease(now)
	if err == nil {
		return nil
	}
	if s.session.State() == SessionClosed {
		s.recordClosedTelemetry()
		if recordErr := s.recordDisconnectedBounded(); recordErr != nil {
			return errors.Join(err, recordErr)
		}
	}
	return err
}

func (s *PersistentSession) Current() (Snapshot, bool, uint64) {
	if s == nil || s.session == nil {
		return Snapshot{}, false, 0
	}
	return s.session.Current()
}
