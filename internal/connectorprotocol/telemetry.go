package connectorprotocol

import (
	"time"

	servertelemetry "github.com/pinksaucepasta/paperboat-server/internal/telemetry"
)

// ConnectorTelemetry is the connector-v1 adapter for the server-owned
// telemetry producer. It accepts only protocol identities and finite states;
// it never forwards tokens, public keys, host names, URLs, or error text.
//
// The adapter deliberately treats telemetry as best effort. Every method
// drops producer errors so an exhausted event queue or a telemetry validation
// problem cannot change a successful protocol or database transition.
type ConnectorTelemetry struct {
	Producer *servertelemetry.Producer
}

func NewConnectorTelemetry(producer *servertelemetry.Producer) *ConnectorTelemetry {
	if producer == nil {
		return nil
	}
	return &ConnectorTelemetry{Producer: producer}
}

type connectorTelemetryIdentity struct {
	AccountID            string
	Reference            SessionRef
	CredentialGeneration uint64
	ConfigGeneration     uint64
}

func (t *ConnectorTelemetry) identity(value connectorTelemetryIdentity) (servertelemetry.ProducerIdentity, servertelemetry.Generations) {
	if ValidateIdentifier(value.Reference.TunnelID) != nil || ValidateIdentifier(value.Reference.ConnectorID) != nil || value.Reference.ProcessGeneration == 0 {
		return servertelemetry.ProducerIdentity{}, servertelemetry.Generations{}
	}
	identity := servertelemetry.ProducerIdentity{
		// A session is the connector resource for this stream. Keeping the
		// resource identity stable lets the lifecycle stream correlate all
		// transitions without exposing the connector's user-facing name.
		ResourceKind: "connector",
		ResourceID:   value.Reference.ConnectorID,
		IDs: servertelemetry.SafeIDs{
			AccountID:   value.AccountID,
			TunnelID:    value.Reference.TunnelID,
			ConnectorID: value.Reference.ConnectorID,
		},
	}
	if ValidateIdentifier(value.Reference.SessionID) == nil {
		identity.IDs.SessionID = value.Reference.SessionID
	}
	if ValidateIdentifier(value.Reference.SessionID) == nil && len(value.Reference.SessionID) <= 124 {
		identity.CorrelationID = "cor_" + value.Reference.SessionID
	}
	return identity, servertelemetry.Generations{
		Process:    value.Reference.ProcessGeneration,
		Credential: value.CredentialGeneration,
		Config:     value.ConfigGeneration,
	}
}

func (t *ConnectorTelemetry) identityWithHost(value connectorTelemetryIdentity, hostID string) (servertelemetry.ProducerIdentity, servertelemetry.Generations) {
	identity, generations := t.identity(value)
	identity.IDs.HostID = hostID
	return identity, generations
}

func usableConnectorTelemetryIdentity(identity servertelemetry.ProducerIdentity, generations servertelemetry.Generations) bool {
	// Failed handshakes can arrive before the protocol has accepted the
	// connector identity. Do not publish an event with generated/empty IDs for
	// those attempts; telemetry must describe an authenticated or safely bound
	// connector only.
	return identity.ResourceKind == "connector" && identity.ResourceID != "" && generations.Process > 0
}

func (t *ConnectorTelemetry) handshake(value connectorTelemetryIdentity, hostID string, outcome servertelemetry.ConnectorHandshakeOutcome, duration time.Duration) {
	if t == nil || t.Producer == nil {
		return
	}
	identity, generations := t.identityWithHost(value, hostID)
	if !usableConnectorTelemetryIdentity(identity, generations) {
		return
	}
	_ = t.Producer.RecordConnectorHandshake(servertelemetry.ConnectorHandshakeInput{
		Outcome: outcome, Duration: boundedTelemetryDuration(duration), Identity: identity, Generations: generations,
	})
}

func (t *ConnectorTelemetry) connection(value connectorTelemetryIdentity, hostID string, outcome servertelemetry.ConnectorConnectionOutcome) {
	if t == nil || t.Producer == nil {
		return
	}
	identity, generations := t.identityWithHost(value, hostID)
	if !usableConnectorTelemetryIdentity(identity, generations) {
		return
	}
	_ = t.Producer.RecordConnectorConnection(servertelemetry.ConnectorConnectionInput{
		Outcome: outcome, Identity: identity, Generations: generations,
	})
}

func (t *ConnectorTelemetry) session(value connectorTelemetryIdentity, hostID string, state servertelemetry.ConnectorSessionState, configGeneration uint64) {
	if t == nil || t.Producer == nil {
		return
	}
	value.ConfigGeneration = configGeneration
	identity, generations := t.identityWithHost(value, hostID)
	if !usableConnectorTelemetryIdentity(identity, generations) {
		return
	}
	_ = t.Producer.RecordConnectorSession(servertelemetry.ConnectorSessionInput{
		State: state, Identity: identity, Generations: generations,
	})
}

func (t *ConnectorTelemetry) reconnect(value connectorTelemetryIdentity, hostID string, outcome servertelemetry.ConnectorReconnectOutcome) {
	if t == nil || t.Producer == nil {
		return
	}
	identity, generations := t.identityWithHost(value, hostID)
	if !usableConnectorTelemetryIdentity(identity, generations) {
		return
	}
	_ = t.Producer.RecordConnectorReconnect(servertelemetry.ConnectorReconnectInput{
		Outcome: outcome, Identity: identity, Generations: generations,
	})
}

func (t *ConnectorTelemetry) backoff(value connectorTelemetryIdentity, hostID string, state servertelemetry.ConnectorBackoffState, duration time.Duration) {
	if t == nil || t.Producer == nil {
		return
	}
	identity, generations := t.identityWithHost(value, hostID)
	if !usableConnectorTelemetryIdentity(identity, generations) {
		return
	}
	_ = t.Producer.RecordConnectorBackoff(servertelemetry.ConnectorBackoffInput{
		State: state, Duration: boundedTelemetryDuration(duration), Identity: identity, Generations: generations,
	})
}

func (t *ConnectorTelemetry) disconnect(value connectorTelemetryIdentity, hostID string, reason DisconnectReason) {
	if t == nil || t.Producer == nil {
		return
	}
	identity, generations := t.identityWithHost(value, hostID)
	if !usableConnectorTelemetryIdentity(identity, generations) {
		return
	}
	_ = t.Producer.RecordConnectorDisconnect(servertelemetry.ConnectorDisconnectInput{
		Reason: mapTelemetryDisconnectReason(reason), Identity: identity, Generations: generations,
	})
}

func (t *ConnectorTelemetry) config(value connectorTelemetryIdentity, hostID string, state servertelemetry.ConfigGenerationState, generation uint64, retry servertelemetry.RetryDecision, nextRetryAt time.Time) {
	if t == nil || t.Producer == nil {
		return
	}
	value.ConfigGeneration = generation
	identity, generations := t.identityWithHost(value, hostID)
	if !usableConnectorTelemetryIdentity(identity, generations) {
		return
	}
	_ = t.Producer.RecordConfigApply(servertelemetry.ConfigApplyInput{
		State: state, Generation: generation, Retry: retry, NextRetryAt: nextRetryAt,
		Identity: identity, Generations: generations,
	})
}

func boundedTelemetryDuration(value time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	if value > 24*time.Hour {
		return 24 * time.Hour
	}
	return value
}

func mapTelemetryDisconnectReason(reason DisconnectReason) servertelemetry.ConnectorDisconnectReason {
	switch reason {
	case ReasonAuthentication, ReasonCredentialExpired:
		return servertelemetry.ConnectorDisconnectAuth
	case ReasonLeaseExpired, ReasonHeartbeatTimeout:
		return servertelemetry.ConnectorDisconnectNetwork
	case ReasonServerShutdown:
		return servertelemetry.ConnectorDisconnectShutdown
	case ReasonProtocolMismatch, ReasonCapabilityMissing, ReasonMalformed, ReasonSnapshotRejected, ReasonGenerationGap, ReasonCredentialRotation, ReasonCanceled, ReasonProtocolClosed:
		return servertelemetry.ConnectorDisconnectProtocol
	case ReasonSessionReplaced, ReasonStaleGeneration:
		return servertelemetry.ConnectorDisconnectServer
	default:
		return servertelemetry.ConnectorDisconnectUnknown
	}
}

func (s *PersistentServer) SetTelemetryProducer(producer *servertelemetry.Producer) {
	if s == nil {
		return
	}
	s.telemetryMu.Lock()
	s.telemetry = NewConnectorTelemetry(producer)
	s.telemetryMu.Unlock()
}

func (s *PersistentServer) connectorTelemetry() *ConnectorTelemetry {
	if s == nil {
		return nil
	}
	s.telemetryMu.RLock()
	defer s.telemetryMu.RUnlock()
	return s.telemetry
}

func (s *PersistentSession) connectorTelemetry() *ConnectorTelemetry {
	if s == nil || s.parent == nil {
		return nil
	}
	return s.parent.connectorTelemetry()
}

func (s *ServerSession) telemetrySnapshot() (accountID, hostID string, ref SessionRef, credentialGeneration, configGeneration uint64) {
	if s == nil {
		return "", "", SessionRef{}, 0, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	accountID, hostID, ref = s.auth.AccountID, s.auth.HostID, s.ref
	credentialGeneration = s.auth.CredentialGeneration
	switch {
	case s.hasCandidate:
		configGeneration = s.candidate.Generation
	case s.hasActive:
		configGeneration = s.active.Generation
	case s.pendingSnapshot != nil:
		configGeneration = s.pendingSnapshot.Generation
	case s.pendingDelta != nil:
		configGeneration = s.pendingDelta.Generation
	}
	return accountID, hostID, ref, credentialGeneration, configGeneration
}

func (s *PersistentSession) recordReadyTelemetry(readiness Readiness) {
	if s == nil || s.session == nil {
		return
	}
	accountID, hostID, ref, credentialGeneration, _ := s.session.telemetrySnapshot()
	observer := s.connectorTelemetry()
	if observer == nil {
		return
	}
	value := connectorTelemetryIdentity{AccountID: accountID, Reference: ref, CredentialGeneration: credentialGeneration, ConfigGeneration: readiness.Generation}
	observer.session(value, hostID, servertelemetry.ConnectorSessionActive, readiness.Generation)
}

func (s *PersistentSession) recordConfigTelemetry(ack Ack, retry servertelemetry.RetryDecision, nextRetryAt time.Time) {
	if s == nil || s.session == nil {
		return
	}
	accountID, hostID, ref, credentialGeneration, _ := s.session.telemetrySnapshot()
	observer := s.connectorTelemetry()
	if observer == nil {
		return
	}
	value := connectorTelemetryIdentity{AccountID: accountID, Reference: ref, CredentialGeneration: credentialGeneration, ConfigGeneration: ack.Generation}
	observer.config(value, hostID, servertelemetry.ConfigGenerationApplied, ack.Generation, retry, nextRetryAt)
}

func (s *PersistentSession) recordDesiredTelemetry(snapshot Snapshot, retry servertelemetry.RetryDecision, nextRetryAt time.Time) {
	if s == nil || s.session == nil {
		return
	}
	accountID, hostID, ref, credentialGeneration, _ := s.session.telemetrySnapshot()
	observer := s.connectorTelemetry()
	if observer == nil {
		return
	}
	value := connectorTelemetryIdentity{AccountID: accountID, Reference: ref, CredentialGeneration: credentialGeneration, ConfigGeneration: snapshot.Generation}
	observer.config(value, hostID, servertelemetry.ConfigGenerationDesired, snapshot.Generation, retry, nextRetryAt)
}

func (s *PersistentSession) currentSnapshotForTelemetry(generation uint64) Snapshot {
	if s == nil || s.session == nil {
		return Snapshot{Generation: generation}
	}
	_, _, ref, _, _ := s.session.telemetrySnapshot()
	return Snapshot{TunnelID: ref.TunnelID, Generation: generation}
}

func (s *PersistentSession) recordClosedTelemetry() {
	if s == nil || s.session == nil {
		return
	}
	if s.session.State() != SessionClosed {
		return
	}
	s.telemetryCloseOnce.Do(func() {
		accountID, hostID, ref, credentialGeneration, configGeneration := s.session.telemetrySnapshot()
		observer := s.connectorTelemetry()
		if observer == nil {
			return
		}
		value := connectorTelemetryIdentity{AccountID: accountID, Reference: ref, CredentialGeneration: credentialGeneration, ConfigGeneration: configGeneration}
		observer.session(value, hostID, servertelemetry.ConnectorSessionClosed, configGeneration)
		observer.connection(value, hostID, servertelemetry.ConnectorConnectionClosed)
		observer.disconnect(value, hostID, s.session.Disconnect().Reason)
	})
}
