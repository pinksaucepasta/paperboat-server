package connectorprotocol

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"
)

type persistenceStoreStub struct {
	authResult            AuthResult
	snapshot              Snapshot
	created               []SessionRef
	applied               []Ack
	ready                 []Readiness
	heartbeats            []Heartbeat
	renewals              []AuthResult
	disconnect            []Disconnect
	authNonces            map[string]struct{}
	drains                []DrainStatus
	appliedErr            error
	readyErr              error
	heartbeatErr          error
	renewalErr            error
	disconnectErr         error
	drainErr              error
	disconnectContextErrs []error
}

func (s *persistenceStoreStub) AuthenticateConnector(_ context.Context, request AuthRequest) (AuthResult, error) {
	if s.authNonces == nil {
		s.authNonces = make(map[string]struct{})
	}
	key := fmt.Sprintf("%s/%d/%s", request.ConnectorID, request.CredentialGeneration, request.Nonce)
	if _, exists := s.authNonces[key]; exists {
		return AuthResult{}, ErrDurableReplay
	}
	s.authNonces[key] = struct{}{}
	return s.authResult, nil
}
func (s *persistenceStoreStub) RenewConnector(context.Context, RenewalRequest) (AuthResult, error) {
	result := s.authResult
	result.CredentialGeneration++
	return result, nil
}
func (s *persistenceStoreStub) Snapshot(context.Context, string) (Snapshot, error) {
	return s.snapshot, nil
}
func (s *persistenceStoreStub) CreateConnectorSession(_ context.Context, ref SessionRef, _ Lease, _ uint64) error {
	s.created = append(s.created, ref)
	return nil
}
func (s *persistenceStoreStub) CreateConnectorSessionV1(_ context.Context, ref SessionRef, _ Welcome, _ uint64) error {
	s.created = append(s.created, ref)
	return nil
}
func (s *persistenceStoreStub) RecordApplied(_ context.Context, _ SessionRef, ack Ack) error {
	s.applied = append(s.applied, ack)
	return s.appliedErr
}
func (s *persistenceStoreStub) RecordReady(_ context.Context, _ SessionRef, readiness Readiness) error {
	s.ready = append(s.ready, readiness)
	return s.readyErr
}
func (s *persistenceStoreStub) RecordHeartbeat(_ context.Context, _ SessionRef, heartbeat Heartbeat, _ HeartbeatAck) error {
	s.heartbeats = append(s.heartbeats, heartbeat)
	return s.heartbeatErr
}
func (s *persistenceStoreStub) RecordRenewal(_ context.Context, _ SessionRef, result AuthResult) error {
	s.renewals = append(s.renewals, result)
	return s.renewalErr
}
func (s *persistenceStoreStub) RecordDisconnected(ctx context.Context, _ SessionRef, disconnect Disconnect) error {
	s.disconnect = append(s.disconnect, disconnect)
	s.disconnectContextErrs = append(s.disconnectContextErrs, ctx.Err())
	return s.disconnectErr
}
func (s *persistenceStoreStub) RecordDrain(_ context.Context, _ SessionRef, _ Drain, status DrainStatus, _ uint32, _ Code) error {
	s.drains = append(s.drains, status)
	return s.drainErr
}

func TestPersistentServerVerifiesProofAndPersistsSessionLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	auth, private := testAuth(t, now, 1)
	snapshot, err := NewSnapshot("tunnel_1", 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	store := &persistenceStoreStub{authResult: AuthResult{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, IdentityKeyID: auth.IdentityKeyID, IdentityKeyThumbprint: auth.IdentityKeyThumbprint, ProcessGeneration: 1, CredentialGeneration: auth.CredentialGeneration, CredentialExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Hour)}, snapshot: snapshot}
	clock := &testClock{now: now}
	verifier := IdentityProofVerifierFuncs{
		AuthFunc: func(_ context.Context, _ AuthRequest, message, signature []byte) error {
			if !ed25519.Verify(private.Public().(ed25519.PublicKey), message, signature) {
				return ErrAuthenticationFailed
			}
			return nil
		},
		RenewalFunc: func(_ context.Context, _ RenewalRequest, message, signature []byte) error {
			if !ed25519.Verify(private.Public().(ed25519.PublicKey), message, signature) {
				return ErrAuthenticationFailed
			}
			return nil
		},
	}
	server, err := NewPersistentServer(store, verifier, ServerConfig{Capabilities: requiredCapabilityList(), Clock: clock, LeaseDuration: time.Minute, HeartbeatInterval: 10 * time.Second, SessionIDs: func() (string, error) { return "sess_1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	session, welcome, first, err := server.Accept(context.Background(), Hello{Protocol: ProtocolName, MinVersion: "1.0", MaxVersion: "1.0", AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: 1, Capabilities: requiredCapabilityList(), Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	if first.ContentHash != snapshot.ContentHash || len(store.created) != 1 || store.created[0].SessionID != welcome.SessionID {
		t.Fatalf("session persistence created=%+v first=%+v welcome=%+v", store.created, first, welcome)
	}
	if err := session.HandleAck(context.Background(), Ack{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, Kind: AckSnapshot, Status: AckApplied, Generation: first.Generation, ContentHash: first.ContentHash}); err != nil {
		t.Fatal(err)
	}
	readiness := Readiness{AccountID: auth.AccountID, SessionID: welcome.SessionID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, ProcessGeneration: 1, Generation: first.Generation, ContentHash: first.ContentHash, EdgeReady: true, RouteReady: true, OriginReady: true}
	if _, err := session.HandleReadiness(context.Background(), readiness); err != nil {
		t.Fatal(err)
	}
	if len(store.applied) != 1 || len(store.ready) != 1 || len(store.heartbeats) != 0 {
		t.Fatalf("lifecycle persistence before adapter heartbeat applied=%d ready=%d heartbeat=%d", len(store.applied), len(store.ready), len(store.heartbeats))
	}
	if _, err := session.HandleHeartbeat(context.Background(), Heartbeat{AccountID: auth.AccountID, SessionID: welcome.SessionID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, ProcessGeneration: 1, LastAppliedGeneration: 1, LastAppliedHash: first.ContentHash, SentAt: now}); err != nil {
		t.Fatal(err)
	}
	if len(store.heartbeats) != 1 {
		t.Fatal("heartbeat was not persisted")
	}
	if err := session.Close(context.Background(), ReasonProtocolClosed); err != nil {
		t.Fatal(err)
	}
	if len(store.disconnect) != 1 || store.disconnect[0].SessionID != welcome.SessionID {
		t.Fatalf("disconnect persistence=%+v", store.disconnect)
	}
}

func TestPersistentAuthenticatorRejectsProofReplay(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	request, private := testAuth(t, now, 1)
	store := &persistenceStoreStub{authResult: AuthResult{AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, HostID: request.HostID, IdentityKeyID: request.IdentityKeyID, IdentityKeyThumbprint: request.IdentityKeyThumbprint, ProcessGeneration: 1, CredentialGeneration: 4, CredentialExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Hour)}}
	authenticator := PersistentAuthenticator{
		Store: store,
		Verifier: IdentityProofVerifierFuncs{
			AuthFunc: func(_ context.Context, _ AuthRequest, message, signature []byte) error {
				if !ed25519.Verify(private.Public().(ed25519.PublicKey), message, signature) {
					return ErrAuthenticationFailed
				}
				return nil
			},
			RenewalFunc: func(_ context.Context, _ RenewalRequest, message, signature []byte) error {
				if !ed25519.Verify(private.Public().(ed25519.PublicKey), message, signature) {
					return ErrAuthenticationFailed
				}
				return nil
			},
		},
		Clock: ClockFunc(func() time.Time { return now }),
	}
	if _, err := authenticator.Authenticate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(context.Background(), request); err == nil {
		t.Fatal("replayed authentication proof accepted")
	}
	mutated := request
	mutated.TunnelID = "tunnel_2"
	if _, err := authenticator.Authenticate(context.Background(), mutated); err == nil || !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("cross-tunnel proof result=%v", err)
	}
}

func newPersistentSessionTest(t *testing.T, store *persistenceStoreStub, now time.Time) (*PersistentSession, AuthRequest, Welcome, Snapshot) {
	t.Helper()
	auth, private := testAuth(t, now, 1)
	snapshot, err := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	store.authResult = AuthResult{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, IdentityKeyID: auth.IdentityKeyID, IdentityKeyThumbprint: auth.IdentityKeyThumbprint, ProcessGeneration: 1, CredentialGeneration: auth.CredentialGeneration, CredentialExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Hour)}
	store.snapshot = snapshot
	clock := &testClock{now: now}
	verifier := IdentityProofVerifierFuncs{
		AuthFunc: func(_ context.Context, _ AuthRequest, message, signature []byte) error {
			if !ed25519.Verify(private.Public().(ed25519.PublicKey), message, signature) {
				return ErrAuthenticationFailed
			}
			return nil
		},
		RenewalFunc: func(_ context.Context, _ RenewalRequest, message, signature []byte) error {
			if !ed25519.Verify(private.Public().(ed25519.PublicKey), message, signature) {
				return ErrAuthenticationFailed
			}
			return nil
		},
	}
	server, err := NewPersistentServer(store, verifier, ServerConfig{Capabilities: requiredCapabilityList(), Clock: clock, LeaseDuration: time.Minute, HeartbeatInterval: 10 * time.Second, SessionIDs: func() (string, error) { return "sess_1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	session, welcome, first, err := server.Accept(context.Background(), Hello{Protocol: ProtocolName, MinVersion: ProtocolVersion, MaxVersion: ProtocolVersion, AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: 1, Capabilities: requiredCapabilityList(), Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	return session, auth, welcome, first
}

func TestPersistentSessionPersistsNegativeSnapshotAckBeforeReturningError(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	store := &persistenceStoreStub{}
	session, auth, welcome, first := newPersistentSessionTest(t, store, now)
	ack := Ack{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, Kind: AckSnapshot, Status: AckRejected, Generation: first.Generation, ContentHash: first.ContentHash, Code: CodeSnapshotRejected}
	if err := session.HandleAck(context.Background(), ack); !errors.Is(err, ErrSnapshotRejected) {
		t.Fatalf("rejected ack error=%v", err)
	}
	if len(store.applied) != 1 || store.applied[0].Status != AckRejected {
		t.Fatalf("negative ack was not persisted: %+v", store.applied)
	}
}

func TestPersistentSessionPersistsGenerationRecoveryAck(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	store := &persistenceStoreStub{}
	session, auth, welcome, first := newPersistentSessionTest(t, store, now)
	ack := Ack{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, Kind: AckSnapshot, Status: AckSnapshotRequired, Generation: first.Generation, ContentHash: first.ContentHash}
	if err := session.HandleAck(context.Background(), ack); !errors.Is(err, ErrSnapshotRequired) {
		t.Fatalf("snapshot recovery error=%v", err)
	}
	if len(store.applied) != 1 || store.applied[0].Status != AckSnapshotRequired {
		t.Fatalf("recovery ack was not persisted: %+v", store.applied)
	}
}

func TestPersistentSessionFailClosedUsesDetachedDisconnectCleanup(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	store := &persistenceStoreStub{readyErr: errors.New("ready persistence failed")}
	session, auth, welcome, first := newPersistentSessionTest(t, store, now)
	ack := Ack{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, Kind: AckSnapshot, Status: AckApplied, Generation: first.Generation, ContentHash: first.ContentHash}
	if err := session.HandleAck(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	readiness := Readiness{AccountID: auth.AccountID, SessionID: welcome.SessionID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, ProcessGeneration: 1, Generation: first.Generation, ContentHash: first.ContentHash, EdgeReady: true, RouteReady: true, OriginReady: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.HandleReadiness(ctx, readiness); err == nil || !errors.Is(err, store.readyErr) {
		t.Fatalf("persistence failure was not returned: %v", err)
	}
	if session.session.State() != SessionClosed || len(store.disconnect) != 1 {
		t.Fatalf("session was not failed closed: state=%s disconnects=%d", session.session.State(), len(store.disconnect))
	}
	if len(store.disconnectContextErrs) != 1 || store.disconnectContextErrs[0] != nil {
		t.Fatalf("disconnect used canceled context: %+v", store.disconnectContextErrs)
	}
}

func TestPersistentSessionPersistsRejectedDrainAck(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	store := &persistenceStoreStub{}
	session, auth, welcome, first := newPersistentSessionTest(t, store, now)
	apply := Ack{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, Kind: AckSnapshot, Status: AckApplied, Generation: first.Generation, ContentHash: first.ContentHash}
	if err := session.HandleAck(context.Background(), apply); err != nil {
		t.Fatal(err)
	}
	readiness := Readiness{AccountID: auth.AccountID, SessionID: welcome.SessionID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, ProcessGeneration: 1, Generation: first.Generation, ContentHash: first.ContentHash, EdgeReady: true, RouteReady: true, OriginReady: true}
	if _, err := session.HandleReadiness(context.Background(), readiness); err != nil {
		t.Fatal(err)
	}
	request, err := session.BeginDrain(context.Background(), "op_drain_1", now.Add(20*time.Second), true)
	if err != nil {
		t.Fatal(err)
	}
	ack := DrainAck{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, SessionID: welcome.SessionID, ProcessGeneration: 1, DrainID: request.DrainID, Generation: request.Generation, ContentHash: request.ContentHash, Status: DrainRejected, Code: CodeDrainRejected}
	if err := session.HandleDrainAck(context.Background(), ack); !errors.Is(err, ErrDrainRejected) {
		t.Fatalf("rejected drain error=%v", err)
	}
	if len(store.drains) != 2 || store.drains[1] != DrainRejected {
		t.Fatalf("rejected drain was not persisted: %+v", store.drains)
	}
}
