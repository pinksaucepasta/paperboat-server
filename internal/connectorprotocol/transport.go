package connectorprotocol

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// ActiveControlSession is the secret-free server projection of one currently
// authenticated connector control stream. It is used only to bind follow-up
// carrier bootstrap reads to the exact session created by Welcome.
type ActiveControlSession struct {
	AccountID             string
	TunnelID              string
	ConnectorID           string
	HostID                string
	SessionID             string
	IdentityKeyID         string
	IdentityKeyThumbprint string
	ProcessGeneration     uint64
	CredentialGeneration  uint64
	ConfigGeneration      uint64
	ConfigContentHash     string
}

func (s ActiveControlSession) validate() error {
	if ValidateIdentifier(s.AccountID) != nil || ValidateIdentifier(s.TunnelID) != nil || ValidateIdentifier(s.ConnectorID) != nil || ValidateIdentifier(s.HostID) != nil || ValidateIdentifier(s.SessionID) != nil || ValidateIdentityKey(s.IdentityKeyID, s.IdentityKeyThumbprint) != nil || s.ProcessGeneration == 0 || s.CredentialGeneration == 0 || s.ConfigGeneration == 0 || !hashPattern.MatchString(s.ConfigContentHash) {
		return ErrInvalidInput
	}
	return nil
}

// ActiveControlSessions owns no stream. Generation-safe detach prevents an
// older connection finishing after replacement from deleting the new entry.
type ActiveControlSessions struct {
	mu       sync.RWMutex
	sessions map[string]activeControlSessionEntry
}

type activeControlSessionEntry struct {
	projection ActiveControlSession
	session    *PersistentSession
}

func NewActiveControlSessions() *ActiveControlSessions {
	return &ActiveControlSessions{sessions: make(map[string]activeControlSessionEntry)}
}

func (s *ActiveControlSessions) attach(projection ActiveControlSession, session *PersistentSession) error {
	if s == nil || session == nil || projection.validate() != nil {
		return ErrInvalidInput
	}
	key := controlSessionKey(projection.TunnelID, projection.ConnectorID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.sessions[key]; ok {
		if current.projection.ProcessGeneration > projection.ProcessGeneration || current.projection.ProcessGeneration == projection.ProcessGeneration && current.projection.SessionID != projection.SessionID {
			return codeError(ErrSessionConflict, ReasonSessionReplaced, true, nil)
		}
	}
	s.sessions[key] = activeControlSessionEntry{projection: projection, session: session}
	return nil
}

func (s *ActiveControlSessions) detach(projection ActiveControlSession) {
	if s == nil {
		return
	}
	key := controlSessionKey(projection.TunnelID, projection.ConnectorID)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[key]
	if ok && current.projection.SessionID == projection.SessionID && current.projection.ProcessGeneration == projection.ProcessGeneration {
		delete(s.sessions, key)
	}
}

// Lookup returns a copy only when every session fence matches.
func (s *ActiveControlSessions) Lookup(tunnelID, connectorID, sessionID string, processGeneration uint64) (ActiveControlSession, bool) {
	if s == nil || ValidateIdentifier(tunnelID) != nil || ValidateIdentifier(connectorID) != nil || ValidateIdentifier(sessionID) != nil || processGeneration == 0 {
		return ActiveControlSession{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	current, ok := s.sessions[controlSessionKey(tunnelID, connectorID)]
	if !ok || current.projection.SessionID != sessionID || current.projection.ProcessGeneration != processGeneration {
		return ActiveControlSession{}, false
	}
	return current.projection, true
}

func controlSessionKey(tunnelID, connectorID string) string { return tunnelID + "\x00" + connectorID }

type ControlTransport struct {
	server   *PersistentServer
	sessions *ActiveControlSessions
	rotation *RotationDispatcher
	drain    *DrainDispatcher
}

func NewControlTransport(server *PersistentServer, sessions *ActiveControlSessions) (*ControlTransport, error) {
	return NewControlTransportWithRotation(server, sessions, nil)
}

func NewControlTransportWithRotation(server *PersistentServer, sessions *ActiveControlSessions, rotation *RotationDispatcher) (*ControlTransport, error) {
	return NewControlTransportWithDispatchers(server, sessions, rotation, nil)
}

func NewControlTransportWithDispatchers(server *PersistentServer, sessions *ActiveControlSessions, rotation *RotationDispatcher, drain *DrainDispatcher) (*ControlTransport, error) {
	if server == nil {
		return nil, ErrInvalidInput
	}
	if sessions == nil {
		sessions = NewActiveControlSessions()
	}
	return &ControlTransport{server: server, sessions: sessions, rotation: rotation, drain: drain}, nil
}

func (t *ControlTransport) Sessions() *ActiveControlSessions {
	if t == nil {
		return nil
	}
	return t.sessions
}

// Serve runs one connector-v1 control stream. The first frame must be Hello;
// the path-provided tunnel and connector are checked before durable auth. All
// writes share one bounded serializer so responses and asynchronous rotation
// frames cannot interleave on the byte stream.
func (t *ControlTransport) Serve(ctx context.Context, stream io.ReadWriteCloser, expectedTunnelID, expectedConnectorID string) (serveErr error) {
	if t == nil || t.server == nil || t.sessions == nil || ctx == nil || stream == nil || ValidateIdentifier(expectedTunnelID) != nil || ValidateIdentifier(expectedConnectorID) != nil {
		return ErrInvalidInput
	}
	defer stream.Close()
	writer := newSerializedFrameWriter(stream)
	first, err := ReadFrame(stream)
	if err != nil {
		return err
	}
	if first.Type != MessageHello {
		return codeError(ErrUnsupportedMessage, ReasonProtocolMismatch, false, nil)
	}
	var hello Hello
	if err = first.DecodePayload(&hello); err != nil {
		return err
	}
	if hello.TunnelID != expectedTunnelID || hello.ConnectorID != expectedConnectorID {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	session, welcome, snapshot, err := t.server.Accept(ctx, hello)
	if err != nil {
		return err
	}
	projection := ActiveControlSession{
		AccountID: hello.AccountID, TunnelID: hello.TunnelID, ConnectorID: hello.ConnectorID,
		HostID: hello.HostID, SessionID: welcome.SessionID, IdentityKeyID: hello.Auth.IdentityKeyID,
		IdentityKeyThumbprint: hello.Auth.IdentityKeyThumbprint, ProcessGeneration: hello.ProcessGeneration,
		CredentialGeneration: hello.Auth.CredentialGeneration, ConfigGeneration: snapshot.Generation,
		ConfigContentHash: snapshot.ContentHash,
	}
	if err = t.sessions.attach(projection, session); err != nil {
		_ = session.Close(context.Background(), ReasonSessionReplaced)
		return err
	}
	defer t.sessions.detach(projection)
	closeReason := ReasonProtocolClosed
	defer func() {
		if ctx.Err() != nil {
			closeReason = ReasonServerShutdown
		}
		closeErr := session.Close(context.Background(), closeReason)
		if serveErr == nil && closeErr != nil {
			serveErr = closeErr
		}
	}()

	welcomeFrame, err := NewFrame(MessageWelcome, first.RequestID, welcome)
	if err != nil {
		return err
	}
	if err = writer.Send(ctx, welcomeFrame); err != nil {
		return err
	}
	snapshotRequestID, err := newOpaqueID("snapshot")
	if err != nil {
		return err
	}
	snapshotFrame, err := NewFrame(MessageSnapshot, snapshotRequestID, snapshot)
	if err != nil {
		return err
	}
	if err = writer.Send(ctx, snapshotFrame); err != nil {
		return err
	}
	if t.rotation != nil {
		live := RotationLiveSession{
			AccountID: hello.AccountID, HostID: hello.HostID, Reference: session.Reference(),
			CredentialGeneration: hello.Auth.CredentialGeneration,
			IdentityKeyID:        hello.Auth.IdentityKeyID, IdentityKeyThumbprint: hello.Auth.IdentityKeyThumbprint,
			NegotiatedCapabilities: append([]string(nil), welcome.Capabilities...), Send: writer.Send,
		}
		if err = t.rotation.RegisterSession(ctx, live); err != nil {
			return err
		}
		defer t.rotation.DetachSession(session.Reference())
	}
	if t.drain != nil {
		live := DrainLiveSession{
			Projection: projection, Session: session,
			NegotiatedCapabilities: append([]string(nil), welcome.Capabilities...), Send: writer.Send,
		}
		if err = t.drain.RegisterSession(ctx, live); err != nil {
			return err
		}
		defer t.drain.DetachSession(session.Reference())
	}

	for {
		frame, readErr := ReadFrame(stream)
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, context.Canceled) || ctx.Err() != nil {
				return nil
			}
			return readErr
		}
		response, terminal, handleErr := handleControlFrame(ctx, session, t.rotation, frame)
		if handleErr != nil {
			_ = writeControlReject(ctx, writer, session.Reference(), hello.AccountID, frame.RequestID, handleErr)
			return handleErr
		}
		if response != nil {
			if err = writer.Send(ctx, *response); err != nil {
				return err
			}
		}
		if terminal {
			if frame.Type == MessageDisconnect {
				var disconnect Disconnect
				if frame.DecodePayload(&disconnect) == nil {
					closeReason = disconnect.Reason
				}
			}
			return nil
		}
	}
}

func handleControlFrame(ctx context.Context, session *PersistentSession, rotation *RotationDispatcher, frame Frame) (*Frame, bool, error) {
	if ctx == nil || session == nil {
		return nil, false, ErrInvalidInput
	}
	switch frame.Type {
	case MessageAck:
		var value Ack
		if err := frame.DecodePayload(&value); err != nil {
			return nil, false, err
		}
		return nil, false, session.HandleAck(ctx, value)
	case MessageReady:
		var value Readiness
		if err := frame.DecodePayload(&value); err != nil {
			return nil, false, err
		}
		ack, err := session.HandleReadiness(ctx, value)
		if err != nil {
			return nil, false, err
		}
		response, err := NewFrame(MessageAck, frame.RequestID, ack)
		return &response, false, err
	case MessageHeartbeat:
		var value Heartbeat
		if err := frame.DecodePayload(&value); err != nil {
			return nil, false, err
		}
		ack, err := session.HandleHeartbeat(ctx, value)
		if err != nil {
			return nil, false, err
		}
		response, err := NewFrame(MessageHeartbeatAck, frame.RequestID, ack)
		return &response, false, err
	case MessageAuthRenew:
		var value RenewalRequest
		if err := frame.DecodePayload(&value); err != nil {
			return nil, false, err
		}
		result, err := session.Renew(ctx, value)
		if err != nil {
			return nil, false, err
		}
		response, err := NewFrame(MessageAuthRenewed, frame.RequestID, result)
		return &response, false, err
	case MessageDrainAck:
		var value DrainAck
		if err := frame.DecodePayload(&value); err != nil {
			return nil, false, err
		}
		return nil, false, session.HandleDrainAck(ctx, value)
	case MessageCredentialRotationProof, MessageCredentialRotationReady, MessageCredentialRotationAck:
		if rotation == nil {
			return nil, false, codeError(ErrUnsupportedMessage, ReasonCredentialRotation, false, nil)
		}
		return nil, false, rotation.HandleFrame(ctx, session.Reference(), frame)
	case MessageDisconnect:
		var value Disconnect
		if err := frame.DecodePayload(&value); err != nil {
			return nil, false, err
		}
		ref := session.Reference()
		if value.TunnelID != ref.TunnelID || value.ConnectorID != ref.ConnectorID || value.SessionID != ref.SessionID || value.ProcessGeneration != ref.ProcessGeneration {
			return nil, false, codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
		}
		return nil, true, nil
	default:
		return nil, false, codeError(ErrUnsupportedMessage, ReasonProtocolMismatch, false, nil)
	}
}

type serializedFrameWriter struct {
	writer io.Writer
	gate   chan struct{}
}

func newSerializedFrameWriter(writer io.Writer) *serializedFrameWriter {
	value := &serializedFrameWriter{writer: writer, gate: make(chan struct{}, 1)}
	value.gate <- struct{}{}
	return value
}

func (w *serializedFrameWriter) Send(ctx context.Context, frame Frame) error {
	if w == nil || w.writer == nil || ctx == nil {
		return ErrInvalidInput
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.gate:
	}
	defer func() { w.gate <- struct{}{} }()
	if deadline, ok := ctx.Deadline(); ok {
		if connection, ok := w.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
			if err := connection.SetWriteDeadline(deadline); err != nil {
				return err
			}
			defer connection.SetWriteDeadline(time.Time{})
		}
	}
	return WriteFrame(w.writer, frame)
}

func writeControlReject(ctx context.Context, writer *serializedFrameWriter, ref SessionRef, accountID, requestID string, cause error) error {
	code := CodeOf(cause)
	if code == "" {
		code = CodeSessionClosed
	}
	reason := ReasonOf(cause)
	if reason == "" {
		reason = ReasonProtocolClosed
	}
	retryable := false
	var typed *Error
	if errors.As(cause, &typed) {
		retryable = typed.Retryable
	}
	reject := Reject{AccountID: accountID, TunnelID: ref.TunnelID, ConnectorID: ref.ConnectorID, SessionID: ref.SessionID, ProcessGeneration: ref.ProcessGeneration, Code: code, Reason: reason, Retryable: retryable}
	frame, err := NewFrame(MessageReject, requestID, reject)
	if err != nil {
		return err
	}
	return writer.Send(ctx, frame)
}
