package connectorprotocol

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestWebSocketHandlerRunsCanonicalControlSession(t *testing.T) {
	now := time.Date(2026, 8, 31, 9, 30, 0, 0, time.UTC)
	auth, private := testAuth(t, now, 1)
	snapshot, err := NewSnapshot(auth.TunnelID, 1, testConfigPayload(1, "app.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	store := &persistenceStoreStub{authResult: AuthResult{
		AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID,
		HostID: auth.HostID, IdentityKeyID: auth.IdentityKeyID, IdentityKeyThumbprint: auth.IdentityKeyThumbprint,
		ProcessGeneration: 1, CredentialGeneration: auth.CredentialGeneration,
		CredentialExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Hour),
	}, snapshot: snapshot}
	persistent, err := NewPersistentServer(store, IdentityProofVerifierFuncs{
		AuthFunc: func(_ context.Context, _ AuthRequest, payload, signature []byte) error {
			if !ed25519.Verify(private.Public().(ed25519.PublicKey), payload, signature) {
				return ErrAuthenticationFailed
			}
			return nil
		},
		RenewalFunc: func(context.Context, RenewalRequest, []byte, []byte) error { return nil },
	}, ServerConfig{
		Capabilities: requiredCapabilityList(), Clock: &testClock{now: now},
		LeaseDuration: time.Minute, HeartbeatInterval: 10 * time.Second,
		SessionIDs: func() (string, error) { return "session_websocket_01", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewControlTransport(persistent, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewWebSocketHandler(transport)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /v1/tunnels/{tunnel_id}/connectors/{connector_id}/control", handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/tunnels/" + auth.TunnelID + "/connectors/" + auth.ConnectorID + "/control"
	connection, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{Subprotocols: []string{ControlWebSocketSubprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	stream := websocket.NetConn(ctx, connection, websocket.MessageBinary)
	defer stream.Close()

	hello := Hello{
		Protocol: ProtocolName, MinVersion: ProtocolVersion, MaxVersion: ProtocolVersion,
		AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID,
		HostID: auth.HostID, ProcessGeneration: 1, Capabilities: requiredCapabilityList(), Auth: auth,
	}
	frame, err := NewFrame(MessageHello, "hello_websocket_01", hello)
	if err != nil {
		t.Fatal(err)
	}
	if err = WriteFrame(stream, frame); err != nil {
		t.Fatal(err)
	}
	welcomeFrame, err := ReadFrame(stream)
	if err != nil || welcomeFrame.Type != MessageWelcome {
		t.Fatalf("welcome frame=%+v err=%v", welcomeFrame, err)
	}
	var welcome Welcome
	if err = welcomeFrame.DecodePayload(&welcome); err != nil {
		t.Fatal(err)
	}
	snapshotFrame, err := ReadFrame(stream)
	if err != nil || snapshotFrame.Type != MessageSnapshot {
		t.Fatalf("snapshot frame=%+v err=%v", snapshotFrame, err)
	}
	disconnect := Disconnect{
		AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID,
		SessionID: welcome.SessionID, ProcessGeneration: 1, Reason: ReasonProtocolClosed,
	}
	frame, err = NewFrame(MessageDisconnect, "disconnect_websocket_01", disconnect)
	if err != nil {
		t.Fatal(err)
	}
	if err = WriteFrame(stream, frame); err != nil {
		t.Fatal(err)
	}
	// Wait for the HTTP handler and its deferred durable disconnect write to
	// finish before inspecting the intentionally simple persistence test stub.
	// httptest.Server.Close blocks until active handlers have returned.
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	server.Close()
	if len(store.created) != 1 || len(store.disconnect) != 1 {
		t.Fatalf("created=%d disconnected=%d", len(store.created), len(store.disconnect))
	}
}

func TestWebSocketHandlerRejectsQueryCredentialsBeforeUpgrade(t *testing.T) {
	handler := &WebSocketHandler{transport: &ControlTransport{}}
	request := httptest.NewRequest(http.MethodGet, "/v1/tunnels/tunnel_01/connectors/connector_01/control?token=secret", nil)
	request.SetPathValue("tunnel_id", "tunnel_01")
	request.SetPathValue("connector_id", "connector_01")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", response.Code)
	}
}
