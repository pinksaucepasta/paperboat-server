package connectorprotocol

import (
	"net/http"

	"github.com/coder/websocket"
)

const ControlWebSocketSubprotocol = "paperboat.connector.v1"

// WebSocketHandler adapts HTTPS upgrade requests to the byte-stream control
// transport. Connector-v1 authentication remains inside the signed Hello; no
// browser origin, cookie, query credential, or bearer fallback is accepted.
type WebSocketHandler struct {
	transport *ControlTransport
}

func NewWebSocketHandler(transport *ControlTransport) (*WebSocketHandler, error) {
	if transport == nil {
		return nil, ErrInvalidInput
	}
	return &WebSocketHandler{transport: transport}, nil
}

func (h *WebSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.transport == nil || r.Method != http.MethodGet {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	tunnelID, connectorID := r.PathValue("tunnel_id"), r.PathValue("connector_id")
	if ValidateIdentifier(tunnelID) != nil || ValidateIdentifier(connectorID) != nil || r.URL.RawQuery != "" {
		http.Error(w, "invalid connector control request", http.StatusBadRequest)
		return
	}
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{ControlWebSocketSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	if connection.Subprotocol() != ControlWebSocketSubprotocol {
		_ = connection.Close(websocket.StatusPolicyViolation, "connector subprotocol required")
		return
	}
	connection.SetReadLimit(MaxFrameBytes + 4)
	stream := websocket.NetConn(r.Context(), connection, websocket.MessageBinary)
	if err = h.transport.Serve(r.Context(), stream, tunnelID, connectorID); err != nil {
		_ = connection.Close(websocket.StatusPolicyViolation, "connector control rejected")
		return
	}
	_ = connection.Close(websocket.StatusNormalClosure, "connector control closed")
}
