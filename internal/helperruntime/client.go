package helperruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	protocolVersion = "1.0"
	subprotocol     = "paperboat.helper.v1"
	maxFrameBytes   = 64 << 10
)

type Client struct {
	HTTPClient *http.Client
}

type Snapshot struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	CWD              string      `json:"cwd"`
	Dimensions       Dimensions  `json:"dimensions"`
	State            string      `json:"state"`
	Generation       uint64      `json:"generation"`
	EarliestSequence uint64      `json:"earliest_sequence"`
	LatestSequence   uint64      `json:"latest_sequence"`
	Exit             *ExitResult `json:"exit,omitempty"`
}

type Dimensions struct {
	Columns uint16 `json:"columns"`
	Rows    uint16 `json:"rows"`
}

type ExitResult struct {
	Code     int       `json:"code"`
	Signal   string    `json:"signal,omitempty"`
	ExitedAt time.Time `json:"exited_at"`
}

type frame struct {
	Type        string          `json:"type"`
	RequestID   string          `json:"request_id"`
	Version     string          `json:"version"`
	OperationID string          `json:"operation_id,omitempty"`
	Capability  string          `json:"capability,omitempty"`
	DeadlineMS  uint32          `json:"deadline_ms,omitempty"`
	Payload     json.RawMessage `json:"payload,omitempty"`
}

type remoteError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (e *remoteError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

func (c Client) Terminal(ctx context.Context, route, credential, action, sessionID, operationID string) (Snapshot, error) {
	endpoint, err := runtimeEndpoint(route)
	if err != nil || credential == "" || sessionID == "" || action == "" || operationID == "" {
		return Snapshot{}, errors.New("invalid helper runtime operation")
	}
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+credential)
	connection, response, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
		HTTPClient:   c.HTTPClient,
		HTTPHeader:   headers,
		Subprotocols: []string{subprotocol},
	})
	if err != nil {
		if response != nil {
			return Snapshot{}, fmt.Errorf("dial helper runtime: %w (status %d)", err, response.StatusCode)
		}
		return Snapshot{}, fmt.Errorf("dial helper runtime: %w", err)
	}
	defer connection.Close(websocket.StatusNormalClosure, "complete")
	connection.SetReadLimit(maxFrameBytes + 4)
	if connection.Subprotocol() != subprotocol {
		return Snapshot{}, errors.New("helper runtime did not negotiate required subprotocol")
	}

	helloID, err := randomID("req_")
	if err != nil {
		return Snapshot{}, err
	}
	helloPayload, _ := json.Marshal(map[string]any{
		"min_version": protocolVersion, "max_version": protocolVersion,
		"capabilities": []string{"terminal.v1", "health.v1"},
	})
	if err := writeFrame(ctx, connection, frame{Type: "hello", RequestID: helloID, Version: protocolVersion, Payload: helloPayload}); err != nil {
		return Snapshot{}, err
	}
	welcome, err := readFrame(ctx, connection)
	if err != nil {
		return Snapshot{}, err
	}
	if welcome.Type != "welcome" || welcome.RequestID != helloID {
		return Snapshot{}, errors.New("helper runtime returned an invalid welcome")
	}
	var negotiated struct {
		Version      string   `json:"version"`
		Capabilities []string `json:"capabilities"`
	}
	if decodeStrict(welcome.Payload, &negotiated) != nil || negotiated.Version != protocolVersion || !contains(negotiated.Capabilities, "terminal.v1") || !contains(negotiated.Capabilities, "health.v1") {
		return Snapshot{}, errors.New("helper runtime did not negotiate required capabilities")
	}

	requestID, err := randomID("req_")
	if err != nil {
		return Snapshot{}, err
	}
	payload, _ := json.Marshal(map[string]string{"action": action, "session_id": sessionID})
	deadline := uint32(30000)
	if remaining, ok := ctx.Deadline(); ok {
		milliseconds := time.Until(remaining).Milliseconds()
		if milliseconds < 1 {
			return Snapshot{}, context.DeadlineExceeded
		}
		if milliseconds < int64(deadline) {
			deadline = uint32(milliseconds)
		}
	}
	request := frame{Type: "request", RequestID: requestID, Version: protocolVersion, OperationID: operationID, Capability: "terminal.v1", DeadlineMS: deadline, Payload: payload}
	if err := writeFrame(ctx, connection, request); err != nil {
		return Snapshot{}, err
	}
	for {
		response, err := readFrame(ctx, connection)
		if err != nil {
			return Snapshot{}, err
		}
		if response.Type == "heartbeat" {
			if err := writeFrame(ctx, connection, response); err != nil {
				return Snapshot{}, err
			}
			continue
		}
		if response.RequestID != requestID {
			return Snapshot{}, errors.New("helper runtime response did not match request")
		}
		if response.Type == "error" {
			var remote remoteError
			if decodeStrict(response.Payload, &remote) != nil || remote.Code == "" {
				return Snapshot{}, errors.New("helper runtime returned an invalid error")
			}
			return Snapshot{}, &remote
		}
		if response.Type != "response" {
			return Snapshot{}, errors.New("helper runtime returned an invalid response")
		}
		var envelope struct {
			Result json.RawMessage `json:"result"`
			Replay bool            `json:"replay"`
		}
		if decodeStrict(response.Payload, &envelope) != nil {
			return Snapshot{}, errors.New("helper runtime returned an invalid terminal snapshot")
		}
		if action == "delete" {
			var empty struct{}
			if decodeStrict(envelope.Result, &empty) != nil {
				return Snapshot{}, errors.New("helper runtime returned an invalid delete acknowledgement")
			}
			return Snapshot{ID: sessionID, State: "deleted"}, nil
		}
		var snapshot Snapshot
		if decodeStrict(envelope.Result, &snapshot) != nil || snapshot.ID != sessionID {
			return Snapshot{}, errors.New("helper runtime returned an invalid terminal snapshot")
		}
		return snapshot, nil
	}
}

func runtimeEndpoint(route string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(route))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("invalid helper runtime route")
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/runtime"
	return u.String(), nil
}

func writeFrame(ctx context.Context, connection *websocket.Conn, value frame) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > maxFrameBytes {
		return errors.New("invalid helper runtime frame")
	}
	message := make([]byte, 4+len(encoded))
	binary.BigEndian.PutUint32(message[:4], uint32(len(encoded)))
	copy(message[4:], encoded)
	return connection.Write(ctx, websocket.MessageText, message)
}

func readFrame(ctx context.Context, connection *websocket.Conn) (frame, error) {
	typ, data, err := connection.Read(ctx)
	if err != nil {
		return frame{}, err
	}
	if typ != websocket.MessageText || len(data) < 5 || int(binary.BigEndian.Uint32(data[:4])) != len(data)-4 || len(data)-4 > maxFrameBytes {
		return frame{}, errors.New("invalid helper runtime frame")
	}
	var value frame
	if decodeStrict(data[4:], &value) != nil || value.Version != protocolVersion || value.Type == "" || value.RequestID == "" {
		return frame{}, errors.New("invalid helper runtime frame")
	}
	return value, nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func randomID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
