package helperruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coder/websocket"
)

func TestTerminalCloseRequiresMatchingCanonicalHelperAcknowledgement(t *testing.T) {
	requests := make(chan frame, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/runtime" || request.Header.Get("Authorization") != "Bearer signed-operation" {
			http.Error(writer, "invalid request", http.StatusUnauthorized)
			return
		}
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{subprotocol}})
		if err != nil {
			return
		}
		defer connection.Close(websocket.StatusNormalClosure, "complete")
		hello, err := readFrame(request.Context(), connection)
		if err != nil {
			return
		}
		welcome, _ := json.Marshal(map[string]any{"version": protocolVersion, "capabilities": []string{"terminal.v1", "health.v1"}})
		if writeFrame(request.Context(), connection, frame{Type: "welcome", RequestID: hello.RequestID, Version: protocolVersion, Payload: welcome}) != nil {
			return
		}
		operation, err := readFrame(request.Context(), connection)
		if err != nil {
			return
		}
		requests <- operation
		payload := json.RawMessage(`{"result":{"id":"pts_1","name":"agent","cwd":"/workspace","dimensions":{"columns":80,"rows":24},"state":"closed","generation":1,"earliest_sequence":0,"latest_sequence":12,"exit":{"code":0,"signal":"SIGTERM","exited_at":"2026-07-22T16:00:00Z"}},"replay":false}`)
		_ = writeFrame(request.Context(), connection, frame{Type: "response", RequestID: operation.RequestID, Version: protocolVersion, Payload: payload})
	}))
	defer server.Close()

	observed, err := (Client{HTTPClient: server.Client()}).Terminal(context.Background(), server.URL, "signed-operation", "close", "pts_1", "tso_00000001")
	if err != nil {
		t.Fatal(err)
	}
	if observed.ID != "pts_1" || observed.State != "closed" || observed.CWD != "/workspace" || observed.LatestSequence != 12 || observed.Dimensions.Columns != 80 || observed.Exit == nil || observed.Exit.Signal != "SIGTERM" {
		t.Fatalf("observed = %#v", observed)
	}
	operation := <-requests
	if operation.Type != "request" || operation.Capability != "terminal.v1" || operation.OperationID != "tso_00000001" {
		t.Fatalf("operation = %#v", operation)
	}
	var payload struct {
		Action    string `json:"action"`
		SessionID string `json:"session_id"`
	}
	if decodeStrict(operation.Payload, &payload) != nil || payload.Action != "close" || payload.SessionID != "pts_1" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestTerminalRejectsMismatchedAcknowledgement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{subprotocol}})
		if err != nil {
			return
		}
		defer connection.Close(websocket.StatusNormalClosure, "complete")
		hello, _ := readFrame(request.Context(), connection)
		welcome, _ := json.Marshal(map[string]any{"version": protocolVersion, "capabilities": []string{"terminal.v1", "health.v1"}})
		_ = writeFrame(request.Context(), connection, frame{Type: "welcome", RequestID: hello.RequestID, Version: protocolVersion, Payload: welcome})
		operation, _ := readFrame(request.Context(), connection)
		payload := json.RawMessage(`{"result":{"id":"pts_other","name":"agent","cwd":"/workspace","dimensions":{"columns":80,"rows":24},"state":"closed","generation":1,"earliest_sequence":0,"latest_sequence":0,"exit":{"code":0,"exited_at":"2026-07-22T16:00:00Z"}},"replay":false}`)
		_ = writeFrame(request.Context(), connection, frame{Type: "response", RequestID: operation.RequestID, Version: protocolVersion, Payload: payload})
	}))
	defer server.Close()

	if _, err := (Client{HTTPClient: server.Client()}).Terminal(context.Background(), server.URL, "signed-operation", "close", "pts_1", "tso_00000001"); err == nil {
		t.Fatal("mismatched session acknowledgement accepted")
	}
}
