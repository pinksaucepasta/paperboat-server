package terminalsessions

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestPostControlDecodesOperationAndProtocolResponse(t *testing.T) {
	service := &Service{http: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/paperboat/terminal-sessions/control" {
			t.Fatalf("request = %s %s", request.Method, request.URL)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != `{"proof":"signed-proof"}` {
			t.Fatalf("body = %s", body)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString(`{"operation":"close","terminals":[]}`)),
		}, nil
	})}}

	response, err := service.postControl(context.Background(), "https://route.example.test", "signed-proof")
	if err != nil {
		t.Fatal(err)
	}
	if response.Operation != "close" || len(response.Terminals) != 0 {
		t.Fatalf("response = %#v", response)
	}
}

func TestRequireControlOperationRejectsMismatchedResponse(t *testing.T) {
	if err := requireControlOperation(terminalControlResponse{Operation: "snapshot"}, "delete_history"); err == nil {
		t.Fatal("expected mismatched operation error")
	}
	if err := requireControlOperation(terminalControlResponse{Operation: "delete_history"}, "delete_history"); err != nil {
		t.Fatal(err)
	}
}
