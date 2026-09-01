package previewdispatch

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
)

type testRouteResolver struct {
	route MachineRoute
	err   error
	calls int
}

func (r *testRouteResolver) ResolvePreviewDispatchRoute(context.Context, string, string) (MachineRoute, error) {
	r.calls++
	return r.route, r.err
}

func testDispatchRequest() previewv1.DispatchRequest {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	request := previewv1.DispatchRequest{
		Schema: previewv1.Schema, Kind: previewv1.PreviewDispatchKind,
		PreviewID: "prv_1", OperationID: "operation_1", AccountID: "acct_1", ActorID: "user_1",
		OwnerDeviceID: "machine_1", OwnerSessionID: "session_1",
		Target: previewv1.Target{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "public",
		Endpoint: "https://preview-abc.preview.example.test", LeaseDeadline: now.Add(time.Hour),
		LeaseETag: previewtunnelapi.ETag(previewv1.Kind, "prv_1", 1), State: "allocating",
		AllocationState: "pending", EdgeState: "pending", OriginState: "unknown",
		CreatedAt: now, LastRenewedAt: now, ExpectedGeneration: 1,
		IdempotencyKey: "create_1", RequestID: "req_1", CorrelationID: "cor_1",
	}
	hash, err := request.ComputeRequestHash()
	if err != nil {
		panic(err)
	}
	request.RequestHash = hash
	return request
}

func TestDecodeOutcomeRejectsOversizedWhitespace(t *testing.T) {
	request := testDispatchRequest()
	body, err := json.Marshal(previewv1.DispatchOutcome{
		Schema: previewv1.Schema, Kind: previewv1.PreviewDispatchKind,
		PreviewID: request.PreviewID, OperationID: request.OperationID,
		State: "accepted", Generation: request.ExpectedGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, []byte(strings.Repeat(" ", maxResponse))...)
	_, err = decodeOutcome(strings.NewReader(string(body)), request, 200)
	var dispatchErr *DispatchError
	if !errors.As(err, &dispatchErr) || dispatchErr.Code != "remote_invalid_response" {
		t.Fatalf("error = %v, want bounded invalid response", err)
	}
}

func TestDecodeOutcomeRejectsDuplicateOperationID(t *testing.T) {
	request := testDispatchRequest()
	body := `{"schema":"paperboat.preview-tunnel/v1","kind":"preview_dispatch","preview_id":"prv_1","operation_id":"operation_1","operation_id":"operation_other","state":"accepted","generation":1}`
	_, err := decodeOutcome(strings.NewReader(body), request, 200)
	var dispatchErr *DispatchError
	if !errors.As(err, &dispatchErr) || dispatchErr.Code != "remote_invalid_response" {
		t.Fatalf("error = %v, want duplicate-field rejection", err)
	}
}

func TestDispatchMintsExactSingleOperationCredentialAndPostsCanonicalRequest(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	request := testDispatchRequest()
	provider, err := mint.NewEphemeral(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var gotBody []byte
	var gotToken string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		if incoming.Method != http.MethodPost || incoming.URL.Path != "/v1/preview-launches" {
			t.Errorf("request = %s %s", incoming.Method, incoming.URL.Path)
		}
		gotToken = strings.TrimPrefix(incoming.Header.Get("Authorization"), "Bearer ")
		gotBody, _ = io.ReadAll(incoming.Body)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(previewv1.DispatchOutcome{Schema: previewv1.Schema, Kind: previewv1.PreviewDispatchKind, PreviewID: request.PreviewID, OperationID: request.OperationID, State: "accepted", Generation: request.ExpectedGeneration})
	}))
	defer server.Close()
	resolver := &testRouteResolver{route: MachineRoute{EnvironmentID: "env_1", BaseURL: server.URL}}
	dispatcher, err := New(Config{Resolver: resolver, Signer: provider, Issuer: "issuer", Client: server.Client(), Timeout: time.Second, Now: func() time.Time { return now }, NewJTI: func() (string, error) { return "jti_preview_1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := dispatcher.Dispatch(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.State != "accepted" || resolver.calls != 1 || len(gotBody) == 0 || gotToken == "" {
		t.Fatalf("outcome=%#v resolver_calls=%d body=%d token=%t", outcome, resolver.calls, len(gotBody), gotToken != "")
	}
	var posted previewv1.DispatchRequest
	if err := json.Unmarshal(gotBody, &posted); err != nil {
		t.Fatal(err)
	}
	if posted != request {
		t.Fatalf("posted request changed canonical projection: got=%#v want=%#v", posted, request)
	}
	claims, err := provider.VerifyCredential(gotToken, "issuer", "preview_launch", now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.AccountID != request.AccountID || claims.ActorID != request.ActorID || claims.MachineID != request.OwnerDeviceID || claims.PreviewID != request.PreviewID || claims.OperationID != request.OperationID || claims.OwnerSessionID != request.OwnerSessionID || claims.ExpectedGeneration != request.ExpectedGeneration || claims.IdempotencyKey != request.IdempotencyKey || claims.RequestID != request.RequestID || claims.CorrelationID != request.CorrelationID || claims.RequestHash != request.RequestHash {
		t.Fatalf("credential claims do not bind request: %#v", claims)
	}
	if claims.Endpoint != request.Endpoint || claims.TargetAddress != request.Target.Address {
		t.Fatalf("credential did not carry the exact safe bindings: endpoint=%q target=%q", claims.Endpoint, claims.TargetAddress)
	}
}

func TestDispatchClassifiesOfflineAndTimeoutAsTypedOutcomes(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	request := testDispatchRequest()
	provider, err := mint.NewEphemeral(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	offlineResolver := &testRouteResolver{err: ErrMachineOffline}
	dispatcher, err := New(Config{Resolver: offlineResolver, Signer: provider, Issuer: "issuer", Timeout: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = dispatcher.Dispatch(context.Background(), request)
	var offline *DispatchError
	if !errors.As(err, &offline) || offline.Code != "machine_unavailable" || offline.Uncertain {
		t.Fatalf("offline error = %#v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		startOnce.Do(func() { close(started) })
		<-release
	}))
	defer server.Close()
	timeoutDispatcher, err := New(Config{Resolver: &testRouteResolver{route: MachineRoute{EnvironmentID: "env_1", BaseURL: server.URL}}, Signer: provider, Issuer: "issuer", Client: server.Client(), Timeout: 20 * time.Millisecond, Now: func() time.Time { return now }, NewJTI: func() (string, error) { return "jti_timeout", nil }})
	if err != nil {
		t.Fatal(err)
	}
	dispatchDone := make(chan error, 1)
	go func() {
		_, dispatchErr := timeoutDispatcher.Dispatch(context.Background(), request)
		dispatchDone <- dispatchErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timeout request did not reach the test server")
	}
	err = <-dispatchDone
	close(release)
	var timeoutErr *DispatchError
	if !errors.As(err, &timeoutErr) || timeoutErr.Code != "timeout" || !timeoutErr.Uncertain || !errors.Is(err, previewv1.ErrDispatchUncertain) {
		t.Fatalf("timeout error = %#v", err)
	}
	if strings.Contains(err.Error(), "jti_timeout") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("timeout error leaked sensitive transport material: %v", err)
	}
}

func TestDispatchRejectsRedirectWithoutForwardingBearer(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	request := testDispatchRequest()
	provider, err := mint.NewEphemeral(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	forwarded := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		forwarded <- incoming.Header.Get("Authorization")
		writer.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		http.Redirect(writer, incoming, target.URL+"/v1/preview-launches", http.StatusFound)
	}))
	defer redirect.Close()
	dispatcher, err := New(Config{Resolver: &testRouteResolver{route: MachineRoute{EnvironmentID: "env_1", BaseURL: redirect.URL}}, Signer: provider, Issuer: "issuer", Client: redirect.Client(), Timeout: time.Second, Now: func() time.Time { return now }, NewJTI: func() (string, error) { return "jti_redirect", nil }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = dispatcher.Dispatch(context.Background(), request)
	var dispatchErr *DispatchError
	if !errors.As(err, &dispatchErr) || !dispatchErr.Uncertain {
		t.Fatalf("redirect error = %#v", err)
	}
	select {
	case bearer := <-forwarded:
		t.Fatalf("redirect forwarded bearer %q", bearer)
	default:
	}
}
