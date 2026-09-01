package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

type fakePreviewTunnelAPI struct {
	operation previewtunnelapi.Operation
	events    previewtunnelapi.EventPage
	err       error
	request   previewtunnelapi.RequestContext
	cancel    context.CancelFunc
}

func (f *fakePreviewTunnelAPI) GetOperation(_ context.Context, request previewtunnelapi.RequestContext, _ string) (previewtunnelapi.Operation, error) {
	f.request = request
	return f.operation, f.err
}

func (f *fakePreviewTunnelAPI) CancelOperation(_ context.Context, request previewtunnelapi.RequestContext, _ string) (previewtunnelapi.Operation, error) {
	f.request = request
	return f.operation, f.err
}

func (f *fakePreviewTunnelAPI) ListEvents(_ context.Context, request previewtunnelapi.RequestContext, _, _, _ string, _ int) (previewtunnelapi.EventPage, error) {
	f.request = request
	if f.cancel != nil {
		f.cancel()
	}
	return f.events, f.err
}

func TestPreviewTunnelOperationHandlerPropagatesIdentity(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	service := &fakePreviewTunnelAPI{operation: previewtunnelapi.Operation{
		Schema: "paperboat.preview-tunnel/v1", Kind: "operation", ID: "op_1", ResourceKind: "tunnel",
		ResourceID: "tun_1", Phase: "ready", State: "succeeded", Progress: 100,
		CorrelationID: "corr_1", CreatedAt: now, UpdatedAt: now,
	}}
	req := httptest.NewRequest(http.MethodGet, "/v1/operations/op_1", nil)
	req.SetPathValue("operation_id", "op_1")
	client := auth.ClientPrincipal{SessionID: "device_1", Scopes: []string{"operations:read"}}
	ctx := context.WithValue(req.Context(), authContextKey{}, principal{
		User: auth.User{ID: "acct_1", Role: auth.RoleUser}, Client: &client,
	})
	ctx = observability.WithRequestID(ctx, "req_1")
	ctx = observability.WithCorrelationID(ctx, "corr_1")
	rec := httptest.NewRecorder()
	previewTunnelOperationGet(service).ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if service.request.Actor.AccountID != "acct_1" || service.request.Actor.DeviceID != "device_1" || service.request.CorrelationID != "corr_1" {
		t.Fatalf("request context = %#v", service.request)
	}
}

func TestPreviewTunnelOperationHandlerReturnsTypedConflict(t *testing.T) {
	service := &fakePreviewTunnelAPI{err: previewtunnelapi.ErrOperationNotCancellable}
	req := httptest.NewRequest(http.MethodDelete, "/v1/operations/op_1", nil)
	req.SetPathValue("operation_id", "op_1")
	ctx := context.WithValue(req.Context(), authContextKey{}, principal{User: auth.User{ID: "acct_1", Role: auth.RoleUser}})
	ctx = observability.WithRequestID(ctx, "req_1")
	ctx = observability.WithCorrelationID(ctx, "corr_1")
	rec := httptest.NewRecorder()
	previewTunnelOperationCancel(service).ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != "operation_not_cancellable" || response.Error.Outcome != "uncertain" || response.Error.CorrelationID != "corr_1" || response.Error.Retryable == nil || *response.Error.Retryable {
		t.Fatalf("error = %#v", response.Error)
	}
}

func TestPreviewTunnelScopeAndCorrelationMiddleware(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if observability.CorrelationID(r.Context()) != "corr_1" {
			t.Fatalf("correlation ID = %q", observability.CorrelationID(r.Context()))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	client := auth.ClientPrincipal{Scopes: []string{"operations:read"}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Correlation-Id", "corr_1")
	ctx := context.WithValue(req.Context(), authContextKey{}, principal{User: auth.User{ID: "acct_1"}, Client: &client})
	rec := httptest.NewRecorder()
	requestID(correlationID(requireScope("operations:write", next))).ServeHTTP(rec, req.WithContext(ctx))
	if called || rec.Code != http.StatusForbidden {
		t.Fatalf("called = %v, status = %d", called, rec.Code)
	}

	client.Scopes = []string{"operations:write"}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Correlation-Id", "corr_1")
	ctx = context.WithValue(req.Context(), authContextKey{}, principal{User: auth.User{ID: "acct_1"}, Client: &client})
	rec = httptest.NewRecorder()
	requestID(correlationID(requireScope("operations:write", next))).ServeHTTP(rec, req.WithContext(ctx))
	if !called || rec.Code != http.StatusNoContent || rec.Header().Get("Correlation-Id") != "corr_1" {
		t.Fatalf("called = %v, status = %d, correlation = %q", called, rec.Code, rec.Header().Get("Correlation-Id"))
	}
}

func TestPreviewTunnelServiceErrorDoesNotExposeCause(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := observability.WithRequestID(req.Context(), "req_1")
	ctx = observability.WithCorrelationID(ctx, "corr_1")
	rec := httptest.NewRecorder()
	writePreviewTunnelServiceError(rec, req.WithContext(ctx), errors.New("Bearer should-never-leak"))
	if rec.Code != http.StatusInternalServerError || rec.Body.String() == "" {
		t.Fatalf("status = %d", rec.Code)
	}
	if json.Valid(rec.Body.Bytes()) == false {
		t.Fatalf("invalid JSON: %s", rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("should-never-leak")) {
		t.Fatalf("cause leaked: %s", rec.Body.String())
	}
}

func TestPreviewTunnelEventsReturnsJSONPage(t *testing.T) {
	service := &fakePreviewTunnelAPI{events: previewtunnelapi.EventPage{Items: []previewtunnelapi.Event{{
		Schema: "paperboat.preview-tunnel/v1", Kind: "event", ID: "evt_1", Cursor: "cur_1",
		EventType: "preview.created", ResourceKind: "preview_lease", ResourceID: "prv_1",
		OccurredAt: time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC),
		Actor:      previewtunnelapi.EventActor{Type: "user", ID: "acct_1"}, CorrelationID: "corr_1",
		SafeMetadata: map[string]any{"generation": 1},
	}}}}
	req := httptest.NewRequest(http.MethodGet, "/v1/previews/prv_1/events?limit=10", nil)
	req.SetPathValue("preview_id", "prv_1")
	ctx := context.WithValue(req.Context(), authContextKey{}, principal{User: auth.User{ID: "acct_1", Role: auth.RoleUser}})
	rec := httptest.NewRecorder()
	previewTunnelEvents(service, "preview_lease", "preview_id").ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"event_type":"preview.created"`)) {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestPreviewTunnelEventsStreamsAndResumes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	service := &fakePreviewTunnelAPI{cancel: cancel, events: previewtunnelapi.EventPage{Items: []previewtunnelapi.Event{{
		Schema: "paperboat.preview-tunnel/v1", Kind: "event", ID: "evt_1", Cursor: "cur_2",
		EventType: "tunnel.paused", ResourceKind: "tunnel", ResourceID: "tun_1",
		OccurredAt: time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC),
		Actor:      previewtunnelapi.EventActor{Type: "host", ID: "host_1"}, CorrelationID: "corr_1",
		SafeMetadata: map[string]any{"generation": 2},
	}}}}
	req := httptest.NewRequest(http.MethodGet, "/v1/tunnels/tun_1/events?cursor=cur_1", nil).WithContext(ctx)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Last-Event-ID", "cur_1")
	req.SetPathValue("tunnel_id", "tun_1")
	authCtx := context.WithValue(req.Context(), authContextKey{}, principal{User: auth.User{ID: "acct_1", Role: auth.RoleUser}})
	rec := httptest.NewRecorder()
	previewTunnelEvents(service, "tunnel", "tunnel_id").ServeHTTP(rec, req.WithContext(authCtx))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/event-stream; charset=utf-8" || !rec.Flushed {
		t.Fatalf("status = %d, content-type = %q, flushed = %v", rec.Code, rec.Header().Get("Content-Type"), rec.Flushed)
	}
	if body := rec.Body.String(); !strings.Contains(body, "id: cur_2\n") || !strings.Contains(body, `"event_type":"tunnel.paused"`) {
		t.Fatalf("stream body = %q", body)
	}
}

func TestPreviewTunnelEventsRejectsConflictingResumeCursors(t *testing.T) {
	service := &fakePreviewTunnelAPI{}
	req := httptest.NewRequest(http.MethodGet, "/v1/tunnels/tun_1/events?cursor=cur_1", nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Last-Event-ID", "cur_other")
	req.SetPathValue("tunnel_id", "tun_1")
	ctx := context.WithValue(req.Context(), authContextKey{}, principal{User: auth.User{ID: "acct_1", Role: auth.RoleUser}})
	rec := httptest.NewRecorder()
	previewTunnelEvents(service, "tunnel", "tunnel_id").ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte(`"code":"invalid_cursor"`)) {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}
