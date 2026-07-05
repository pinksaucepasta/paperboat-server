package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

type readinessFunc func(context.Context) error

func (f readinessFunc) Ready(ctx context.Context) error {
	return f(ctx)
}

func TestHealthDoesNotRequireReadiness(t *testing.T) {
	router := NewRouter(Options{
		Config: config.Default(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessChecker: readinessFunc(func(context.Context) error {
			return errors.New("not ready")
		}),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Request-Id") == "" {
		t.Fatal("missing request id")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing secure headers")
	}
}

func TestReadyReflectsDependencyState(t *testing.T) {
	router := NewRouter(Options{
		Config: config.Default(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessChecker: readinessFunc(func(context.Context) error {
			return errors.New("db down")
		}),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error.Code != "provider_unavailable" {
		t.Fatalf("error code = %q", payload.Error.Code)
	}
}

func TestCORSAllowsConfiguredOrigins(t *testing.T) {
	cfg := config.Default()
	cfg.HTTP.AllowedOrigins = []string{"https://dashboard.example"}
	router := NewRouter(Options{
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessChecker: readinessFunc(func(context.Context) error {
			return nil
		}),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/api/projects", strings.NewReader(""))
	req.Header.Set("Origin", "https://dashboard.example")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example" {
		t.Fatalf("allow origin = %q", got)
	}
}

func TestUnknownEndpointIsStructuredError(t *testing.T) {
	router := NewRouter(Options{
		Config: config.Default(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessChecker: readinessFunc(func(context.Context) error {
			return nil
		}),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("expected structured error, got %s", rec.Body.String())
	}
}

func TestTimeoutUsesStructuredError(t *testing.T) {
	handler := requestID(timeout(time.Nanosecond, slog.New(slog.NewTextHandler(io.Discard, nil)), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/slow", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error.Code != "provider_unavailable" {
		t.Fatalf("error code = %q", payload.Error.Code)
	}
	if payload.Error.RequestID == "" {
		t.Fatal("missing request id in timeout response")
	}
}

func TestTimeoutIsolatesLateHandlerHeaders(t *testing.T) {
	releaseHandler := make(chan struct{})
	handlerDone := make(chan struct{})
	handler := requestID(timeout(time.Nanosecond, slog.New(slog.NewTextHandler(io.Discard, nil)), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		<-r.Context().Done()
		<-releaseHandler
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Late-Header", "ignored")
		if _, err := w.Write([]byte("late")); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("late write error = %v, want context deadline exceeded", err)
		}
	})))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/slow", nil)
	handler.ServeHTTP(rec, req)
	close(releaseHandler)
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish after timeout")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
	if got := rec.Header().Get("X-Late-Header"); got != "" {
		t.Fatalf("late header leaked into response: %q", got)
	}
}

func TestTimeoutRecoversHandlerPanic(t *testing.T) {
	handler := requestID(timeout(time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error.Code != "internal_error" {
		t.Fatalf("error code = %q", payload.Error.Code)
	}
	if payload.Error.RequestID == "" {
		t.Fatal("missing request id in panic response")
	}
}

func TestTimeoutDoesNotBufferStreamingResponse(t *testing.T) {
	handlerDone := make(chan struct{})
	handler := requestID(timeout(10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("event: ready\n\n")); err != nil {
			t.Errorf("write stream event: %v", err)
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	})))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	req.Header.Set("Accept", "text/event-stream")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "event: ready\n\n" {
		t.Fatalf("body = %q", got)
	}
	if !rec.Flushed {
		t.Fatal("streaming response was not flushed")
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("streaming handler did not complete")
	}
}

func TestTimeoutBypassesStreamingRequestDeadline(t *testing.T) {
	handler := requestID(timeout(time.Nanosecond, slog.New(slog.NewTextHandler(io.Discard, nil)), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			t.Fatal("streaming request context was canceled by request timeout")
		default:
		}
		w.WriteHeader(http.StatusOK)
	})))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	req.Header.Set("Accept", "text/event-stream")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestRouterPreservesStreamingFlushSupport(t *testing.T) {
	cfg := config.Default()
	cfg.HTTP.RequestTimeout = time.Nanosecond
	router := NewRouter(Options{
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessChecker: readinessFunc(func(context.Context) error {
			return nil
		}),
		OverrideHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("event: ready\n\n")); err != nil {
				t.Errorf("write stream event: %v", err)
			}
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("response writer does not expose http.Flusher")
			}
			flusher.Flush()
		}),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	req.Header.Set("Accept", "text/event-stream")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "event: ready\n\n" {
		t.Fatalf("body = %q", got)
	}
	if !rec.Flushed {
		t.Fatal("streaming response was not flushed through router stack")
	}
}
