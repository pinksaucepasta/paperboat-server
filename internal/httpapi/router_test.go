package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
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

func TestNetworkCheckIsExactEmptyNoStoreResponse(t *testing.T) {
	router := NewRouter(Options{Config: config.Default(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/network-check/v1", nil))
	if recorder.Code != http.StatusNoContent || recorder.Body.Len() != 0 || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d body=%q cache=%q", recorder.Code, recorder.Body.String(), recorder.Header().Get("Cache-Control"))
	}
}

type probeRegionReaderFunc func(context.Context) ([]controlplane.ProbeRegion, error)

func (f probeRegionReaderFunc) ListProbeRegions(ctx context.Context) ([]controlplane.ProbeRegion, error) {
	return f(ctx)
}

func TestNetworkCheckRegionsReturnsOnlyReaderDocumentWithoutCaching(t *testing.T) {
	want := controlplane.ProbeRegion{RelayID: "pprbt-helsinki", Region: "helsinki", Name: "Helsinki", STUNURL: "stun:stun.example.test:3478", HTTPSURL: "https://relay.example.test/network-check/v1"}
	router := NewRouter(Options{
		Config: config.Default(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ProbeRegions: probeRegionReaderFunc(func(context.Context) ([]controlplane.ProbeRegion, error) {
			return []controlplane.ProbeRegion{want}, nil
		}),
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/network-check/regions/v1", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q body=%s", recorder.Code, recorder.Header().Get("Cache-Control"), recorder.Body.String())
	}
	var response struct {
		Data struct {
			Regions []controlplane.ProbeRegion `json:"regions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || len(response.Data.Regions) != 1 || response.Data.Regions[0] != want {
		t.Fatalf("response=%s err=%v", recorder.Body.String(), err)
	}
}

func TestNetworkCheckRegionsMapsReaderFailure(t *testing.T) {
	router := NewRouter(Options{
		Config: config.Default(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ProbeRegions: probeRegionReaderFunc(func(context.Context) ([]controlplane.ProbeRegion, error) {
			return nil, errors.New("database unavailable")
		}),
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/network-check/regions/v1", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestDiagnosticUploadUnavailableDoesNotFallThroughToEdgeControl(t *testing.T) {
	edge := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"code":"edge_control"}`))
	})
	router := NewRouter(Options{Config: config.Default(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), EdgeControl: edge})
	for _, path := range []string{"/v1/diagnostic-upload-intents", "/v1/diagnostic-upload-intents/diag_test/complete"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"code":"diagnostic_upload_unavailable"`) || strings.Contains(recorder.Body.String(), "edge_control") {
			t.Fatalf("path=%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestRetiredHostedEnvironmentAccesssAreNotRegistered(t *testing.T) {
	router := NewRouter(Options{Config: config.Default(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	for _, path := range []string{
		"/v1/projects/prj_retired/connect",
		"/v1/projects/prj_retired/helper-connect",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, nil)
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("POST %s status = %d, want unregistered-route 404", path, rec.Code)
		}
	}
}

func TestRequestIDRejectsUnsafeClientValue(t *testing.T) {
	router := NewRouter(Options{Config: config.Default(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Request-Id", "user supplied/path")
	router.ServeHTTP(rec, req)
	got := rec.Header().Get("Request-Id")
	if got == "" || got == "user supplied/path" {
		t.Fatalf("request id = %q", got)
	}
}

func TestMetricsAreLocalOnly(t *testing.T) {
	router := NewRouter(Options{Config: config.Default(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	local := httptest.NewRecorder()
	localReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	localReq.RemoteAddr = "127.0.0.1:1234"
	router.ServeHTTP(local, localReq)
	if local.Code != http.StatusOK || !strings.Contains(local.Body.String(), "device_requested_total") {
		t.Fatalf("local status = %d, body = %s", local.Code, local.Body.String())
	}
	remote := httptest.NewRecorder()
	remoteReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	remoteReq.RemoteAddr = "203.0.113.10:1234"
	router.ServeHTTP(remote, remoteReq)
	if remote.Code != http.StatusForbidden {
		t.Fatalf("remote status = %d, body = %s", remote.Code, remote.Body.String())
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
	req := httptest.NewRequest(http.MethodOptions, "/v1/projects", strings.NewReader(""))
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
	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
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

func TestPolarWebhookReturnsRetryableStatusForRetryableBillingError(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run webhook handler integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	body := []byte(`{"id":"evt_retryable_handler","type":"order.paid","data":{"external_user_id":"usr_missing","product_id":"prod_missing","price_id":"price_missing"}}`)
	secret := "whsec_" + base64.StdEncoding.EncodeToString([]byte("handler-secret"))
	webhookID := "msg_retryable_handler"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := signedWebhookSignature(t, []byte(secret), webhookID, timestamp, body)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/polar", bytes.NewReader(body))
	req.Header.Set("Webhook-Id", webhookID)
	req.Header.Set("Webhook-Timestamp", timestamp)
	req.Header.Set("Webhook-Signature", signature)
	polarWebhook(service, secret, 5*time.Minute).ServeHTTP(rec, req)

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

func signedWebhookSignature(t *testing.T, key []byte, webhookID, timestamp string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(webhookID + "." + timestamp + "."))
	_, _ = mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
