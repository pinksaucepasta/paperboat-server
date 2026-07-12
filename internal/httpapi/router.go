package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/catalog"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	pbgithub "github.com/pinksaucepasta/paperboat-server/internal/github"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
)

type ReadinessChecker interface {
	Ready(context.Context) error
}

type Options struct {
	Config           config.Config
	Logger           *slog.Logger
	ReadinessChecker ReadinessChecker
	Auth             *auth.Service
	DeviceAuth       *auth.DeviceService
	Billing          *billing.Service
	Catalog          catalog.Reader
	CatalogWriter    catalog.RegionWriter
	Fly              fly.Client
	GitHub           *pbgithub.Service
	Projects         *projects.Service
	Agentunnel       *agentunnel.Service
	MeteringRepo     *metering.RuntimeRepository
	MintKeys         *mint.Provider
	OverrideHandler  http.Handler
}

func NewRouter(opts Options) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	var handler http.Handler
	if opts.OverrideHandler != nil {
		handler = opts.OverrideHandler
	} else {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", health)
		mux.HandleFunc("GET /readyz", ready(opts.ReadinessChecker))
		mux.HandleFunc("GET /metrics", metrics)
		if opts.MintKeys != nil {
			mux.Handle("GET /.well-known/jwks.json", opts.MintKeys)
		}
		if opts.Auth != nil {
			registerAuthRoutes(mux, opts)
		}
		if opts.Billing != nil {
			mux.HandleFunc("POST /api/webhooks/polar", polarWebhook(opts.Billing, opts.Config.Secrets.PolarWebhookSecret, opts.Config.Billing.PolarWebhookTolerance))
		}
		if opts.MeteringRepo != nil {
			mux.HandleFunc("POST /api/machine/activity-heartbeat", activityHeartbeat(opts.MeteringRepo))
		}
		mux.HandleFunc("/", notImplemented)
		handler = mux
	}
	handler = secureHeaders(handler)
	handler = cors(opts.Config.HTTP.AllowedOrigins, handler)
	handler = bodyLimit(opts.Config.HTTP.MaxBodyBytes, handler)
	handler = timeout(opts.Config.HTTP.RequestTimeout, opts.Logger, handler)
	handler = recoverer(opts.Logger, handler)
	handler = accessLog(opts.Logger, handler)
	handler = requestID(handler)
	return handler
}

func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{
		"status": "healthy",
	}})
}

func metrics(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		writeError(w, r, http.StatusForbidden, "forbidden", "Metrics are available only from localhost.")
		return
	}
	writeJSON(w, http.StatusOK, SuccessResponse{Data: observability.MetricsSnapshot()})
}

func ready(checker ReadinessChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if checker == nil {
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Readiness checks are not configured.")
			return
		}
		if err := checker.Ready(r.Context()); err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Service dependencies are not ready.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{
			"status": "ready",
		}})
	}
}

func notImplemented(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotImplemented, "provider_unavailable", "This endpoint is not implemented in the current server phase.")
}

func registerAuthRoutes(mux *http.ServeMux, opts Options) {
	mux.HandleFunc("GET /api/auth/workos/state", workOSState(opts.Auth))
	mux.HandleFunc("POST /api/auth/workos/callback", workOSCallback(opts.Auth))
	mux.Handle("POST /api/auth/logout", requireAuth(opts.Auth, logout(opts.Auth, opts.Agentunnel)))
	mux.Handle("GET /api/auth/csrf", requireAuth(opts.Auth, csrf(opts.Auth)))
	mux.Handle("GET /api/me", requireAuth(opts.Auth, me(opts.Auth)))
	if opts.DeviceAuth != nil {
		requestNetwork := newRequestNetwork(opts.Config.HTTP.TrustedProxyCIDRs)
		mux.HandleFunc("POST /api/auth/device/authorize", deviceAuthorize(opts.DeviceAuth, requestNetwork))
		mux.HandleFunc("POST /api/auth/device/token", deviceToken(opts.DeviceAuth, requestNetwork))
		mux.Handle("GET /api/auth/device/requests/{user_code}", requireAuth(opts.Auth, deviceRequest(opts.DeviceAuth)))
		mux.Handle("POST /api/auth/device/requests/{user_code}/approve", requireAuth(opts.Auth, requireCSRF(opts.Auth, deviceDecision(opts.DeviceAuth, true))))
		mux.Handle("POST /api/auth/device/requests/{user_code}/deny", requireAuth(opts.Auth, requireCSRF(opts.Auth, deviceDecision(opts.DeviceAuth, false))))
		mux.HandleFunc("POST /api/auth/token/refresh", tokenRefresh(opts.DeviceAuth))
		mux.HandleFunc("POST /api/auth/token/revoke", tokenRevoke(opts.DeviceAuth))
		mux.Handle("GET /api/auth/clients", requireAnyAuth(opts.Auth, opts.DeviceAuth, requireScope("account:read", clientsList(opts.DeviceAuth))))
		mux.Handle("DELETE /api/auth/clients/{client_session_id}", requireAnyAuth(opts.Auth, opts.DeviceAuth, requireCSRF(opts.Auth, requireScope("clients:revoke", clientDelete(opts.DeviceAuth)))))
	}
	if opts.Billing != nil {
		mux.Handle("GET /api/billing/entitlement", requireAuth(opts.Auth, billingEntitlement(opts.Billing)))
		mux.Handle("GET /api/billing/usage", requireAuth(opts.Auth, billingUsage(opts.Billing)))
		mux.Handle("GET /api/billing/plan-products", requireAuth(opts.Auth, billingPlanProducts(opts.Billing)))
		mux.Handle("POST /api/billing/checkout", requireAuth(opts.Auth, requireCSRF(opts.Auth, billingCheckout(opts.Billing))))
		mux.Handle("POST /api/billing/customer-portal", requireAuth(opts.Auth, requireCSRF(opts.Auth, billingCustomerPortal(opts.Billing))))
		if opts.Projects != nil {
			mux.Handle("GET /api/dashboard/usage-summary", requireAuth(opts.Auth, requireEntitlement(opts.Auth, dashboardUsageSummary(opts.Billing, opts.Projects))))
		}
	} else {
		mux.Handle("GET /api/billing/entitlement", requireAuth(opts.Auth, http.HandlerFunc(paymentRequired)))
		mux.Handle("GET /api/billing/usage", requireAuth(opts.Auth, http.HandlerFunc(paymentRequired)))
		mux.Handle("GET /api/billing/plan-products", requireAuth(opts.Auth, http.HandlerFunc(paymentRequired)))
		mux.Handle("POST /api/billing/checkout", requireAuth(opts.Auth, requireCSRF(opts.Auth, http.HandlerFunc(notImplemented))))
		mux.Handle("POST /api/billing/customer-portal", requireAuth(opts.Auth, requireCSRF(opts.Auth, http.HandlerFunc(notImplemented))))
	}
	if opts.Catalog != nil {
		mux.Handle("GET /api/catalog/plans", requireAuth(opts.Auth, catalogPlans(opts.Catalog)))
		mux.Handle("GET /api/catalog/machine-types", requireAuth(opts.Auth, catalogMachineTypes(opts.Catalog)))
		mux.Handle("GET /api/catalog/presets", requireAuth(opts.Auth, catalogPresets(opts.Catalog)))
		mux.Handle("GET /api/catalog/idle-timeouts", requireAuth(opts.Auth, catalogIdleTimeouts(opts.Catalog)))
		mux.Handle("GET /api/catalog/regions", requireAuth(opts.Auth, catalogRegions(opts.Catalog, opts.Fly, opts.CatalogWriter)))
	} else {
		mux.Handle("GET /api/catalog/plans", requireAuth(opts.Auth, http.HandlerFunc(notImplemented)))
		mux.Handle("GET /api/catalog/machine-types", requireAuth(opts.Auth, http.HandlerFunc(notImplemented)))
		mux.Handle("GET /api/catalog/presets", requireAuth(opts.Auth, http.HandlerFunc(notImplemented)))
		mux.Handle("GET /api/catalog/idle-timeouts", requireAuth(opts.Auth, http.HandlerFunc(notImplemented)))
		mux.Handle("GET /api/catalog/regions", requireAuth(opts.Auth, http.HandlerFunc(notImplemented)))
	}
	if opts.GitHub != nil {
		mux.Handle("GET /api/github/status", requireAuth(opts.Auth, githubStatus(opts.GitHub)))
		mux.Handle("GET /api/github/repositories", requireAuth(opts.Auth, requireEntitlement(opts.Auth, githubRepositories(opts.GitHub))))
		mux.Handle("POST /api/github/oauth/start", requireAuth(opts.Auth, requireCSRF(opts.Auth, githubOAuthStart(opts.Auth, opts.GitHub))))
		mux.Handle("GET /api/github/oauth/callback", requireAuth(opts.Auth, githubOAuthBrowserCallback(opts.Auth, opts.GitHub)))
		mux.Handle("POST /api/github/oauth/callback", requireAuth(opts.Auth, requireCSRF(opts.Auth, githubOAuthCallback(opts.Auth, opts.GitHub))))
		mux.Handle("POST /api/github/config-repo/provision", requireAuth(opts.Auth, requireCSRF(opts.Auth, githubProvisionConfigRepo(opts.GitHub))))
		if opts.Projects != nil {
			projectAuth := func(scope string, next http.Handler) http.Handler {
				if opts.DeviceAuth != nil {
					return requireAnyAuth(opts.Auth, opts.DeviceAuth, requireScope(scope, next))
				}
				return requireAuth(opts.Auth, next)
			}
			mux.Handle("GET /api/projects", projectAuth("projects:read", requireEntitlement(opts.Auth, projectsList(opts.Projects))))
			mux.Handle("POST /api/projects", requireAuth(opts.Auth, requireEntitlement(opts.Auth, requireGitHubConnection(opts.GitHub, projectsCreate(opts.Projects)))))
			mux.Handle("GET /api/projects/{project_id}", requireAuth(opts.Auth, requireEntitlement(opts.Auth, projectsGet(opts.Projects))))
			mux.Handle("PATCH /api/projects/{project_id}", requireAuth(opts.Auth, requireEntitlement(opts.Auth, projectsUpdate(opts.Projects))))
			mux.Handle("DELETE /api/projects/{project_id}", requireAuth(opts.Auth, requireEntitlement(opts.Auth, projectsDelete(opts.Projects, opts.Agentunnel))))
			mux.Handle("POST /api/projects/{project_id}/start", requireAuth(opts.Auth, requireEntitlement(opts.Auth, requireCSRF(opts.Auth, projectsStart(opts.Projects)))))
			mux.Handle("POST /api/projects/{project_id}/stop", requireAuth(opts.Auth, requireEntitlement(opts.Auth, requireCSRF(opts.Auth, projectsStop(opts.Projects, opts.Agentunnel)))))
			mux.Handle("POST /api/projects/{project_id}/restart", requireAuth(opts.Auth, requireEntitlement(opts.Auth, requireCSRF(opts.Auth, projectsRestart(opts.Projects)))))
			mux.Handle("POST /api/projects/{project_id}/keep-alive", requireAuth(opts.Auth, requireEntitlement(opts.Auth, requireCSRF(opts.Auth, projectsKeepAlive(opts.Projects)))))
			mux.Handle("POST /api/projects/{project_id}/activity", projectAuth("projects:connect", requireEntitlement(opts.Auth, projectsActivity(opts.Projects))))
			mux.Handle("GET /api/projects/{project_id}/events", requireAuth(opts.Auth, requireEntitlement(opts.Auth, projectsEvents(opts.Projects))))
			if opts.Agentunnel != nil {
				mux.Handle("POST /api/projects/{project_id}/connect", requireAuth(opts.Auth, requireEntitlement(opts.Auth, projectsConnect(opts.Agentunnel, agentunnel.ConnectGeneric))))
				mux.Handle("POST /api/projects/{project_id}/papercode-connect", requireAuth(opts.Auth, requireEntitlement(opts.Auth, projectsConnect(opts.Agentunnel, agentunnel.ConnectPapercode))))
				mux.Handle("POST /api/projects/{project_id}/cli-connect", requireBearerAuth(opts.DeviceAuth, requireScope("projects:connect", requireEntitlement(opts.Auth, projectsConnect(opts.Agentunnel, agentunnel.ConnectCLI)))))
				mux.Handle("GET /api/projects/{project_id}/connection-status", requireBearerAuth(opts.DeviceAuth, requireScope("projects:connect", requireEntitlement(opts.Auth, projectsConnectionStatus(opts.Agentunnel)))))
			}
		} else {
			mux.Handle("POST /api/projects", requireAuth(opts.Auth, requireEntitlement(opts.Auth, requireGitHubConnection(opts.GitHub, http.HandlerFunc(notImplemented)))))
		}
	}
	if opts.Projects == nil {
		mux.Handle("/api/projects", requireAuth(opts.Auth, requireEntitlement(opts.Auth, http.HandlerFunc(notImplemented))))
		mux.Handle("/api/projects/", requireAuth(opts.Auth, requireEntitlement(opts.Auth, http.HandlerFunc(notImplemented))))
	}
	if opts.Billing != nil {
		mux.Handle("POST /api/admin/users/{user_id}/adjust-credits", requireAuth(opts.Auth, requireCSRF(opts.Auth, requireAdmin(adminAdjustCredits(opts.Billing)))))
		mux.Handle("POST /api/admin/users/{user_id}/adjust-storage", requireAuth(opts.Auth, requireCSRF(opts.Auth, requireAdmin(adminAdjustStorage(opts.Billing)))))
	}
	mux.Handle("/api/admin/", requireAuth(opts.Auth, requireAdmin(http.HandlerFunc(notImplemented))))
}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := observability.NormalizeRequestID(r.Header.Get("Request-Id"))
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("Request-Id", requestID)
		next.ServeHTTP(w, r.WithContext(observability.WithRequestID(r.Context(), requestID)))
	})
}

func accessLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		observability.LoggerWithRequest(r.Context(), logger).Info("http_request",
			"method", r.Method,
			"path", safeLogPath(r.URL.Path),
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func safeLogPath(path string) string {
	if strings.HasPrefix(path, "/api/auth/device/requests/") {
		suffix := strings.TrimPrefix(path, "/api/auth/device/requests/")
		switch {
		case strings.HasSuffix(suffix, "/approve"):
			return "/api/auth/device/requests/{user_code}/approve"
		case strings.HasSuffix(suffix, "/deny"):
			return "/api/auth/device/requests/{user_code}/deny"
		default:
			return "/api/auth/device/requests/{user_code}"
		}
	}
	return path
}

func recoverer(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				writePanicError(w, r, logger, value)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func timeout(duration time.Duration, logger *slog.Logger, next http.Handler) http.Handler {
	if duration <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStreamingRequest(r) {
			next.ServeHTTP(w, r)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), duration)
		defer cancel()

		tw := newTimeoutResponseWriter(w)
		results := make(chan handlerResult, 1)
		go func() {
			defer func() {
				if value := recover(); value != nil {
					results <- handlerResult{panicValue: value}
					return
				}
				results <- handlerResult{}
			}()
			next.ServeHTTP(tw, r.WithContext(ctx))
		}()

		select {
		case result := <-results:
			if result.panicValue != nil {
				writePanicError(w, r, logger, result.panicValue)
				return
			}
		case <-ctx.Done():
			if !tw.markTimedOut() {
				return
			}
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Request timed out.")
		}
	})
}

func isStreamingRequest(r *http.Request) bool {
	for _, accept := range r.Header.Values("Accept") {
		for _, part := range strings.Split(accept, ",") {
			mediaType := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
			if mediaType == "text/event-stream" {
				return true
			}
		}
	}
	return false
}

func bodyLimit(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && limit > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

func cors(allowedOrigins []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && slices.Contains(allowedOrigins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func writePanicError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, value any) {
	observability.LoggerWithRequest(r.Context(), logger).Error("panic recovered", "panic", value, "stack", string(debug.Stack()))
	writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *statusRecorder) FlushError() error {
	if flusher, ok := r.ResponseWriter.(interface{ FlushError() error }); ok {
		return flusher.FlushError()
	}
	r.Flush()
	return nil
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

type handlerResult struct {
	panicValue any
}

type timeoutResponseWriter struct {
	dst      http.ResponseWriter
	header   http.Header
	mu       sync.Mutex
	started  bool
	timedOut bool
}

func newTimeoutResponseWriter(dst http.ResponseWriter) *timeoutResponseWriter {
	return &timeoutResponseWriter{
		dst:    dst,
		header: make(http.Header),
	}
}

func (w *timeoutResponseWriter) Header() http.Header {
	return w.header
}

func (w *timeoutResponseWriter) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timedOut || w.started {
		return
	}
	w.started = true
	copyHeader(w.dst.Header(), w.header)
	w.dst.WriteHeader(status)
}

func (w *timeoutResponseWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timedOut {
		return 0, context.DeadlineExceeded
	}
	if !w.started {
		w.started = true
		copyHeader(w.dst.Header(), w.header)
	}
	return w.dst.Write(b)
}

func (w *timeoutResponseWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timedOut {
		return
	}
	w.started = true
	copyHeader(w.dst.Header(), w.header)
	if flusher, ok := w.dst.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *timeoutResponseWriter) markTimedOut() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		w.timedOut = true
		return false
	}
	w.timedOut = true
	return true
}

func (w *timeoutResponseWriter) Unwrap() http.ResponseWriter {
	return w.dst
}

var errFlusherUnsupported = errors.New("response writer does not support flushing")

func (w *timeoutResponseWriter) FlushError() error {
	if _, ok := w.dst.(http.Flusher); !ok {
		return errFlusherUnsupported
	}
	w.Flush()
	return nil
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func requestIDFromContext(ctx context.Context) string {
	return observability.RequestID(ctx)
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req_unknown"
	}
	return "req_" + hex.EncodeToString(b[:])
}
