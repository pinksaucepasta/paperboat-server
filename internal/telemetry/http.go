package telemetry

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/felixge/httpsnoop"
)

// HTTPIdentity extracts safe request and correlation IDs already assigned by
// trusted middleware. It must never return headers, URLs, bodies, or tokens.
type HTTPIdentity func(context.Context) (requestID, correlationID string)

// HTTPObserver records bounded server request telemetry. The route family is
// caller-supplied from a finite allowlist so user-controlled paths and
// hostnames can never become metric labels.
type HTTPObserver struct {
	Metrics  *Metrics
	Events   *EventLog
	Identity HTTPIdentity
	Now      func() time.Time
}

func (o HTTPObserver) Wrap(routeFamily string, next http.Handler) http.Handler {
	return o.WrapFunc(func(*http.Request) string { return routeFamily }, next)
}

// WrapFunc classifies requests into a finite route family at request time.
// The classifier output is normalized before it can reach metrics or events.
func (o HTTPObserver) WrapFunc(routeFamily func(*http.Request) string, next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		family := "other"
		if routeFamily != nil {
			family = normalizeHTTPRouteFamily(routeFamily(r))
		}
		started := o.now()
		captured := httpsnoop.CaptureMetrics(next, w, r)
		statusClass := httpStatusClass(captured.Code)
		outcome := OutcomeSuccess
		severity := SeverityInfo
		code := "http_request_succeeded"
		message := "HTTP request completed."
		if captured.Code >= http.StatusBadRequest && captured.Code < http.StatusInternalServerError {
			outcome, severity, code, message = OutcomeRejected, SeverityWarn, "http_request_rejected", "HTTP request was rejected."
		} else if captured.Code >= http.StatusInternalServerError {
			outcome, severity, code, message = OutcomeFailed, SeverityError, "http_request_failed", "HTTP request failed."
		}
		if o.Metrics != nil {
			_ = o.Metrics.IncCounter(MetricHTTPRequests, MetricLabels{
				"method": methodLabel(r.Method), "route_family": family, "status_class": statusClass,
			})
			_ = o.Metrics.ObserveHistogram(MetricHTTPDuration, MetricLabels{"route_family": family, "status_class": statusClass}, captured.Duration.Seconds())
		}
		if o.Events == nil || o.Identity == nil {
			return
		}
		requestID, correlationID := o.Identity(r.Context())
		if requestID == "" || correlationID == "" {
			return
		}
		_, _ = o.Events.Record(EventInput{
			At: started.Add(captured.Duration), Severity: severity, Component: DimensionService,
			Name: "http_request", Code: code, Outcome: outcome, Message: message,
			RequestID: requestID, CorrelationID: correlationID, Retry: RetryNone,
		})
	})
}

func (o HTTPObserver) now() time.Time {
	if o.Now == nil {
		return time.Now().UTC()
	}
	return o.Now().UTC()
}

func normalizeHTTPRouteFamily(value string) string {
	switch value {
	case "health", "public_api", "edge_control", "release", "internal":
		return value
	default:
		return "other"
	}
}

func methodLabel(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet:
		return "get"
	case http.MethodPost:
		return "post"
	case http.MethodPut:
		return "put"
	case http.MethodPatch:
		return "patch"
	case http.MethodDelete:
		return "delete"
	default:
		return "other"
	}
}

func httpStatusClass(status int) string {
	if status < 100 {
		status = http.StatusOK
	}
	switch status / 100 {
	case 1:
		return "1xx"
	case 2:
		return "2xx"
	case 3:
		return "3xx"
	case 4:
		return "4xx"
	default:
		return "5xx"
	}
}
