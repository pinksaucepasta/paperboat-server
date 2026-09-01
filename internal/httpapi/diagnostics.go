package httpapi

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/telemetry"
)

// telemetryDiagnosticsPath is intentionally outside the public /v1 API. The
// endpoint is a literal-loopback operator surface and is never authenticated
// by a browser or a remote proxy.
const telemetryDiagnosticsPath = "/diagnostics"

func telemetryDiagnostics(source *telemetry.Diagnostics) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// Diagnostics can contain current operational state. Never let an
		// intermediary cache either a successful snapshot or an error that
		// could disclose endpoint availability.
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if request == nil || !diagnosticsLoopback(request) {
			writeDiagnosticsError(writer, request, http.StatusForbidden, "forbidden", "Diagnostics are available only from localhost.")
			return
		}
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writeDiagnosticsError(writer, request, http.StatusMethodNotAllowed, "method_not_allowed", "Diagnostics support GET only.")
			return
		}
		if request.URL == nil || request.URL.Path != telemetryDiagnosticsPath || request.URL.RawQuery != "" || request.URL.Fragment != "" || request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
			writeDiagnosticsError(writer, request, http.StatusNotFound, "not_found", "The requested endpoint was not found.")
			return
		}
		if source == nil {
			writeDiagnosticUnavailable(writer, request)
			return
		}
		requestID := requestIDFromContext(request.Context())
		correlationID := observability.CorrelationID(request.Context())
		body, err := source.JSONWithIdentity(requestID, correlationID)
		if err != nil || len(body) > telemetry.MaximumDiagnosticsBytes || len(body) > 16<<20 {
			writeDiagnosticUnavailable(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	})
}

func writeDiagnosticUnavailable(writer http.ResponseWriter, request *http.Request) {
	writeDiagnosticsError(writer, request, http.StatusServiceUnavailable, "diagnostics_unavailable", "Diagnostics are temporarily unavailable.")
}

func writeDiagnosticsError(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	if request == nil {
		request = &http.Request{}
	}
	writeError(writer, request, status, code, message)
}

func diagnosticsLoopback(request *http.Request) bool {
	if request == nil {
		return false
	}
	remoteAddress := strings.TrimSpace(request.RemoteAddr)
	if remoteAddress == "" {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
