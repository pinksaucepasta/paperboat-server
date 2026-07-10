package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
)

func deviceAuthorize(service *auth.DeviceService, requestNetwork func(*http.Request) string) http.HandlerFunc {
	type request struct {
		ClientID    string   `json:"client_id"`
		ClientLabel string   `json:"client_label"`
		DeviceType  string   `json:"device_type"`
		OS          string   `json:"os"`
		Scopes      []string `json:"scopes"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		out, err := service.Authorize(r.Context(), auth.DeviceAuthorizationInput{ClientID: body.ClientID, ClientLabel: body.ClientLabel, DeviceType: body.DeviceType, OS: body.OS, Scopes: body.Scopes, Network: requestNetwork(r)})
		if writeDeviceError(w, r, err) {
			return
		}
		noStore(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"device_code": out.DeviceCode, "user_code": out.UserCode, "verification_uri": out.VerificationURI, "verification_uri_complete": out.VerificationURIComplete, "expires_in": out.ExpiresIn, "interval": out.Interval}})
	}
}

func deviceToken(service *auth.DeviceService, requestNetwork func(*http.Request) string) http.HandlerFunc {
	type request struct {
		ClientID   string `json:"client_id"`
		DeviceCode string `json:"device_code"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		out, err := service.Poll(r.Context(), auth.DeviceTokenInput{ClientID: body.ClientID, DeviceCode: body.DeviceCode, Network: requestNetwork(r)})
		if writeDeviceError(w, r, err) {
			return
		}
		writeTokenSet(w, out)
	}
}

func deviceRequest(service *auth.DeviceService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := principalFromContext(r.Context())
		if err := service.RateAccount(r.Context(), p.User.ID); writeDeviceError(w, r, err) {
			return
		}
		out, err := service.Request(r.Context(), r.PathValue("user_code"))
		if writeDeviceError(w, r, err) {
			return
		}
		noStore(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: deviceRequestPayload(out)})
	}
}
func deviceDecision(service *auth.DeviceService, approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := principalFromContext(r.Context())
		out, err := service.Decide(r.Context(), r.PathValue("user_code"), p.User.ID, approve)
		if writeDeviceError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: deviceRequestPayload(out)})
	}
}

func tokenRefresh(service *auth.DeviceService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		out, err := service.Refresh(r.Context(), token)
		if writeDeviceError(w, r, err) {
			return
		}
		writeTokenSet(w, out)
	}
}
func tokenRevoke(service *auth.DeviceService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		if err := service.RevokeToken(r.Context(), token, "logout"); writeDeviceError(w, r, err) {
			return
		}
		noStore(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"status": "revoked"}})
	}
}

func clientsList(service *auth.DeviceService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := principalFromContext(r.Context())
		limit, err := queryInt(r, "limit", 50)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Query parameters are invalid.")
			return
		}
		offset, err := queryInt(r, "offset", 0)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Query parameters are invalid.")
			return
		}
		current := ""
		if p.Client != nil {
			current = p.Client.SessionID
		}
		page, err := service.ListClients(r.Context(), p.User.ID, r.URL.Query().Get("state"), current, limit, offset)
		if writeDeviceError(w, r, err) {
			return
		}
		items := make([]map[string]any, 0, len(page.Items))
		for _, i := range page.Items {
			items = append(items, map[string]any{"client_session_id": i.ID, "client_id": i.ClientID, "client_label": i.ClientLabel, "device_type": i.DeviceType, "os": i.OS, "scopes": i.Scopes, "state": i.State, "created_at": i.CreatedAt, "approved_at": i.ApprovedAt, "last_used_at": i.LastUsedAt, "revoked_at": i.RevokedAt, "revocation_reason": i.RevocationReason, "current": i.Current})
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"items": items, "pagination": map[string]any{"limit": page.Limit, "offset": page.Offset, "total": page.Total, "next_offset": page.NextOffset}}})
	}
}
func clientDelete(service *auth.DeviceService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := principalFromContext(r.Context())
		if err := service.RevokeClient(r.Context(), p.User.ID, r.PathValue("client_session_id"), "user_revoked"); err != nil {
			writeClientDeleteError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func writeClientDeleteError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "not_found", "Authorized client was not found.")
		return
	}
	writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
}

func deviceRequestPayload(out auth.DeviceRequest) map[string]any {
	return map[string]any{"client_label": out.ClientLabel, "device_type": out.DeviceType, "os": out.OS, "scopes": out.Scopes, "issued_at": out.IssuedAt, "expires_at": out.ExpiresAt, "user_code": out.UserCode, "state": out.State}
}
func writeTokenSet(w http.ResponseWriter, out auth.TokenSet) {
	noStore(w)
	writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"access_token": out.AccessToken, "refresh_token": out.RefreshToken, "token_type": out.TokenType, "expires_in": out.ExpiresIn, "scope": out.Scope, "client_session_id": out.ClientSessionID}})
}
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
func writeDeviceError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	var e *auth.DeviceError
	if !errors.As(err, &e) {
		if errors.Is(err, auth.ErrUnauthenticated) {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
		} else {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
		}
		return true
	}
	status := http.StatusBadRequest
	message := "Authorization request is invalid."
	details := map[string]any{}
	switch e.Code {
	case "rate_limited":
		status = http.StatusTooManyRequests
		message = "Too many requests."
		w.Header().Set("Retry-After", strconv.Itoa(e.RetryAfter))
	case "slow_down":
		message = "Polling too quickly."
		details["interval"] = e.Interval
	case "authorization_pending":
		message = "Authorization is pending."
	case "access_denied":
		message = "Authorization was denied."
	case "device_request_expired", "device_request_consumed":
		status = http.StatusGone
		message = "Authorization request is no longer available."
	case "device_request_not_pending":
		status = http.StatusConflict
		message = "Authorization request is not pending."
	case "device_request_not_found":
		status = http.StatusNotFound
		message = "Authorization request was not found."
	}
	noStore(w)
	writeErrorDetails(w, r, status, e.Code, message, details)
	return true
}
func decodeStrictJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must contain one JSON object.")
		return false
	}
	return true
}
func newRequestNetwork(trustedCIDRs []string) func(*http.Request) string {
	trusted := make([]*net.IPNet, 0, len(trustedCIDRs))
	for _, raw := range trustedCIDRs {
		if _, network, err := net.ParseCIDR(strings.TrimSpace(raw)); err == nil {
			trusted = append(trusted, network)
		}
	}
	return func(r *http.Request) string {
		direct := remoteIP(r.RemoteAddr)
		if direct == nil || !ipInNetworks(direct, trusted) {
			return ipString(direct, r.RemoteAddr)
		}
		if flyIP := net.ParseIP(strings.TrimSpace(r.Header.Get("Fly-Client-IP"))); flyIP != nil {
			return flyIP.String()
		}
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := net.ParseIP(strings.TrimSpace(parts[i]))
			if ip != nil && !ipInNetworks(ip, trusted) {
				return ip.String()
			}
		}
		return ipString(direct, r.RemoteAddr)
	}
}
func remoteIP(address string) net.IP {
	address = strings.TrimSpace(address)
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(address)
}
func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
func ipString(ip net.IP, fallback string) string {
	if ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(fallback)
}
func queryInt(r *http.Request, name string, def int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	return strconv.Atoi(raw)
}
