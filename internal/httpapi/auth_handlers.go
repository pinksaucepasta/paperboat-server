package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
)

type authContextKey struct{}

type principal struct {
	User    auth.User
	Session auth.Session
	Client  *auth.ClientPrincipal
}

func workOSState(service *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := service.NewOAuthState()
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		service.SetOAuthStateCookie(w, state)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"state": state}})
	}
}

func workOSCallback(service *auth.Service) http.HandlerFunc {
	type request struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
		State       string `json:"state"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		if err := service.ValidateOAuthState(r, body.State); err != nil {
			writeError(w, r, http.StatusForbidden, "oauth_state_failed", "OAuth state validation failed.")
			return
		}
		user, session, err := service.VerifyCallback(r.Context(), auth.CallbackInput{
			Code:        body.Code,
			RedirectURI: body.RedirectURI,
			State:       body.State,
		})
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "auth_callback_failed", "Authentication callback could not be verified.")
			return
		}
		service.ClearOAuthStateCookie(w)
		service.SetSessionCookies(w, session)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: mePayload(user)})
	}
}

func workOSReauthState(service *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		purpose := r.URL.Query().Get("purpose")
		state, err := service.NewReauthState(p.User.ID, purpose)
		if err != nil {
			writeError(w, r, 400, "invalid_request", "Reauthentication purpose is invalid.")
			return
		}
		service.SetOAuthStateCookie(w, state)
		writeJSON(w, 200, SuccessResponse{Data: map[string]any{"state": state}})
	}
}

func workOSReauthCallback(service *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Code        string `json:"code"`
			RedirectURI string `json:"redirect_uri"`
			State       string `json:"state"`
			Purpose     string `json:"purpose"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			writeError(w, r, 400, "invalid_request", "Request body must be valid JSON.")
			return
		}
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		proof, err := service.VerifyReauthentication(r.Context(), r, auth.CallbackInput{Code: body.Code, RedirectURI: body.RedirectURI, State: body.State}, p.User, body.Purpose)
		if err != nil {
			writeError(w, r, 401, "reauthentication_failed", "Reauthentication could not be verified.")
			return
		}
		service.ClearOAuthStateCookie(w)
		service.SetReauthProofCookie(w, proof)
		writeJSON(w, 200, SuccessResponse{Data: map[string]any{"reauthenticated": true, "purpose": body.Purpose}})
	}
}

func logout(service *auth.Service, access *agentunnel.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if unsafeMethod(r.Method) {
			if err := service.ValidateCSRF(r.Context(), r); err != nil {
				writeError(w, r, http.StatusForbidden, "csrf_failed", "CSRF validation failed.")
				return
			}
		}
		if err := service.Logout(r.Context(), r); err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		if access != nil {
			if p, ok := principalFromContext(r.Context()); ok {
				if err := access.RevokeUserSessions(r.Context(), p.User.ID, "logout"); err != nil {
					writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
					return
				}
			}
		}
		service.ClearSessionCookies(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"status": "logged_out"}})
	}
}

func csrf(service *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := service.CSRFToken(r)
		if !ok {
			p, principalOK := principalFromContext(r.Context())
			if !principalOK {
				writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
				return
			}
			refreshed, err := service.RefreshCSRF(r.Context(), p.Session)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
				return
			}
			service.SetCSRFCookie(w, refreshed, p.Session.ExpiresAt)
			token = refreshed
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"csrf_token": token}})
	}
}

func me(_ *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: mePayload(p.User)})
	}
}

func mePayload(user auth.User) map[string]any {
	return map[string]any{
		"id":             user.ID,
		"email":          user.PrimaryEmail,
		"display_name":   user.DisplayName,
		"status":         user.Status,
		"role":           string(user.Role),
		"workos_subject": user.WorkOSSubject,
	}
}

func requireAuth(service *auth.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, session, err := service.AuthenticateRequest(r.Context(), r)
		if errors.Is(err, auth.ErrUnauthenticated) {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		if shouldRotateForRequest(r) && service.ShouldRotate(session) {
			rotated, err := service.RotateSession(r.Context(), session)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
				return
			}
			session = rotated
			service.SetSessionCookies(w, session)
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, principal{User: user, Session: session})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireAnyAuth(service *auth.Service, devices *auth.DeviceService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token, ok := bearerToken(r); ok {
			client, err := devices.Authenticate(r.Context(), token)
			if err != nil {
				writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
				return
			}
			ctx := context.WithValue(r.Context(), authContextKey{}, principal{User: client.User, Client: &client})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		requireAuth(service, next).ServeHTTP(w, r)
	})
}

func requireBearerAuth(devices *auth.DeviceService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		client, err := devices.Authenticate(r.Context(), token)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, principal{User: client.User, Client: &client})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		if p.Client != nil && !p.Client.HasScope(scope) {
			writeError(w, r, http.StatusForbidden, "insufficient_scope", "The client is not authorized for this operation.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func shouldRotateForRequest(r *http.Request) bool {
	return !unsafeMethod(r.Method) && r.URL.Path != "/api/auth/csrf"
}

func requireCSRF(service *auth.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := principalFromContext(r.Context()); ok && p.Client != nil {
			next.ServeHTTP(w, r)
			return
		}
		if unsafeMethod(r.Method) {
			if err := service.ValidateCSRF(r.Context(), r); err != nil {
				writeError(w, r, http.StatusForbidden, "csrf_failed", "CSRF validation failed.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) (string, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func requireEntitlement(service *auth.Service, next http.Handler) http.Handler {
	return requireCSRF(service, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		ok, err := service.HasActiveEntitlement(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		if !ok {
			paymentRequired(w, r)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || (p.User.Role != auth.RoleAdmin && p.User.Role != auth.RoleSupport) {
			writeError(w, r, http.StatusForbidden, "forbidden", "You are not allowed to access this resource.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func paymentRequired(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusPaymentRequired, "payment_required", "An active subscription or trial is required to use this feature.")
}

func principalFromContext(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(authContextKey{}).(principal)
	return p, ok
}

func unsafeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}
