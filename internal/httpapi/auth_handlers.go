package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
)

type authContextKey struct{}

type principal struct {
	User    auth.User
	Session auth.Session
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

func logout(service *auth.Service) http.HandlerFunc {
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

func shouldRotateForRequest(r *http.Request) bool {
	return !unsafeMethod(r.Method) && r.URL.Path != "/api/auth/csrf"
}

func requireCSRF(service *auth.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unsafeMethod(r.Method) {
			if err := service.ValidateCSRF(r.Context(), r); err != nil {
				writeError(w, r, http.StatusForbidden, "csrf_failed", "CSRF validation failed.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
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
	writeError(w, r, http.StatusPaymentRequired, "payment_required", "An active paid plan is required to use this feature.")
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
