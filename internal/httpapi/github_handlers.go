package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	pbgithub "github.com/pinksaucepasta/paperboat-server/internal/github"
)

func githubStatus(service *pbgithub.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		status, err := service.Status(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: status})
	}
}

func githubOAuthStart(authService *auth.Service, service *pbgithub.Service) http.HandlerFunc {
	type request struct {
		RedirectURI string `json:"redirect_uri"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		state, err := authService.NewOAuthState()
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		url, err := service.OAuthAuthorizeURL(state, body.RedirectURI)
		if errors.Is(err, pbgithub.ErrClientNotConfigured) {
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "GitHub OAuth is not configured.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		authService.SetOAuthStateCookie(w, state)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"state": state, "authorization_url": url}})
	}
}

func githubOAuthCallback(authService *auth.Service, service *pbgithub.Service) http.HandlerFunc {
	type request struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
		State       string `json:"state"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		if err := authService.ValidateOAuthState(r, body.State); err != nil {
			writeError(w, r, http.StatusForbidden, "oauth_state_failed", "OAuth state validation failed.")
			return
		}
		status, err := service.CompleteOAuth(r.Context(), p.User.ID, body.Code, body.RedirectURI)
		if errors.Is(err, pbgithub.ErrMissingScopes) {
			writeError(w, r, http.StatusForbidden, "github_scope_denied", "GitHub authorization is missing required scopes.")
			return
		}
		if errors.Is(err, pbgithub.ErrIdentityLinkedToAnotherUser) {
			writeError(w, r, http.StatusConflict, "github_identity_conflict", "This GitHub account is already connected to another Paperboat user.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "github_oauth_failed", "GitHub OAuth callback could not be verified.")
			return
		}
		authService.ClearOAuthStateCookie(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: status})
	}
}

func githubOAuthBrowserCallback(authService *auth.Service, service *pbgithub.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if err := authService.ValidateOAuthState(r, state); err != nil {
			writeError(w, r, http.StatusForbidden, "oauth_state_failed", "OAuth state validation failed.")
			return
		}
		status, err := service.CompleteOAuth(r.Context(), p.User.ID, code, service.DefaultCallbackURL())
		if errors.Is(err, pbgithub.ErrMissingScopes) {
			writeError(w, r, http.StatusForbidden, "github_scope_denied", "GitHub authorization is missing required scopes.")
			return
		}
		if errors.Is(err, pbgithub.ErrIdentityLinkedToAnotherUser) {
			writeError(w, r, http.StatusConflict, "github_identity_conflict", "This GitHub account is already connected to another Paperboat user.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "github_oauth_failed", "GitHub OAuth callback could not be verified.")
			return
		}
		authService.ClearOAuthStateCookie(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: status})
	}
}

func githubRepositories(service *pbgithub.Service) http.HandlerFunc {
	type repositoryResponse struct {
		Owner         string `json:"owner"`
		Name          string `json:"name"`
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
		CloneURL      string `json:"clone_url"`
		HTMLURL       string `json:"html_url"`
		Private       bool   `json:"private"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		repos, err := service.ListRepos(r.Context(), p.User.ID)
		switch {
		case errors.Is(err, pbgithub.ErrNotConnected):
			writeError(w, r, http.StatusConflict, "github_required", "Connect GitHub before listing repositories.")
			return
		case errors.Is(err, pbgithub.ErrMissingScopes):
			writeError(w, r, http.StatusForbidden, "github_scope_denied", "GitHub authorization is missing required scopes.")
			return
		case err != nil:
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "GitHub repositories could not be loaded.")
			return
		}
		out := make([]repositoryResponse, 0, len(repos))
		for _, repo := range repos {
			out = append(out, repositoryResponse{
				Owner:         repo.Owner,
				Name:          repo.Name,
				FullName:      repo.Owner + "/" + repo.Name,
				DefaultBranch: repo.DefaultBranch,
				CloneURL:      repo.CloneURL,
				HTMLURL:       repo.HTMLURL,
				Private:       repo.Private,
			})
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	}
}

func githubProvisionConfigRepo(service *pbgithub.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		repo, err := service.ProvisionConfigRepo(r.Context(), p.User.ID, r.Header.Get("Idempotency-Key"))
		switch {
		case errors.Is(err, pbgithub.ErrIdempotencyKeyRequired):
			writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required.")
			return
		case errors.Is(err, pbgithub.ErrNotConnected):
			writeError(w, r, http.StatusConflict, "github_required", "Connect GitHub before provisioning the config repository.")
			return
		case errors.Is(err, pbgithub.ErrMissingScopes):
			writeError(w, r, http.StatusForbidden, "github_scope_denied", "GitHub authorization is missing required scopes.")
			return
		case err != nil:
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "GitHub config repository provisioning failed.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: repo})
	}
}

func requireGitHubConnection(service *pbgithub.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		err := service.EnsureConnected(r.Context(), p.User.ID)
		switch {
		case errors.Is(err, pbgithub.ErrNotConnected):
			writeError(w, r, http.StatusConflict, "github_required", "Connect GitHub before creating a project.")
			return
		case errors.Is(err, pbgithub.ErrMissingScopes):
			writeError(w, r, http.StatusForbidden, "github_scope_denied", "GitHub authorization is missing required scopes.")
			return
		case err != nil:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		next.ServeHTTP(w, r)
	})
}
