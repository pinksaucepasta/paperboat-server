package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/lazyaccess"
)

type LazyPolicyAPI interface {
	Upsert(context.Context, string, lazyaccess.UpsertRequest) (lazyaccess.Policy, error)
	Get(context.Context, string, string) (lazyaccess.Policy, error)
	Delete(context.Context, string, string, int64) error
}

func registerLazyPolicyRoutes(mux *http.ServeMux, service LazyPolicyAPI, read, write func(http.Handler) http.Handler) {
	handler := func(action string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			noStore(w)
			principal, ok := principalFromContext(r.Context())
			if !ok || principal.User.ID == "" {
				writeError(w, r, 401, "authentication_required", "Sign in to manage private service policies.")
				return
			}
			var out any
			var err error
			switch action {
			case "upsert":
				limitEnvironmentJSON(w, r, 16<<10)
				var input lazyaccess.UpsertRequest
				if !decodeLazyPolicy(w, r, &input) {
					return
				}
				out, err = service.Upsert(r.Context(), principal.User.ID, input)
			case "get":
				out, err = service.Get(r.Context(), principal.User.ID, r.PathValue("policy_id"))
			case "delete":
				limitEnvironmentJSON(w, r, 1024)
				var input struct {
					ExpectedGeneration int64 `json:"expected_generation"`
				}
				if !decodeLazyPolicy(w, r, &input) {
					return
				}
				err = service.Delete(r.Context(), principal.User.ID, r.PathValue("policy_id"), input.ExpectedGeneration)
			}
			if err != nil {
				lazyPolicyError(w, r, err)
				return
			}
			if action == "delete" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
		})
	}
	mux.Handle("PUT /v1/lazy-policies", write(handler("upsert")))
	mux.Handle("GET /v1/lazy-policies/{policy_id}", read(handler("get")))
	mux.Handle("DELETE /v1/lazy-policies/{policy_id}", write(handler("delete")))
}

func lazyPolicyError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, lazyaccess.ErrInvalid):
		writeError(w, r, 400, "invalid_policy", "Provide an exact loopback HTTP target, private or team access, an expiry and port-based ownership.")
	case errors.Is(err, lazyaccess.ErrDenied):
		writeError(w, r, 404, "not_found", "Policy or owned machine not found.")
	case errors.Is(err, lazyaccess.ErrConflict):
		writeError(w, r, 409, "policy_changed", "Policy or machine installation changed. Read the current state and reapprove before retrying.")
	case errors.Is(err, lazyaccess.ErrCapacity):
		w.Header().Set("Retry-After", "1")
		writeError(w, r, 429, "policy_limit", "The environment policy target limit is reached. Remove an unused policy before retrying.")
	default:
		writeError(w, r, 503, "policy_unavailable", "Policy storage is unavailable. Read the current policy before retrying a mutation.")
	}
}

func decodeLazyPolicy(w http.ResponseWriter, r *http.Request, v any) bool {
	raw, err := browserBody(w, r)
	if err == nil {
		err = browserDecode(raw, v)
	}
	if err != nil {
		writeError(w, r, 400, "invalid_policy", "Policy JSON must be bounded and contain only unique supported fields.")
		return false
	}
	return true
}
