package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

func routeIntentCreate(service *controlplane.RouteService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		var in struct {
			Kind       string `json:"kind"`
			PublicHost string `json:"public_host"`
			TargetHost string `json:"target_host"`
			TargetPort int32  `json:"target_port"`
		}
		if !decodeStrictJSON(w, r, &in) {
			return
		}
		operationKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if operationKey == "" {
			writeError(w, r, 400, "idempotency_key_required", "Idempotency-Key header is required.")
			return
		}
		item, err := service.Create(r.Context(), p.User.ID, operationKey, r.PathValue("environment_id"), in.Kind, in.PublicHost, in.TargetHost, in.TargetPort)
		if err != nil {
			status, code := 400, "validation_failed"
			if errors.Is(err, controlplane.ErrRouteDenied) {
				status, code = 404, "not_found_or_forbidden"
			}
			writeError(w, r, status, code, "Route intent could not be created.")
			return
		}
		writeJSON(w, 201, SuccessResponse{Data: item})
	}
}

func routeIntentTransition(service *controlplane.RouteService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		var in struct {
			DesiredState     string `json:"desired_state"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if !decodeStrictJSON(w, r, &in) {
			return
		}
		operationKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if operationKey == "" {
			writeError(w, r, 400, "idempotency_key_required", "Idempotency-Key header is required.")
			return
		}
		item, err := service.Transition(r.Context(), p.User.ID, operationKey, r.PathValue("route_id"), in.DesiredState, in.ExpectedRevision)
		if err != nil {
			status, code := 400, "validation_failed"
			if errors.Is(err, controlplane.ErrRouteConflict) {
				status, code = 409, "version_conflict"
			}
			if errors.Is(err, controlplane.ErrRouteDenied) {
				status, code = 404, "not_found_or_forbidden"
			}
			writeError(w, r, status, code, "Route intent could not be changed.")
			return
		}
		writeJSON(w, 200, SuccessResponse{Data: item})
	}
}
