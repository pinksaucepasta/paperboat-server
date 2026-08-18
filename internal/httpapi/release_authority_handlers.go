package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/releaseauthority"
)

func releaseAuthorityRequests(service *releaseauthority.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items, err := service.ListRequests(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to read release authority requests.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"requests": items}})
	}
}
func releaseAuthorityRequestCreate(service *releaseauthority.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		decoder := json.NewDecoder(io.LimitReader(r.Body, 4097))
		decoder.DisallowUnknownFields()
		var input releaseauthority.Request
		var extra any
		if decoder.Decode(&input) != nil || decoder.Decode(&extra) != io.EOF {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		result, err := service.Request(r.Context(), principal.User.ID, r.Header.Get("Idempotency-Key"), input)
		if errors.Is(err, releaseauthority.ErrInvalid) {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Release authority request details are invalid.")
		} else if errors.Is(err, releaseauthority.ErrConflict) {
			writeError(w, r, http.StatusConflict, "idempotency_conflict", "Idempotency-Key conflicts with an earlier release authority request.")
		} else if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to create release authority request.")
		} else {
			writeJSON(w, http.StatusCreated, SuccessResponse{Data: result})
		}
	}
}

func releaseAuthorityBundles(service *releaseauthority.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items, err := service.List(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to read release authority decisions.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"bundles": items}})
	}
}

func releaseAuthorityBundleImport(service *releaseauthority.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
		if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Signed bundle must be a JSON document no larger than 64 KiB.")
			return
		}
		result, err := service.Import(r.Context(), principal.User.ID, r.Header.Get("Idempotency-Key"), raw)
		switch {
		case errors.Is(err, releaseauthority.ErrInvalid):
			writeError(w, r, http.StatusBadRequest, "release_authority_bundle_invalid", "The signed release authority bundle is invalid or expired.")
		case errors.Is(err, releaseauthority.ErrSignature):
			writeError(w, r, http.StatusForbidden, "release_authority_signature_invalid", "The bundle does not meet the configured release-authority signing threshold.")
		case errors.Is(err, releaseauthority.ErrConflict):
			writeError(w, r, http.StatusConflict, "release_authority_import_conflict", "The bundle policy revision or Idempotency-Key conflicts with an earlier import.")
		case err != nil:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to import the signed release authority bundle.")
		default:
			writeJSON(w, http.StatusCreated, SuccessResponse{Data: result})
		}
	}
}
