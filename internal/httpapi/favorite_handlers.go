package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/favorites"
)

func favoritesList(service *favorites.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		items, err := service.List(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Favorites could not be loaded.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: items})
	}
}

func favoriteSet(service *favorites.Service) http.HandlerFunc {
	type request struct {
		Kind       string `json:"kind"`
		ResourceID string `json:"resource_id"`
		Favorite   bool   `json:"favorite"`
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
		body.Kind, body.ResourceID = strings.TrimSpace(body.Kind), strings.TrimSpace(body.ResourceID)
		if err := service.Set(r.Context(), p.User.ID, body.Kind, body.ResourceID, body.Favorite); err != nil {
			if errors.Is(err, favorites.ErrLimit) {
				writeError(w, r, http.StatusConflict, "favorite_limit_reached", "You can favorite up to five items.")
				return
			}
			if errors.Is(err, favorites.ErrResourceNotFound) {
				writeError(w, r, http.StatusNotFound, "favorite_resource_not_found", "The selected resource was not found.")
				return
			}
			if strings.Contains(err.Error(), "unsupported favorite") || strings.Contains(err.Error(), "resource id is required") {
				writeError(w, r, http.StatusBadRequest, "invalid_favorite", "Favorite kind and resource ID are required.")
				return
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Favorite could not be updated.")
			return
		}
		items, err := service.List(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Favorites could not be loaded.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: items})
	}
}
