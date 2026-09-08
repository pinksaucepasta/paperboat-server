package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/nativeprivateaccess"
)

func nativePrivateGrant(service *nativeprivateaccess.Service) http.HandlerFunc {
	type request struct {
		OperationID  string `json:"operation_id"`
		ResourceKind string `json:"resource_kind"`
		ResourceID   string `json:"resource_id"`
		RouteID      string `json:"route_id"`
		Protocol     string `json:"protocol"`
		Selector     string `json:"selector,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body request
		decoder := json.NewDecoder(io.LimitReader(r.Body, 4097))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Native private access request is invalid.")
			return
		}
		exactAny := body.ResourceKind != "" || body.ResourceID != "" || body.RouteID != "" || body.Protocol != ""
		exact := body.ResourceKind != "" && body.ResourceID != "" && body.RouteID != "" && body.Protocol != ""
		selector := strings.TrimSpace(body.Selector)
		if body.OperationID == "" || strings.TrimSpace(body.OperationID) != body.OperationID || exactAny != exact || (exact == (selector != "")) || body.Selector != selector {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Native private access request is invalid.")
			return
		}
		grant, err := service.Issue(r.Context(), nativeprivateaccess.Request{AccountID: p.User.ID, UserID: p.User.ID, CLIClientSessionID: p.Client.SessionID, OperationID: body.OperationID, ResourceKind: body.ResourceKind, ResourceID: body.ResourceID, RouteID: body.RouteID, Protocol: body.Protocol, Selector: selector})
		switch {
		case errors.Is(err, nativeprivateaccess.ErrInvalid):
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Native private access request is invalid.")
		case errors.Is(err, nativeprivateaccess.ErrDenied):
			writeError(w, r, http.StatusForbidden, "forbidden", "Native private access is not allowed.")
		case err != nil:
			writeError(w, r, http.StatusServiceUnavailable, "native_private_unavailable", "Native private access is temporarily unavailable.")
		default:
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, SuccessResponse{Data: grant})
		}
	}
}
