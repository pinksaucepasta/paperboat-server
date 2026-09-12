package httpapi

import (
	"github.com/pinksaucepasta/paperboat-server/internal/inspectaccess"
	"net/http"
)

func (h *InspectorHandlers) ResolveAccess(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	account, ok := vaultScopePrincipal(w, r)
	if !ok {
		return
	}
	limitEnvironmentJSON(w, r, 4<<10)
	var body inspectaccess.AccessRequest
	if !decodeStrictJSON(w, r, &body) {
		return
	}
	if body.EdgeNodeID != "" || body.EdgeProcessEpoch != "" {
		inspectorError(w, r, inspectaccess.ErrInvalid)
		return
	}
	body.AccountID = account
	if p, ok := principalFromContext(r.Context()); ok && p.Client != nil {
		body.CLIClientSessionID = p.Client.SessionID
	}
	out, err := h.Access.ResolveAccess(r.Context(), body)
	if err != nil {
		inspectorError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
}

func (h *InspectorHandlers) Targets(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	account, ok := vaultScopePrincipal(w, r)
	if !ok {
		return
	}
	limitEnvironmentJSON(w, r, 4<<10)
	var body struct {
		Selector string `json:"selector"`
		Action   string `json:"action"`
	}
	if !decodeStrictJSON(w, r, &body) {
		return
	}
	out, err := h.Access.Targets(r.Context(), account, body.Selector, body.Action)
	if err != nil {
		inspectorError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
}
