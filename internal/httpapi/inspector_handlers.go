package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/inspectaccess"
	"github.com/pinksaucepasta/paperboat-server/internal/previewattachment"
)

type InspectorHandlers struct {
	Access  *inspectaccess.Service
	Machine previewattachment.MachineProofVerifier
}

func inspectorError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, inspectaccess.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "invalid_inspector_request", "The inspector request is invalid.")
	case errors.Is(err, inspectaccess.ErrNotAuthorized):
		writeError(w, r, http.StatusForbidden, "inspector_not_authorized", "The inspector action is not authorized for this principal.")
	case errors.Is(err, inspectaccess.ErrCapacity):
		writeError(w, r, http.StatusTooManyRequests, "inspector_capacity_reached", "Too many active inspector credentials; revoke unused ones and retry.")
	default:
		writeError(w, r, http.StatusInternalServerError, "inspector_unavailable", "The inspector request failed.")
	}
}

// IssueCredential mints a short-lived opaque credential for the caller's own
// current authority. The token is shown once in this response and never
// logged; issuance for another principal is impossible by construction.
func (h *InspectorHandlers) IssueCredential(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	account, ok := vaultScopePrincipal(w, r)
	if !ok {
		return
	}
	limitEnvironmentJSON(w, r, 4<<10)
	var body struct {
		ResourceKind string `json:"resource_kind"`
		ResourceID   string `json:"resource_id"`
		RouteID      string `json:"route_id"`
		Action       string `json:"action"`
		TTLSeconds   int64  `json:"ttl_seconds"`
	}
	if !decodeStrictJSON(w, r, &body) {
		return
	}
	ttl := 5 * time.Minute
	if body.TTLSeconds != 0 {
		ttl = time.Duration(body.TTLSeconds) * time.Second
	}
	out, err := h.Access.Issue(r.Context(), inspectaccess.IssueRequest{AccountID: account, ResourceKind: body.ResourceKind, ResourceID: body.ResourceID, RouteID: body.RouteID, Action: body.Action, TTL: ttl})
	if err != nil {
		inspectorError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"credential_id": out.CredentialID, "token": out.Token, "expires_at": out.ExpiresAt.UTC().Format(time.RFC3339Nano)}})
}

// RevokeCredential revokes one credential. The holder or the current resource
// owner may revoke.
func (h *InspectorHandlers) RevokeCredential(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	account, ok := vaultScopePrincipal(w, r)
	if !ok {
		return
	}
	limitEnvironmentJSON(w, r, 4<<10)
	id := r.PathValue("credential_id")
	if id == "" {
		var body struct {
			CredentialID string `json:"credential_id"`
		}
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		id = body.CredentialID
	}
	if err := h.Access.RevokeCredential(r.Context(), account, id); err != nil {
		inspectorError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"revoked": true}})
}

// Authorize re-resolves current authority for a presented credential on the
// daemon's machine-authenticated control channel and returns a 10-second
// decision. The machine account must equal the resource owner.
func (h *InspectorHandlers) Authorize(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	raw, err := browserBody(w, r)
	if err != nil {
		inspectorError(w, r, err)
		return
	}
	proof, err := h.Machine.VerifyMachineRequest(r.Context(), r, raw)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine authentication required.")
		return
	}
	var body struct {
		CredentialToken string `json:"credential_token"`
		ResourceKind    string `json:"resource_kind"`
		ResourceID      string `json:"resource_id"`
		RouteID         string `json:"route_id"`
		Action          string `json:"action"`
	}
	if err = browserDecode(raw, &body); err != nil {
		inspectorError(w, r, err)
		return
	}
	out, err := h.Access.Authorize(r.Context(), inspectaccess.AuthorizeRequest{MachineAccount: proof.UserID, Token: body.CredentialToken, ResourceKind: body.ResourceKind, ResourceID: body.ResourceID, RouteID: body.RouteID, Action: body.Action})
	if err != nil {
		inspectorError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{
		"account_id": out.AccountID, "owner_account_id": out.OwnerAccountID,
		"resource_kind": out.ResourceKind, "resource_id": out.ResourceID, "route_id": out.RouteID,
		"resource_generation": out.ResourceGeneration, "route_generation": out.RouteGeneration, "target_generation": out.TargetGeneration,
		"team_id": out.TeamID, "team_generation": out.TeamGeneration, "membership_generation": out.MembershipGeneration, "binding_generation": out.BindingGeneration, "grant_generation": out.GrantGeneration,
		"credential_id": out.CredentialID, "issued_at": out.IssuedAt.UTC().Format(time.RFC3339Nano), "expires_at": out.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}})
}
