package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/browseraccess"
	"github.com/pinksaucepasta/paperboat-server/internal/browseringress"
	"github.com/pinksaucepasta/paperboat-server/internal/canonicaljson"
	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-server/internal/lazyaccess"
	"github.com/pinksaucepasta/paperboat-server/internal/previewattachment"
)

type BrowserAccessHandlers struct {
	Lazy    *lazyaccess.Activator
	Access  *browseraccess.Service
	Ingress *browseringress.Service
	Edge    previewattachment.PreviewEdgeRequestVerifier
	Machine previewattachment.MachineProofVerifier
}

func browserAccessError(w http.ResponseWriter, r *http.Request, err error) {
	var activation *lazyaccess.ActivationError
	switch {
	case errors.As(err, &activation):
		status := 503
		if activation.Code == "activation_timeout" {
			status = 504
		}
		if activation.Code == "generation_conflict" {
			status = 409
		}
		writeError(w, r, status, activation.Code, "Private service activation did not complete. No application request was forwarded; retry after checking host and service readiness.")
	case errors.Is(err, lazyaccess.ErrCapacity):
		w.Header().Set("Retry-After", "1")
		writeError(w, r, 429, "activation_limit", "Private service activation is busy. Retry after one second.")
	case errors.Is(err, browseraccess.ErrInvalid):
		writeError(w, r, 400, "invalid_request", "Invalid browser access request.")
	case errors.Is(err, browseraccess.ErrExpired), errors.Is(err, browseraccess.ErrAlreadyRedeemed):
		writeError(w, r, 401, "authentication_required", "Sign in again.")
	case errors.Is(err, browseraccess.ErrNotAuthorized), errors.Is(err, connectorprotocol.ErrIngressDenied):
		writeError(w, r, 404, "not_found", "Resource not found.")
	default:
		writeError(w, r, 503, "authorization_unavailable", "Browser authorization is unavailable.")
	}
}
func browserDecode(raw []byte, v any) error {
	if canonicaljson.RejectDuplicateFields(raw) != nil {
		return browseraccess.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return browseraccess.ErrInvalid
	}
	return nil
}
func browserBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, browseraccess.ErrInvalid
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		return nil, browseraccess.ErrInvalid
	}
	return raw, nil
}
func (h *BrowserAccessHandlers) Issue(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	p, ok := principalFromContext(r.Context())
	if !ok || p.Client != nil || p.Session.ID == "" {
		writeError(w, r, 401, "authentication_required", "Sign in again.")
		return
	}
	raw, err := browserBody(w, r)
	if err != nil {
		browserAccessError(w, r, err)
		return
	}
	var input browseraccess.IssueRequest
	if err = browserDecode(raw, &input); err != nil {
		browserAccessError(w, r, err)
		return
	}
	input.Principal = p.Session
	out, err := h.Access.Issue(r.Context(), input)
	if err != nil {
		browserAccessError(w, r, err)
		return
	}
	writeJSON(w, 200, SuccessResponse{Data: out})
}
func (h *BrowserAccessHandlers) EdgeRequest(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	raw, err := browserBody(w, r)
	if err != nil {
		browserAccessError(w, r, err)
		return
	}
	edge, err := h.Edge.VerifyPreviewEdgeRequest(r.Context(), r, raw)
	if err != nil {
		writeError(w, r, 401, "edge_identity_invalid", "Edge authentication required.")
		return
	}
	var out any
	switch r.PathValue("operation") {
	case "begin":
		var input browseraccess.BeginRequest
		if err = browserDecode(raw, &input); err == nil {
			out, err = h.Access.Begin(r.Context(), input)
		}
	case "redeem":
		var input browseraccess.RedeemRequest
		if err = browserDecode(raw, &input); err == nil {
			out, err = h.Access.Redeem(r.Context(), input)
		}
	case "authorize", "activate":
		var input struct {
			browseraccess.AuthorizeRequest
			CredentialKind string `json:"credential_kind,omitempty"`
		}
		if err = browserDecode(raw, &input); err == nil {
			var a browseraccess.Authorization
			switch input.CredentialKind {
			case "", "browser":
				a, err = h.Access.Authorize(r.Context(), input.AuthorizeRequest)
			case "machine":
				a, err = h.Access.AuthorizeMachineCredential(r.Context(), input.Token, input.Host, input.ResourceKind, input.ResourceID, input.RouteID, "use")
			default:
				err = browseraccess.ErrInvalid
			}
			if err == nil && r.PathValue("operation") == "activate" {
				if h.Lazy == nil || a.ResourceKind != "lazy_policy" {
					err = browseraccess.ErrNotAuthorized
				} else {
					original := a
					check := func(ctx context.Context) error {
						var current browseraccess.Authorization
						var e error
						if input.CredentialKind == "machine" {
							current, e = h.Access.AuthorizeMachineCredential(ctx, input.Token, input.Host, "lazy_policy", original.ResourceID, original.RouteID, "use")
						} else {
							current, e = h.Access.Authorize(ctx, browseraccess.AuthorizeRequest{Token: input.Token, Host: input.Host, ResourceKind: "lazy_policy", ResourceID: original.ResourceID, RouteID: original.RouteID})
						}
						if e == nil && (current.ResourceGeneration != original.ResourceGeneration || current.OwnerAccountID != original.OwnerAccountID) {
							return browseraccess.ErrNotAuthorized
						}
						a = current
						return e
					}
					_, err = h.Lazy.Activate(r.Context(), lazyaccess.ActivationRequest{PolicyID: a.ResourceID, OwnerAccountID: a.OwnerAccountID, PolicyGeneration: a.ResourceGeneration, AuthorityDeadline: a.SessionExpiresAt, Check: check})
				}
			}
			if err == nil {
				out, err = h.Ingress.Resolve(r.Context(), a, edge.NodeID, edge.ProcessEpoch)
			}
		}
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		browserAccessError(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}
func (h *BrowserAccessHandlers) MachineRequest(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	raw, err := browserBody(w, r)
	if err != nil {
		browserAccessError(w, r, err)
		return
	}
	proof, err := h.Machine.VerifyMachineRequest(r.Context(), r, raw)
	if err != nil {
		writeError(w, r, 401, "machine_identity_invalid", "Machine authentication required.")
		return
	}
	var input struct {
		Decision connectorprotocol.IngressDecision `json:"decision"`
		Open     connectorprotocol.StreamOpen      `json:"open"`
	}
	if err = browserDecode(raw, &input); err != nil {
		browserAccessError(w, r, err)
		return
	}
	d := input.Decision
	// Expired decisions are selectors during refresh, never fresh authority.
	if d.Binding.Validate() != nil || input.Open.Validate() != nil || d.Binding.Audience == "public" || d.Binding.AccountID != proof.UserID || d.Binding.HostID != proof.MachineID || d.Binding.InstallationGeneration != proof.InstallationGeneration {
		browserAccessError(w, r, connectorprotocol.ErrIngressDenied)
		return
	}
	kind, id := "tunnel", d.Binding.TunnelID
	if d.Binding.Lifecycle == connectorprotocol.TunnelEphemeral {
		kind, id = "preview", d.Binding.PublicationID
	}
	a, err := h.Access.AuthorizeGrant(r.Context(), d.GrantID, d.Binding.Hostname, kind, id, d.Binding.RouteID)
	if err != nil {
		browserAccessError(w, r, err)
		return
	}
	current, err := h.Ingress.Resolve(r.Context(), a, d.EdgeNodeID, d.EdgeProcessEpoch)
	if err != nil {
		browserAccessError(w, r, err)
		return
	}
	d.IssuedAt, d.ExpiresAt = current.IssuedAt, current.ExpiresAt
	if d.Authorize(current, input.Open, current.EdgeNodeID, current.EdgeProcessEpoch, time.Now().UTC()) != nil {
		browserAccessError(w, r, connectorprotocol.ErrIngressDenied)
		return
	}
	writeJSON(w, 200, SuccessResponse{Data: current})
}

func (h *BrowserAccessHandlers) MachineCredential(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	p, ok := principalFromContext(r.Context())
	if !ok {
		writeError(w, r, 401, "authentication_required", "Sign in again.")
		return
	}
	raw, err := browserBody(w, r)
	if err != nil {
		browserAccessError(w, r, err)
		return
	}
	var input struct {
		Host         string `json:"host"`
		ResourceKind string `json:"resource_kind"`
		ResourceID   string `json:"resource_id"`
		RouteID      string `json:"route_id"`
	}
	if err = browserDecode(raw, &input); err != nil {
		browserAccessError(w, r, err)
		return
	}
	out, err := h.Access.IssueMachineCredential(r.Context(), browseraccess.MachineCredentialRequest{AccountID: p.User.ID, Host: input.Host, ResourceKind: input.ResourceKind, ResourceID: input.ResourceID, RouteID: input.RouteID, Action: "use", TTL: 5 * time.Minute})
	if err != nil {
		browserAccessError(w, r, err)
		return
	}
	writeJSON(w, 200, SuccessResponse{Data: out})
}
