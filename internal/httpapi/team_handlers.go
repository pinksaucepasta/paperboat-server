package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

type teamAPI interface {
	List(context.Context, string) ([]teams.Team, error)
	Get(context.Context, string, string) (teams.Team, error)
	Create(context.Context, string, teams.CreateRequest) (teams.Team, error)
	Mutate(context.Context, string, string, teams.MutationRequest) (teams.Team, error)
	Invite(context.Context, string, string, teams.InviteRequest) (teams.Invitation, error)
	Accept(context.Context, string, string, teams.AcceptRequest) (teams.Team, error)
	CancelInvite(context.Context, string, string, string, teams.MutationRequest) (teams.Team, error)
	Grant(context.Context, string, string, teams.GrantRequest) (teams.Team, error)
	Attach(context.Context, string, string, teams.AttachRequest) (teams.Team, error)
}

func registerTeamRoutes(mux *http.ServeMux, service teamAPI, read, write func(http.Handler) http.Handler) {
	handle := func(pattern, action string, mutation bool) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			account, ok := vaultScopePrincipal(w, r)
			if !ok {
				return
			}
			team := r.PathValue("team_id")
			limitEnvironmentJSON(w, r, 16<<10)
			var out any
			var err error
			switch action {
			case "list":
				out, err = service.List(r.Context(), account)
			case "get":
				out, err = service.Get(r.Context(), account, team)
			case "create":
				var in teams.CreateRequest
				if !decodeStrictJSON(w, r, &in) {
					return
				}
				out, err = service.Create(r.Context(), account, in)
			case "mutate":
				var in teams.MutationRequest
				if !decodeStrictJSON(w, r, &in) {
					return
				}
				out, err = service.Mutate(r.Context(), account, team, in)
			case "invite":
				var in teams.InviteRequest
				if !decodeStrictJSON(w, r, &in) {
					return
				}
				out, err = service.Invite(r.Context(), account, team, in)
			case "accept":
				var in teams.AcceptRequest
				if !decodeStrictJSON(w, r, &in) {
					return
				}
				out, err = service.Accept(r.Context(), account, r.PathValue("invitation_id"), in)
			case "cancel":
				var in teams.MutationRequest
				if !decodeStrictJSON(w, r, &in) {
					return
				}
				out, err = service.CancelInvite(r.Context(), account, team, r.PathValue("invitation_id"), in)
			case "grant":
				var in teams.GrantRequest
				if !decodeStrictJSON(w, r, &in) {
					return
				}
				out, err = service.Grant(r.Context(), account, team, in)
			case "attach":
				var in teams.AttachRequest
				if !decodeStrictJSON(w, r, &in) {
					return
				}
				out, err = service.Attach(r.Context(), account, team, in)
			}
			switch {
			case errors.Is(err, teams.ErrForbidden):
				writeError(w, r, http.StatusForbidden, "forbidden", "Current team role and exact resource permission are required.")
			case errors.Is(err, teams.ErrNotFound):
				writeError(w, r, http.StatusNotFound, "not_found", "Team or resource is unavailable.")
			case errors.Is(err, teams.ErrConflict):
				writeError(w, r, http.StatusConflict, "team_changed", "Team changed. Refresh its current state before retrying.")
			case errors.Is(err, teams.ErrExpired):
				writeError(w, r, http.StatusConflict, "invitation_unavailable", "Invitation expired, was cancelled or has already been accepted.")
			case errors.Is(err, teams.ErrInvalid):
				writeError(w, r, http.StatusBadRequest, "invalid_request", "Check the team action, resource permission and confirmation.")
			case errors.Is(err, teams.ErrLimit):
				writeError(w, r, http.StatusConflict, "team_limit", "Team capacity reached. Remove unused entries before retrying.")
			case err != nil:
				writeError(w, r, http.StatusInternalServerError, "internal_error", "Team operation could not be confirmed. Retry the same operation to reconcile its result.")
			default:
				writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
			}
		})
		if mutation {
			mux.Handle(pattern, write(h))
		} else {
			mux.Handle(pattern, read(h))
		}
	}
	handle("GET /v1/teams", "list", false)
	handle("POST /v1/teams", "create", true)
	handle("GET /v1/teams/{team_id}", "get", false)
	handle("POST /v1/teams/{team_id}/actions", "mutate", true)
	handle("POST /v1/teams/{team_id}/invitations", "invite", true)
	handle("POST /v1/team-invitations/{invitation_id}/accept", "accept", true)
	handle("POST /v1/teams/{team_id}/invitations/{invitation_id}/cancel", "cancel", true)
	handle("POST /v1/teams/{team_id}/grants", "grant", true)
	handle("POST /v1/teams/{team_id}/resources", "attach", true)
}
