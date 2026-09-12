package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/teaminbox"
)

func teamInboxError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, teaminbox.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "invalid_team_inbox_request", "The Team Inbox request is invalid.")
	case errors.Is(err, teaminbox.ErrForbidden):
		writeError(w, r, http.StatusForbidden, "team_inbox_forbidden", "The file grant does not authorize this transfer.")
	case errors.Is(err, teaminbox.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "team_inbox_request_not_found", "The Team Inbox request was not found.")
	case errors.Is(err, teaminbox.ErrPending):
		writeError(w, r, http.StatusConflict, "team_inbox_pending", "The recipient has not approved this transfer yet.")
	case errors.Is(err, teaminbox.ErrDeclined):
		writeError(w, r, http.StatusConflict, "team_inbox_declined", "The recipient declined this transfer.")
	case errors.Is(err, teaminbox.ErrExpired):
		writeError(w, r, http.StatusGone, "team_inbox_expired", "The transfer request expired.")
	case errors.Is(err, teaminbox.ErrRevoked):
		writeError(w, r, http.StatusForbidden, "team_inbox_revoked", "Team access for this transfer was revoked.")
	case errors.Is(err, teaminbox.ErrConflict):
		writeError(w, r, http.StatusConflict, "team_inbox_conflict", "The Team Inbox request changed; refresh its status.")
	case errors.Is(err, teaminbox.ErrLimit):
		writeError(w, r, http.StatusTooManyRequests, "team_inbox_limit", "The recipient has too many pending transfer requests.")
	case errors.Is(err, teaminbox.ErrOffline):
		writeError(w, r, http.StatusConflict, "team_inbox_recipient_offline", "The recipient is offline; Paperboat does not store file payloads for later delivery.")
	default:
		writeError(w, r, http.StatusServiceUnavailable, "team_inbox_unavailable", "Team Inbox is temporarily unavailable.")
	}
}

func registerTeamInboxRoutes(mux *http.ServeMux, service *teaminbox.Service, read, write func(http.Handler) http.Handler) {
	principal := func(w http.ResponseWriter, r *http.Request) (string, bool) { return vaultScopePrincipal(w, r) }
	mux.Handle("GET /v1/teams/{team_id}/receipt-smtp", read(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := principal(w, r)
		if !ok {
			return
		}
		out, err := service.TeamSMTP(r.Context(), account, r.PathValue("team_id"))
		if err != nil {
			teamInboxError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})))
	mux.Handle("PUT /v1/teams/{team_id}/receipt-smtp", write(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := principal(w, r)
		if !ok {
			return
		}
		limitEnvironmentJSON(w, r, 8192)
		var in teaminbox.SMTPConfig
		if !decodeStrictJSON(w, r, &in) {
			return
		}
		out, err := service.SetTeamSMTP(r.Context(), account, r.PathValue("team_id"), in, in.Generation)
		if err != nil {
			teamInboxError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})))
	mux.Handle("DELETE /v1/teams/{team_id}/receipt-smtp", write(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := principal(w, r)
		if !ok {
			return
		}
		limitEnvironmentJSON(w, r, 1024)
		var in struct {
			ExpectedGeneration uint64 `json:"expected_generation"`
		}
		if !decodeStrictJSON(w, r, &in) {
			return
		}
		if err := service.DeleteTeamSMTP(r.Context(), account, r.PathValue("team_id"), in.ExpectedGeneration); err != nil {
			teamInboxError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("GET /v1/team-inbox/policy", read(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := principal(w, r)
		if !ok {
			return
		}
		out, err := service.Policy(r.Context(), account)
		if err != nil {
			teamInboxError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})))
	mux.Handle("PUT /v1/team-inbox/policy", write(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := principal(w, r)
		if !ok {
			return
		}
		limitEnvironmentJSON(w, r, 4096)
		var in struct {
			Acceptance         string `json:"acceptance"`
			ReceiptEmail       bool   `json:"receipt_email"`
			ExpectedGeneration uint64 `json:"expected_generation"`
		}
		if !decodeStrictJSON(w, r, &in) {
			return
		}
		out, err := service.SetPolicy(r.Context(), account, teaminbox.Policy{Acceptance: in.Acceptance, ReceiptEmail: in.ReceiptEmail}, in.ExpectedGeneration)
		if err != nil {
			teamInboxError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})))
	mux.Handle("GET /v1/team-inbox/requests", read(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := principal(w, r)
		if !ok {
			return
		}
		out, err := service.List(r.Context(), account)
		if err != nil {
			teamInboxError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})))
	mux.Handle("POST /v1/team-inbox/requests", write(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := principal(w, r)
		if !ok {
			return
		}
		limitEnvironmentJSON(w, r, teaminbox.MaximumManifestBytes)
		var in struct {
			RequestID            string           `json:"request_id"`
			OperationID          string           `json:"operation_id"`
			SourceMachineID      string           `json:"source_machine_id"`
			DestinationMachineID string           `json:"destination_machine_id"`
			BatchID              string           `json:"batch_id"`
			Files                []teaminbox.File `json:"files"`
			ExpiresAt            time.Time        `json:"expires_at"`
		}
		if !decodeStrictJSON(w, r, &in) {
			return
		}
		out, err := service.Create(r.Context(), teaminbox.RequestInput{RequestID: in.RequestID, OperationID: in.OperationID, SenderAccount: account, SourceMachineID: in.SourceMachineID, DestinationMachineID: in.DestinationMachineID, BatchID: in.BatchID, Files: in.Files, ExpiresAt: in.ExpiresAt})
		if err != nil {
			teamInboxError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: out})
	})))
	mux.Handle("GET /v1/team-inbox/requests/{request_id}", read(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := principal(w, r)
		if !ok {
			return
		}
		out, err := service.Get(r.Context(), account, r.PathValue("request_id"))
		if err != nil {
			teamInboxError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})))
	for action, decision := range map[string]string{"approve": "approved", "decline": "declined"} {
		decision := decision
		mux.Handle("POST /v1/team-inbox/requests/{request_id}/"+action, write(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			account, ok := principal(w, r)
			if !ok {
				return
			}
			limitEnvironmentJSON(w, r, 1024)
			var in struct {
				ExpectedGeneration uint64 `json:"expected_generation"`
			}
			if !decodeStrictJSON(w, r, &in) {
				return
			}
			out, err := service.Decide(r.Context(), account, r.PathValue("request_id"), decision, in.ExpectedGeneration)
			if err != nil {
				teamInboxError(w, r, err)
				return
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
		})))
	}
	mux.Handle("POST /v1/team-inbox/requests/{request_id}/complete", write(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := principal(w, r)
		if !ok {
			return
		}
		limitEnvironmentJSON(w, r, 1024)
		var in struct {
			ManifestDigest string `json:"manifest_digest"`
		}
		if !decodeStrictJSON(w, r, &in) {
			return
		}
		request, err := service.Get(r.Context(), account, r.PathValue("request_id"))
		if err != nil {
			teamInboxError(w, r, err)
			return
		}
		out, err := service.Complete(r.Context(), request.RecipientAccount, request.RequestID, in.ManifestDigest)
		if err != nil {
			teamInboxError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
	})))
}
