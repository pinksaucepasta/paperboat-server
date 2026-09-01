package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
)

type PreviewTunnelAPI interface {
	GetOperation(context.Context, previewtunnelapi.RequestContext, string) (previewtunnelapi.Operation, error)
	CancelOperation(context.Context, previewtunnelapi.RequestContext, string) (previewtunnelapi.Operation, error)
	ListEvents(context.Context, previewtunnelapi.RequestContext, string, string, string, int) (previewtunnelapi.EventPage, error)
}

const (
	previewTunnelEventBatchSize = 100
	previewTunnelEventPoll      = 2 * time.Second
	previewTunnelEventHeartbeat = 15 * time.Second
)

func previewTunnelOperationGet(service PreviewTunnelAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := previewTunnelRequestContext(w, r)
		if !ok {
			return
		}
		operation, err := service.GetOperation(r.Context(), request, r.PathValue("operation_id"))
		if err != nil {
			writePreviewTunnelServiceError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, SuccessResponse{Data: operation})
	}
}

func previewTunnelOperationCancel(service PreviewTunnelAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := previewTunnelRequestContext(w, r)
		if !ok {
			return
		}
		operation, err := service.CancelOperation(r.Context(), request, r.PathValue("operation_id"))
		if err != nil {
			writePreviewTunnelServiceError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, SuccessResponse{Data: operation})
	}
}

func previewTunnelEvents(service PreviewTunnelAPI, resourceKind, pathParameter string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := previewTunnelRequestContext(w, r)
		if !ok {
			return
		}
		resourceID := strings.TrimSpace(r.PathValue(pathParameter))
		cursor, err := previewTunnelEventCursor(r)
		if err != nil {
			writePreviewTunnelEventError(w, r, err)
			return
		}
		if !isStreamingRequest(r) {
			limit, limitErr := previewtunnelapi.PageLimit(r.URL.Query().Get("limit"))
			if limitErr != nil {
				writePreviewTunnelEventError(w, r, limitErr)
				return
			}
			page, listErr := service.ListEvents(r.Context(), request, resourceKind, resourceID, cursor, limit)
			if listErr != nil {
				writePreviewTunnelEventError(w, r, listErr)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, SuccessResponse{Data: page})
			return
		}

		page, err := service.ListEvents(r.Context(), request, resourceKind, resourceID, cursor, previewTunnelEventBatchSize)
		if err != nil {
			writePreviewTunnelEventError(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		if _, err := fmt.Fprint(w, "retry: 2000\n\n"); err != nil {
			return
		}
		controller := http.NewResponseController(w)
		if err := controller.Flush(); err != nil {
			return
		}

		lastHeartbeat := time.Now()
		for {
			for _, event := range page.Items {
				payload, marshalErr := json.Marshal(event)
				if marshalErr != nil {
					return
				}
				if _, writeErr := fmt.Fprintf(w, "id: %s\ndata: %s\n\n", event.Cursor, payload); writeErr != nil {
					return
				}
				cursor = event.Cursor
			}
			if len(page.Items) > 0 {
				if err := controller.Flush(); err != nil {
					return
				}
				lastHeartbeat = time.Now()
			}
			if page.NextCursor != "" {
				cursor = page.NextCursor
				page, err = service.ListEvents(r.Context(), request, resourceKind, resourceID, cursor, previewTunnelEventBatchSize)
				if err != nil {
					return
				}
				continue
			}

			timer := time.NewTimer(previewTunnelEventPoll)
			select {
			case <-r.Context().Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if time.Since(lastHeartbeat) >= previewTunnelEventHeartbeat {
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
					return
				}
				if err := controller.Flush(); err != nil {
					return
				}
				lastHeartbeat = time.Now()
			}
			page, err = service.ListEvents(r.Context(), request, resourceKind, resourceID, cursor, previewTunnelEventBatchSize)
			if err != nil {
				return
			}
		}
	}
}

func previewTunnelEventCursor(r *http.Request) (string, error) {
	queryCursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	lastEventID := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if queryCursor != "" && lastEventID != "" && queryCursor != lastEventID {
		return "", previewtunnelapi.ErrInvalidCursor
	}
	if queryCursor != "" {
		return queryCursor, nil
	}
	return lastEventID, nil
}

func previewTunnelRequestContext(w http.ResponseWriter, r *http.Request) (previewtunnelapi.RequestContext, bool) {
	p, ok := principalFromContext(r.Context())
	if !ok {
		writePreviewTunnelError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.", "unchanged", false, "authenticate")
		return previewtunnelapi.RequestContext{}, false
	}
	actor := previewtunnelapi.Actor{AccountID: p.User.ID, ActorID: p.User.ID, Role: string(p.User.Role)}
	if p.Client != nil {
		actor.DeviceID = p.Client.SessionID
		actor.Scopes = append([]string(nil), p.Client.Scopes...)
	}
	return previewtunnelapi.RequestContext{
		Actor: actor, RequestID: observability.RequestID(r.Context()),
		CorrelationID: observability.CorrelationID(r.Context()),
	}, true
}

func writePreviewTunnelServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, previewtunnelstore.ErrNotFound):
		writePreviewTunnelError(w, r, http.StatusNotFound, "operation_not_found", "The operation was not found.", "unchanged", false, "refresh")
	case errors.Is(err, previewtunnelapi.ErrForbidden), errors.Is(err, previewtunnelapi.ErrHostActorRequired):
		writePreviewTunnelError(w, r, http.StatusForbidden, "forbidden", "You are not allowed to access this operation.", "unchanged", false, "authenticate_with_required_scope")
	case errors.Is(err, previewtunnelapi.ErrOperationNotCancellable):
		writePreviewTunnelError(w, r, http.StatusConflict, "operation_not_cancellable", "The operation has started work that cannot be cancelled safely.", "uncertain", false, "wait_for_operation")
	case errors.Is(err, previewtunnelapi.ErrInvalidCursor):
		writePreviewTunnelError(w, r, http.StatusBadRequest, "invalid_cursor", "The event cursor is invalid for this resource.", "unchanged", false, "restart_event_stream")
	default:
		writePreviewTunnelError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.", "uncertain", true, "retry")
	}
}

func writePreviewTunnelEventError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, previewtunnelapi.ErrForbidden), errors.Is(err, previewtunnelapi.ErrHostActorRequired):
		writePreviewTunnelError(w, r, http.StatusForbidden, "forbidden", "You are not allowed to access these events.", "unchanged", false, "authenticate_with_required_scope")
	case errors.Is(err, previewtunnelapi.ErrInvalidCursor):
		writePreviewTunnelError(w, r, http.StatusBadRequest, "invalid_cursor", "The event cursor is invalid for this resource.", "unchanged", false, "restart_event_stream")
	case errors.Is(err, previewtunnelapi.ErrUnsafeMetadata):
		writePreviewTunnelError(w, r, http.StatusInternalServerError, "unsafe_event_metadata", "An event could not be returned safely.", "unchanged", false, "contact_support")
	default:
		writePreviewTunnelError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.", "uncertain", true, "retry")
	}
}

func writePreviewTunnelError(w http.ResponseWriter, r *http.Request, status int, code, message, outcome string, retryable bool, repairAction string) {
	writeJSON(w, status, ErrorResponse{Error: APIError{
		Schema: "paperboat.preview-tunnel/v1", Kind: "error", Code: code, Component: "control",
		Message: message, Outcome: outcome, Retryable: &retryable, RepairAction: repairAction,
		RequestID: requestIDFromContext(r.Context()), CorrelationID: observability.CorrelationID(r.Context()),
	}})
}
