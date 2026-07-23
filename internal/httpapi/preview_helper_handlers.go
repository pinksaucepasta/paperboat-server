package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

func helperPreviewOperation(previews *controlplane.PreviewService, identities *controlplane.EnrollmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
		if err != nil || len(body) > 1<<20 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Preview operation is invalid.")
			return
		}
		proof, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Credential is invalid.")
			return
		}
		claims, err := identities.VerifyPreviewRequest(r.Context(), r.Header.Get("X-Paperboat-Helper-Identity"), mustBearer(r), proof, body, r.Method, r.URL.Path)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Credential is invalid.")
			return
		}
		var input struct {
			Action            string `json:"action"`
			LogicalName       string `json:"logical_name,omitempty"`
			TargetHost        string `json:"target_host,omitempty"`
			TargetPort        int32  `json:"target_port,omitempty"`
			AcknowledgePublic bool   `json:"public_acknowledgement,omitempty"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || input.Action == "" {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Preview operation is invalid.")
			return
		}
		switch input.Action {
		case "list":
			items, listErr := previews.ListForHelper(r.Context(), claims.HelperID, claims.EnvironmentID)
			if listErr != nil {
				previewHelperError(w, r, listErr)
				return
			}
			out := make([]previewResponse, 0, len(items))
			for _, item := range items {
				out = append(out, newPreviewResponse(item))
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: out})
		case "register":
			if input.TargetHost == "" {
				input.TargetHost = "127.0.0.1"
			}
			item, operationErr := previews.CreateOrUpdateForHelper(r.Context(), claims.HelperID, claims.OperationID, claims.EnvironmentID, input.LogicalName, input.TargetHost, input.TargetPort, input.AcknowledgePublic)
			if operationErr != nil {
				previewHelperError(w, r, operationErr)
				return
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: newPreviewResponse(item)})
		case "remove":
			item, operationErr := previews.RemoveForHelper(r.Context(), claims.HelperID, claims.OperationID, claims.EnvironmentID, input.LogicalName)
			if operationErr != nil {
				previewHelperError(w, r, operationErr)
				return
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: newPreviewResponse(item)})
		default:
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Unsupported preview operation.")
		}
	}
}

func mustBearer(r *http.Request) string {
	token, _ := bearerToken(r)
	return token
}

func previewHelperError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, controlplane.ErrPreviewAcknowledgment):
		writeError(w, r, http.StatusBadRequest, "public_access_acknowledgement_required", "Public access acknowledgement is required for a new preview.")
	case errors.Is(err, controlplane.ErrPreviewRemoved), errors.Is(err, controlplane.ErrPreviewDenied):
		writeError(w, r, http.StatusNotFound, "not_found_or_forbidden", "Preview was not found.")
	case errors.Is(err, controlplane.ErrPreviewConflict):
		writeError(w, r, http.StatusConflict, "operation_conflict", "Preview operation conflicts with an earlier request.")
	default:
		writeError(w, r, http.StatusBadRequest, "validation_failed", "Preview operation is invalid.")
	}
}
