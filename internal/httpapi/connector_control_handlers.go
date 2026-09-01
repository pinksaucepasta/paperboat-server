package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

const connectorBootstrapBodyLimit = 8 << 10

type activeConnectorControlSessionReader interface {
	Lookup(tunnelID, connectorID, sessionID string, processGeneration uint64) (connectorprotocol.ActiveControlSession, bool)
}

func NewConnectorCarrierBootstrapHandler(sessions *connectorprotocol.ActiveControlSessions, source connectorprotocol.CarrierBootstrapSource, identities *controlplane.EnrollmentService) (http.Handler, error) {
	if sessions == nil || source == nil || identities == nil {
		return nil, connectorprotocol.ErrInvalidInput
	}
	return connectorCarrierBootstrap(sessions, source, identities), nil
}

func connectorCarrierBootstrap(sessions activeConnectorControlSessionReader, source connectorprotocol.CarrierBootstrapSource, identities machineRequestVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if sessions == nil || source == nil || identities == nil {
			writePreviewTunnelError(w, r, http.StatusServiceUnavailable, "connector_control_unavailable", "Connector control is temporarily unavailable.", "unchanged", true, "retry")
			return
		}
		contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || contentType != "application/json" {
			writePreviewTunnelError(w, r, http.StatusUnsupportedMediaType, "invalid_content_type", "Content-Type must be application/json.", "unchanged", false, "fix_request")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, connectorBootstrapBodyLimit+1))
		if err != nil || len(body) == 0 || len(body) > connectorBootstrapBodyLimit {
			writePreviewTunnelError(w, r, http.StatusBadRequest, "invalid_request", "Connector bootstrap request is invalid.", "unchanged", false, "fix_request")
			return
		}
		if _, err = previewtunnelapi.RequestHash(body); err != nil {
			writePreviewTunnelError(w, r, http.StatusBadRequest, "invalid_request", "Connector bootstrap request is invalid.", "unchanged", false, "fix_request")
			return
		}
		var request connectorprotocol.CarrierBootstrapRequest
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.Validate() != nil {
			writePreviewTunnelError(w, r, http.StatusBadRequest, "invalid_request", "Connector bootstrap request is invalid.", "unchanged", false, "fix_request")
			return
		}
		tunnelID, connectorID := r.PathValue("tunnel_id"), r.PathValue("connector_id")
		active, ok := sessions.Lookup(tunnelID, connectorID, request.SessionID, request.ProcessGeneration)
		if !ok || active.ConfigGeneration != request.ConfigGeneration || active.ConfigContentHash != request.ConfigContentHash {
			writePreviewTunnelError(w, r, http.StatusConflict, "connector_session_stale", "The connector session changed before carrier bootstrap.", "unchanged", true, "reconnect")
			return
		}
		proofValues := r.Header.Values("X-Paperboat-Machine-Proof")
		identityValues := r.Header.Values("X-Paperboat-Machine-Identity")
		operationValues := r.Header.Values("Idempotency-Key")
		if len(proofValues) != 1 || len(identityValues) != 1 || len(operationValues) != 1 || strings.TrimSpace(operationValues[0]) == "" {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_required", "A current machine identity is required.", "unchanged", false, "reauthenticate")
			return
		}
		proof, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(proofValues[0]))
		if err != nil || len(proof) == 0 {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "The machine identity could not be verified.", "unchanged", false, "reauthenticate")
			return
		}
		claims, err := identities.VerifyMachineRequest(r.Context(), strings.TrimSpace(identityValues[0]), proof, r.Method, r.URL.Path, body)
		if err != nil || claims.MachineID != active.HostID || claims.UserID != active.AccountID || claims.OperationID != strings.TrimSpace(operationValues[0]) {
			writePreviewTunnelError(w, r, http.StatusForbidden, "connector_access_forbidden", "This machine cannot bootstrap the connector session.", "unchanged", false, "use_authorized_host")
			return
		}
		descriptor, err := source.Descriptor(r.Context(), active)
		if err != nil {
			if errors.Is(err, connectorprotocol.ErrNotReady) {
				writePreviewTunnelError(w, r, http.StatusServiceUnavailable, "carrier_unavailable", "No authenticated carrier endpoint is ready.", "unchanged", true, "retry")
				return
			}
			writePreviewTunnelError(w, r, http.StatusServiceUnavailable, "connector_control_unavailable", "Connector control is temporarily unavailable.", "unchanged", true, "retry")
			return
		}
		if descriptor.Validate(time.Now().UTC()) != nil || descriptor.AccountID != active.AccountID || descriptor.TunnelID != active.TunnelID || descriptor.ConnectorID != active.ConnectorID || descriptor.HostID != active.HostID || descriptor.SessionID != active.SessionID || descriptor.ProcessGeneration != active.ProcessGeneration || descriptor.ConfigGeneration != active.ConfigGeneration || descriptor.ConfigContentHash != active.ConfigContentHash {
			writePreviewTunnelError(w, r, http.StatusServiceUnavailable, "connector_control_invalid", "Connector control returned an invalid carrier binding.", "unchanged", true, "retry")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: descriptor})
	}
}
