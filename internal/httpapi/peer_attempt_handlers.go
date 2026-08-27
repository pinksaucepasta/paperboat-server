package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/peersessions"
)

type peerAttemptService interface {
	Issue(context.Context, peersessions.Request) (peersessions.Pair, error)
	NextControlled(context.Context, string, string, int64) (peersessions.Pair, error)
	Revoke(context.Context, string, string, string, int64, string) error
}

type controlledPeerAttemptWaiter interface {
	WaitNextControlled(context.Context, string, string, int64) (peersessions.Pair, error)
}

type peerAttemptDescriptor struct {
	Version                 int                      `json:"version"`
	AccountID               string                   `json:"account_id"`
	DeviceID                string                   `json:"device_id"`
	OperationID             string                   `json:"operation_id"`
	IntentID                string                   `json:"intent_id"`
	EnvironmentID           string                   `json:"environment_id"`
	Purpose                 string                   `json:"purpose"`
	Consumer                string                   `json:"consumer"`
	InitiatorEndpointID     string                   `json:"initiator_endpoint_id"`
	ResponderEndpointID     string                   `json:"responder_endpoint_id"`
	Role                    string                   `json:"role"`
	AttemptGeneration       int64                    `json:"attempt_generation"`
	NetworkGeneration       int64                    `json:"network_generation"`
	HostGeneration          int64                    `json:"host_generation"`
	AuthorizationGeneration int64                    `json:"authorization_generation"`
	IssuedAt                string                   `json:"issued_at"`
	ExpiresAt               string                   `json:"expires_at"`
	EndpointCertificates    []peerAttemptCertificate `json:"endpoint_certificates"`
	TrustedKeys             []trustedKeyDocument     `json:"trusted_keys"`
	Direct                  peerAttemptDirect        `json:"direct"`
	Signaling               peerAttemptSignaling     `json:"signaling"`
	Relays                  []peerAttemptRelay       `json:"relays"`
	Policy                  peerAttemptPolicy        `json:"policy"`
	StreamPolicy            *peerAttemptStreamPolicy `json:"stream_policy,omitempty"`
	Transfer                *peerAttemptTransfer     `json:"transfer,omitempty"`
}

type peerAttemptCertificate struct {
	EndpointID  string `json:"endpoint_id"`
	KeyID       string `json:"key_id"`
	Certificate string `json:"certificate"`
}
type peerAttemptDirect struct {
	ICEUfrag    string   `json:"ice_ufrag"`
	ICEPassword string   `json:"ice_password"`
	STUNURLs    []string `json:"stun_urls"`
}
type peerAttemptSignaling struct {
	URL         string `json:"url"`
	Credential  string `json:"credential"`
	Subprotocol string `json:"subprotocol"`
}
type peerAttemptRelay struct {
	Region          string `json:"region"`
	RouteGeneration int64  `json:"route_generation"`
	QUICURL         string `json:"quic_url"`
	WSSURL          string `json:"wss_url"`
	RouteToken      string `json:"route_token"`
	PMTUToken       string `json:"pmtu_token"`
	PMTUURL         string `json:"pmtu_url"`
	ExpiresAt       string `json:"expires_at"`
}
type peerAttemptPolicy struct {
	AllowedPaths     []string `json:"allowed_paths"`
	RelayDeadlineMS  int      `json:"relay_deadline_ms"`
	HealthIntervalMS int      `json:"health_interval_ms"`
	MaxCandidates    int      `json:"max_candidates"`
}

type peerAttemptStreamPolicy struct {
	Protocol         string   `json:"protocol"`
	AllowedConsumers []string `json:"allowed_consumers"`
	MaximumStreams   int      `json:"maximum_streams"`
}
type peerAttemptTransfer struct {
	TransferID string `json:"transfer_id"`
	Generation int64  `json:"generation"`
	ExpiresAt  string `json:"expires_at"`
}

func peerAttemptCreate(service peerAttemptService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok || principal.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "CLI authentication is required.")
			return
		}
		var body struct {
			OperationID                       string                           `json:"operation_id"`
			EnvironmentID                     string                           `json:"environment_id"`
			Purpose                           string                           `json:"purpose"`
			Consumer                          string                           `json:"consumer"`
			ControllingCertificateFingerprint string                           `json:"controlling_certificate_fingerprint"`
			ControlledCertificateFingerprint  string                           `json:"controlled_certificate_fingerprint"`
			AttemptGeneration                 int64                            `json:"attempt_generation"`
			NetworkGeneration                 int64                            `json:"network_generation"`
			AllowedPaths                      []string                         `json:"allowed_paths"`
			RelayLatency                      *peersessions.RelayLatencyVector `json:"relay_latency,omitempty"`
			Transfer                          *struct {
				TransferID string `json:"transfer_id"`
				Generation int64  `json:"generation"`
				ExpiresAt  string `json:"expires_at"`
			} `json:"transfer,omitempty"`
		}
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		controlling, controllingErr := decodeFingerprint(body.ControllingCertificateFingerprint)
		controlled, controlledErr := decodeFingerprint(body.ControlledCertificateFingerprint)
		if controllingErr != nil || controlledErr != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Peer attempt request is invalid.")
			return
		}
		var transfer *peersessions.TransferBinding
		if body.Transfer != nil {
			expiresAt, parseErr := time.Parse(time.RFC3339, body.Transfer.ExpiresAt)
			if parseErr != nil || expiresAt.Format("2006-01-02T15:04:05Z") != body.Transfer.ExpiresAt {
				writeError(w, r, http.StatusBadRequest, "invalid_request", "Peer attempt request is invalid.")
				return
			}
			transfer = &peersessions.TransferBinding{TransferID: body.Transfer.TransferID, Generation: body.Transfer.Generation, ExpiresAt: expiresAt}
		}
		pair, err := service.Issue(r.Context(), peersessions.Request{OperationKey: body.OperationID, UserID: principal.User.ID, CLIClientSessionID: principal.Client.SessionID, EnvironmentID: body.EnvironmentID, Purpose: body.Purpose, Consumer: body.Consumer, ControllingCertificateFingerprint: controlling[:], ControlledCertificateFingerprint: controlled[:], AttemptGeneration: body.AttemptGeneration, NetworkGeneration: body.NetworkGeneration, AllowedPaths: body.AllowedPaths, Transfer: transfer, RelayLatency: body.RelayLatency})
		if peerAttemptError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: peerAttemptResponse(pair, "controlling")})
	}
}

func peerAttemptDelete(service peerAttemptService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		generation, err := strconv.ParseInt(r.PathValue("attempt_generation"), 10, 64)
		operationID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if !ok || principal.Client == nil || generation <= 0 || err != nil || operationID == "" {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Peer attempt cancellation request is invalid.")
			return
		}
		if peerAttemptError(w, r, service.Revoke(r.Context(), principal.User.ID, operationID, r.PathValue("intent_id"), generation, "superseded")) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"intent_id": r.PathValue("intent_id"), "attempt_generation": generation, "state": "revoked"}})
	}
}

func controlledPeerAttemptNext(service peerAttemptService, verifier machineEndpointProofVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxMachineControlRequest+1))
		if err != nil || len(body) > maxMachineControlRequest {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Controlled peer attempt request is invalid.")
			return
		}
		var document struct {
			OperationID string `json:"operation_id"`
			Generation  int64  `json:"generation"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		proof, proofErr := base64.RawURLEncoding.Strict().DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
		scheme, credential, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(document.OperationID) < 8 || len(document.OperationID) > 128 || document.Generation <= 0 || proofErr != nil || len(proof) == 0 || !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(credential) == "" {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine identity proof was rejected.")
			return
		}
		claims, err := verifier.VerifyMachineRequest(r.Context(), strings.TrimSpace(credential), proof, r.Method, r.URL.Path, body)
		if err != nil || claims.OperationID != document.OperationID || claims.InstallationGeneration != document.Generation {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine identity proof was rejected.")
			return
		}
		var pair peersessions.Pair
		if waiter, ok := service.(controlledPeerAttemptWaiter); ok {
			waitCtx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
			pair, err = waiter.WaitNextControlled(waitCtx, claims.UserID, claims.MachineID, document.Generation)
			cancel()
			if errors.Is(err, context.DeadlineExceeded) {
				err = peersessions.ErrUnavailable
			}
		} else {
			pair, err = service.NextControlled(r.Context(), claims.UserID, claims.MachineID, document.Generation)
		}
		if errors.Is(err, peersessions.ErrUnavailable) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if peerAttemptError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: peerAttemptResponse(pair, "controlled")})
	}
}

func peerAttemptResponse(pair peersessions.Pair, role string) peerAttemptDescriptor {
	credential := pair.Controlling.Token
	if role == "controlled" {
		credential = pair.Controlled.Token
	}
	allowedPaths := append([]string(nil), pair.AllowedPaths...)
	if len(allowedPaths) == 0 {
		allowedPaths = []string{"direct_quic", "relay_quic", "relay_wss"}
		if pair.Purpose == "direct_probe" {
			allowedPaths = []string{"direct_quic"}
		}
	}
	result := peerAttemptDescriptor{Version: 1, AccountID: pair.UserID, DeviceID: pair.CLIClientSessionID, OperationID: pair.OperationKey, IntentID: pair.IntentID, EnvironmentID: pair.EnvironmentID, Purpose: pair.Purpose, InitiatorEndpointID: pair.Controlling.EndpointID, ResponderEndpointID: pair.Controlled.EndpointID, Role: role, AttemptGeneration: pair.AttemptGeneration, NetworkGeneration: pair.NetworkGeneration, HostGeneration: pair.HostGeneration, AuthorizationGeneration: pair.AuthorizationGeneration, IssuedAt: pair.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"), ExpiresAt: pair.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"), EndpointCertificates: []peerAttemptCertificate{{EndpointID: pair.Controlling.EndpointID, KeyID: pair.ControllingCertificateKeyID, Certificate: base64.RawURLEncoding.EncodeToString(pair.ControllingCertificate)}, {EndpointID: pair.Controlled.EndpointID, KeyID: pair.ControlledCertificateKeyID, Certificate: base64.RawURLEncoding.EncodeToString(pair.ControlledCertificate)}}, TrustedKeys: peerAttemptTrustedKeyDocuments(pair.TrustedKeys), Direct: peerAttemptDirect{ICEUfrag: pair.ICEUfrag, ICEPassword: pair.ICEPassword, STUNURLs: []string{"stun:" + pair.STUNHost + ":" + strconv.Itoa(int(pair.STUNPort))}}, Signaling: peerAttemptSignaling{URL: "wss://" + pair.SignalingHost + "/v1/peer-signaling", Credential: credential, Subprotocol: "paperboat.peer-signaling.v1"}, Relays: []peerAttemptRelay{{Region: pair.Relay.Region, RouteGeneration: pair.Relay.RouteGeneration, QUICURL: "https://" + pair.SignalingHost + "/v1/peer-relay", WSSURL: "wss://" + pair.SignalingHost + "/v1/peer-relay", RouteToken: pair.Relay.Token, PMTUToken: pair.Relay.PMTUToken, PMTUURL: "udp://" + pair.STUNHost + ":" + strconv.Itoa(int(pair.STUNPort)), ExpiresAt: pair.Relay.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")}}, Policy: peerAttemptPolicy{AllowedPaths: allowedPaths, RelayDeadlineMS: 15000, HealthIntervalMS: 15000, MaxCandidates: 32}}
	result.Consumer = pair.Consumer
	if pair.Purpose == "peer_transport" {
		result.StreamPolicy = &peerAttemptStreamPolicy{Protocol: "paperboat.peer-stream.v1", AllowedConsumers: []string{"terminal", "exec", "ssh", "private_preview", "codex"}, MaximumStreams: 64}
	}
	if pair.Transfer != nil {
		result.Transfer = &peerAttemptTransfer{TransferID: pair.Transfer.TransferID, Generation: pair.Transfer.Generation, ExpiresAt: pair.Transfer.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")}
	}
	return result
}

func peerAttemptTrustedKeyDocuments(keys []peersessions.TrustedKey) []trustedKeyDocument {
	documents := make([]trustedKeyDocument, 0, len(keys))
	for _, key := range keys {
		documents = append(documents, trustedKeyDocument{
			KeyID: key.KeyID, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey),
			Fingerprint: hex.EncodeToString(key.Fingerprint), Generation: uint64(key.Generation),
		})
	}
	return documents
}

func peerAttemptError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	status, code := http.StatusBadRequest, "invalid_request"
	switch {
	case errors.Is(err, peersessions.ErrConflict):
		status, code = http.StatusConflict, "operation_conflict"
	case errors.Is(err, peersessions.ErrUnavailable):
		status, code = http.StatusServiceUnavailable, "route_unavailable"
	}
	writeError(w, r, status, code, "Peer attempt could not be completed.")
	return true
}
