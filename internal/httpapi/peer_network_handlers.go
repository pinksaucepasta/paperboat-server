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
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/peersessions"
)

type peerNetworkRegisterBody struct {
	OperationID                string `json:"operation_id"`
	WireGuardPublicKey         string `json:"wireguard_public_key"`
	DiscoPublicKey             string `json:"disco_public_key"`
	ExpectedKeyGeneration      int64  `json:"expected_key_generation"`
	QUICCertificateFingerprint string `json:"quic_certificate_fingerprint"`
}
type peerNetworkConfigBody struct {
	OperationID string `json:"operation_id"`
}
type peerNetworkService interface {
	Register(context.Context, peersessions.NetworkRegistration) (peersessions.NetworkRegistrationResult, error)
	Configuration(context.Context, peersessions.NetworkConfigRequest) (peersessions.NetworkConfigResult, error)
}

func decodePeerNetworkRegister(body peerNetworkRegisterBody) ([]byte, []byte, []byte, bool) {
	key, e1 := base64.RawURLEncoding.Strict().DecodeString(body.WireGuardPublicKey)
	disco, e2 := base64.RawURLEncoding.Strict().DecodeString(body.DiscoPublicKey)
	fingerprint, e3 := hex.DecodeString(body.QUICCertificateFingerprint)
	return key, disco, fingerprint, e1 == nil && e2 == nil && e3 == nil && len(key) == 32 && len(disco) == 32 && len(fingerprint) == 32 && base64.RawURLEncoding.EncodeToString(key) == body.WireGuardPublicKey && base64.RawURLEncoding.EncodeToString(disco) == body.DiscoPublicKey && hex.EncodeToString(fingerprint) == body.QUICCertificateFingerprint
}
func peerNetworkError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, peersessions.ErrConflict):
		writeError(w, r, http.StatusConflict, "peer_network_conflict", "The peer network key generation changed. Refresh registration state before retrying rotation.")
	case errors.Is(err, peersessions.ErrDenied):
		writeError(w, r, http.StatusForbidden, "peer_network_denied", "Current endpoint authority no longer permits peer networking. Remove installed peers and reauthorize the endpoint.")
	case errors.Is(err, peersessions.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Peer network request is invalid.")
	default:
		writeError(w, r, http.StatusServiceUnavailable, "peer_network_unavailable", "Peer network authority is temporarily unavailable. Retry before the current configuration expires.")
	}
}

func peerNetworkRegister(s peerNetworkService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "CLI authentication is required.")
			return
		}
		var body peerNetworkRegisterBody
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		key, disco, fingerprint, valid := decodePeerNetworkRegister(body)
		if !valid {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Peer network registration is invalid.")
			return
		}
		value, err := s.Register(r.Context(), peersessions.NetworkRegistration{OperationID: body.OperationID, UserID: p.User.ID, EndpointID: p.Client.SessionID, Role: "cli", EndpointGeneration: 1, ExpectedKeyGeneration: body.ExpectedKeyGeneration, WireGuardPublicKey: key, DiscoPublicKey: disco, QUICCertificateFingerprint: fingerprint})
		if err != nil {
			peerNetworkError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: value})
	}
}
func peerNetworkConfig(s peerNetworkService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "CLI authentication is required.")
			return
		}
		var body peerNetworkConfigBody
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		value, err := s.Configuration(r.Context(), peersessions.NetworkConfigRequest{OperationID: body.OperationID, UserID: p.User.ID, EndpointID: p.Client.SessionID})
		if err != nil {
			peerNetworkError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: value})
	}
}

func machinePeerNetworkRegister(s peerNetworkService, v machineEndpointProofVerifier) http.HandlerFunc {
	return machinePeerNetwork(s, v, true)
}
func machinePeerNetworkConfig(s peerNetworkService, v machineEndpointProofVerifier) http.HandlerFunc {
	return machinePeerNetwork(s, v, false)
}
func machinePeerNetwork(s peerNetworkService, v machineEndpointProofVerifier, register bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxMachineControlRequest+1))
		if err != nil || len(raw) > maxMachineControlRequest {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Peer network request is invalid.")
			return
		}
		var operation struct {
			OperationID string `json:"operation_id"`
		}
		if json.Unmarshal(raw, &operation) != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Peer network request is invalid.")
			return
		}
		proof, e1 := base64.RawURLEncoding.Strict().DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
		scheme, credential, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		if e1 != nil || len(proof) == 0 || !found || !strings.EqualFold(scheme, "Bearer") {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine identity proof was rejected.")
			return
		}
		claims, e2 := v.VerifyMachineRequest(r.Context(), strings.TrimSpace(credential), proof, r.Method, r.URL.Path, raw)
		if e2 != nil || claims.OperationID != operation.OperationID {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine identity proof was rejected.")
			return
		}
		if register {
			var body peerNetworkRegisterBody
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&body) != nil {
				writeError(w, r, http.StatusBadRequest, "invalid_request", "Peer network registration is invalid.")
				return
			}
			key, disco, fingerprint, valid := decodePeerNetworkRegister(body)
			if !valid {
				writeError(w, r, http.StatusBadRequest, "invalid_request", "Peer network registration is invalid.")
				return
			}
			value, e := s.Register(r.Context(), peersessions.NetworkRegistration{OperationID: body.OperationID, UserID: claims.UserID, EndpointID: claims.MachineID, Role: "machine", MachineID: claims.MachineID, EndpointGeneration: claims.InstallationGeneration, MachineGeneration: claims.InstallationGeneration, ExpectedKeyGeneration: body.ExpectedKeyGeneration, WireGuardPublicKey: key, DiscoPublicKey: disco, QUICCertificateFingerprint: fingerprint})
			if e != nil {
				peerNetworkError(w, r, e)
				return
			}
			writeJSON(w, http.StatusOK, SuccessResponse{Data: value})
			return
		}
		var body peerNetworkConfigBody
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Peer network configuration request is invalid.")
			return
		}
		value, e := s.Configuration(r.Context(), peersessions.NetworkConfigRequest{OperationID: body.OperationID, UserID: claims.UserID, EndpointID: claims.MachineID})
		if e != nil {
			peerNetworkError(w, r, e)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: value})
	}
}
