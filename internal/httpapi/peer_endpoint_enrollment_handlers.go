package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

type machineEndpointProofVerifier interface {
	VerifyMachineRequest(context.Context, string, []byte, string, string, []byte) (controlplane.MachineRequestClaims, error)
}

type machineEndpointRequester interface {
	RequestMachineEndpoint(context.Context, peeridentity.MachineEndpointRequest) (peeridentity.EndpointEnrollmentRequest, error)
}

type cliEndpointRequester interface {
	RequestCLIEndpoint(context.Context, peeridentity.CLIEndpointRequest) (peeridentity.EndpointEnrollmentRequest, error)
}

type pendingEndpointReader interface {
	PendingEndpoints(context.Context, string, time.Time) ([]peeridentity.EndpointEnrollmentRequest, error)
}

type machineEndpointStatusReader interface {
	Get(context.Context, string, string, uint64, time.Time) (peeridentity.Certificate, error)
	Root(context.Context, string) (peeridentity.AccountRoot, error)
}

type endpointEnrollmentDocument struct {
	RequestID      string `json:"request_id"`
	EndpointID     string `json:"endpoint_id"`
	Role           string `json:"role"`
	State          string `json:"state"`
	Generation     uint64 `json:"generation"`
	NoisePublicKey string `json:"noise_public_key"`
	QUICPublicKey  string `json:"quic_public_key"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
	SafetyCode     string `json:"safety_code"`
}

func machineEndpointRequest(service machineEndpointRequester, verifier machineEndpointProofVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxMachineControlRequest+1))
		if err != nil || len(body) > maxMachineControlRequest {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Machine endpoint request is invalid.")
			return
		}
		var document struct {
			OperationID    string `json:"operation_id"`
			Generation     uint64 `json:"generation"`
			NoisePublicKey string `json:"noise_public_key"`
			QUICPublicKey  string `json:"quic_public_key"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Machine endpoint request is invalid.")
			return
		}
		noise, noiseErr := decodeCanonicalBase64URL(document.NoisePublicKey)
		quic, quicErr := decodeCanonicalBase64URL(document.QUICPublicKey)
		proof, proofErr := base64.RawURLEncoding.Strict().DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
		scheme, credential, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		if len(document.OperationID) < 8 || len(document.OperationID) > 128 || document.Generation == 0 || len(noise) != 32 || len(quic) != 32 || noiseErr != nil || quicErr != nil || proofErr != nil || len(proof) == 0 || !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(credential) == "" {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine endpoint identity proof was rejected.")
			return
		}
		claims, err := verifier.VerifyMachineRequest(r.Context(), strings.TrimSpace(credential), proof, r.Method, r.URL.Path, body)
		if err != nil || claims.OperationID != document.OperationID || claims.InstallationGeneration <= 0 || uint64(claims.InstallationGeneration) != document.Generation {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine endpoint identity proof was rejected.")
			return
		}
		var noiseKey, quicKey [32]byte
		copy(noiseKey[:], noise)
		copy(quicKey[:], quic)
		value, err := service.RequestMachineEndpoint(r.Context(), peeridentity.MachineEndpointRequest{OperationID: document.OperationID, UserID: claims.UserID, EndpointID: claims.MachineID, Generation: uint64(claims.InstallationGeneration), NoisePublicKey: noiseKey, QUICPublicKey: quicKey, Now: time.Now().UTC()})
		if err != nil {
			status, code := http.StatusBadRequest, "invalid_request"
			switch {
			case errors.Is(err, peeridentity.ErrConflict):
				status, code = http.StatusConflict, "operation_conflict"
			case errors.Is(err, peeridentity.ErrUnavailable):
				status, code = http.StatusServiceUnavailable, "temporarily_unavailable"
			}
			writeError(w, r, status, code, "Machine endpoint request could not be created.")
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: endpointEnrollmentResponse(value)})
	}
}

func cliEndpointRequest(service cliEndpointRequester) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok || principal.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "CLI authentication is required.")
			return
		}
		var document struct {
			OperationID    string `json:"operation_id"`
			EndpointID     string `json:"endpoint_id"`
			Generation     uint64 `json:"generation"`
			NoisePublicKey string `json:"noise_public_key"`
			QUICPublicKey  string `json:"quic_public_key"`
		}
		if !decodeStrictJSON(w, r, &document) {
			return
		}
		noise, noiseErr := decodeCanonicalBase64URL(document.NoisePublicKey)
		quic, quicErr := decodeCanonicalBase64URL(document.QUICPublicKey)
		if r.Header.Get("Idempotency-Key") != document.OperationID || len(document.OperationID) < 8 || len(document.OperationID) > 128 || document.EndpointID != principal.Client.SessionID || document.Generation != 1 || noiseErr != nil || quicErr != nil || len(noise) != 32 || len(quic) != 32 {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "CLI endpoint enrollment request is invalid.")
			return
		}
		var noiseKey, quicKey [32]byte
		copy(noiseKey[:], noise)
		copy(quicKey[:], quic)
		value, err := service.RequestCLIEndpoint(r.Context(), peeridentity.CLIEndpointRequest{OperationID: document.OperationID, UserID: principal.User.ID, EndpointID: document.EndpointID, Generation: document.Generation, NoisePublicKey: noiseKey, QUICPublicKey: quicKey, Now: time.Now().UTC()})
		if err != nil {
			status, code := http.StatusBadRequest, "invalid_request"
			if errors.Is(err, peeridentity.ErrConflict) {
				status, code = http.StatusConflict, "operation_conflict"
			}
			if errors.Is(err, peeridentity.ErrUnavailable) {
				status, code = http.StatusServiceUnavailable, "temporarily_unavailable"
			}
			writeError(w, r, status, code, "CLI endpoint enrollment request could not be created.")
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: endpointEnrollmentResponse(value)})
	}
}

func machineEndpointStatus(service machineEndpointStatusReader, verifier machineEndpointProofVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxMachineControlRequest+1))
		if err != nil || len(body) > maxMachineControlRequest {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Machine endpoint status request is invalid.")
			return
		}
		var document struct {
			OperationID string `json:"operation_id"`
			Generation  uint64 `json:"generation"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		proof, proofErr := base64.RawURLEncoding.Strict().DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
		scheme, credential, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(document.OperationID) < 8 || len(document.OperationID) > 128 || document.Generation == 0 || proofErr != nil || len(proof) == 0 || !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(credential) == "" {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine endpoint identity proof was rejected.")
			return
		}
		claims, err := verifier.VerifyMachineRequest(r.Context(), strings.TrimSpace(credential), proof, r.Method, r.URL.Path, body)
		if err != nil || claims.OperationID != document.OperationID || claims.InstallationGeneration <= 0 || uint64(claims.InstallationGeneration) != document.Generation {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine endpoint identity proof was rejected.")
			return
		}
		now := time.Now().UTC()
		certificate, err := service.Get(r.Context(), claims.UserID, claims.MachineID, document.Generation, now)
		if errors.Is(err, peeridentity.ErrUnavailable) {
			writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]any{"state": "pending"}})
			return
		}
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", "Machine endpoint status could not be retrieved.")
			return
		}
		root, err := service.Root(r.Context(), claims.UserID)
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", "Machine endpoint authority could not be retrieved.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"state": "approved", "root_public_key": base64.RawURLEncoding.EncodeToString(root.PublicKey), "certificate": certificateDocument(certificate)}})
	}
}

func pendingEndpoints(service pendingEndpointReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok || principal.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "CLI authentication is required.")
			return
		}
		values, err := service.PendingEndpoints(r.Context(), principal.User.ID, time.Now().UTC())
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", "Pending endpoint identities could not be retrieved.")
			return
		}
		documents := make([]endpointEnrollmentDocument, 0, len(values))
		for _, value := range values {
			documents = append(documents, endpointEnrollmentResponse(value))
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: documents})
	}
}

func endpointEnrollmentResponse(value peeridentity.EndpointEnrollmentRequest) endpointEnrollmentDocument {
	return endpointEnrollmentDocument{RequestID: value.ID, EndpointID: value.EndpointID, Role: value.Role.String(), State: value.State, Generation: value.Generation, NoisePublicKey: base64.RawURLEncoding.EncodeToString(value.NoisePublicKey[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(value.QUICPublicKey[:]), CreatedAt: value.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: value.ExpiresAt.UTC().Format(time.RFC3339), SafetyCode: value.SafetyCode()}
}
