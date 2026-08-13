package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/managedssh"
)

const maxManagedSSHRequest = 64 << 10

type managedSSHService interface {
	RegisterClient(context.Context, managedssh.RegisterClientRequest) (managedssh.ClientKey, error)
	RevokeClient(context.Context, managedssh.RevokeClientRequest) (managedssh.ClientKey, error)
	RegisterTarget(context.Context, managedssh.RegisterTargetRequest) (managedssh.MachineTarget, error)
	UpdateTargetPort(context.Context, managedssh.UpdateTargetPortRequest) (managedssh.MachineTarget, error)
	GetTarget(context.Context, managedssh.GetTargetRequest) (managedssh.MachineTarget, error)
	ObserveHost(context.Context, managedssh.ObserveHostRequest) (managedssh.HostKeySet, error)
	PromoteHost(context.Context, managedssh.PromoteHostRequest) (managedssh.HostKeySet, error)
	GetActiveHost(context.Context, managedssh.GetHostKeySetRequest) (managedssh.HostKeySet, error)
	GetPendingHost(context.Context, managedssh.GetHostKeySetRequest) (managedssh.HostKeySet, error)
	ListClientKeys(context.Context, managedssh.ListClientKeysRequest) (managedssh.ClientKeySet, error)
}

type machineRequestVerifier interface {
	VerifyMachineRequest(context.Context, string, []byte, string, string, []byte) (controlplane.MachineRequestClaims, error)
}

type managedSSHClientKeyDocument struct {
	Type                  string `json:"type"`
	Version               int    `json:"version"`
	Fingerprint           string `json:"fingerprint"`
	PublicKey             string `json:"public_key"`
	State                 string `json:"state"`
	ReconciliationVersion uint64 `json:"reconciliation_version"`
	CreatedAt             string `json:"created_at"`
	RevokedAt             string `json:"revoked_at,omitempty"`
}

type managedSSHTargetDocument struct {
	Type                  string `json:"type"`
	Version               int    `json:"version"`
	MachineID             string `json:"machine_id"`
	MachineGeneration     uint64 `json:"machine_generation"`
	OSUser                string `json:"os_user"`
	Port                  uint16 `json:"port"`
	ReconciliationVersion uint64 `json:"reconciliation_version"`
	CreatedAt             string `json:"created_at"`
	UpdatedAt             string `json:"updated_at"`
}

type managedSSHHostKeySetDocument struct {
	Type                  string   `json:"type"`
	Version               int      `json:"version"`
	SetID                 string   `json:"set_id"`
	MachineID             string   `json:"machine_id"`
	MachineGeneration     uint64   `json:"machine_generation"`
	ObservationGeneration uint64   `json:"observation_generation"`
	Fingerprint           string   `json:"fingerprint"`
	Keys                  []string `json:"keys"`
	State                 string   `json:"state"`
	ReconciliationVersion uint64   `json:"reconciliation_version"`
	ObservedAt            string   `json:"observed_at"`
	PromotedAt            string   `json:"promoted_at,omitempty"`
}

type managedSSHAuthorizedKeysDocument struct {
	Type              string   `json:"type"`
	Version           int      `json:"version"`
	MachineID         string   `json:"machine_id"`
	MachineGeneration uint64   `json:"machine_generation"`
	Keys              []string `json:"keys"`
}

func managedSSHClientKeyPut(service managedSSHService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		var body struct {
			PublicKey string `json:"public_key"`
		}
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "CLI authentication is required.")
			return
		}
		if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
			writeManagedSSHInvalid(w, r)
			return
		}
		if !decodeManagedSSHJSON(w, r, &body) {
			return
		}
		fingerprint, err := managedssh.ClientFingerprint(body.PublicKey)
		if err != nil || encodeSSHFingerprint(fingerprint) != r.PathValue("fingerprint") {
			writeManagedSSHInvalid(w, r)
			return
		}
		value, err := service.RegisterClient(r.Context(), managedssh.RegisterClientRequest{OperationID: strings.TrimSpace(r.Header.Get("Idempotency-Key")), UserID: p.User.ID, CLIClientSessionID: p.Client.SessionID, PublicKey: body.PublicKey, Now: time.Now().UTC()})
		if managedSSHError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: managedSSHClientKeyResponse(value)})
	}
}

func managedSSHClientKeyDelete(service managedSSHService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		var body struct {
			Reason string `json:"reason"`
		}
		fingerprint, fingerprintErr := decodeSSHFingerprint(r.PathValue("fingerprint"))
		if !ok || p.Client == nil || fingerprintErr != nil || strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" || !decodeManagedSSHJSON(w, r, &body) {
			return
		}
		value, err := service.RevokeClient(r.Context(), managedssh.RevokeClientRequest{OperationID: strings.TrimSpace(r.Header.Get("Idempotency-Key")), ActorUserID: p.User.ID, Fingerprint: fingerprint, Reason: body.Reason, Now: time.Now().UTC()})
		if managedSSHError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: managedSSHClientKeyResponse(value)})
	}
}

func managedSSHTargetPut(service managedSSHService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		var body struct {
			MachineGeneration             uint64 `json:"machine_generation"`
			OSUser                        string `json:"os_user"`
			Port                          uint16 `json:"port"`
			ExpectedReconciliationVersion uint64 `json:"expected_reconciliation_version,omitempty"`
		}
		operationID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if !ok || operationID == "" || !decodeManagedSSHJSON(w, r, &body) {
			return
		}
		var value managedssh.MachineTarget
		var err error
		if body.ExpectedReconciliationVersion == 0 {
			value, err = service.RegisterTarget(r.Context(), managedssh.RegisterTargetRequest{OperationID: operationID, ActorUserID: p.User.ID, UserMachineID: r.PathValue("machine_id"), MachineGeneration: body.MachineGeneration, OSUser: body.OSUser, TargetPort: body.Port, Now: time.Now().UTC()})
		} else {
			if body.OSUser != "" {
				writeManagedSSHInvalid(w, r)
				return
			}
			value, err = service.UpdateTargetPort(r.Context(), managedssh.UpdateTargetPortRequest{OperationID: operationID, ActorUserID: p.User.ID, UserMachineID: r.PathValue("machine_id"), MachineGeneration: body.MachineGeneration, TargetPort: body.Port, ExpectedReconciliationVersion: body.ExpectedReconciliationVersion, Now: time.Now().UTC()})
		}
		if managedSSHError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: managedSSHTargetResponse(value)})
	}
}

func managedSSHTargetGet(service managedSSHService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		generation, err := parsePositiveQueryGeneration(r)
		if !ok || err != nil {
			writeManagedSSHInvalid(w, r)
			return
		}
		value, err := service.GetTarget(r.Context(), managedssh.GetTargetRequest{ActorUserID: p.User.ID, UserMachineID: r.PathValue("machine_id"), MachineGeneration: generation})
		if managedSSHError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: managedSSHTargetResponse(value)})
	}
}

func managedSSHHostKeysObserve(service managedSSHService, identities machineRequestVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readManagedSSHBody(w, r)
		if !ok {
			return
		}
		proof, err := base64.RawURLEncoding.Strict().DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "Machine authentication is required.")
			return
		}
		claims, err := identities.VerifyMachineRequest(r.Context(), r.Header.Get("X-Paperboat-Machine-Identity"), proof, r.Method, r.URL.Path, body)
		if err != nil || claims.MachineID != r.PathValue("machine_id") || claims.InstallationGeneration <= 0 {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "Machine authentication is required.")
			return
		}
		var input struct {
			SetID                 string   `json:"set_id"`
			ObservationGeneration uint64   `json:"observation_generation"`
			PublicKeys            []string `json:"public_keys"`
		}
		if !decodeManagedSSHBytes(body, &input) {
			writeManagedSSHInvalid(w, r)
			return
		}
		value, err := service.ObserveHost(r.Context(), managedssh.ObserveHostRequest{OperationID: claims.OperationID, SetID: input.SetID, UserID: claims.UserID, UserMachineID: claims.MachineID, MachineGeneration: uint64(claims.InstallationGeneration), ObservationGeneration: input.ObservationGeneration, PublicKeys: input.PublicKeys, Now: time.Now().UTC()})
		if managedSSHError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: managedSSHHostKeySetResponse(value)})
	}
}

func managedSSHAuthorizedKeys(service managedSSHService, identities machineRequestVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readManagedSSHBody(w, r)
		if !ok {
			return
		}
		var input struct{}
		if !decodeManagedSSHBytes(body, &input) {
			writeManagedSSHInvalid(w, r)
			return
		}
		proof, err := base64.RawURLEncoding.Strict().DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "Machine authentication is required.")
			return
		}
		claims, err := identities.VerifyMachineRequest(r.Context(), r.Header.Get("X-Paperboat-Machine-Identity"), proof, r.Method, r.URL.Path, body)
		if err != nil || claims.MachineID != r.PathValue("machine_id") || claims.InstallationGeneration <= 0 {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "Machine authentication is required.")
			return
		}
		set, err := service.ListClientKeys(r.Context(), managedssh.ListClientKeysRequest{ActorUserID: claims.UserID, UserMachineID: claims.MachineID, MachineGeneration: uint64(claims.InstallationGeneration)})
		if managedSSHError(w, r, err) {
			return
		}
		keys := make([]string, len(set.Keys))
		for index := range set.Keys {
			keys[index] = set.Keys[index].PublicKey
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: managedSSHAuthorizedKeysDocument{Type: "authorized_key_set", Version: 1, MachineID: set.UserMachineID, MachineGeneration: set.MachineGeneration, Keys: keys}})
	}
}

func managedSSHHostKeysGet(service managedSSHService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		generation, err := parsePositiveQueryGeneration(r)
		if !ok || err != nil {
			writeManagedSSHInvalid(w, r)
			return
		}
		request := managedssh.GetHostKeySetRequest{ActorUserID: p.User.ID, UserMachineID: r.PathValue("machine_id"), MachineGeneration: generation}
		var value managedssh.HostKeySet
		if state := r.URL.Query().Get("state"); state == "pending" {
			value, err = service.GetPendingHost(r.Context(), request)
		} else if state == "" || state == "active" {
			value, err = service.GetActiveHost(r.Context(), request)
		} else {
			writeManagedSSHInvalid(w, r)
			return
		}
		if managedSSHError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: managedSSHHostKeySetResponse(value)})
	}
}

func managedSSHHostKeysPromote(service managedSSHService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		var body struct {
			MachineGeneration   uint64 `json:"machine_generation"`
			ExpectedFingerprint string `json:"expected_fingerprint"`
		}
		operationID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if !ok || operationID == "" || !decodeManagedSSHJSON(w, r, &body) {
			return
		}
		fingerprint, err := decodeSSHFingerprint(body.ExpectedFingerprint)
		if err != nil {
			writeManagedSSHInvalid(w, r)
			return
		}
		value, err := service.PromoteHost(r.Context(), managedssh.PromoteHostRequest{OperationID: operationID, ActorUserID: p.User.ID, UserMachineID: r.PathValue("machine_id"), MachineGeneration: body.MachineGeneration, SetID: r.PathValue("set_id"), ExpectedFingerprint: fingerprint, Now: time.Now().UTC()})
		if managedSSHError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: managedSSHHostKeySetResponse(value)})
	}
}

func managedSSHClientKeyResponse(value managedssh.ClientKey) managedSSHClientKeyDocument {
	result := managedSSHClientKeyDocument{Type: "client_key", Version: 1, Fingerprint: encodeSSHFingerprint(value.Fingerprint), PublicKey: value.PublicKey, State: value.State, ReconciliationVersion: value.ReconciliationVersion, CreatedAt: value.CreatedAt.UTC().Format(time.RFC3339)}
	if !value.RevokedAt.IsZero() {
		result.RevokedAt = value.RevokedAt.UTC().Format(time.RFC3339)
	}
	return result
}

func managedSSHTargetResponse(value managedssh.MachineTarget) managedSSHTargetDocument {
	return managedSSHTargetDocument{Type: "machine_target", Version: 1, MachineID: value.UserMachineID, MachineGeneration: value.MachineGeneration, OSUser: value.OSUser, Port: value.TargetPort, ReconciliationVersion: value.ReconciliationVersion, CreatedAt: value.CreatedAt.UTC().Format(time.RFC3339), UpdatedAt: value.UpdatedAt.UTC().Format(time.RFC3339)}
}

func managedSSHHostKeySetResponse(value managedssh.HostKeySet) managedSSHHostKeySetDocument {
	keys := make([]string, len(value.Keys))
	for i := range value.Keys {
		keys[i] = value.Keys[i].PublicKey
	}
	result := managedSSHHostKeySetDocument{Type: "host_key_set", Version: 1, SetID: value.ID, MachineID: value.UserMachineID, MachineGeneration: value.MachineGeneration, ObservationGeneration: value.ObservationGeneration, Fingerprint: encodeSSHFingerprint(value.Fingerprint), Keys: keys, State: value.State, ReconciliationVersion: value.ReconciliationVersion, ObservedAt: value.ObservedAt.UTC().Format(time.RFC3339)}
	if !value.PromotedAt.IsZero() {
		result.PromotedAt = value.PromotedAt.UTC().Format(time.RFC3339)
	}
	return result
}

func encodeSSHFingerprint(value [sha256.Size]byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(value[:])
}

func decodeSSHFingerprint(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if !strings.HasPrefix(value, "SHA256:") {
		return result, errors.New("invalid fingerprint")
	}
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(value, "SHA256:"))
	if err != nil || len(decoded) != len(result) {
		return result, errors.New("invalid fingerprint")
	}
	copy(result[:], decoded)
	if encodeSSHFingerprint(result) != value {
		return [sha256.Size]byte{}, errors.New("invalid fingerprint")
	}
	return result, nil
}

func parsePositiveQueryGeneration(r *http.Request) (uint64, error) {
	values := r.URL.Query()["machine_generation"]
	if len(values) != 1 {
		return 0, errors.New("invalid generation")
	}
	value, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil || value == 0 {
		return 0, errors.New("invalid generation")
	}
	return value, nil
}

func decodeManagedSSHJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	body, ok := readManagedSSHBody(w, r)
	if !ok {
		return false
	}
	if !decodeManagedSSHBytes(body, target) {
		writeManagedSSHInvalid(w, r)
		return false
	}
	return true
}

func readManagedSSHBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxManagedSSHRequest+1))
	if err != nil || len(body) > maxManagedSSHRequest {
		writeManagedSSHInvalid(w, r)
		return nil, false
	}
	return body, true
}

func decodeManagedSSHBytes(body []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}

func managedSSHError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	status, code := http.StatusBadRequest, "invalid_request"
	switch {
	case errors.Is(err, managedssh.ErrConflict):
		status, code = http.StatusConflict, "operation_conflict"
	case errors.Is(err, managedssh.ErrUnavailable):
		status, code = http.StatusNotFound, "not_found"
	}
	writeError(w, r, status, code, "Managed SSH request could not be completed.")
	return true
}

func writeManagedSSHInvalid(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusBadRequest, "invalid_request", "Managed SSH request is invalid.")
}
