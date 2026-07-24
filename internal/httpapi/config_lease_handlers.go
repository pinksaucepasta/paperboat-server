package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

const maxConfigLeaseRequestBytes = 16 << 10

func configLeaseAcquire(service *controlplane.ConfigLeaseService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readConfigLeaseBody(w, r)
		if !ok {
			return
		}
		var input struct {
			OperationID        string `json:"operation_id"`
			BaseRemoteRevision string `json:"base_remote_revision"`
			TTLSeconds         int64  `json:"ttl_seconds"`
		}
		if !decodeStrictConfigLeaseJSON(body, &input) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Lease request is invalid.")
			return
		}
		holder, ok := authenticateConfigLease(w, r, service, body)
		if !ok {
			return
		}
		holder.BaseRemoteRevision = strings.TrimSpace(input.BaseRemoteRevision)
		lease, err := service.Acquire(r.Context(), strings.TrimSpace(input.OperationID), holder, time.Duration(input.TTLSeconds)*time.Second)
		if errors.Is(err, controlplane.ErrConfigLeaseBusy) {
			writeError(w, r, http.StatusConflict, "lease_busy", "The configuration repository has another active writer.")
			return
		}
		if errors.Is(err, controlplane.ErrConfigLeaseReplay) {
			writeError(w, r, http.StatusConflict, "operation_conflict", "Lease operation conflicts with an existing request.")
			return
		}
		if errors.Is(err, controlplane.ErrConfigWritesDisabled) {
			writeError(w, r, http.StatusForbidden, "config_writes_disabled", "Configuration writes are disabled for this rollout cohort.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "lease_invalid", "Configuration lease authorization is no longer valid.")
			return
		}
		noStore(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: lease})
	}
}

func configLeaseRenew(service *controlplane.ConfigLeaseService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readConfigLeaseBody(w, r)
		if !ok {
			return
		}
		var input struct {
			OperationID  string `json:"operation_id"`
			LeaseID      string `json:"lease_id"`
			FencingToken int64  `json:"fencing_token"`
			TTLSeconds   int64  `json:"ttl_seconds"`
		}
		if !decodeStrictConfigLeaseJSON(body, &input) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Lease request is invalid.")
			return
		}
		holder, ok := authenticateConfigLease(w, r, service, body)
		if !ok {
			return
		}
		lease, err := service.Renew(r.Context(), strings.TrimSpace(input.OperationID), holder, strings.TrimSpace(input.LeaseID), input.FencingToken, time.Duration(input.TTLSeconds)*time.Second)
		writeConfigLeaseMutation(w, r, lease, err)
	}
}

func configLeaseRelease(service *controlplane.ConfigLeaseService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readConfigLeaseBody(w, r)
		if !ok {
			return
		}
		var input struct {
			OperationID  string `json:"operation_id"`
			LeaseID      string `json:"lease_id"`
			FencingToken int64  `json:"fencing_token"`
		}
		if !decodeStrictConfigLeaseJSON(body, &input) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Lease request is invalid.")
			return
		}
		holder, ok := authenticateConfigLease(w, r, service, body)
		if !ok {
			return
		}
		err := service.Release(r.Context(), strings.TrimSpace(input.OperationID), holder, strings.TrimSpace(input.LeaseID), input.FencingToken)
		if errors.Is(err, controlplane.ErrConfigLeaseLost) {
			writeError(w, r, http.StatusConflict, "lease_lost", "The configuration repository lease is no longer valid.")
			return
		}
		if errors.Is(err, controlplane.ErrConfigLeaseReplay) {
			writeError(w, r, http.StatusConflict, "operation_conflict", "Lease operation conflicts with an existing request.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "lease_invalid", "Configuration lease authorization is no longer valid.")
			return
		}
		noStore(w)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]bool{"released": true}})
	}
}

func authenticateConfigLease(w http.ResponseWriter, r *http.Request, service *controlplane.ConfigLeaseService, body []byte) (controlplane.ConfigLeaseHolder, bool) {
	proof, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
	identityToken := strings.TrimSpace(r.Header.Get("X-Paperboat-Helper-Identity"))
	credential, bearerOK := bearerToken(r)
	if err != nil || identityToken == "" || !bearerOK {
		writeError(w, r, http.StatusUnauthorized, "lease_invalid", "Configuration lease authorization is invalid.")
		return controlplane.ConfigLeaseHolder{}, false
	}
	holder, err := service.Authenticate(r.Context(), identityToken, credential, proof, body, r.Method, r.URL.Path)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "lease_invalid", "Configuration lease authorization is invalid.")
		return controlplane.ConfigLeaseHolder{}, false
	}
	return holder, true
}

func readConfigLeaseBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxConfigLeaseRequestBytes+1))
	if err != nil || len(body) > maxConfigLeaseRequestBytes || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Lease request is invalid.")
		return nil, false
	}
	return body, true
}

func decodeStrictConfigLeaseJSON(body []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}

func writeConfigLeaseMutation(w http.ResponseWriter, r *http.Request, lease controlplane.ConfigLease, err error) {
	if errors.Is(err, controlplane.ErrConfigLeaseLost) {
		writeError(w, r, http.StatusConflict, "lease_lost", "The configuration repository lease is no longer valid.")
		return
	}
	if errors.Is(err, controlplane.ErrConfigLeaseReplay) {
		writeError(w, r, http.StatusConflict, "operation_conflict", "Lease operation conflicts with an existing request.")
		return
	}
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "lease_invalid", "Configuration lease authorization is no longer valid.")
		return
	}
	noStore(w)
	writeJSON(w, http.StatusOK, SuccessResponse{Data: lease})
}
