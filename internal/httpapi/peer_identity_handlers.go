package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

type endpointCertificateRegistrar interface {
	Register(context.Context, peeridentity.RegisterRequest) (peeridentity.Certificate, error)
}

type e2eeBootstrapper interface {
	Bootstrap(context.Context, peeridentity.BootstrapRequest) (peeridentity.Certificate, error)
}

type e2eeRootReader interface {
	Root(context.Context, string) (peeridentity.AccountRoot, error)
}

type endpointCertificateReader interface {
	Get(context.Context, string, string, uint64, time.Time) (peeridentity.Certificate, error)
}

type endpointCertificateRevoker interface {
	Revoke(context.Context, string, string, string, uint64, uint64, string, time.Time) (peeridentity.Certificate, error)
}

type endpointCertificateDocument struct {
	Version                int    `json:"version"`
	AccountID              string `json:"account_id"`
	RootFingerprint        string `json:"root_fingerprint"`
	EndpointID             string `json:"endpoint_id"`
	Role                   string `json:"role"`
	Generation             uint64 `json:"generation"`
	Serial                 uint64 `json:"serial"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
	Certificate            string `json:"certificate"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
}

type e2eeBootstrapDocument struct {
	RootPublicKey string                      `json:"root_public_key"`
	Certificate   endpointCertificateDocument `json:"certificate"`
}

type e2eeRootDocument struct {
	Version     int    `json:"version"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Generation  uint64 `json:"generation"`
}

func e2eeRootGet(service e2eeRootReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok || principal.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "CLI authentication is required.")
			return
		}
		root, err := service.Root(r.Context(), principal.User.ID)
		if err != nil {
			status, code := http.StatusBadRequest, "invalid_request"
			if errors.Is(err, peeridentity.ErrUnavailable) {
				status, code = http.StatusNotFound, "not_found"
			}
			writeError(w, r, status, code, "E2EE root could not be retrieved.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: e2eeRootDocument{Version: 1, PublicKey: base64.RawURLEncoding.EncodeToString(root.PublicKey), Fingerprint: hex.EncodeToString(root.Fingerprint[:]), Generation: root.Generation}})
	}
}

func e2eeBootstrap(service e2eeBootstrapper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok || principal.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "CLI authentication is required.")
			return
		}
		var document e2eeBootstrapDocument
		if !decodeStrictJSON(w, r, &document) {
			return
		}
		operationID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		rootPublic, rootErr := decodeCanonicalBase64URL(document.RootPublicKey)
		certificate, certificateErr := decodeCanonicalBase64URL(document.Certificate.Certificate)
		rootFingerprint, rootFingerprintErr := decodeFingerprint(document.Certificate.RootFingerprint)
		certificateFingerprint, fingerprintErr := decodeFingerprint(document.Certificate.CertificateFingerprint)
		issuedAt, issuedErr := parseCanonicalTime(document.Certificate.IssuedAt)
		expiresAt, expiresErr := parseCanonicalTime(document.Certificate.ExpiresAt)
		if operationID == "" || len(rootPublic) != 32 || rootErr != nil || certificateErr != nil || rootFingerprintErr != nil || fingerprintErr != nil || issuedErr != nil || expiresErr != nil || document.Certificate.Version != 1 || document.Certificate.AccountID != principal.User.ID || document.Certificate.EndpointID != principal.Client.SessionID || document.Certificate.Role != "cli" || document.Certificate.Generation != 1 || document.Certificate.Serial == 0 {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "E2EE bootstrap request is invalid.")
			return
		}
		value, err := service.Bootstrap(r.Context(), peeridentity.BootstrapRequest{RegisterRequest: peeridentity.RegisterRequest{OperationID: operationID, UserID: principal.User.ID, Certificate: certificate, Expected: peeridentity.Expected{AccountID: principal.User.ID, Role: peeridentity.RoleCLI, EndpointID: principal.Client.SessionID, Generation: 1, Serial: document.Certificate.Serial}, ExpectedRootFingerprint: rootFingerprint, ExpectedCertificateFingerprint: certificateFingerprint, ExpectedIssuedAt: issuedAt, ExpectedExpiresAt: expiresAt, Now: time.Now().UTC()}, CLIClientSessionID: principal.Client.SessionID, RootPublicKey: rootPublic, AllowRootReplacement: r.Header.Get("X-Paperboat-Fresh-Enrollment") == "1"})
		if err != nil {
			status, code := http.StatusBadRequest, "invalid_identity"
			switch {
			case errors.Is(err, peeridentity.ErrConflict):
				status, code = http.StatusConflict, "identity_conflict"
			case errors.Is(err, peeridentity.ErrUnavailable):
				status, code = http.StatusServiceUnavailable, "temporarily_unavailable"
			case errors.Is(err, peeridentity.ErrNotCurrent):
				code = "certificate_expired"
			}
			writeError(w, r, status, code, "E2EE identity could not be bootstrapped.")
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: e2eeBootstrapDocument{RootPublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Certificate: certificateDocument(value)}})
	}
}

func endpointCertificateRegister(service endpointCertificateRegistrar) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "Authentication is required.")
			return
		}
		var document endpointCertificateDocument
		if !decodeStrictJSON(w, r, &document) {
			return
		}
		operationID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		generation, generationErr := strconv.ParseUint(r.PathValue("generation"), 10, 64)
		role := endpointRole(document.Role)
		certificate, certificateErr := decodeCanonicalBase64URL(document.Certificate)
		rootFingerprint, rootErr := decodeFingerprint(document.RootFingerprint)
		certificateFingerprint, fingerprintErr := decodeFingerprint(document.CertificateFingerprint)
		issuedAt, issuedErr := parseCanonicalTime(document.IssuedAt)
		expiresAt, expiresErr := parseCanonicalTime(document.ExpiresAt)
		if operationID == "" || document.Version != 1 || document.AccountID != principal.User.ID ||
			document.EndpointID != r.PathValue("endpoint_id") || generationErr != nil || generation != document.Generation ||
			role.String() == "" || certificateErr != nil || rootErr != nil || fingerprintErr != nil || issuedErr != nil || expiresErr != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Endpoint certificate request is invalid.")
			return
		}
		value, err := service.Register(r.Context(), peeridentity.RegisterRequest{
			OperationID: operationID, UserID: principal.User.ID, Certificate: certificate,
			Expected:                peeridentity.Expected{AccountID: document.AccountID, Role: role, EndpointID: document.EndpointID, Generation: document.Generation, Serial: document.Serial},
			ExpectedRootFingerprint: rootFingerprint, ExpectedCertificateFingerprint: certificateFingerprint,
			ExpectedIssuedAt: issuedAt, ExpectedExpiresAt: expiresAt, Now: time.Now().UTC(),
		})
		if err != nil {
			status, code := http.StatusBadRequest, "invalid_certificate"
			switch {
			case errors.Is(err, peeridentity.ErrConflict):
				status, code = http.StatusConflict, "operation_conflict"
			case errors.Is(err, peeridentity.ErrUnavailable):
				status, code = http.StatusServiceUnavailable, "temporarily_unavailable"
			case errors.Is(err, peeridentity.ErrNotCurrent):
				status, code = http.StatusBadRequest, "certificate_expired"
			}
			writeError(w, r, status, code, "Endpoint certificate could not be registered.")
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: certificateDocument(value)})
	}
}

func endpointCertificateGet(service endpointCertificateReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		generation, err := strconv.ParseUint(r.PathValue("generation"), 10, 64)
		if !ok || err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Endpoint certificate request is invalid.")
			return
		}
		value, err := service.Get(r.Context(), principal.User.ID, r.PathValue("endpoint_id"), generation, time.Now().UTC())
		if err != nil {
			status, code := http.StatusBadRequest, "invalid_request"
			if errors.Is(err, peeridentity.ErrUnavailable) {
				status, code = http.StatusNotFound, "not_found"
			}
			writeError(w, r, status, code, "Endpoint certificate could not be retrieved.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: certificateDocument(value)})
	}
}

func endpointCertificateRevoke(service endpointCertificateRevoker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		generation, generationErr := strconv.ParseUint(r.PathValue("generation"), 10, 64)
		operationID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		serial, serialErr := parseQuotedSerial(r.Header.Get("If-Match"))
		if !ok || generationErr != nil || operationID == "" || serialErr != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Endpoint certificate revocation request is invalid.")
			return
		}
		value, err := service.Revoke(r.Context(), operationID, principal.User.ID, r.PathValue("endpoint_id"), generation, serial, "endpoint_removed", time.Now().UTC())
		if err != nil {
			status, code := http.StatusBadRequest, "invalid_request"
			switch {
			case errors.Is(err, peeridentity.ErrConflict):
				status, code = http.StatusConflict, "operation_conflict"
			case errors.Is(err, peeridentity.ErrUnavailable):
				status, code = http.StatusNotFound, "not_found"
			}
			writeError(w, r, status, code, "Endpoint certificate could not be revoked.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: certificateDocument(value)})
	}
}

func certificateDocument(value peeridentity.Certificate) endpointCertificateDocument {
	return endpointCertificateDocument{
		Version: 1, AccountID: value.AccountID, RootFingerprint: hex.EncodeToString(value.RootFingerprint[:]),
		EndpointID: value.EndpointID, Role: value.Role.String(), Generation: value.Generation, Serial: value.Serial,
		IssuedAt: value.IssuedAt.UTC().Format(time.RFC3339), ExpiresAt: value.ExpiresAt.UTC().Format(time.RFC3339),
		Certificate: base64.RawURLEncoding.EncodeToString(value.Raw), CertificateFingerprint: hex.EncodeToString(value.Fingerprint[:]),
	}
}

func endpointRole(value string) peeridentity.Role {
	switch value {
	case "cli":
		return peeridentity.RoleCLI
	case "machine":
		return peeridentity.RoleMachine
	default:
		return 0
	}
}

func decodeCanonicalBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid base64url")
	}
	return decoded, nil
}

func decodeFingerprint(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) || hex.EncodeToString(decoded) != value {
		return result, errors.New("invalid fingerprint")
	}
	copy(result[:], decoded)
	return result, nil
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Nanosecond() != 0 || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("invalid timestamp")
	}
	return parsed, nil
}

func parseQuotedSerial(value string) (uint64, error) {
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, errors.New("invalid serial etag")
	}
	return strconv.ParseUint(value[1:len(value)-1], 10, 64)
}
