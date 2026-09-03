package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

type recordingCertificateRegistrar struct {
	request peeridentity.RegisterRequest
	result  peeridentity.Certificate
	err     error
}

type recordingBootstrapper struct {
	request peeridentity.BootstrapRequest
	result  peeridentity.Certificate
	err     error
}

func (b *recordingBootstrapper) Bootstrap(_ context.Context, request peeridentity.BootstrapRequest) (peeridentity.Certificate, error) {
	b.request = request
	return b.result, b.err
}

func TestE2EEBootstrapBindsAuthenticatedCLISession(t *testing.T) {
	rootPublic := bytes.Repeat([]byte{3}, 32)
	raw := bytes.Repeat([]byte{4}, 172)
	rootFingerprint := sha256.Sum256(rootPublic)
	certificateFingerprint := sha256.Sum256(raw)
	issued := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	expires := issued.Add(time.Hour)
	keyID, _ := peeridentity.KeyID(rootPublic)
	document := e2eeBootstrapRequestDocument{RootPublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Certificate: endpointCertificateDocument{Version: 1, AccountID: "account_01", KeyID: keyID, EndpointID: "cli_session_01", Role: "cli", Generation: 1, Serial: 1, IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:])}}
	body, _ := json.Marshal(document)
	bootstrapper := &recordingBootstrapper{result: peeridentity.Certificate{AccountID: "account_01", KeyID: keyID, Role: peeridentity.RoleCLI, EndpointID: "cli_session_01", Generation: 1, Serial: 1, IssuedAt: issued, ExpiresAt: expires, RootFingerprint: rootFingerprint, Fingerprint: certificateFingerprint, Raw: raw}}
	request := httptest.NewRequest(http.MethodPost, "/v1/e2ee/bootstrap", bytes.NewReader(body))
	request.Header.Set("Idempotency-Key", "operation_bootstrap_01")
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}, Client: &auth.ClientPrincipal{SessionID: "cli_session_01"}}))
	response := httptest.NewRecorder()
	e2eeBootstrap(bootstrapper).ServeHTTP(response, request)
	if response.Code != http.StatusCreated || bootstrapper.request.CLIClientSessionID != "cli_session_01" || bootstrapper.request.Expected.EndpointID != "cli_session_01" || !bytes.Equal(bootstrapper.request.RootPublicKey, rootPublic) {
		t.Fatalf("status=%d request=%+v body=%s", response.Code, bootstrapper.request, response.Body.String())
	}
}

func TestE2EEBootstrapReportsSecretSafeValidationStage(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/e2ee/bootstrap", bytes.NewBufferString(`{"root_public_key":"not-base64","certificate":{"version":1,"account_id":"account_01","endpoint_id":"cli_session_01","role":"cli","generation":1,"serial":1}}`))
	request.Header.Set("Idempotency-Key", "operation_bootstrap_01")
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}, Client: &auth.ClientPrincipal{SessionID: "cli_session_01"}}))
	response := httptest.NewRecorder()
	e2eeBootstrap(&recordingBootstrapper{}).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !bytes.Contains(response.Body.Bytes(), []byte(`"stage":"root_public_key_encoding"`)) || bytes.Contains(response.Body.Bytes(), []byte("not-base64")) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestE2EEBootstrapReportsSafeServiceErrorClass(t *testing.T) {
	rootPublic := bytes.Repeat([]byte{3}, 32)
	raw := bytes.Repeat([]byte{4}, 172)
	certificateFingerprint := sha256.Sum256(raw)
	issued := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	keyID, _ := peeridentity.KeyID(rootPublic)
	document := e2eeBootstrapRequestDocument{RootPublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Certificate: endpointCertificateDocument{Version: 1, AccountID: "account_01", KeyID: keyID, EndpointID: "cli_session_01", Role: "cli", Generation: 1, Serial: 1, IssuedAt: issued.Format(time.RFC3339), ExpiresAt: issued.Add(time.Hour).Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:])}}
	body, _ := json.Marshal(document)
	request := httptest.NewRequest(http.MethodPost, "/v1/e2ee/bootstrap", bytes.NewReader(body))
	request.Header.Set("Idempotency-Key", "operation_bootstrap_01")
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}, Client: &auth.ClientPrincipal{SessionID: "cli_session_01"}}))
	response := httptest.NewRecorder()
	e2eeBootstrap(&recordingBootstrapper{err: peeridentity.ErrInvalid}).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !bytes.Contains(response.Body.Bytes(), []byte(`"stage":"service"`)) || !bytes.Contains(response.Body.Bytes(), []byte(`"reason":"invalid"`)) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func (r *recordingCertificateRegistrar) Register(_ context.Context, request peeridentity.RegisterRequest) (peeridentity.Certificate, error) {
	r.request = request
	return r.result, r.err
}

func TestEndpointCertificateRegisterMapsCanonicalDocument(t *testing.T) {
	raw := bytes.Repeat([]byte{1}, 172)
	rootFingerprint := sha256.Sum256([]byte("root"))
	keyID := "aek_" + hex.EncodeToString(rootFingerprint[:])
	certificateFingerprint := sha256.Sum256(raw)
	issued := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	expires := issued.Add(time.Hour)
	registrar := &recordingCertificateRegistrar{result: peeridentity.Certificate{
		AccountID: "account_01", KeyID: keyID, Role: peeridentity.RoleCLI, EndpointID: "cli_01", Generation: 2, Serial: 7,
		IssuedAt: issued, ExpiresAt: expires, RootFingerprint: rootFingerprint, Fingerprint: certificateFingerprint, Raw: raw,
	}}
	document := endpointCertificateDocument{
		Version: 1, AccountID: "account_01", KeyID: keyID, EndpointID: "cli_01",
		Role: "cli", Generation: 2, Serial: 7, IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339),
		Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:]),
	}
	body, _ := json.Marshal(document)
	request := httptest.NewRequest(http.MethodPut, "/v1/endpoints/cli_01/certificates/2", bytes.NewReader(body))
	request.SetPathValue("endpoint_id", "cli_01")
	request.SetPathValue("generation", "2")
	request.Header.Set("Idempotency-Key", "operation_endpoint_01")
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}}))
	response := httptest.NewRecorder()
	endpointCertificateRegister(registrar).ServeHTTP(response, request)
	if response.Code != http.StatusCreated || registrar.request.OperationID != "operation_endpoint_01" || registrar.request.Expected.EndpointID != "cli_01" || registrar.request.ExpectedCertificateFingerprint != certificateFingerprint {
		t.Fatalf("status=%d request=%+v body=%s", response.Code, registrar.request, response.Body.String())
	}
}

func TestEndpointCertificateRegisterRejectsNonCanonicalAndMapsConflicts(t *testing.T) {
	registrar := &recordingCertificateRegistrar{}
	request := httptest.NewRequest(http.MethodPut, "/v1/endpoints/cli_01/certificates/1", bytes.NewBufferString(`{"version":1}`))
	request.SetPathValue("endpoint_id", "cli_01")
	request.SetPathValue("generation", "1")
	request.Header.Set("Idempotency-Key", "operation_endpoint_01")
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}}))
	response := httptest.NewRecorder()
	endpointCertificateRegister(registrar).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !bytes.Contains(response.Body.Bytes(), []byte(`"code":"invalid_request"`)) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	raw := bytes.Repeat([]byte{1}, 172)
	fingerprint := sha256.Sum256(raw)
	document := endpointCertificateDocument{Version: 1, AccountID: "account_01", KeyID: "aek_" + hex.EncodeToString(fingerprint[:]), EndpointID: "cli_01", Role: "cli", Generation: 1, Serial: 1, IssuedAt: "2026-08-03T12:00:00Z", ExpiresAt: "2026-08-03T13:00:00Z", Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(fingerprint[:])}
	body, _ := json.Marshal(document)
	registrar.err = peeridentity.ErrConflict
	request = httptest.NewRequest(http.MethodPut, "/v1/endpoints/cli_01/certificates/1", bytes.NewReader(body))
	request.SetPathValue("endpoint_id", "cli_01")
	request.SetPathValue("generation", "1")
	request.Header.Set("Idempotency-Key", "operation_endpoint_01")
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}}))
	response = httptest.NewRecorder()
	endpointCertificateRegister(registrar).ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !bytes.Contains(response.Body.Bytes(), []byte(`"code":"operation_conflict"`)) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	registrar.err = errors.New("unexpected")
}
