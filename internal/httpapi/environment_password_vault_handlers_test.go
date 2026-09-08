package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/environment"
)

type passwordVaultAPIStub struct {
	environmentVariableAPI
	getAccount string
	getErr     error
	putAccount string
	putRaw     []byte
	putErr     error
}

func (s *passwordVaultAPIStub) PasswordVaultIssuer() string {
	return "https://control.example"
}

func (s *passwordVaultAPIStub) GetPasswordVault(_ context.Context, account string) (environment.PasswordVaultHead, error) {
	s.getAccount = account
	if s.getErr != nil {
		return environment.PasswordVaultHead{}, s.getErr
	}
	return environment.PasswordVaultHead{Issuer: "https://control.example", AccountID: account, Generation: 1, DocumentID: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Envelope: "AQ"}, nil
}
func (s *passwordVaultAPIStub) PutPasswordVault(_ context.Context, account string, raw []byte) (environment.PasswordVaultHead, error) {
	s.putAccount, s.putRaw = account, append([]byte(nil), raw...)
	if s.putErr != nil {
		return environment.PasswordVaultHead{}, s.putErr
	}
	return environment.PasswordVaultHead{Issuer: "https://control.example", AccountID: account, Generation: 1, DocumentID: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Envelope: "AQ"}, nil
}

func TestEnvironmentPasswordVaultPutReportsCASConflict(t *testing.T) {
	stub := &passwordVaultAPIStub{putErr: environment.ErrPasswordVaultConflict}
	ctx := context.WithValue(context.Background(), authContextKey{}, principal{User: auth.User{ID: "account_1"}})
	result := httptest.NewRecorder()
	environmentPasswordVaultPut(stub).ServeHTTP(result, httptest.NewRequest(http.MethodPut, "/v1/environment-vault", jsonReader(t, map[string]any{"envelope": "AQ"})).WithContext(ctx))
	if result.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d body=%s", result.Code, result.Body.String())
	}
}

func TestEnvironmentPasswordVaultGetReturnsConfiguredIssuerBeforeGenesis(t *testing.T) {
	stub := &passwordVaultAPIStub{getErr: environment.ErrNotFound}
	ctx := context.WithValue(context.Background(), authContextKey{}, principal{User: auth.User{ID: "account_1"}})
	result := httptest.NewRecorder()
	environmentPasswordVaultGet(stub).ServeHTTP(result, httptest.NewRequest(http.MethodGet, "/v1/environment-vault", nil).WithContext(ctx))
	if result.Code != http.StatusNotFound || !bytes.Contains(result.Body.Bytes(), []byte(`"code":"not_found"`)) ||
		!bytes.Contains(result.Body.Bytes(), []byte(`"issuer":"https://control.example"`)) {
		t.Fatalf("genesis response status=%d body=%s", result.Code, result.Body.String())
	}
}

func TestEnvironmentPasswordVaultHandlersUseAuthenticatedAccount(t *testing.T) {
	stub := &passwordVaultAPIStub{}
	principalContext := context.WithValue(context.Background(), authContextKey{}, principal{User: auth.User{ID: "account_authenticated"}})

	get := httptest.NewRequest(http.MethodGet, "/v1/environment-vault", nil).WithContext(principalContext)
	getResult := httptest.NewRecorder()
	environmentPasswordVaultGet(stub).ServeHTTP(getResult, get)
	if getResult.Code != http.StatusOK || stub.getAccount != "account_authenticated" || getResult.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET status=%d account=%q headers=%v", getResult.Code, stub.getAccount, getResult.Header())
	}

	put := httptest.NewRequest(http.MethodPut, "/v1/environment-vault", jsonReader(t, map[string]any{"envelope": "AQ"})).WithContext(principalContext)
	putResult := httptest.NewRecorder()
	environmentPasswordVaultPut(stub).ServeHTTP(putResult, put)
	if putResult.Code != http.StatusOK || stub.putAccount != "account_authenticated" || len(stub.putRaw) != 1 || stub.putRaw[0] != 1 {
		t.Fatalf("PUT status=%d account=%q raw=%x", putResult.Code, stub.putAccount, stub.putRaw)
	}
}

func TestEnvironmentPasswordVaultHandlersRequirePrincipalAndStrictBody(t *testing.T) {
	stub := &passwordVaultAPIStub{}
	unauthenticated := httptest.NewRecorder()
	environmentPasswordVaultGet(stub).ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/v1/environment-vault", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET status=%d", unauthenticated.Code)
	}

	ctx := context.WithValue(context.Background(), authContextKey{}, principal{User: auth.User{ID: "account_1"}})
	bad := httptest.NewRecorder()
	environmentPasswordVaultPut(stub).ServeHTTP(bad, httptest.NewRequest(http.MethodPut, "/v1/environment-vault", jsonReader(t, map[string]any{"envelope": "AQ", "account_id": "account_other"})).WithContext(ctx))
	if bad.Code != http.StatusBadRequest || stub.putAccount != "" {
		t.Fatalf("client-selected account accepted: status=%d account=%q", bad.Code, stub.putAccount)
	}
}

func jsonReader(t *testing.T, value any) *bytes.Reader {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(raw)
}
