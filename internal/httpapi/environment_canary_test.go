package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// This checks HTTP opacity, not the vault cryptographic protocol.
func TestEnvironmentPasswordVaultHTTPPlaintextCanary(t *testing.T) {
	canary := []byte("task235-private-recovery-canary")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	encrypted := aead.Seal(nonce, nonce, canary, nil)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	stub := &passwordVaultAPIStub{}
	ctx := context.WithValue(context.Background(), authContextKey{}, principal{User: auth.User{ID: "account_canary"}})
	body := map[string]any{"envelope": base64.RawURLEncoding.EncodeToString(encrypted)}
	result := httptest.NewRecorder()
	environmentPasswordVaultPut(stub).ServeHTTP(result, httptest.NewRequest(http.MethodPut, "/v1/environment-vault", jsonReader(t, body)).WithContext(ctx))
	if result.Code != http.StatusOK || !bytes.Equal(stub.putRaw, encrypted) || stub.putAccount != "account_canary" {
		t.Fatal("opaque vault request was not forwarded under authenticated account")
	}
	if bytes.Contains(stub.putRaw, canary) || bytes.Contains(result.Body.Bytes(), canary) || bytes.Contains(logs.Bytes(), canary) {
		t.Fatal("plaintext canary reached server boundary")
	}
	for _, authenticated := range []bool{false, true} {
		rejected := &passwordVaultAPIStub{}
		request := httptest.NewRequest(http.MethodPut, "/v1/environment-vault", jsonReader(t, map[string]any{"envelope": body["envelope"], "password": string(canary)}))
		want := http.StatusUnauthorized
		if authenticated {
			request = request.WithContext(ctx)
			want = http.StatusBadRequest
		}
		response := httptest.NewRecorder()
		environmentPasswordVaultPut(rejected).ServeHTTP(response, request)
		if response.Code != want || rejected.putAccount != "" || bytes.Contains(response.Body.Bytes(), canary) || bytes.Contains(logs.Bytes(), canary) {
			t.Fatal("plaintext field or unauthenticated request was accepted or disclosed")
		}
	}
}
