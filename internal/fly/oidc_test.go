package fly

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func TestWorkloadIdentityVerifierValidatesFlyClaims(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	issuer = server.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "jwks_uri": issuer + "/keys",
			"id_token_signing_alg_values_supported": []string{"EdDSA"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": "fly-test",
			"x": base64.RawURLEncoding.EncodeToString(publicKey),
		}}})
	})
	verifier, err := newWorkloadIdentityVerifier(issuer, "https://control.example/v1/helpers/enroll/hosted", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": issuer, "aud": "https://control.example/v1/helpers/enroll/hosted",
		"iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"jti": "fly-oidc-token-1", "app_name": "paperboat-projects",
		"machine_id": "machine-1", "machine_name": "pbvm-project-1",
		"image_digest": "sha256:" + strings.Repeat("a", 64),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = "fly-test"
	raw, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := verifier.Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if identity.AppName != "paperboat-projects" || identity.MachineID != "machine-1" || identity.TokenID != "fly-oidc-token-1" {
		t.Fatalf("identity = %#v", identity)
	}

	wrongAudience := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": issuer, "aud": "https://attacker.example", "iat": now.Unix(), "nbf": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "jti": "fly-oidc-token-2",
		"app_name": "paperboat-projects", "machine_id": "machine-1",
		"machine_name": "pbvm-project-1", "image_digest": "sha256:" + strings.Repeat("a", 64),
	})
	wrongAudience.Header["kid"] = "fly-test"
	rawWrongAudience, err := wrongAudience.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), rawWrongAudience); err == nil {
		t.Fatal("wrong audience workload identity was accepted")
	}
}

func TestNewWorkloadIdentityVerifierRejectsUnsafeOrgSlug(t *testing.T) {
	for _, value := range []string{"", "org/other", "org?query", "org#fragment"} {
		if _, err := NewWorkloadIdentityVerifier(value, "audience", http.DefaultClient); err == nil {
			t.Fatalf("org slug %q was accepted", value)
		}
	}
}
