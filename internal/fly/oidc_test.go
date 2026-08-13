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
	verifier, err := newWorkloadIdentityVerifier(issuer, "https://control.example/v1/hosted-helper-enrollments", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claims := map[string]any{
		"iss": issuer, "aud": "https://control.example/v1/hosted-helper-enrollments",
		"iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"jti": "fly-oidc-token-1", "app_name": "paperboat-projects",
		"machine_id": "machine-1", "machine_name": "pbvm-project-1",
		"image_digest": "sha256:" + strings.Repeat("a", 64),
	}
	raw, err := signTestJWT(privateKey, "fly-test", claims)
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

	wrongAudienceClaims := map[string]any{
		"iss": issuer, "aud": "https://attacker.example", "iat": now.Unix(), "nbf": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "jti": "fly-oidc-token-2",
		"app_name": "paperboat-projects", "machine_id": "machine-1",
		"machine_name": "pbvm-project-1", "image_digest": "sha256:" + strings.Repeat("a", 64),
	}
	rawWrongAudience, err := signTestJWT(privateKey, "fly-test", wrongAudienceClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), rawWrongAudience); err == nil {
		t.Fatal("wrong audience workload identity was accepted")
	}
}

func signTestJWT(privateKey ed25519.PrivateKey, keyID string, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "kid": keyID, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	message := encodedHeader + "." + encodedPayload
	signature := ed25519.Sign(privateKey, []byte(message))
	return message + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func TestNewWorkloadIdentityVerifierRejectsUnsafeOrgSlug(t *testing.T) {
	for _, value := range []string{"", "org/other", "org?query", "org#fragment"} {
		if _, err := NewWorkloadIdentityVerifier(value, "audience", http.DefaultClient); err == nil {
			t.Fatalf("org slug %q was accepted", value)
		}
	}
}
