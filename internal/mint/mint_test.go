package mint

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testKey(seedByte byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte(strings.Repeat(string([]byte{seedByte}), ed25519.SeedSize)))
}

func TestSignPublishesFrozenClaims(t *testing.T) {
	provider, err := New([]Key{{ID: "key-2", PrivateKey: testKey(2)}, {ID: "key-1", PrivateKey: testKey(1)}}, "key-2", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Unix(1_700_000_000, 0)
	token, err := provider.Sign(ProofInput{Issuer: "https://api.example.test", EnvironmentID: "env_1", UserID: "usr_1", ClientSessionID: "cls_1", JTI: "jti_1", Nonce: "nonce_1", IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("parts = %d", len(parts))
	}
	var header map[string]any
	var payload map[string]any
	decodeJSONPart(t, parts[0], &header)
	decodeJSONPart(t, parts[1], &payload)
	if header["alg"] != "EdDSA" || header["typ"] != ProofType || header["kid"] != "key-2" {
		t.Fatalf("header = %#v", header)
	}
	if payload["aud"] != "t3-env:env_1" || payload["sub"] != "usr_1" || payload["clientSessionId"] != "cls_1" {
		t.Fatalf("payload = %#v", payload)
	}
	if _, ok := payload["cnf"]; ok {
		t.Fatal("unexpected cnf claim")
	}
	if !ed25519.Verify(testKey(2).Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), mustDecode(t, parts[2])) {
		t.Fatal("invalid signature")
	}
}

func TestJWKSIncludesRotationOverlapKeys(t *testing.T) {
	provider, err := New([]Key{{ID: "current", PrivateKey: testKey(3)}, {ID: "previous", PrivateKey: testKey(4)}}, "current", 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	provider.ServeHTTP(recorder, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if got := recorder.Header().Get("Cache-Control"); got != "public, max-age=90" {
		t.Fatalf("cache-control = %q", got)
	}
	var body struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Keys) != 2 {
		t.Fatalf("keys = %d", len(body.Keys))
	}
	ids := map[string]bool{}
	for _, key := range body.Keys {
		ids[key["kid"]] = true
		if key["kty"] != "OKP" || key["crv"] != "Ed25519" || key["alg"] != "EdDSA" || key["use"] != "sig" {
			t.Fatalf("key = %#v", key)
		}
	}
	if !ids["current"] || !ids["previous"] {
		t.Fatalf("ids = %#v", ids)
	}
}

func TestSigningKeyRollbackUsesPublishedOverlapKey(t *testing.T) {
	keys := []Key{{ID: "current", PrivateKey: testKey(7)}, {ID: "previous", PrivateKey: testKey(8)}}
	now := time.Unix(1_700_000_000, 0)
	input := ProofInput{Issuer: "issuer", EnvironmentID: "env", UserID: "user", ClientSessionID: "client", JTI: "jti", Nonce: "nonce", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	current, err := New(keys, "current", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := New(keys, "previous", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	currentToken, _ := current.Sign(input)
	rollbackToken, _ := rolledBack.Sign(input)
	var currentHeader map[string]any
	var rollbackHeader map[string]any
	decodeJSONPart(t, strings.Split(currentToken, ".")[0], &currentHeader)
	decodeJSONPart(t, strings.Split(rollbackToken, ".")[0], &rollbackHeader)
	if currentHeader["kid"] != "current" || rollbackHeader["kid"] != "previous" {
		t.Fatalf("current=%#v rollback=%#v", currentHeader, rollbackHeader)
	}
}

func TestSignRejectsOverlongProof(t *testing.T) {
	provider, _ := New([]Key{{ID: "key", PrivateKey: testKey(5)}}, "key", time.Minute)
	now := time.Now()
	_, err := provider.Sign(ProofInput{Issuer: "issuer", EnvironmentID: "env", UserID: "user", ClientSessionID: "client", JTI: "jti", Nonce: "nonce", IssuedAt: now, ExpiresAt: now.Add(MaxProofTTL + time.Second)})
	if err == nil {
		t.Fatal("expected lifetime error")
	}
}

func TestSignRevocationUsesSeparateTypeAndScope(t *testing.T) {
	provider, _ := New([]Key{{ID: "key", PrivateKey: testKey(6)}}, "key", time.Minute)
	now := time.Unix(1_700_000_000, 0)
	token, err := provider.SignRevocation(RevocationInput{
		ProofInput: ProofInput{Issuer: "issuer", EnvironmentID: "env", UserID: "user", ClientSessionID: "client", JTI: "jti", Nonce: "nonce", IssuedAt: now, ExpiresAt: now.Add(time.Minute)},
		SessionIDs: []string{"session-1"}, Reason: "logout",
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	var header map[string]any
	var payload map[string]any
	decodeJSONPart(t, parts[0], &header)
	decodeJSONPart(t, parts[1], &payload)
	if header["typ"] != RevokeType || payload["reason"] != "logout" {
		t.Fatalf("header=%#v payload=%#v", header, payload)
	}
	if scope := payload["scope"].([]any); len(scope) != 1 || scope[0] != RevokeScope {
		t.Fatalf("scope=%#v", scope)
	}
}

func decodeJSONPart(t *testing.T, part string, target any) {
	t.Helper()
	if err := json.Unmarshal(mustDecode(t, part), target); err != nil {
		t.Fatal(err)
	}
}
func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
