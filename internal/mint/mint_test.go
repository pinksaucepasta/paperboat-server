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

func TestSignCredentialUsesExactClassBindings(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	provider, err := New([]Key{{ID: "key-1", PrivateKey: testKey(1)}}, "key-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := provider.SignCredential(CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-enrollment", Subject: "env_1", JTI: "jti_enroll_1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "helper_enrollment", Scopes: []string{"helper:enroll"}, EnvironmentID: "env_1", EnrollmentID: "enr_1"})
	if err != nil || token == "" {
		t.Fatalf("enrollment credential = %q, %v", token, err)
	}
	claims, err := provider.VerifyCredential(token, "https://api.example.test", "helper_enrollment", now)
	if err != nil || claims.EnrollmentID != "enr_1" || claims.EnvironmentID != "env_1" {
		t.Fatalf("verified claims = %#v, %v", claims, err)
	}
	tampered := token[:len(token)-1] + "A"
	if _, err := provider.VerifyCredential(tampered, "https://api.example.test", "helper_enrollment", now); err == nil {
		t.Fatal("tampered credential accepted")
	}
	if _, err := provider.SignCredential(CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-enrollment", Subject: "env_1", JTI: "jti_enroll_2", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "helper_enrollment", Scopes: []string{"helper:connect"}, EnvironmentID: "env_1", EnrollmentID: "enr_1"}); err == nil {
		t.Fatal("broader or wrong scope accepted")
	}
}

func TestSignCredentialConfigSyncBindsAssignmentAndWarning(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	provider, err := New([]Key{{ID: "key-config", PrivateKey: testKey(11)}}, "key-config", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := provider.SignCredential(CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-helper", Subject: "helper_1", JTI: "jti_config_1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "config_sync", Scopes: []string{"config:pull", "config:apply", "config:report"}, EnvironmentID: "env_1", HelperID: "helper_1", AssignmentID: "assignment_1", WarningRevision: "warning_7"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, "https://api.example.test", "config_sync", now)
	if err != nil || claims.AssignmentID != "assignment_1" || claims.WarningRevision != "warning_7" || claims.HelperID != "helper_1" {
		t.Fatalf("claims = %#v, %v", claims, err)
	}
	if _, err := provider.SignCredential(CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-helper", Subject: "helper_1", JTI: "jti_config_2", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "config_sync", Scopes: []string{"config:pull"}, EnvironmentID: "env_1", HelperID: "helper_1", AssignmentID: "assignment_1", WarningRevision: "warning_7"}); err == nil {
		t.Fatal("incomplete config scopes accepted")
	}
}

func TestSignPreviewRegistrationBindsHelperAndEnvironment(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	provider, err := New([]Key{{ID: "key-preview", PrivateKey: testKey(12)}}, "key-preview", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-control", Subject: "helper_1", JTI: "jti_preview_1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "preview_registration", Scopes: []string{"preview:register"}, EnvironmentID: "env_1", HelperID: "helper_1"}
	token, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, "https://api.example.test", "preview_registration", now)
	if err != nil || claims.EnvironmentID != "env_1" || claims.HelperID != "helper_1" {
		t.Fatalf("claims = %#v, %v", claims, err)
	}
	input.HelperID = ""
	if _, err := provider.SignCredential(input); err == nil {
		t.Fatal("preview credential without helper binding was accepted")
	}
	input.HelperID = "helper_1"
	input.Scopes = []string{"helper:renew"}
	if _, err := provider.SignCredential(input); err == nil {
		t.Fatal("preview credential with wrong scope was accepted")
	}
	input.Scopes = []string{"preview:register", "helper:renew"}
	if _, err := provider.SignCredential(input); err == nil {
		t.Fatal("preview credential with broader scope was accepted")
	}
}

func TestSignTerminalControlBindsOperationAndTerminalIDs(t *testing.T) {
	provider, _ := New([]Key{{ID: "key", PrivateKey: testKey(9)}}, "key", time.Minute)
	now := time.Unix(1_700_000_000, 0)
	token, err := provider.SignTerminalControl(TerminalControlInput{Issuer: "https://api.example", EnvironmentID: "env_1", UserID: "usr_1", JTI: "jti_1", Nonce: "nonce_1", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Operation: "delete_history", ThreadID: "paperboat-cli", TerminalIDs: []string{"term_a", "term_b"}})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	var header, payload map[string]any
	decodeJSONPart(t, parts[0], &header)
	decodeJSONPart(t, parts[1], &payload)
	if header["typ"] != TerminalControlType || payload["scope"].([]any)[0] != TerminalControlScope || payload["operation"] != "delete_history" || payload["threadId"] != "paperboat-cli" {
		t.Fatalf("header=%#v payload=%#v", header, payload)
	}
	if got := payload["terminalIds"].([]any); len(got) != 2 || got[0] != "term_a" {
		t.Fatalf("terminal IDs=%#v", got)
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

func TestSignHealthUsesDedicatedTypeAndScope(t *testing.T) {
	provider, _ := New([]Key{{ID: "health-key", PrivateKey: testKey(9)}}, "health-key", time.Minute)
	now := time.Unix(1_700_000_000, 0)
	token, err := provider.SignHealth(ProofInput{
		Issuer: "https://paperboat.example", EnvironmentID: "env_1", UserID: "usr_1",
		ClientSessionID: "cls_1", JTI: "health-jti", Nonce: "health-nonce",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	var header map[string]any
	var payload map[string]any
	decodeJSONPart(t, parts[0], &header)
	decodeJSONPart(t, parts[1], &payload)
	if header["typ"] != HealthType || header["kid"] != "health-key" {
		t.Fatalf("header=%#v", header)
	}
	if payload["aud"] != "t3-env:env_1" || payload["sub"] != "usr_1" || payload["environmentId"] != "env_1" || payload["clientSessionId"] != "cls_1" {
		t.Fatalf("payload=%#v", payload)
	}
	if scope := payload["scope"].([]any); len(scope) != 1 || scope[0] != HealthScope {
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
