package controlplane

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVerifyHelperProofBindsRequestAndIdentity(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", ed25519.SeedSize)))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"edge_pool":"default"}`)
	bodyHash := sha256.Sum256(body)
	claims := HelperProofClaims{HelperID: "hlp_1", EnvironmentID: "env_1", OperationID: "operation_1", Method: "POST", Path: "/v1/connectors/admission", BodySHA256: base64.RawURLEncoding.EncodeToString(bodyHash[:]), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(helperProofEnvelope{Algorithm: "EdDSA", Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyHelperProof(publicKey, envelope, "hlp_1", "env_1", "POST", "/v1/connectors/admission", body, now)
	if err != nil || verified.OperationID != "operation_1" {
		t.Fatalf("verified = %#v, %v", verified, err)
	}
	if _, err := verifyHelperProof(publicKey, envelope, "hlp_1", "env_1", "POST", "/v1/connectors/admission", []byte(`{}`), now); !errors.Is(err, ErrHelperProof) {
		t.Fatalf("relabeled body error = %v", err)
	}
	if _, err := verifyHelperProof(publicKey, envelope, "hlp_1", "env_1", "POST", "/v1/connectors/admission", body, now.Add(2*time.Minute)); !errors.Is(err, ErrHelperProof) {
		t.Fatalf("expired proof error = %v", err)
	}
}

func TestStrictHelperProofJSONRejectsDuplicateKeys(t *testing.T) {
	var claims HelperProofClaims
	if err := strictProofJSON([]byte(`{"helper_id":"hlp_1","helper_id":"hlp_2"}`), &claims); !errors.Is(err, ErrHelperProof) {
		t.Fatalf("duplicate proof error = %v", err)
	}
}
