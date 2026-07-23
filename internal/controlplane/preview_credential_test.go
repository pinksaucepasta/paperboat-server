package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

func TestVerifyPreviewRequestRejectsExpiredAndMismatchedCredentials(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	signer, err := mint.New([]mint.Key{{ID: "preview-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", ed25519.SeedSize)))}}, "preview-test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := NewEnrollmentService(store, signer, nil, "https://api.example.test", "preview-test-encryption-key")
	service.clock = func() time.Time { return now }

	suffix := strings.ReplaceAll(t.Name(), "/", "_")
	identity, helperKey := enrollPreviewTestHelper(t, ctx, service, suffix+"_primary")
	otherIdentity, _ := enrollPreviewTestHelper(t, ctx, service, suffix+"_other")
	body := []byte(`{}`)
	proof := previewTestProof(t, helperKey, identity.HelperID, identity.EnvironmentID, body, now)

	credential := func(helperID, environmentID string, issuedAt, expiresAt time.Time) string {
		t.Helper()
		token, err := signer.SignCredential(mint.CredentialInput{
			Issuer: "https://api.example.test", Audience: "paperboat-control", Subject: helperID,
			JTI: "jti_" + helperID + "_" + environmentID, IssuedAt: issuedAt, ExpiresAt: expiresAt,
			CredentialClass: "preview_registration", Scopes: []string{"preview:register"},
			EnvironmentID: environmentID, HelperID: helperID,
		})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	tests := map[string]string{
		"expired":                credential(identity.HelperID, identity.EnvironmentID, now.Add(-6*time.Minute), now.Add(-time.Minute)),
		"mismatched helper":      credential(otherIdentity.HelperID, identity.EnvironmentID, now, now.Add(5*time.Minute)),
		"mismatched environment": credential(identity.HelperID, otherIdentity.EnvironmentID, now, now.Add(5*time.Minute)),
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := service.VerifyPreviewRequest(ctx, identity.Credential, token, proof, body, "POST", "/v1/previews/operations"); err == nil {
				t.Fatal("invalid preview credential was accepted")
			}
		})
	}
}

func enrollPreviewTestHelper(t *testing.T, ctx context.Context, service *EnrollmentService, suffix string) (HelperIdentity, ed25519.PrivateKey) {
	t.Helper()
	userID := "usr_preview_" + suffix
	environmentID := "env_preview_" + suffix
	if _, err := service.store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active') ON CONFLICT (id) DO NOTHING`, userID, "workos_"+userID, suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET owner_user_id=EXCLUDED.owner_user_id`, environmentID, "workspace_"+suffix, userID); err != nil {
		t.Fatal(err)
	}
	grant, err := service.Issue(ctx, userID, "issue:"+environmentID, environmentID, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte(fmt.Sprintf("preview-helper:%s", suffix)))
	key := ed25519.NewKeyFromSeed(seed[:])
	identity, err := service.Exchange(ctx, grant.Credential, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return identity, key
}

func previewTestProof(t *testing.T, key ed25519.PrivateKey, helperID, environmentID string, body []byte, now time.Time) []byte {
	t.Helper()
	hash := sha256.Sum256(body)
	claims := HelperProofClaims{
		HelperID: helperID, EnvironmentID: environmentID, OperationID: "preview-operation-01",
		Method: "POST", Path: "/v1/previews/operations", BodySHA256: base64.RawURLEncoding.EncodeToString(hash[:]),
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := json.Marshal(helperProofEnvelope{Algorithm: "EdDSA", Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
