package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
)

func testConnectorCredentialKey() (ed25519.PrivateKey, string) {
	seed := bytes.Repeat([]byte{11}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	return private, ConnectorCredentialThumbprint(private.Public().(ed25519.PublicKey))
}

func TestConnectorCredentialProofBindsTokenDigestWithoutEmbeddingToken(t *testing.T) {
	private, thumbprint := testConnectorCredentialKey()
	const token = "pbce_one-time-secret-token"
	payload := ConnectorCredentialProofPayload("tun_1", "host_1", token, "keychain://paperboat/connector", thumbprint, "idem_1")
	if bytes.Contains(payload, []byte(token)) {
		t.Fatalf("proof payload contains the reusable enrollment token: %s", payload)
	}
	if !bytes.Contains(payload, []byte(`"enrollment_token_sha256"`)) {
		t.Fatalf("proof payload does not name the token digest: %s", payload)
	}
	tokenHash := sha256Hex(token)
	if !bytes.Contains(payload, []byte(tokenHash)) {
		t.Fatalf("proof payload does not contain the token digest: %s", payload)
	}
	proof := ed25519.Sign(private, payload)
	if !VerifyConnectorCredentialProof("ed25519", private.Public().(ed25519.PublicKey), proof, "tun_1", "host_1", token, "keychain://paperboat/connector", thumbprint, "idem_1") {
		t.Fatal("valid connector credential proof was rejected")
	}
	if VerifyConnectorCredentialProof("ed25519", private.Public().(ed25519.PublicKey), proof, "tun_1", "host_1", token+"-changed", "keychain://paperboat/connector", thumbprint, "idem_1") {
		t.Fatal("proof accepted for a changed enrollment token")
	}
}

func TestConnectorCredentialThumbprintMatchesConnectorIdentityFormat(t *testing.T) {
	private, thumbprint := testConnectorCredentialKey()
	public := private.Public().(ed25519.PublicKey)
	want, err := connectorprotocol.IdentityThumbprint(public)
	if err != nil {
		t.Fatal(err)
	}
	if thumbprint != want {
		t.Fatalf("thumbprint=%q, want %q", thumbprint, want)
	}
	if strings.HasPrefix(thumbprint, "sha256:") || connectorprotocol.ValidateIdentityKey("ed25519:"+thumbprint, thumbprint) != nil {
		t.Fatalf("thumbprint is not the connector identity thumbprint: %q", thumbprint)
	}
	if ConnectorCredentialThumbprint(public[:ed25519.PublicKeySize-1]) != "" {
		t.Fatal("short public key produced a thumbprint")
	}
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
