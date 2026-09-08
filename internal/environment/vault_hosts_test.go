package environment

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func vaultProjectionFixture(t *testing.T, c vaultProjectionClaims, seed byte) []byte {
	t.Helper()
	claims, err := EncodeCanonical(c)
	if err != nil {
		t.Fatal(err)
	}
	enc, ciphertext := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 48)
	message, _ := EncodeCanonical([]any{"paperboat.environment.host-projection-signature", uint64(1), claims, enc, ciphertext})
	raw, err := EncodeCanonical(vaultProjectionEnvelope{Claims: claims, Enc: enc, Ciphertext: ciphertext, Signature: ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)), message)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestVaultProjectionExactSignatureIdentityAndSourceBounds(t *testing.T) {
	writer := fixtureVaultMetadata(t, "user_a", 1, make([]byte, 32))
	claims := vaultProjectionClaims{Domain: "paperboat.environment.host-projection", Version: 1, Issuer: "https://control.example", OwnerAccount: "user_a", MachineID: "host_a", InstallationGeneration: 1, HostKeyGeneration: 1, HostPublic: bytes.Repeat([]byte{72}, 32), SelectionGeneration: 1, Revision: 1, Previous: make([]byte, 32), Sources: []vaultProjectionSource{}, WriterVaultGeneration: 1, WriterPublic: writer.WriterPublicKey[:]}
	if _, err := parseVaultProjection(vaultProjectionFixture(t, claims, 11), claims.Issuer, writer); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"writer", "account", "nonce", "signature", "nil_sources", "order", "bounds"} {
		t.Run(mutation, func(t *testing.T) {
			c := claims
			seed := byte(11)
			switch mutation {
			case "writer":
				c.WriterPublic = bytes.Repeat([]byte{9}, 32)
			case "account":
				c.OwnerAccount = "user_b"
			case "nonce":
				c.Previous = bytes.Repeat([]byte{9}, 32)
			case "signature":
				seed = 12
			case "nil_sources":
				c.Sources = nil
			case "order":
				c.Sources = []vaultProjectionSource{{OwnerKind: "personal", OwnerID: "user_b", Epoch: 1, Revision: 1, Digest: make([]byte, 32)}, {OwnerKind: "personal", OwnerID: "user_a", Epoch: 1, Revision: 1, Digest: make([]byte, 32)}}
			case "bounds":
				c.Revision = MaxBrowserInteger + 1
			}
			if _, err := parseVaultProjection(vaultProjectionFixture(t, c, seed), claims.Issuer, writer); err == nil {
				t.Fatal("invalid projection accepted")
			}
		})
	}
	observation := VaultProjectionObservation{Schema: VaultProjectionObservationSchema, ObservationSeq: 1, HostRecipientKeyID: vaultHostKeyID(claims.HostPublic), State: "pending", ObservedAt: time.Now().UTC()}
	if !observation.Valid() {
		t.Fatal("pending observation rejected")
	}
	observation.State = "failed"
	if observation.Valid() {
		t.Fatal("failed observation omitted error")
	}
	errorCode := "decrypt_failed"
	observation.ErrorCode = &errorCode
	if !observation.Valid() {
		t.Fatal("bounded error rejected")
	}
}
