package peeridentity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestApprovedEndpointCertificateVector(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/contracts/p2p-v1/fixtures/endpoint-certificate.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RootPublicKey          string `json:"root_public_key"`
		KeyID                  string `json:"key_id"`
		Certificate            string `json:"certificate"`
		CertificateFingerprint string `json:"certificate_fingerprint"`
		Now                    string `json:"now"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	root, rootErr := base64.RawURLEncoding.Strict().DecodeString(vector.RootPublicKey)
	certificateRaw, certificateErr := base64.RawURLEncoding.Strict().DecodeString(vector.Certificate)
	now, timeErr := time.Parse(time.RFC3339, vector.Now)
	if rootErr != nil || certificateErr != nil || timeErr != nil {
		t.Fatalf("root=%v certificate=%v time=%v", rootErr, certificateErr, timeErr)
	}
	certificate, err := Verify(certificateRaw, ed25519.PublicKey(root), Expected{AccountID: "account_01", Role: RoleCLI, EndpointID: "cli_01", Generation: 2, Serial: 7}, now)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := KeyID(ed25519.PublicKey(root))
	if err != nil || keyID != vector.KeyID || hex.EncodeToString(certificate.Fingerprint[:]) != vector.CertificateFingerprint {
		t.Fatalf("key_id=%s certificate=%s error=%v", keyID, hex.EncodeToString(certificate.Fingerprint[:]), err)
	}
}
