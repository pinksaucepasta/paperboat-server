package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestValidateCarrierServerCertificateChainBindsHostnameValidityAndPin(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge"}, DNSNames: []string{"edge.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := "sha256:" + hex.EncodeToString(digest[:])
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err := validateCarrierServerCertificateChain(chain, pin, "edge.example.test", now); err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		pin, host string
		now       time.Time
	}{
		"wrong pin":  {pin: "sha256:" + string(make([]byte, 64)), host: "edge.example.test", now: now},
		"wrong host": {pin: pin, host: "other.example.test", now: now},
		"expired":    {pin: pin, host: "edge.example.test", now: now.Add(2 * time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCarrierServerCertificateChain(chain, test.pin, test.host, test.now); err == nil {
				t.Fatal("invalid carrier server trust accepted")
			}
		})
	}
}
