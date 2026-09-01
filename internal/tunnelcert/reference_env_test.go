package tunnelcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

func TestEnvironmentReferenceNameSeparatesNormalizedReferences(t *testing.T) {
	left, err := EnvironmentReferenceName("PAPERBOAT_CERT_SECRET_", "secret://a/b")
	if err != nil {
		t.Fatal(err)
	}
	right, err := EnvironmentReferenceName("PAPERBOAT_CERT_SECRET_", "secret:/a/b")
	if err != nil {
		t.Fatal(err)
	}
	if left == right || !strings.HasPrefix(left, "PAPERBOAT_CERT_SECRET_") {
		t.Fatalf("references collided or used wrong prefix: %q %q", left, right)
	}
	if _, err := EnvironmentReferenceName("PAPERBOAT_CERT_SECRET_", "-----BEGIN PRIVATE KEY-----"); !errors.Is(err, ErrMasterKeyUnavailable) {
		t.Fatalf("raw key reference error = %v", err)
	}
}

func TestEnvironmentSignerSourceParsesAndWipesOnlyPEMInput(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemValue := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	envName, err := EnvironmentReferenceName("PAPERBOAT_CERT_SECRET_", "secret://acme/account")
	if err != nil {
		t.Fatal(err)
	}
	source := EnvironmentSignerSource{EnvironmentReferenceSource: EnvironmentReferenceSource{Prefix: "PAPERBOAT_CERT_SECRET_", LookupEnv: func(name string) (string, bool) {
		if name == envName {
			return string(pemValue), true
		}
		return "", false
	}}}
	signer, err := source.ResolveSigner(context.Background(), "secret://acme/account")
	if err != nil || signer == nil {
		t.Fatalf("ResolveSigner = %v", err)
	}
	if _, err := source.ResolveSigner(context.Background(), "secret://missing"); !errors.Is(err, ErrMasterKeyUnavailable) {
		t.Fatalf("missing signer error = %v", err)
	}
}
