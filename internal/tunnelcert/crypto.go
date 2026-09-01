package tunnelcert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

// MasterKeySource resolves a reference to the active envelope master key.  A
// reference, not the key, is stored in configuration and certificate records.
// Implementations should read from a process secret manager or a protected
// file descriptor and must not log the returned bytes.
type MasterKeySource interface {
	Resolve(context.Context, string) ([]byte, error)
}

type bundleEnvelope struct {
	CertificatePEM []byte `json:"certificate_pem"`
	PrivateKeyPEM  []byte `json:"private_key_pem"`
	Issuer         string `json:"issuer"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
}

func resolveKey(ctx context.Context, source MasterKeySource, reference string) ([]byte, error) {
	if source == nil || !validKeyReference(reference) {
		return nil, fmt.Errorf("%w: key reference is required", ErrMasterKeyUnavailable)
	}
	key, err := source.Resolve(ctx, reference)
	if err != nil || len(key) < 32 {
		clear(key)
		return nil, ErrMasterKeyUnavailable
	}
	return key, nil
}

// Seal encrypts both certificate and private key as one authenticated envelope.
// The returned bytes are storage-only and contain no plaintext PEM.
func Seal(ctx context.Context, source MasterKeySource, reference string, bundle CertificateBundle) ([]byte, error) {
	key, err := resolveKey(ctx, source, reference)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	payload, err := json.Marshal(bundleEnvelope{
		CertificatePEM: bundle.CertificatePEM,
		PrivateKeyPEM:  bundle.PrivateKeyPEM,
		Issuer:         bundle.Issuer,
		NotBefore:      bundle.NotBefore.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		NotAfter:       bundle.NotAfter.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode certificate envelope: %v", ErrInvalid, err)
	}
	defer clear(payload)
	ciphertext, err := secrets.EncryptBytes(key, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encrypt certificate envelope: %v", ErrMasterKeyUnavailable, err)
	}
	return ciphertext, nil
}

// SealParts encrypts the certificate chain and private key independently.  A
// record can therefore be audited or re-distributed without ever carrying a
// plaintext key into a database row or API response.
func SealParts(ctx context.Context, source MasterKeySource, reference string, bundle CertificateBundle) ([]byte, []byte, error) {
	key, err := resolveKey(ctx, source, reference)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)
	certificate, err := secrets.EncryptBytes(key, bundle.CertificatePEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: encrypt certificate: %v", ErrMasterKeyUnavailable, err)
	}
	privateKey, err := secrets.EncryptBytes(key, bundle.PrivateKeyPEM)
	if err != nil {
		clear(certificate)
		return nil, nil, fmt.Errorf("%w: encrypt private key: %v", ErrMasterKeyUnavailable, err)
	}
	return certificate, privateKey, nil
}

// Open decrypts a storage envelope.  It is intentionally not part of any
// public/API view; only authenticated edge distribution code should call it.
func Open(ctx context.Context, source MasterKeySource, reference string, ciphertext []byte) (CertificateBundle, error) {
	key, err := resolveKey(ctx, source, reference)
	if err != nil {
		return CertificateBundle{}, err
	}
	defer clear(key)
	plaintext, err := secrets.DecryptBytes(key, ciphertext)
	if err != nil {
		return CertificateBundle{}, fmt.Errorf("%w: decrypt certificate envelope", ErrMasterKeyUnavailable)
	}
	defer clear(plaintext)
	var envelope bundleEnvelope
	if err := json.Unmarshal(plaintext, &envelope); err != nil {
		return CertificateBundle{}, fmt.Errorf("%w: invalid certificate envelope", ErrInvalid)
	}
	defer clear(envelope.CertificatePEM)
	defer clear(envelope.PrivateKeyPEM)
	return CertificateBundle{CertificatePEM: append([]byte(nil), envelope.CertificatePEM...), PrivateKeyPEM: append([]byte(nil), envelope.PrivateKeyPEM...), Issuer: envelope.Issuer}, nil
}

func OpenParts(ctx context.Context, source MasterKeySource, reference string, certificateCiphertext, privateKeyCiphertext []byte) (CertificateBundle, error) {
	key, err := resolveKey(ctx, source, reference)
	if err != nil {
		return CertificateBundle{}, err
	}
	defer clear(key)
	certificate, err := secrets.DecryptBytes(key, certificateCiphertext)
	if err != nil {
		return CertificateBundle{}, fmt.Errorf("%w: certificate envelope", ErrMasterKeyUnavailable)
	}
	defer clear(certificate)
	privateKey, err := secrets.DecryptBytes(key, privateKeyCiphertext)
	if err != nil {
		return CertificateBundle{}, fmt.Errorf("%w: private-key envelope", ErrMasterKeyUnavailable)
	}
	defer clear(privateKey)
	return CertificateBundle{CertificatePEM: append([]byte(nil), certificate...), PrivateKeyPEM: append([]byte(nil), privateKey...)}, nil
}

// ReferenceKeySource is a small process-local implementation useful for tests
// and for deployments backed by an already-resolved secret manager.  Its map
// stores only in-memory key material and has no JSON/string projection.
type ReferenceKeySource struct {
	Keys map[string][]byte
}

func (s ReferenceKeySource) Resolve(_ context.Context, reference string) ([]byte, error) {
	if s.Keys == nil {
		return nil, errors.New("key reference not found")
	}
	key, ok := s.Keys[reference]
	if !ok {
		return nil, errors.New("key reference not found")
	}
	return append([]byte(nil), key...), nil
}
