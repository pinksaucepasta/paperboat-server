package tunnelcert

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

const defaultCertificateSecretEnvPrefix = "PAPERBOAT_CERT_SECRET_"

// EnvironmentReferenceSource is a reference-only adapter for deployments
// whose secret manager injects values into the server process environment.
// Configuration contains only the reference. The resolved bytes are bounded,
// returned to the caller, and never included in an error or projection.
// Operators should prefer a native secret-manager implementation in hosted
// deployments; this adapter keeps the production constructor testable and
// does not persist values.
type EnvironmentReferenceSource struct {
	Prefix    string
	LookupEnv func(string) (string, bool)
}

// EnvironmentReferenceName returns the deterministic environment name for a
// reference. A short digest suffix prevents punctuation-normalization
// collisions between otherwise distinct references.
func EnvironmentReferenceName(prefix, reference string) (string, error) {
	if !validKeyReference(reference) {
		return "", ErrMasterKeyUnavailable
	}
	if strings.TrimSpace(prefix) == "" {
		prefix = defaultCertificateSecretEnvPrefix
	}
	if strings.TrimSpace(prefix) != prefix || strings.ContainsAny(prefix, "\r\n\x00") {
		return "", ErrMasterKeyUnavailable
	}
	var normalized strings.Builder
	for _, value := range strings.ToUpper(reference) {
		if value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' {
			normalized.WriteRune(value)
		} else {
			normalized.WriteByte('_')
		}
	}
	digest := sha256.Sum256([]byte(reference))
	return prefix + normalized.String() + "_" + hex.EncodeToString(digest[:6]), nil
}

func (s EnvironmentReferenceSource) Resolve(ctx context.Context, reference string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, err := EnvironmentReferenceName(s.Prefix, reference)
	if err != nil {
		return nil, err
	}
	lookup := s.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	value, ok := lookup(name)
	if !ok || value == "" || len(value) > 1<<20 || strings.ContainsRune(value, '\x00') {
		return nil, errors.New("reference value unavailable")
	}
	return []byte(value), nil
}

// EnvironmentSignerSource resolves an ACME account signer from a PEM value
// injected under a reference. The PEM buffer is wiped after parsing.
type EnvironmentSignerSource struct {
	EnvironmentReferenceSource
}

func (s EnvironmentSignerSource) ResolveSigner(ctx context.Context, reference string) (crypto.Signer, error) {
	value, err := s.Resolve(ctx, reference)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, ErrMasterKeyUnavailable
	}
	defer clearBytes(value)
	key, err := parsePrivateKey(value)
	if err != nil {
		return nil, ErrMasterKeyUnavailable
	}
	signer, ok := key.(crypto.Signer)
	if !ok || !supportedAccountKey(signer) {
		return nil, ErrMasterKeyUnavailable
	}
	return signer, nil
}

var _ MasterKeySource = EnvironmentReferenceSource{}
var _ DNSSecretSource = EnvironmentReferenceSource{}
var _ SignerReferenceSource = EnvironmentSignerSource{}
