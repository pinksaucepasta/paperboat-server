package tunnelcert

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// Validate checks the complete server-to-edge binding before any transport
// call. The edge target is not just a node name: process and assignment
// generations are part of the fence, and the in-memory bundle must match the
// encrypted certificate metadata selected from durable storage.
func (r DistributionRequest) Validate() error {
	if err := r.Certificate.validateDistributionMetadata(); err != nil {
		return err
	}
	if err := r.Target.Validate(); err != nil {
		return err
	}
	identity, err := r.Bundle.Validate(r.Certificate.Hostname, time.Now().UTC(), 0)
	if err != nil {
		return err
	}
	if identity.Fingerprint != r.Certificate.Fingerprint || identity.Hostname != r.Certificate.Hostname || identity.Issuer != r.Certificate.Issuer {
		return fmt.Errorf("%w: certificate bundle metadata does not match durable record", ErrGenerationConflict)
	}
	if !r.Certificate.NotBefore.IsZero() && !identity.NotBefore.Equal(r.Certificate.NotBefore) || !r.Certificate.ExpiresAt.IsZero() && !identity.NotAfter.Equal(r.Certificate.ExpiresAt) {
		return fmt.Errorf("%w: certificate timestamps do not match durable record", ErrGenerationConflict)
	}
	return nil
}

func (target DistributionTarget) Validate() error {
	if !validIdentifier(target.NodeID) || !validEpoch(target.ProcessEpoch) || target.Generation == 0 {
		return fmt.Errorf("%w: edge target binding is invalid", ErrInvalid)
	}
	return nil
}

func (s StoredCertificate) validateDistributionMetadata() error {
	if !validIdentifier(s.ID) || !validMetadata(s.Hostname, 253) || !validKeyReference(s.MasterKeyReference) || !validMetadata(s.CertificateReference, 256) || s.DomainGeneration == 0 || s.CertificateGeneration == 0 || s.Fingerprint == [sha256.Size]byte{} {
		return fmt.Errorf("%w: certificate metadata is invalid", ErrInvalid)
	}
	if err := s.Target().Validate(); err != nil {
		return err
	}
	if _, _, err := normalizeHostname(s.Hostname); err != nil {
		return err
	}
	switch s.State {
	case StateStaged, StateActive, StateSuperseded:
	default:
		return fmt.Errorf("%w: certificate state cannot be distributed", ErrCertificateRevoked)
	}
	return nil
}

func distributionError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrInvalid) || errors.Is(err, ErrGenerationConflict) || errors.Is(err, ErrCertificateInvalid) || errors.Is(err, ErrCertificateRevoked) {
		return err
	}
	return fmt.Errorf("%w: distribution request rejected", ErrDistributionUnavailable)
}
