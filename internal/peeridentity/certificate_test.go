package peeridentity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestVerifyCanonicalEndpointCertificate(t *testing.T) {
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	raw := signedFixture(t, rootPrivate, "account_01", RoleMachine, "machine_01", 3, 7, now.Add(-time.Minute), now.Add(time.Hour))
	certificate, err := Verify(raw, rootPublic, Expected{AccountID: "account_01", Role: RoleMachine, EndpointID: "machine_01", Generation: 3, Serial: 7}, now)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Fingerprint != sha256.Sum256(raw) || certificate.Role.String() != "machine" || len(certificate.Raw) != len(raw) {
		t.Fatalf("certificate=%+v", certificate)
	}
	raw[10] ^= 1
	if _, err := Verify(raw, rootPublic, Expected{}, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("tamper error=%v", err)
	}
}

func TestVerifyRejectsIdentityValidityAndNonCanonicalBytes(t *testing.T) {
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	raw := signedFixture(t, rootPrivate, "account_01", RoleCLI, "cli_01", 1, 2, now.Add(-time.Minute), now.Add(time.Minute))
	if _, err := Verify(raw, rootPublic, Expected{EndpointID: "other"}, now); !errors.Is(err, ErrIdentity) {
		t.Fatalf("identity error=%v", err)
	}
	if _, err := Verify(raw, rootPublic, Expected{}, now.Add(time.Minute)); !errors.Is(err, ErrNotCurrent) {
		t.Fatalf("expiry error=%v", err)
	}
	for _, invalid := range [][]byte{nil, raw[:len(raw)-1], append(append([]byte(nil), raw...), 0)} {
		if _, err := Verify(invalid, rootPublic, Expected{}, now); err == nil {
			t.Fatalf("accepted invalid certificate length=%d", len(invalid))
		}
	}
}

func signedFixture(t *testing.T, root ed25519.PrivateKey, account string, role Role, endpoint string, generation, serial uint64, issued, expires time.Time) []byte {
	t.Helper()
	noise := [32]byte{1}
	quic := [32]byte{2}
	payload := []byte{'P', 'B', 'E', 'C', 1}
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(account)))
	payload = append(payload, account...)
	payload = append(payload, byte(role))
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(endpoint)))
	payload = append(payload, endpoint...)
	payload = append(payload, noise[:]...)
	payload = append(payload, quic[:]...)
	payload = binary.BigEndian.AppendUint64(payload, generation)
	payload = binary.BigEndian.AppendUint64(payload, serial)
	payload = binary.BigEndian.AppendUint64(payload, uint64(issued.Unix()))
	payload = binary.BigEndian.AppendUint64(payload, uint64(expires.Unix()))
	return append(payload, ed25519.Sign(root, payload)...)
}
