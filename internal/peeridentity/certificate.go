// Package peeridentity validates account-rooted endpoint certificates at the
// server trust boundary.
package peeridentity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"time"
)

const (
	protocolVersion = 1
	maximumInteger  = 9007199254740991
	minimumBytes    = 4 + 1 + 2 + 1 + 1 + 2 + 1 + 32 + 32 + 8*4 + ed25519.SignatureSize
	maximumBytes    = 4 + 1 + 2 + 128 + 1 + 2 + 128 + 32 + 32 + 8*4 + ed25519.SignatureSize
)

var (
	ErrInvalid     = errors.New("endpoint certificate is invalid")
	ErrSignature   = errors.New("endpoint certificate signature is invalid")
	ErrIdentity    = errors.New("endpoint certificate identity does not match")
	ErrNotCurrent  = errors.New("endpoint certificate is not currently valid")
	identifierExpr = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
)

type Role uint8

const (
	RoleCLI Role = iota + 1
	RoleMachine
)

func (r Role) String() string {
	switch r {
	case RoleCLI:
		return "cli"
	case RoleMachine:
		return "machine"
	default:
		return ""
	}
}

type Certificate struct {
	AccountID       string
	KeyID           string
	Role            Role
	EndpointID      string
	NoisePublicKey  [32]byte
	QUICPublicKey   [32]byte
	Generation      uint64
	Serial          uint64
	IssuedAt        time.Time
	ExpiresAt       time.Time
	Fingerprint     [sha256.Size]byte
	RootFingerprint [sha256.Size]byte
	Raw             []byte
}

type Expected struct {
	AccountID  string
	Role       Role
	EndpointID string
	Generation uint64
	Serial     uint64
}

func Verify(raw []byte, rootPublic ed25519.PublicKey, expected Expected, now time.Time) (Certificate, error) {
	if len(rootPublic) != ed25519.PublicKeySize || now.IsZero() {
		return Certificate{}, ErrInvalid
	}
	certificate, payload, signature, err := parse(raw)
	if err != nil {
		return Certificate{}, err
	}
	if !ed25519.Verify(rootPublic, payload, signature) {
		return Certificate{}, ErrSignature
	}
	if expected.AccountID != "" && !constantString(certificate.AccountID, expected.AccountID) ||
		expected.EndpointID != "" && !constantString(certificate.EndpointID, expected.EndpointID) ||
		expected.Role != 0 && certificate.Role != expected.Role ||
		expected.Generation != 0 && certificate.Generation != expected.Generation ||
		expected.Serial != 0 && certificate.Serial != expected.Serial {
		return Certificate{}, ErrIdentity
	}
	now = now.UTC()
	if now.Before(certificate.IssuedAt) || !now.Before(certificate.ExpiresAt) {
		return Certificate{}, ErrNotCurrent
	}
	return certificate, nil
}

func RootFingerprint(rootPublic ed25519.PublicKey) (string, error) {
	if len(rootPublic) != ed25519.PublicKeySize {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(rootPublic)
	return hex.EncodeToString(digest[:]), nil
}

func parse(raw []byte) (Certificate, []byte, []byte, error) {
	if len(raw) < minimumBytes || len(raw) > maximumBytes {
		return Certificate{}, nil, nil, ErrInvalid
	}
	payload := raw[:len(raw)-ed25519.SignatureSize]
	if len(payload) < 5 || string(payload[:4]) != "PBEC" || payload[4] != protocolVersion {
		return Certificate{}, nil, nil, ErrInvalid
	}
	offset := 5
	accountID, err := readString(payload, &offset)
	if err != nil || offset >= len(payload) {
		return Certificate{}, nil, nil, ErrInvalid
	}
	role := Role(payload[offset])
	offset++
	endpointID, err := readString(payload, &offset)
	if err != nil || len(payload)-offset != 32+32+8*4 {
		return Certificate{}, nil, nil, ErrInvalid
	}
	certificate := Certificate{AccountID: accountID, Role: role, EndpointID: endpointID}
	copy(certificate.NoisePublicKey[:], payload[offset:offset+32])
	offset += 32
	copy(certificate.QUICPublicKey[:], payload[offset:offset+32])
	offset += 32
	certificate.Generation = binary.BigEndian.Uint64(payload[offset:])
	offset += 8
	certificate.Serial = binary.BigEndian.Uint64(payload[offset:])
	offset += 8
	issued := int64(binary.BigEndian.Uint64(payload[offset:]))
	offset += 8
	expires := int64(binary.BigEndian.Uint64(payload[offset:]))
	certificate.IssuedAt = time.Unix(issued, 0).UTC()
	certificate.ExpiresAt = time.Unix(expires, 0).UTC()
	if !validCertificate(certificate) {
		return Certificate{}, nil, nil, ErrInvalid
	}
	certificate.Fingerprint = sha256.Sum256(raw)
	certificate.Raw = append([]byte(nil), raw...)
	return certificate, payload, raw[len(payload):], nil
}

func validCertificate(value Certificate) bool {
	if !identifierExpr.MatchString(value.AccountID) || !identifierExpr.MatchString(value.EndpointID) ||
		value.Role.String() == "" || value.Generation == 0 || value.Generation > maximumInteger ||
		value.Serial == 0 || value.Serial > maximumInteger ||
		value.IssuedAt.IsZero() || !value.ExpiresAt.After(value.IssuedAt) {
		return false
	}
	var zero [32]byte
	return subtle.ConstantTimeCompare(value.NoisePublicKey[:], zero[:]) != 1 &&
		subtle.ConstantTimeCompare(value.QUICPublicKey[:], zero[:]) != 1
}

func readString(payload []byte, offset *int) (string, error) {
	if len(payload)-*offset < 2 {
		return "", ErrInvalid
	}
	length := int(binary.BigEndian.Uint16(payload[*offset:]))
	*offset += 2
	if length == 0 || length > 128 || len(payload)-*offset < length {
		return "", ErrInvalid
	}
	value := string(payload[*offset : *offset+length])
	*offset += length
	return value, nil
}

func constantString(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
