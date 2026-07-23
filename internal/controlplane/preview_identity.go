package controlplane

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

var (
	ErrPreviewIdentityInvalid = errors.New("preview identity is invalid")
	ErrPreviewKeyInvalid      = errors.New("preview identity key is invalid")
	ErrPreviewDomainInvalid   = errors.New("preview base domain is invalid")
)

const (
	previewKeyPrefix = "p-"
	previewKeyLength = 26
	previewMaxName   = 128
)

// PreviewIdentity derives the stable public key for an environment and logical
// preview name. Counter zero is the first allocation; a positive counter is
// used only after the database detects a key collision.
func PreviewIdentity(key []byte, environmentID, logicalName string, counter uint64) (string, error) {
	if len(key) < 32 {
		return "", ErrPreviewKeyInvalid
	}
	if environmentID == "" || logicalName == "" || len(logicalName) > previewMaxName || strings.IndexByte(environmentID, 0) >= 0 || strings.IndexByte(logicalName, 0) >= 0 {
		return "", ErrPreviewIdentityInvalid
	}
	message := make([]byte, 0, len(environmentID)+1+len(logicalName)+9)
	message = append(message, environmentID...)
	message = append(message, 0)
	message = append(message, logicalName...)
	if counter > 0 {
		message = append(message, 0)
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], counter)
		message = append(message, encoded[:]...)
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(message)
	// 130 bits are exactly 26 base32 characters. Truncating the encoded
	// digest (rather than the raw bytes) preserves the contract's bit width.
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil))
	return previewKeyPrefix + strings.ToLower(encoded[:previewKeyLength]), nil
}

func PreviewHostname(baseDomain, previewKey string) (string, error) {
	baseDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(baseDomain), "."))
	if !validRouteHost(baseDomain) || net.ParseIP(baseDomain) != nil {
		return "", ErrPreviewDomainInvalid
	}
	if len(previewKey) != len(previewKeyPrefix)+previewKeyLength || !strings.HasPrefix(previewKey, previewKeyPrefix) {
		return "", ErrPreviewIdentityInvalid
	}
	for _, r := range previewKey[len(previewKeyPrefix):] {
		if !(r >= 'a' && r <= 'z' || r >= '2' && r <= '7') {
			return "", ErrPreviewIdentityInvalid
		}
	}
	host := previewKey + "." + baseDomain
	if len(host) > 253 {
		return "", fmt.Errorf("%w: hostname too long", ErrPreviewDomainInvalid)
	}
	return host, nil
}
