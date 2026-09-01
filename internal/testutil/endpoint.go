// Package testutil contains deterministic values used by database-backed
// tests. Production endpoint allocation remains random and lives in
// tunnelv1.
package testutil

import (
	"crypto/sha256"
	"encoding/hex"
)

// EndpointUUID returns a deterministic RFC-variant UUID suitable for a
// managed tunnel endpoint fixture. A seed keeps concurrent acceptance tests
// isolated without weakening the production allocation path.
func EndpointUUID(seed string) string {
	digest := sha256.Sum256([]byte("paperboat-test-endpoint:" + seed))
	digest[6] = (digest[6] & 0x0f) | 0x40
	digest[8] = (digest[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(digest[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}
