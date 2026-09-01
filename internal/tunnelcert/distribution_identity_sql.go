package tunnelcert

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

const distributionNodeFreshness = 2 * time.Minute

// SQLDistributionNodePublicKeyLookup binds a proof to the currently
// registered carrier process. It accepts registered-but-not-ready nodes so a
// cold edge can receive its initial certificate before Caddy reports ready;
// stale/offline/replaced processes are rejected.
type SQLDistributionNodePublicKeyLookup struct {
	db  *db.DB
	now func() time.Time
}

func NewSQLDistributionNodePublicKeyLookup(database *db.DB, now func() time.Time) (*SQLDistributionNodePublicKeyLookup, error) {
	if database == nil || database.SQL() == nil {
		return nil, ErrDistributionIdentityInvalid
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &SQLDistributionNodePublicKeyLookup{db: database, now: now}, nil
}

func (l *SQLDistributionNodePublicKeyLookup) LookupDistributionNodePublicKey(ctx context.Context, nodeID, processEpoch string) (ed25519.PublicKey, error) {
	if l == nil || l.db == nil || ctx == nil || !validDistributionIdentity(nodeID, processEpoch) {
		return nil, ErrDistributionIdentityInvalid
	}
	row, err := l.db.Queries().GetDistributionNodeIdentityV1(ctx, nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDistributionIdentityInvalid
	}
	if err != nil || row.ProcessEpoch != processEpoch || row.State != "registered" && row.State != "ready" || row.State == "ready" && !row.Ready || !row.LastHeartbeatAt.Valid || !row.LastHeartbeatAt.Time.After(l.now().UTC().Add(-distributionNodeFreshness)) || !row.CarrierServerSpkiSha256.Valid || !row.CarrierServerCertificateChainPem.Valid {
		return nil, ErrDistributionIdentityInvalid
	}
	publicKey, err := parseDistributionNodeCertificate(row.CarrierServerCertificateChainPem.String, row.CarrierServerSpkiSha256.String)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func parseDistributionNodeCertificate(chainPEM, expectedSPKI string) (ed25519.PublicKey, error) {
	if len(chainPEM) == 0 || len(chainPEM) > 64<<10 || !strings.HasPrefix(expectedSPKI, "sha256:") || len(expectedSPKI) != len("sha256:")+64 {
		return nil, ErrDistributionIdentityInvalid
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(expectedSPKI, "sha256:"))
	if err != nil || len(expected) != sha256.Size {
		return nil, ErrDistributionIdentityInvalid
	}
	block, rest := pem.Decode([]byte(chainPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, ErrDistributionIdentityInvalid
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrDistributionIdentityInvalid
	}
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrDistributionIdentityInvalid
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, ErrDistributionIdentityInvalid
	}
	digest := sha256.Sum256(spki)
	if !bytesEqual(expected, digest[:]) {
		return nil, fmt.Errorf("%w: carrier public key pin mismatch", ErrDistributionIdentityInvalid)
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
