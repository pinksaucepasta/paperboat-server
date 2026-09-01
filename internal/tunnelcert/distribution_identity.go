package tunnelcert

// This file authenticates the edge process that is allowed to pull and
// acknowledge certificate bundles. The shared edge-control bearer is only an
// outer transport credential: it must not be sufficient to select another
// node's pending key material.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	distributionProofTimestampHeader = "X-Paperboat-Edge-Proof-Issued-At"
	distributionProofNonceHeader     = "X-Paperboat-Edge-Proof-Nonce"
	distributionProofSignatureHeader = "X-Paperboat-Edge-Proof"
	distributionProofNonceBytes      = 24
	distributionProofMaxAge          = 2 * time.Minute
	distributionProofFutureSkew      = 30 * time.Second
	// A process-local replay ledger is deliberately bounded. If all entries are
	// still live, fail closed until their proof windows expire instead of
	// evicting a valid nonce and reopening replay.
	maxDistributionProofReplayEntries = 8192
)

var ErrDistributionIdentityInvalid = errors.New("invalid certificate distribution node proof")

// DistributionNodePublicKeyLookup resolves the public key for the currently
// registered process epoch. Implementations must not select a key from the
// request body alone.
type DistributionNodePublicKeyLookup interface {
	LookupDistributionNodePublicKey(context.Context, string, string) (ed25519.PublicKey, error)
}

type DistributionNodePublicKeyLookupFunc func(context.Context, string, string) (ed25519.PublicKey, error)

func (f DistributionNodePublicKeyLookupFunc) LookupDistributionNodePublicKey(ctx context.Context, nodeID, processEpoch string) (ed25519.PublicKey, error) {
	return f(ctx, nodeID, processEpoch)
}

// SignedDistributionNodeIdentityResolver verifies the exact HTTP method,
// path, raw body digest, node, process epoch, timestamp, and single-use nonce.
// The request body is restored after verification so the distribution
// decoder sees the exact bytes that were signed.
type SignedDistributionNodeIdentityResolver struct {
	lookup DistributionNodePublicKeyLookup
	now    func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

func NewSignedDistributionNodeIdentityResolver(lookup DistributionNodePublicKeyLookup, now func() time.Time) (*SignedDistributionNodeIdentityResolver, error) {
	if lookup == nil {
		return nil, ErrDistributionIdentityInvalid
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &SignedDistributionNodeIdentityResolver{lookup: lookup, now: now, seen: make(map[string]time.Time)}, nil
}

func (r *SignedDistributionNodeIdentityResolver) ResolveDistributionNode(ctx context.Context, request *http.Request) (DistributionNodeIdentity, error) {
	if r == nil || request == nil || ctx == nil || request.Method != http.MethodPost || request.Body == nil {
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	if request.URL == nil || request.URL.RawQuery != "" || request.URL.Fragment != "" || request.URL.Path != CertificateDistributionPullPath && request.URL.Path != CertificateDistributionAckPath && request.URL.Path != CertificateDistributionRequestPath {
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	nodeID := strings.TrimSpace(request.Header.Get("X-Paperboat-Edge-Node-ID"))
	processEpoch := strings.TrimSpace(request.Header.Get("X-Paperboat-Edge-Process-Epoch"))
	if !validDistributionIdentity(nodeID, processEpoch) {
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, request.Header.Get(distributionProofTimestampHeader))
	if err != nil {
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	nonce := request.Header.Get(distributionProofNonceHeader)
	nonceBytes, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(nonceBytes) != distributionProofNonceBytes {
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	signatureValue := request.Header.Get(distributionProofSignatureHeader)
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signatureValue)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	now := r.now().UTC()
	if now.IsZero() || issuedAt.IsZero() || issuedAt.After(now.Add(distributionProofFutureSkew)) || now.Sub(issuedAt) > distributionProofMaxAge {
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxDistributionBody+1))
	if err != nil || len(body) == 0 || len(body) > maxDistributionBody {
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	_ = request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(body))
	key, err := r.lookup.LookupDistributionNodePublicKey(ctx, nodeID, processEpoch)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	digest := sha256.Sum256(body)
	transcript := distributionIdentityTranscript(request.Method, request.URL.Path, nodeID, processEpoch, issuedAt, nonce, hex.EncodeToString(digest[:]))
	if !ed25519.Verify(key, []byte(transcript), signature) {
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	// Only a successfully verified proof consumes its nonce. Purge old entries
	// while holding the same lock so concurrent replays cannot both pass.
	seenKey := nodeID + "\x00" + processEpoch + "\x00" + nonce
	r.mu.Lock()
	for key, expiry := range r.seen {
		if !expiry.After(now) {
			delete(r.seen, key)
		}
	}
	_, replayed := r.seen[seenKey]
	if !replayed && len(r.seen) >= maxDistributionProofReplayEntries {
		r.mu.Unlock()
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	if !replayed {
		r.seen[seenKey] = issuedAt.Add(distributionProofMaxAge)
	}
	r.mu.Unlock()
	if replayed {
		return DistributionNodeIdentity{}, ErrDistributionIdentityInvalid
	}
	return DistributionNodeIdentity{NodeID: nodeID, ProcessEpoch: processEpoch}, nil
}

func distributionIdentityTranscript(method, path, nodeID, processEpoch string, issuedAt time.Time, nonce, bodyDigest string) string {
	return strings.Join([]string{
		"paperboat-edge-distribution-proof-v1",
		method,
		path,
		nodeID,
		processEpoch,
		issuedAt.UTC().Format(time.RFC3339Nano),
		nonce,
		bodyDigest,
	}, "\n")
}
