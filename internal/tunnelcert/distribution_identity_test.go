package tunnelcert

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type distributionTestKeyLookup struct {
	keys map[string]ed25519.PublicKey
}

func (l distributionTestKeyLookup) LookupDistributionNodePublicKey(_ context.Context, nodeID, processEpoch string) (ed25519.PublicKey, error) {
	key := l.keys[nodeID+"\x00"+processEpoch]
	if len(key) == 0 {
		return nil, ErrDistributionIdentityInvalid
	}
	return key, nil
}

func TestSignedDistributionNodeIdentityResolverFencesNodeEpochBodyAndReplay(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	publicOne, privateOne, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicTwo, privateTwo, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lookup := distributionTestKeyLookup{keys: map[string]ed25519.PublicKey{
		"edge_01\x00epoch_0001": publicOne,
		"edge_02\x00epoch_0002": publicTwo,
	}}
	resolver, err := NewSignedDistributionNodeIdentityResolver(lookup, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"edge_node_id":"edge_01","edge_process_epoch":"epoch_0001","limit":1}`)
	issuedAt := now.Add(-time.Second)
	nonce := distributionTestNonce(1)
	request := signedDistributionRequest(t, CertificateDistributionPullPath, "edge_01", "epoch_0001", issuedAt, nonce, body, privateOne)
	identity, err := resolver.ResolveDistributionNode(context.Background(), request)
	if err != nil || identity.NodeID != "edge_01" || identity.ProcessEpoch != "epoch_0001" {
		t.Fatalf("valid identity = %+v, err=%v", identity, err)
	}
	restored, err := ioReadAllAndClose(request.Body)
	if err != nil || !bytes.Equal(restored, body) {
		t.Fatalf("restored body = %q, err=%v", restored, err)
	}
	if _, err := resolver.ResolveDistributionNode(context.Background(), signedDistributionRequest(t, CertificateDistributionPullPath, "edge_01", "epoch_0001", issuedAt, nonce, body, privateOne)); err == nil {
		t.Fatal("replayed proof was accepted")
	}

	wrongBody := []byte(`{"edge_node_id":"edge_01","edge_process_epoch":"epoch_0001","limit":2}`)
	tampered := signedDistributionRequest(t, CertificateDistributionPullPath, "edge_01", "epoch_0001", issuedAt, distributionTestNonce(2), body, privateOne)
	tampered.Body = io.NopCloser(bytes.NewReader(wrongBody))
	if _, err := resolver.ResolveDistributionNode(context.Background(), tampered); err == nil {
		t.Fatal("body-tampered proof was accepted")
	}
	wrongNode := signedDistributionRequest(t, CertificateDistributionPullPath, "edge_02", "epoch_0002", issuedAt, distributionTestNonce(3), body, privateOne)
	if _, err := resolver.ResolveDistributionNode(context.Background(), wrongNode); err == nil {
		t.Fatal("wrong-node proof was accepted")
	}
	wrongEpoch := signedDistributionRequest(t, CertificateDistributionPullPath, "edge_01", "epoch_0002", issuedAt, distributionTestNonce(4), body, privateOne)
	if _, err := resolver.ResolveDistributionNode(context.Background(), wrongEpoch); err == nil {
		t.Fatal("stale or unregistered process epoch was accepted")
	}
	expired := signedDistributionRequest(t, CertificateDistributionPullPath, "edge_02", "epoch_0002", now.Add(-distributionProofMaxAge-time.Second), distributionTestNonce(5), body, privateTwo)
	if _, err := resolver.ResolveDistributionNode(context.Background(), expired); err == nil {
		t.Fatal("expired proof was accepted")
	}
	future := signedDistributionRequest(t, CertificateDistributionPullPath, "edge_02", "epoch_0002", now.Add(distributionProofFutureSkew+time.Second), distributionTestNonce(6), body, privateTwo)
	if _, err := resolver.ResolveDistributionNode(context.Background(), future); err == nil {
		t.Fatal("future proof was accepted")
	}
}

func TestSignedDistributionNodeIdentityResolverConsumesNonceOnceConcurrently(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewSignedDistributionNodeIdentityResolver(distributionTestKeyLookup{keys: map[string]ed25519.PublicKey{"edge_01\x00epoch_0001": publicKey}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"edge_node_id":"edge_01","edge_process_epoch":"epoch_0001","limit":1}`)
	requestBytes := make([]byte, distributionProofNonceBytes)
	for index := range requestBytes {
		requestBytes[index] = byte(index + 7)
	}
	nonce := base64.RawURLEncoding.EncodeToString(requestBytes)
	requests := make([]*http.Request, 16)
	for index := range requests {
		requests[index] = signedDistributionRequest(t, CertificateDistributionAckPath, "edge_01", "epoch_0001", now, nonce, body, privateKey)
	}
	var wait sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for _, request := range requests {
		wait.Add(1)
		go func(request *http.Request) {
			defer wait.Done()
			if _, err := resolver.ResolveDistributionNode(context.Background(), request); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}(request)
	}
	wait.Wait()
	if successes != 1 {
		t.Fatalf("concurrent proof successes = %d, want 1", successes)
	}
}

func TestDistributionHubUsesSignedNodeIdentityNotHeaders(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewSignedDistributionNodeIdentityResolver(distributionTestKeyLookup{keys: map[string]ed25519.PublicKey{"edge_01\x00epoch_0001": publicKey}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	hub, err := NewDistributionHub(DistributionHubConfig{Credential: []byte("distribution-credential-012345678901234567890123456789"), Now: func() time.Time { return now }, Identity: resolver})
	if err != nil {
		t.Fatal(err)
	}
	requestBody := []byte(`{"edge_node_id":"edge_01","edge_process_epoch":"epoch_0001","limit":1}`)
	request := signedDistributionRequest(t, CertificateDistributionPullPath, "edge_01", "epoch_0001", now, distributionTestNonce(11), requestBody, privateKey)
	request.Header.Set("Authorization", "Bearer distribution-credential-012345678901234567890123456789")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Paperboat-Edge-Node-ID", "edge_02")
	request.Header.Set("X-Paperboat-Edge-Process-Epoch", "epoch_0002")
	recorder := httptest.NewRecorder()
	hub.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("header-swapped pull status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func signedDistributionRequest(t *testing.T, path, nodeID, processEpoch string, issuedAt time.Time, nonce string, body []byte, privateKey ed25519.PrivateKey) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	digest := sha256Sum(body)
	signature := ed25519.Sign(privateKey, []byte(distributionIdentityTranscript(http.MethodPost, path, nodeID, processEpoch, issuedAt, nonce, digest)))
	request.Header.Set("X-Paperboat-Edge-Node-ID", nodeID)
	request.Header.Set("X-Paperboat-Edge-Process-Epoch", processEpoch)
	request.Header.Set(distributionProofTimestampHeader, issuedAt.UTC().Format(time.RFC3339Nano))
	request.Header.Set(distributionProofNonceHeader, nonce)
	request.Header.Set(distributionProofSignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func distributionTestNonce(seed byte) string {
	value := make([]byte, distributionProofNonceBytes)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func sha256Sum(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func ioReadAllAndClose(body io.ReadCloser) ([]byte, error) {
	value, err := io.ReadAll(body)
	closeErr := body.Close()
	if err != nil {
		return nil, err
	}
	return value, closeErr
}
