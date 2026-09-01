package tunnelcert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDistributionHubBindsPullToAuthenticatedNode(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	hub, err := NewDistributionHub(DistributionHubConfig{
		Credential: []byte("distribution-credential-012345678901234567890123456789"),
		Now:        func() time.Time { return now },
		Identity: DistributionNodeIdentityResolverFunc(func(_ context.Context, request *http.Request) (DistributionNodeIdentity, error) {
			return DistributionNodeIdentity{NodeID: request.Header.Get("X-Paperboat-Edge-Node-ID"), ProcessEpoch: request.Header.Get("X-Paperboat-Edge-Process-Epoch")}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := DistributionRequest{Certificate: StoredCertificate{
		ID: "certificate_01", AccountID: "account_01", TunnelID: "tunnel_01", DomainID: "domain_01", Hostname: "preview.example.test",
		DomainGeneration: 1, CertificateGeneration: 1, Fingerprint: [32]byte{1}, Issuer: "test", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(24 * time.Hour),
	}, Target: DistributionTarget{NodeID: "edge_01", ProcessEpoch: "epoch_0001", Generation: 1}}
	if _, err := hub.enqueue(context.Background(), "stage", request); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub.Handler())
	defer server.Close()

	pull := func(node, epoch string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(distributionPull{EdgeNodeID: node, EdgeProcessEpoch: epoch, Limit: 1})
		req := httptest.NewRequest(http.MethodPost, CertificateDistributionPullPath, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer distribution-credential-012345678901234567890123456789")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Paperboat-Edge-Node-ID", node)
		req.Header.Set("X-Paperboat-Edge-Process-Epoch", epoch)
		recorder := httptest.NewRecorder()
		hub.Handler().ServeHTTP(recorder, req)
		return recorder
	}

	crossNodeBody, _ := json.Marshal(distributionPull{EdgeNodeID: "edge_02", EdgeProcessEpoch: "epoch_0002", Limit: 1})
	crossNode := httptest.NewRequest(http.MethodPost, server.URL+CertificateDistributionPullPath, bytes.NewReader(crossNodeBody))
	crossNode.Header.Set("Authorization", "Bearer distribution-credential-012345678901234567890123456789")
	crossNode.Header.Set("Content-Type", "application/json")
	crossNode.Header.Set("X-Paperboat-Edge-Node-ID", "edge_01")
	crossNode.Header.Set("X-Paperboat-Edge-Process-Epoch", "epoch_0001")
	crossResponse := httptest.NewRecorder()
	hub.Handler().ServeHTTP(crossResponse, crossNode)
	if crossResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-node pull status = %d, want %d", crossResponse.Code, http.StatusForbidden)
	}

	response := pull("edge_01", "epoch_0001")
	if response.Code != http.StatusOK {
		t.Fatalf("bound pull status = %d", response.Code)
	}
	var document struct {
		Complete bool                  `json:"complete"`
		Messages []DistributionMessage `json:"messages"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if !document.Complete || len(document.Messages) != 1 {
		t.Fatalf("pull document = %+v", document)
	}
}

func TestDistributionHubRequestsExactLeafThroughAuthenticatedNode(t *testing.T) {
	credential := "distribution-credential-012345678901234567890123456789"
	var got DistributionNodeIdentity
	var gotHostname string
	hub, err := NewDistributionHub(DistributionHubConfig{
		Credential: []byte(credential),
		Identity: DistributionNodeIdentityResolverFunc(func(_ context.Context, request *http.Request) (DistributionNodeIdentity, error) {
			return DistributionNodeIdentity{NodeID: request.Header.Get("X-Paperboat-Edge-Node-ID"), ProcessEpoch: request.Header.Get("X-Paperboat-Edge-Process-Epoch")}, nil
		}),
		OnDemand: func(_ context.Context, identity DistributionNodeIdentity, hostname string) error {
			got = identity
			gotHostname = hostname
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(distributionRequest{Hostname: "leaf.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, CertificateDistributionRequestPath, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Paperboat-Edge-Node-ID", "edge_01")
	request.Header.Set("X-Paperboat-Edge-Process-Epoch", "epoch_0001")
	response := httptest.NewRecorder()
	hub.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("request status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if got != (DistributionNodeIdentity{NodeID: "edge_01", ProcessEpoch: "epoch_0001"}) || gotHostname != "leaf.example.test" {
		t.Fatalf("request callback = identity=%+v hostname=%q", got, gotHostname)
	}

	uppercaseBody, _ := json.Marshal(distributionRequest{Hostname: "Leaf.Example.Test"})
	uppercaseRequest := httptest.NewRequest(http.MethodPost, CertificateDistributionRequestPath, bytes.NewReader(uppercaseBody))
	uppercaseRequest.Header.Set("Authorization", "Bearer "+credential)
	uppercaseRequest.Header.Set("Content-Type", "application/json")
	uppercaseRequest.Header.Set("X-Paperboat-Edge-Node-ID", "edge_01")
	uppercaseRequest.Header.Set("X-Paperboat-Edge-Process-Epoch", "epoch_0001")
	uppercaseResponse := httptest.NewRecorder()
	hub.Handler().ServeHTTP(uppercaseResponse, uppercaseRequest)
	if uppercaseResponse.Code != http.StatusBadRequest {
		t.Fatalf("non-canonical request status = %d, want %d", uppercaseResponse.Code, http.StatusBadRequest)
	}
}

func TestDistributionMessageTTLIsIndependentFromCertificateExpiry(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	hub, err := NewDistributionHub(DistributionHubConfig{
		Credential: []byte("distribution-credential-012345678901234567890123456789"),
		Now:        func() time.Time { return now },
		Identity: DistributionNodeIdentityResolverFunc(func(_ context.Context, _ *http.Request) (DistributionNodeIdentity, error) {
			return DistributionNodeIdentity{NodeID: "edge_01", ProcessEpoch: "epoch_0001"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	certificateExpiry := now.Add(90 * 24 * time.Hour)
	request := DistributionRequest{Certificate: StoredCertificate{
		ID: "certificate_01", AccountID: "account_01", TunnelID: "tunnel_01", DomainID: "domain_01", Hostname: "preview.example.test",
		DomainGeneration: 1, CertificateGeneration: 1, Fingerprint: [32]byte{1}, Issuer: "test", NotBefore: now.Add(-time.Minute), ExpiresAt: certificateExpiry,
	}, Target: DistributionTarget{NodeID: "edge_01", ProcessEpoch: "epoch_0001", Generation: 1}}
	if _, err := hub.enqueue(context.Background(), "stage", request); err != nil {
		t.Fatal(err)
	}
	message, err := hub.enqueue(context.Background(), "activate", DistributionRequest{Certificate: StoredCertificate{
		ID: "certificate_01", AccountID: "account_01", TunnelID: "tunnel_01", DomainID: "domain_01", Hostname: "preview.example.test",
		DomainGeneration: 1, CertificateGeneration: 1, Fingerprint: [32]byte{1}, Issuer: "test", NotBefore: now.Add(-time.Minute), ExpiresAt: certificateExpiry,
	}, Target: DistributionTarget{NodeID: "edge_01", ProcessEpoch: "epoch_0001", Generation: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if got := message.ExpiresAt.Sub(now); got != maxDistributionLifetime {
		t.Fatalf("transport TTL = %s, want %s", got, maxDistributionLifetime)
	}
	if !message.CertificateExpiresAt.Equal(certificateExpiry) {
		t.Fatalf("certificate expiry = %s, want %s", message.CertificateExpiresAt, certificateExpiry)
	}

	now = now.Add(maxDistributionLifetime + time.Second)
	if err := hub.waitStatus(context.Background(), distributionKey("activate", DistributionRequest{Certificate: StoredCertificate{
		ID: "certificate_01", AccountID: "account_01", TunnelID: "tunnel_01", DomainID: "domain_01", Hostname: "preview.example.test",
		DomainGeneration: 1, CertificateGeneration: 1, Fingerprint: [32]byte{1},
	}, Target: DistributionTarget{NodeID: "edge_01", ProcessEpoch: "epoch_0001", Generation: 1}}), "active"); err == nil {
		t.Fatal("expired transport message remained waitable")
	}
}

func TestDistributionHubExpiresWipesAndReclaimsPendingCapacity(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	hub, err := NewDistributionHub(DistributionHubConfig{
		Credential:     []byte("distribution-credential-012345678901234567890123456789"),
		MaximumPending: 1,
		Now:            func() time.Time { return now },
		Identity: DistributionNodeIdentityResolverFunc(func(context.Context, *http.Request) (DistributionNodeIdentity, error) {
			return DistributionNodeIdentity{NodeID: "edge_01", ProcessEpoch: "epoch_0001"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := DistributionRequest{Certificate: StoredCertificate{
		ID: "certificate_01", AccountID: "account_01", TunnelID: "tunnel_01", DomainID: "domain_01", Hostname: "preview.example.test",
		DomainGeneration: 1, CertificateGeneration: 1, Fingerprint: [32]byte{1}, Issuer: "test", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}, Bundle: CertificateBundle{CertificatePEM: []byte("certificate-secret"), PrivateKeyPEM: []byte("private-key-secret")}, Target: DistributionTarget{NodeID: "edge_01", ProcessEpoch: "epoch_0001", Generation: 1}}
	if _, err := hub.enqueue(context.Background(), "stage", request); err != nil {
		t.Fatal(err)
	}
	key := distributionKey("stage", request)
	hub.mu.Lock()
	entry := hub.pending[key]
	certificatePEM := entry.message.CertificatePEM
	privateKeyPEM := entry.message.PrivateKeyPEM
	hub.mu.Unlock()
	now = now.Add(maxDistributionLifetime + time.Second)
	replacement := request
	replacement.Certificate.ID = "certificate_02"
	replacement.Bundle.CertificatePEM = []byte("replacement-certificate")
	replacement.Bundle.PrivateKeyPEM = []byte("replacement-private-key")
	if _, err := hub.enqueue(context.Background(), "stage", replacement); err != nil {
		t.Fatalf("expired pending capacity was not reclaimed: %v", err)
	}
	if len(certificatePEM) == 0 || len(privateKeyPEM) == 0 || !allZeroBytes(certificatePEM) || !allZeroBytes(privateKeyPEM) {
		t.Fatalf("expired key buffers were not wiped: certificate=%q private=%q", certificatePEM, privateKeyPEM)
	}
}

func TestDistributionHubBoundsAggregatePendingSecretBytes(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	hub, err := NewDistributionHub(DistributionHubConfig{
		Credential:          []byte("distribution-credential-012345678901234567890123456789"),
		MaximumPendingBytes: 32,
		Now:                 func() time.Time { return now },
		Identity: DistributionNodeIdentityResolverFunc(func(context.Context, *http.Request) (DistributionNodeIdentity, error) {
			return DistributionNodeIdentity{NodeID: "edge_01", ProcessEpoch: "epoch_0001"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := DistributionRequest{Certificate: StoredCertificate{
		ID: "certificate_01", AccountID: "account_01", TunnelID: "tunnel_01", DomainID: "domain_01", Hostname: "preview.example.test",
		DomainGeneration: 1, CertificateGeneration: 1, Fingerprint: [32]byte{1}, Issuer: "test", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}, Bundle: CertificateBundle{CertificatePEM: []byte("certificate-secret"), PrivateKeyPEM: []byte("private-key-secret")}, Target: DistributionTarget{NodeID: "edge_01", ProcessEpoch: "epoch_0001", Generation: 1}}
	if _, err := hub.enqueue(context.Background(), "stage", request); !errors.Is(err, ErrDistributionTransportFailed) {
		t.Fatalf("oversized aggregate secret material was accepted: %v", err)
	}
}

func allZeroBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func TestDistributionHubPagesPendingMessagesWithStableCursor(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	hub, err := NewDistributionHub(DistributionHubConfig{
		Credential: []byte("distribution-credential-012345678901234567890123456789"),
		Now:        func() time.Time { return now },
		Identity: DistributionNodeIdentityResolverFunc(func(context.Context, *http.Request) (DistributionNodeIdentity, error) {
			return DistributionNodeIdentity{NodeID: "edge_01", ProcessEpoch: "epoch_0001"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxDistributionMessages+1; index++ {
		request := DistributionRequest{Certificate: StoredCertificate{
			ID: fmt.Sprintf("certificate_%03d", index), AccountID: "account_01", TunnelID: "tunnel_01", DomainID: "domain_01", Hostname: "preview.example.test",
			DomainGeneration: 1, CertificateGeneration: uint64(index + 1), Fingerprint: [32]byte{byte(index + 1)}, Issuer: "test", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		}, Target: DistributionTarget{NodeID: "edge_01", ProcessEpoch: "epoch_0001", Generation: uint64(index + 1)}}
		if _, err := hub.enqueue(context.Background(), "stage", request); err != nil {
			t.Fatalf("enqueue %d: %v", index, err)
		}
	}
	pull := func(cursor string) struct {
		Complete   bool                  `json:"complete"`
		NextCursor string                `json:"next_cursor"`
		Messages   []DistributionMessage `json:"messages"`
	} {
		body, _ := json.Marshal(distributionPull{EdgeNodeID: "edge_01", EdgeProcessEpoch: "epoch_0001", Limit: maxDistributionMessages, Cursor: cursor})
		req := httptest.NewRequest(http.MethodPost, CertificateDistributionPullPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Paperboat-Edge-Node-ID", "edge_01")
		req.Header.Set("X-Paperboat-Edge-Process-Epoch", "epoch_0001")
		req = req.WithContext(withDistributionNodeIdentity(context.Background(), DistributionNodeIdentity{NodeID: "edge_01", ProcessEpoch: "epoch_0001"}))
		recorder := httptest.NewRecorder()
		hub.handlePull(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("pull status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var result struct {
			Complete   bool                  `json:"complete"`
			NextCursor string                `json:"next_cursor"`
			Messages   []DistributionMessage `json:"messages"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := pull("")
	if first.Complete || len(first.Messages) != maxDistributionMessages || first.NextCursor == "" {
		t.Fatalf("first page = complete=%v messages=%d cursor=%q", first.Complete, len(first.Messages), first.NextCursor)
	}
	second := pull(first.NextCursor)
	if !second.Complete || len(second.Messages) != 1 || second.NextCursor != "" {
		t.Fatalf("second page = complete=%v messages=%d cursor=%q", second.Complete, len(second.Messages), second.NextCursor)
	}
}

func TestDistributionHubRejectsActionsWithoutExactStageAndCloseWakesWaiters(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	hub, err := NewDistributionHub(DistributionHubConfig{
		Credential: []byte("distribution-credential-012345678901234567890123456789"),
		Now:        func() time.Time { return now },
		Identity: DistributionNodeIdentityResolverFunc(func(context.Context, *http.Request) (DistributionNodeIdentity, error) {
			return DistributionNodeIdentity{NodeID: "edge_01", ProcessEpoch: "epoch_0001"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := DistributionRequest{Certificate: StoredCertificate{
		ID: "certificate_01", AccountID: "account_01", TunnelID: "tunnel_01", DomainID: "domain_01", Hostname: "preview.example.test",
		DomainGeneration: 1, CertificateGeneration: 1, Fingerprint: [32]byte{1}, Issuer: "test", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}, Target: DistributionTarget{NodeID: "edge_01", ProcessEpoch: "epoch_0001", Generation: 1}}
	if _, err := hub.enqueue(context.Background(), "activate", request); !errors.Is(err, ErrDistributionTransportStale) {
		t.Fatalf("unstaged action error = %v", err)
	}
	if _, err := hub.enqueue(context.Background(), "stage", request); err != nil {
		t.Fatal(err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- hub.wait(context.Background(), distributionKey("stage", request)) }()
	if err := hub.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waitErr:
		if !errors.Is(err, ErrDistributionTransportStale) {
			t.Fatalf("closed wait error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake distribution waiter")
	}
	if _, err := hub.enqueue(context.Background(), "stage", request); !errors.Is(err, ErrDistributionTransportInvalid) {
		t.Fatalf("closed enqueue error = %v", err)
	}
}

func TestDistributionHubRequiresAuthenticatedNodeResolver(t *testing.T) {
	if _, err := NewDistributionHub(DistributionHubConfig{Credential: []byte("distribution-credential-012345678901234567890123456789")}); err == nil {
		t.Fatal("hub accepted body-only node identity")
	}
}

func TestDistributionHubCloseWipesOwnedCredential(t *testing.T) {
	credential := []byte("distribution-credential-012345678901234567890123456789")
	hub, err := NewDistributionHub(DistributionHubConfig{
		Credential: credential,
		Identity: DistributionNodeIdentityResolverFunc(func(context.Context, *http.Request) (DistributionNodeIdentity, error) {
			return DistributionNodeIdentity{NodeID: "edge_01", ProcessEpoch: "epoch_0001"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	owned := hub.credential
	if len(owned) == 0 || &owned[0] == &credential[0] {
		t.Fatal("hub did not take an owned credential copy")
	}
	if err := hub.Close(); err != nil {
		t.Fatal(err)
	}
	if len(owned) == 0 || !allZeroBytes(owned) || hub.credential != nil {
		t.Fatalf("hub credential was not wiped: %q", owned)
	}
	if !bytes.Equal(credential, []byte("distribution-credential-012345678901234567890123456789")) {
		t.Fatal("closing hub modified caller credential")
	}
}
