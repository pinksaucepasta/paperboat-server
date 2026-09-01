package tunnelcert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTRK35CertificateReplacementFailuresPreserveOldActiveUntilRetry(t *testing.T) {
	for _, test := range []struct {
		name string
		fail string
		want error
	}{
		{name: "edge stage", fail: "stage", want: ErrDistributionUnavailable},
		{name: "edge readiness", fail: "ready", want: ErrCertificateNotReady},
		{name: "edge activation", fail: "activate", want: ErrDistributionUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
			issuer := &testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}
			coordinator, store, distributor, _ := coordinatorForTest(t, issuer)
			domain := testDomain("app.example.test", StrategyDelegatedDNS01)
			first, err := coordinator.Ensure(context.Background(), domain)
			if err != nil {
				t.Fatal(err)
			}

			coordinator.config.Now = func() time.Time { return now.Add(time.Hour) }
			domain.CertificateReference = first.Certificate.Reference
			domain.RenewalDue = true
			issuer.bundle = testBundle(t, []string{"app.example.test"}, now.Add(time.Hour), 24*time.Hour)
			distributor.FailAt = test.fail
			if _, err := coordinator.Ensure(context.Background(), domain); !errors.Is(err, test.want) {
				t.Fatalf("replacement failure = %v, want %v", err, test.want)
			}
			current, found, err := store.Current(context.Background(), domain.ID)
			if err != nil || !found {
				t.Fatalf("old active lookup = %+v found=%t err=%v", current, found, err)
			}
			if current.ID != first.Certificate.Reference[len("tcert_"):] || current.State != StateActive || current.CertificateGeneration != first.Certificate.CertificateGeneration {
				t.Fatalf("partial replacement changed old active: current=%+v first=%+v", current, first.Certificate)
			}

			// The failed staged row has consumed its generation and binding.
			// Clearing the edge fault must issue a fresh generation rather than
			// reusing that failed row or replacing the old active early.
			distributor.FailAt = ""
			retry, err := coordinator.Ensure(context.Background(), domain)
			if err != nil || !retry.Issued || retry.Certificate.State != StateActive || retry.Certificate.CertificateGeneration != first.Certificate.CertificateGeneration+2 {
				t.Fatalf("replacement retry = %+v err=%v", retry, err)
			}
			current, found, err = store.Current(context.Background(), domain.ID)
			if err != nil || !found || current.ID != retry.Certificate.Reference[len("tcert_"):] || current.State != StateActive {
				t.Fatalf("retried current = %+v found=%t err=%v", current, found, err)
			}
		})
	}
}

type trk35CleanupDistributor struct {
	*MemoryDistributor
	mu          sync.Mutex
	failRetire  bool
	retireCalls int
	pending     map[string]StoredCertificate
}

func newTRK35CleanupDistributor() *trk35CleanupDistributor {
	return &trk35CleanupDistributor{MemoryDistributor: NewMemoryDistributor(), pending: make(map[string]StoredCertificate)}
}

func (d *trk35CleanupDistributor) RetireCertificate(_ context.Context, certificate StoredCertificate) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.retireCalls++
	if d.failRetire {
		d.pending[certificate.ID] = certificate
		return ErrDistributionUnavailable
	}
	delete(d.pending, certificate.ID)
	return nil
}

func (d *trk35CleanupDistributor) ReconcileCertificateDistributionCleanup(ctx context.Context, limit int) (int, error) {
	if limit < 1 {
		return 0, ErrInvalid
	}
	d.mu.Lock()
	ids := make([]string, 0, len(d.pending))
	for id := range d.pending {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	certificates := make([]StoredCertificate, 0, len(ids))
	for _, id := range ids {
		certificates = append(certificates, d.pending[id])
	}
	d.mu.Unlock()

	cleaned := 0
	var joined error
	for _, certificate := range certificates {
		if err := d.RetireCertificate(ctx, certificate); err != nil {
			joined = errors.Join(joined, err)
			continue
		}
		cleaned++
	}
	return cleaned, joined
}

func TestTRK35CertificateCleanupRetriesAfterReplacementAndKeepsNewActive(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}
	coordinator, store, _, _ := coordinatorForTest(t, issuer)
	distributor := newTRK35CleanupDistributor()
	coordinator.config.Distributor = distributor
	domain := testDomain("app.example.test", StrategyDelegatedDNS01)
	first, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}

	coordinator.config.Now = func() time.Time { return now.Add(time.Hour) }
	domain.CertificateReference = first.Certificate.Reference
	domain.RenewalDue = true
	issuer.bundle = testBundle(t, []string{"app.example.test"}, now.Add(time.Hour), 24*time.Hour)
	distributor.failRetire = true
	second, err := coordinator.Ensure(context.Background(), domain)
	if err != nil || !second.Issued || !second.CleanupPending || second.CleanupError == nil {
		t.Fatalf("replacement with cleanup failure = %+v err=%v", second, err)
	}
	current, found, err := store.Current(context.Background(), domain.ID)
	if err != nil || !found || current.ID != second.Certificate.Reference[len("tcert_"):] || current.State != StateActive {
		t.Fatalf("new active was not retained during cleanup retry: %+v found=%t err=%v", current, found, err)
	}
	store.mu.Lock()
	old := store.all[first.Certificate.Reference[len("tcert_"):]]
	store.mu.Unlock()
	if old.State != StateSuperseded {
		t.Fatalf("old certificate state = %q, want superseded while edge cleanup is pending", old.State)
	}

	distributor.failRetire = false
	cleaned, err := coordinator.ReconcileDistributionCleanup(context.Background(), 1)
	if err != nil || cleaned != 1 {
		t.Fatalf("cleanup retry = cleaned %d err %v", cleaned, err)
	}
	distributor.mu.Lock()
	remaining, calls := len(distributor.pending), distributor.retireCalls
	distributor.mu.Unlock()
	if remaining != 0 || calls != 2 {
		t.Fatalf("cleanup retry state = pending %d retire calls %d, want 0 and 2", remaining, calls)
	}
	current, found, err = store.Current(context.Background(), domain.ID)
	if err != nil || !found || current.ID != second.Certificate.Reference[len("tcert_"):] || current.State != StateActive {
		t.Fatalf("cleanup retry changed new active: %+v found=%t err=%v", current, found, err)
	}
}

func TestTRK35CertificateRevocationEdgeFailureLeavesDurableRetryMarker(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &revokingTestIssuer{testIssuer: testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}}
	coordinator, baseStore, distributor, _ := coordinatorForTest(t, &issuer.testIssuer)
	coordinator.config.Issuer = issuer
	result, err := coordinator.Ensure(context.Background(), testDomain("app.example.test", StrategyDelegatedDNS01))
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryRevocationStore{MemoryStore: baseStore}
	coordinator.config.Store = store
	distributor.FailAt = "revoke"
	revoked, err := coordinator.Revoke(context.Background(), "dom_001", "edge-revoke-fault")
	if err == nil || !errors.Is(err, ErrDistributionUnavailable) {
		t.Fatalf("edge revocation failure = %v, want ErrDistributionUnavailable", err)
	}
	if revoked.State != StateRevoked || issuer.revoked != 1 {
		t.Fatalf("revocation result = %+v authority calls=%d", revoked, issuer.revoked)
	}
	if _, found, err := store.Current(context.Background(), "dom_001"); err != nil || found {
		t.Fatalf("revoked certificate remained current: found=%t err=%v", found, err)
	}
	store.mu.Lock()
	persisted := store.all[result.Certificate.Reference[len("tcert_"):]]
	store.mu.Unlock()
	if persisted.State != StateRevoked || persisted.FailureCode != "ca_revocation_pending" {
		t.Fatalf("revocation retry marker = state=%q failure=%q", persisted.State, persisted.FailureCode)
	}
}

func TestTRK35DistributionHubOverloadBoundsPendingAndReplayState(t *testing.T) {
	now := time.Date(2026, 8, 31, 15, 0, 0, 0, time.UTC)
	identity := DistributionNodeIdentity{NodeID: "edge_trk35", ProcessEpoch: "epoch_trk35_001"}
	hub, err := NewDistributionHub(DistributionHubConfig{
		Credential:          []byte("distribution-credential-trk35-012345678901234567890123456789"),
		MaximumPending:      2,
		MaximumPendingBytes: 1024,
		Now:                 func() time.Time { return now },
		Identity: DistributionNodeIdentityResolverFunc(func(context.Context, *http.Request) (DistributionNodeIdentity, error) {
			return identity, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	requests := []DistributionRequest{trk35DistributionRequest(1, now, identity), trk35DistributionRequest(2, now, identity)}
	messages := make([]DistributionMessage, 0, len(requests))
	for _, request := range requests {
		message, err := hub.enqueue(context.Background(), "stage", request)
		if err != nil {
			t.Fatal(err)
		}
		messages = append(messages, message)
	}
	if _, err := hub.enqueue(context.Background(), "stage", trk35DistributionRequest(3, now, identity)); !errors.Is(err, ErrDistributionTransportFailed) {
		t.Fatalf("overload error = %v, want ErrDistributionTransportFailed", err)
	}
	hub.mu.Lock()
	pending, pendingBytes := len(hub.pending), hub.pendingBytes
	hub.mu.Unlock()
	if pending != 2 || pendingBytes <= 0 || pendingBytes > hub.maximumBytes {
		t.Fatalf("overload queue = pending %d bytes %d, want bounded two entries", pending, pendingBytes)
	}

	// A mismatched transcript is rejected without consuming the pending entry,
	// while an exact ACK is idempotent even after the entry moves to replay state.
	wrong := trk35DistributionAck(messages[0])
	wrong.Fingerprint = strings.Repeat("A", len(messages[0].Fingerprint))
	if status := trk35HandleDistributionAck(t, hub, identity, wrong); status != http.StatusConflict {
		t.Fatalf("mismatched ACK status = %d, want %d", status, http.StatusConflict)
	}
	if status := trk35HandleDistributionAck(t, hub, identity, trk35DistributionAck(messages[0])); status != http.StatusNoContent {
		t.Fatalf("first ACK status = %d, want %d", status, http.StatusNoContent)
	}
	if status := trk35HandleDistributionAck(t, hub, identity, trk35DistributionAck(messages[0])); status != http.StatusNoContent {
		t.Fatalf("duplicate ACK status = %d, want %d", status, http.StatusNoContent)
	}
	if status := trk35HandleDistributionAck(t, hub, identity, trk35DistributionAck(messages[1])); status != http.StatusNoContent {
		t.Fatalf("second ACK status = %d, want %d", status, http.StatusNoContent)
	}

	// Refill and drain repeatedly. The pending plaintext budget and replay
	// ledger must stay bounded even when successful completions outnumber the
	// configured pending capacity by an order of magnitude.
	for index := 4; index < 32; index++ {
		request := trk35DistributionRequest(index, now, identity)
		message, err := hub.enqueue(context.Background(), "stage", request)
		if err != nil {
			t.Fatalf("refill %d: %v", index, err)
		}
		if status := trk35HandleDistributionAck(t, hub, identity, trk35DistributionAck(message)); status != http.StatusNoContent {
			t.Fatalf("refill ACK %d status = %d", index, status)
		}
		hub.mu.Lock()
		pending, pendingBytes, results := len(hub.pending), hub.pendingBytes, len(hub.results)
		hub.mu.Unlock()
		if pending > hub.maximum || pendingBytes > hub.maximumBytes || results > hub.maximum*2 {
			t.Fatalf("bounded queue exceeded at %d: pending=%d bytes=%d results=%d", index, pending, pendingBytes, results)
		}
	}
	hub.mu.Lock()
	pending, pendingBytes, results := len(hub.pending), hub.pendingBytes, len(hub.results)
	hub.mu.Unlock()
	if pending != 0 || pendingBytes != 0 || results > hub.maximum*2 {
		t.Fatalf("final bounded queue = pending %d bytes %d results %d", pending, pendingBytes, results)
	}
}

func trk35DistributionRequest(index int, now time.Time, identity DistributionNodeIdentity) DistributionRequest {
	return DistributionRequest{
		Certificate: StoredCertificate{
			ID: fmt.Sprintf("certificate_trk35_%03d", index), AccountID: "account_trk35", TunnelID: "tunnel_trk35", DomainID: "domain_trk35", Hostname: "preview.example.test",
			DomainGeneration: 1, CertificateGeneration: uint64(index), Fingerprint: [32]byte{byte(index)}, Issuer: "test", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		},
		Bundle: CertificateBundle{CertificatePEM: []byte("certificate-secret"), PrivateKeyPEM: []byte("private-key-secret")},
		Target: DistributionTarget{NodeID: identity.NodeID, ProcessEpoch: identity.ProcessEpoch, Generation: uint64(index)},
	}
}

func trk35DistributionAck(message DistributionMessage) distributionAck {
	return distributionAck{
		Version: message.Version, Action: message.Action, CertificateID: message.CertificateID,
		AccountID: message.AccountID, TunnelID: message.TunnelID, DomainID: message.DomainID,
		TargetKind: message.TargetKind, RouteID: message.RouteID, PreviewID: message.PreviewID,
		PreviewGeneration: message.PreviewGeneration, PreviewState: message.PreviewState, PreviewExpiresAt: message.PreviewExpiresAt,
		Hostname: message.Hostname, DomainGeneration: message.DomainGeneration, CertificateGeneration: message.CertificateGeneration,
		EdgeNodeID: message.EdgeNodeID, EdgeProcessEpoch: message.EdgeProcessEpoch, AssignmentGeneration: message.AssignmentGeneration,
		Fingerprint: message.Fingerprint, Status: "ready",
	}
}

func trk35HandleDistributionAck(t *testing.T, hub *DistributionHub, identity DistributionNodeIdentity, ack distributionAck) int {
	t.Helper()
	body, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, CertificateDistributionAckPath, strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(withDistributionNodeIdentity(context.Background(), identity))
	recorder := httptest.NewRecorder()
	hub.handleAck(recorder, request)
	return recorder.Code
}
