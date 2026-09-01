package tunnelcert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

type testIssuer struct {
	bundle CertificateBundle
	err    error
	seen   []IssueRequest
}

func (i *testIssuer) Issue(_ context.Context, request IssueRequest) (CertificateBundle, error) {
	i.seen = append(i.seen, request)
	if i.err != nil {
		return CertificateBundle{}, i.err
	}
	return cloneCertificateBundle(i.bundle), nil
}

type revokingTestIssuer struct {
	testIssuer
	revokeErr error
	revoked   int
}

func (i *revokingTestIssuer) RevokeBundle(_ context.Context, bundle CertificateBundle) error {
	if len(bundle.CertificatePEM) == 0 || len(bundle.PrivateKeyPEM) == 0 {
		return ErrCertificateInvalid
	}
	i.revoked++
	return i.revokeErr
}

type memoryRevocationStore struct {
	*MemoryStore
}

func (s *memoryRevocationStore) ListPendingCertificateRevocations(_ context.Context, limit int) ([]StoredCertificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]StoredCertificate, 0, limit)
	for _, value := range s.all {
		if value.State == StateRevoked && value.FailureCode == "ca_revocation_pending" {
			value.Envelope = append([]byte(nil), value.Envelope...)
			value.CertificateCiphertext = append([]byte(nil), value.CertificateCiphertext...)
			value.PrivateKeyCiphertext = append([]byte(nil), value.PrivateKeyCiphertext...)
			result = append(result, value)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

func (s *memoryRevocationStore) MarkCertificateRevocationResult(_ context.Context, id string, confirmed bool, _ string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.all[id]
	if !ok || value.State != StateRevoked {
		return ErrGenerationConflict
	}
	if confirmed {
		value.FailureCode = "ca_revoked"
	} else {
		value.FailureCode = "ca_revocation_pending"
	}
	value.UpdatedAt = now
	s.all[id] = value
	return nil
}

type testFallback struct{ bundle CertificateBundle }

func (f testFallback) IssueWildcardFallback(context.Context, IssueRequest) (CertificateBundle, error) {
	return f.bundle, nil
}

func (f testFallback) IssueLeaf(context.Context, IssueRequest) (CertificateBundle, error) {
	return cloneCertificateBundle(f.bundle), nil
}

func testBundle(t *testing.T, names []string, now time.Time, lifetime time.Duration) CertificateBundle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(lifetime), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return CertificateBundle{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), Issuer: "test-ca"}
}

func coordinatorForTest(t *testing.T, issuer Issuer) (*Coordinator, *MemoryStore, *MemoryDistributor, *MemoryOperations) {
	t.Helper()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	distributor := NewMemoryDistributor()
	operations := &MemoryOperations{}
	coordinator, err := NewCoordinator(Config{Store: store, Locks: NewMemoryLock(), Keys: ReferenceKeySource{Keys: map[string][]byte{"master/current": bytes32()}}, Issuer: issuer, CAA: MemoryCAA{Result: CAAResult{State: "ready"}}, Delegated: MemoryDelegator{Challenge: DNSChallenge{Name: "_acme-challenge.app.example.test", Type: "TXT", Value: "bounded-token", TTL: 5 * time.Minute}}, Distributor: distributor, Operations: operations, MasterKeyReference: "master/current", OwnerID: "server-a", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, store, distributor, operations
}

func bytes32() []byte { return bytesOf(32) }

func bytesOf(size int) []byte {
	value := make([]byte, size)
	for index := range value {
		value[index] = byte(index + 1)
	}
	return value
}

func testDomain(hostname string, strategy Strategy) Domain {
	return Domain{ID: "dom_001", AccountID: "acct_001", TunnelID: "tun_001", Hostname: hostname, Generation: 4, Strategy: strategy, OwnershipState: "verified", CAAState: "ready", EdgeTargets: []EdgeTarget{{NodeID: "edge_b", ProcessEpoch: "epoch-0002", Generation: 9}, {NodeID: "edge_a", ProcessEpoch: "epoch-0001", Generation: 7}}}
}

func TestSealOpenNeverStoresPlaintextAndRejectsTampering(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	bundle := testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)
	source := ReferenceKeySource{Keys: map[string][]byte{"ref/current": bytes32()}}
	ciphertext, err := Seal(context.Background(), source, "ref/current", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ciphertext), "PRIVATE KEY") || strings.Contains(string(ciphertext), "CERTIFICATE") {
		t.Fatal("ciphertext contains PEM marker")
	}
	opened, err := Open(context.Background(), source, "ref/current", ciphertext)
	if err != nil || string(opened.PrivateKeyPEM) != string(bundle.PrivateKeyPEM) || string(opened.CertificatePEM) != string(bundle.CertificatePEM) {
		t.Fatalf("opened bundle mismatch: %v", err)
	}
	ciphertext[0] ^= 1
	if _, err := Open(context.Background(), source, "ref/current", ciphertext); !errors.Is(err, ErrMasterKeyUnavailable) {
		t.Fatalf("tampered envelope error = %v", err)
	}
	if _, err := Open(context.Background(), ReferenceKeySource{Keys: map[string][]byte{"ref/current": bytesOf(32)}}, "ref/missing", ciphertext); !errors.Is(err, ErrMasterKeyUnavailable) {
		t.Fatalf("missing reference error = %v", err)
	}
}

func TestCertificateMasterKeyRequiresReferenceNotMaterial(t *testing.T) {
	bundle := testBundle(t, []string{"app.example.test"}, time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC), 24*time.Hour)
	if _, err := Seal(context.Background(), ReferenceKeySource{Keys: map[string][]byte{"ref/current": bytes32()}}, "-----BEGIN PRIVATE KEY-----", bundle); !errors.Is(err, ErrMasterKeyUnavailable) {
		t.Fatalf("raw master key error = %v", err)
	}
	if _, err := NewCoordinator(Config{Store: NewMemoryStore(), Locks: NewMemoryLock(), Keys: ReferenceKeySource{Keys: map[string][]byte{"ref/current": bytes32()}}, Issuer: &testIssuer{}, CAA: MemoryCAA{Result: CAAResult{State: "ready"}}, Distributor: NewMemoryDistributor(), MasterKeyReference: string(bytesOf(32)), OwnerID: "server-a"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("raw coordinator key error = %v", err)
	}
}

func TestCertificateHostnameNormalizesIDNA(t *testing.T) {
	host, wildcard, err := normalizeHostname("BÜCHER.Example.")
	if err != nil || wildcard || host != "xn--bcher-kva.example" {
		t.Fatalf("IDNA hostname = %q wildcard=%v err=%v", host, wildcard, err)
	}
	host, wildcard, err = normalizeHostname("*.BÜCHER.Example.")
	if err != nil || !wildcard || host != "*.xn--bcher-kva.example" {
		t.Fatalf("IDNA wildcard = %q wildcard=%v err=%v", host, wildcard, err)
	}
}

func TestDelegatedChallengeTargetIsStableAndBounded(t *testing.T) {
	target, err := DelegatedChallengeTarget("dom_001", "acct_001", "tun_001", "dns-challenge://dom_001", "challenge.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(target, "pb-") || !strings.HasSuffix(target, ".challenge.example.test") || len(target) > 253 {
		t.Fatalf("delegated target = %q", target)
	}
	if again, err := DelegatedChallengeTarget("dom_001", "acct_001", "tun_001", "dns-challenge://dom_001", "challenge.example.test"); err != nil || again != target {
		t.Fatalf("delegated target is not stable: %q, %v", again, err)
	}
	longLabel := strings.Repeat("a", 63)
	nearLimitZone := strings.Join([]string{longLabel, longLabel, longLabel, strings.Repeat("b", 30)}, ".")
	if _, err := DelegatedChallengeTarget("dom_001", "acct_001", "tun_001", "dns-challenge://dom_001", nearLimitZone); !errors.Is(err, ErrDNSChallengeUnavailable) {
		t.Fatalf("oversized final delegated target error = %v", err)
	}
}

func TestCertificateBundleValidationBindsHostnameKeyAndLifetime(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	bundle := testBundle(t, []string{"*.example.test"}, now, 24*time.Hour)
	identity, err := bundle.Validate("app.example.test", now, 48*time.Hour)
	if err != nil || identity.Hostname != "app.example.test" {
		t.Fatalf("wildcard validation = %+v, %v", identity, err)
	}
	if _, err := bundle.Validate("other.example.test", now, time.Hour); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("lifetime mismatch = %v", err)
	}
	wrongKey := testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)
	wrongKey.PrivateKeyPEM = bundle.PrivateKeyPEM
	if _, err := wrongKey.Validate("app.example.test", now, 48*time.Hour); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("key mismatch = %v", err)
	}
}

func TestCoordinatorStagesAllEdgesBeforeActivationAndCompletesCreate(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 60*24*time.Hour)}
	coordinator, store, distributor, operations := coordinatorForTest(t, issuer)
	coordinator.config.Now = func() time.Time { return now }
	result, err := coordinator.Ensure(context.Background(), testDomain("app.example.test", StrategyDelegatedDNS01))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Issued || result.Fallback || result.Certificate.State != StateActive || result.Certificate.CertificateGeneration != 1 {
		t.Fatalf("result = %+v", result)
	}
	wantEvents := []string{"stage:edge_a", "stage:edge_b", "ready:edge_a", "ready:edge_b", "activate:edge_a", "activate:edge_b"}
	if strings.Join(distributor.Events, ",") != strings.Join(wantEvents, ",") {
		t.Fatalf("events = %v, want %v", distributor.Events, wantEvents)
	}
	if len(operations.Completed) != 1 || !strings.HasSuffix(operations.Completed[0], ":1") {
		t.Fatalf("operation completion = %v", operations.Completed)
	}
	stored, ok, err := store.Current(context.Background(), "dom_001")
	if err != nil || !ok || stored.State != StateActive {
		t.Fatalf("stored = %+v, %v, %v", stored, ok, err)
	}
	if stored.View().ValidateSafe() != nil || strings.Contains(string(mustJSON(t, stored.View())), "PRIVATE KEY") {
		t.Fatal("safe view exposed key material")
	}
	if len(issuer.seen) != 1 || issuer.seen[0].Challenge.Name != "_acme-challenge.app.example.test" {
		t.Fatalf("issuer request = %+v", issuer.seen)
	}
}

func TestCoordinatorManagedCustomerWildcardUsesDelegatedDNS01AcrossRenewal(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	wildcard := "*.user.me"
	issuer := &testIssuer{bundle: testBundle(t, []string{wildcard}, now, 24*time.Hour)}
	coordinator, store, _, _ := coordinatorForTest(t, issuer)
	coordinator.config.Delegated = MemoryDelegator{Challenge: DNSChallenge{
		Name: "_acme-challenge.user.me", Type: "TXT", Value: "wildcard-token", TTL: 5 * time.Minute,
	}}
	domain := testDomain(wildcard, StrategyDelegatedDNS01)
	first, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Issued || first.Fallback {
		t.Fatalf("managed customer wildcard = %+v", first)
	}
	if len(issuer.seen) != 1 || issuer.seen[0].Domain.Hostname != wildcard || issuer.seen[0].Strategy != StrategyDelegatedDNS01 {
		t.Fatalf("wildcard issuance request = %+v", issuer.seen)
	}

	domain.CertificateReference = first.Certificate.Reference
	domain.RenewalDue = true
	renewalNow := now.Add(time.Hour)
	coordinator.config.Now = func() time.Time { return renewalNow }
	issuer.bundle = testBundle(t, []string{wildcard}, renewalNow, 24*time.Hour)
	second, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Issued || second.Fallback || second.Certificate.CertificateGeneration != first.Certificate.CertificateGeneration+1 {
		t.Fatalf("managed customer wildcard renewal = %+v", second)
	}
	if len(issuer.seen) != 2 {
		t.Fatalf("wildcard issuer calls = %d, want 2", len(issuer.seen))
	}
	for index, request := range issuer.seen {
		if request.Domain.Hostname != wildcard || request.Domain.Strategy != StrategyDelegatedDNS01 {
			t.Fatalf("wildcard request %d = %+v", index, request)
		}
	}
	current, found, err := store.Current(context.Background(), domain.ID)
	if err != nil || !found || current.Hostname != wildcard || current.Strategy != StrategyDelegatedDNS01 || current.CertificateGeneration != second.Certificate.CertificateGeneration {
		t.Fatalf("managed customer wildcard current = %+v found=%v err=%v", current, found, err)
	}
}

func TestCoordinatorPreviewTargetUsesLeaseIdentityAndRebindsWithoutIssuance(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"*.preview.example.test"}, now, 60*24*time.Hour)}
	coordinator, store, distributor, _ := coordinatorForTest(t, issuer)
	domain := testDomain("*.preview.example.test", StrategyDelegatedDNS01)
	domain.TunnelID = ""
	domain.TargetKind = TargetPreviewLease
	domain.PreviewID = "preview_001"
	domain.PreviewGeneration = 4
	domain.PreviewState = "active"
	domain.PreviewExpiresAt = now.Add(time.Hour)
	first, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Issued || first.Certificate.TargetKind != TargetPreviewLease || first.Certificate.PreviewID != domain.PreviewID || first.Certificate.PreviewGeneration != domain.PreviewGeneration {
		t.Fatalf("preview result = %+v", first)
	}
	if len(issuer.seen) != 1 {
		t.Fatalf("preview issuer calls = %d, want 1", len(issuer.seen))
	}
	if _, found, err := store.Current(context.Background(), domain.ID); err != nil || found {
		t.Fatalf("preview leaked into durable current: found=%v err=%v", found, err)
	}
	current, found, err := store.CurrentPreview(context.Background(), domain.AccountID, domain.ID, domain.PreviewID)
	if err != nil || !found {
		t.Fatalf("preview current = %+v found=%v err=%v", current, found, err)
	}
	rebound := domain
	rebound.PreviewGeneration++
	rebound.PreviewExpiresAt = now.Add(2 * time.Hour)
	reboundResult, err := coordinator.RebindPreviewCertificate(context.Background(), rebound, now)
	if err != nil || !reboundResult {
		t.Fatalf("preview rebind = %v err=%v", reboundResult, err)
	}
	reboundCurrent, found, err := store.CurrentPreview(context.Background(), domain.AccountID, domain.ID, domain.PreviewID)
	if err != nil || !found || reboundCurrent.CertificateGeneration != current.CertificateGeneration || reboundCurrent.ID != current.ID || reboundCurrent.PreviewGeneration != rebound.PreviewGeneration {
		t.Fatalf("preview rebound current = %+v found=%v err=%v", reboundCurrent, found, err)
	}
	if len(issuer.seen) != 1 {
		t.Fatalf("preview rebind caused issuance: %d", len(issuer.seen))
	}
	if len(distributor.Events) != 6 {
		t.Fatalf("preview rebind redistributed unexpectedly: %v", distributor.Events)
	}
}

func TestCoordinatorPreviewActivityUsesInjectedClock(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"*.preview-clock.example.test"}, now, 60*24*time.Hour)}
	coordinator, _, _, _ := coordinatorForTest(t, issuer)
	domain := testDomain("*.preview-clock.example.test", StrategyDelegatedDNS01)
	domain.TunnelID = ""
	domain.TargetKind = TargetPreviewLease
	domain.PreviewID = "preview_clock_001"
	domain.PreviewGeneration = 1
	domain.PreviewState = "active"
	domain.PreviewExpiresAt = now.Add(time.Minute)
	if _, err := coordinator.Ensure(context.Background(), domain); err != nil {
		t.Fatalf("active lease at injected clock = %v", err)
	}
	coordinator.config.Now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := coordinator.Ensure(context.Background(), domain); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("expired lease error = %v, want ErrCertificateRevoked", err)
	}
}

func TestCoordinatorPreviewCurrentTargetDoesNotSuppressRenewal(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"*.preview-renew.example.test"}, now, 60*24*time.Hour)}
	coordinator, store, _, _ := coordinatorForTest(t, issuer)
	domain := testDomain("*.preview-renew.example.test", StrategyDelegatedDNS01)
	domain.TunnelID = ""
	domain.TargetKind = TargetPreviewLease
	domain.PreviewID = "preview_renew_001"
	domain.PreviewGeneration = 2
	domain.PreviewState = "active"
	domain.PreviewExpiresAt = now.Add(time.Hour)
	first, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	domain.CertificateReference = first.Certificate.Reference
	domain.RenewalDue = true
	if rebound, err := coordinator.RebindPreviewCertificate(context.Background(), domain, now); err != nil || rebound {
		t.Fatalf("current-target rebind = %v, err=%v; renewal must continue through Ensure", rebound, err)
	}
	second, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Issued || second.Certificate.CertificateGeneration != first.Certificate.CertificateGeneration+1 {
		t.Fatalf("preview renewal = %+v, first=%+v", second, first)
	}
	if len(issuer.seen) != 2 {
		t.Fatalf("preview renewal issuer calls = %d, want 2", len(issuer.seen))
	}
	current, found, err := store.CurrentPreview(context.Background(), domain.AccountID, domain.ID, domain.PreviewID)
	if err != nil || !found || current.CertificateGeneration != second.Certificate.CertificateGeneration {
		t.Fatalf("preview renewed current = %+v found=%v err=%v", current, found, err)
	}
}

func TestCoordinatorRedistributesActiveCertificateToLateEdgeWithoutIssuance(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 60*24*time.Hour)}
	coordinator, _, distributor, _ := coordinatorForTest(t, issuer)
	domain := testDomain("app.example.test", StrategyDelegatedDNS01)
	first, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	domain.CertificateReference = first.Certificate.Reference
	domain.EdgeTargets = append(domain.EdgeTargets, EdgeTarget{NodeID: "edge_c", ProcessEpoch: "epoch-0003", Generation: 11})
	second, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if second.Certificate.CertificateGeneration != first.Certificate.CertificateGeneration || second.Issued {
		t.Fatalf("late edge changed certificate generation: first=%+v second=%+v", first.Certificate, second.Certificate)
	}
	if len(issuer.seen) != 1 {
		t.Fatalf("late edge caused a second issuance: %d", len(issuer.seen))
	}
	want := []string{"stage:edge_a", "stage:edge_b", "ready:edge_a", "ready:edge_b", "activate:edge_a", "activate:edge_b", "stage:edge_c", "ready:edge_c", "activate:edge_c"}
	if strings.Join(distributor.Events, ",") != strings.Join(want, ",") {
		t.Fatalf("late edge events = %v, want %v", distributor.Events, want)
	}
}

func TestCoordinatorCAAAndLockDiagnosticsAreTyped(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}
	store := NewMemoryStore()
	locks := NewMemoryLock()
	lockHeld, err := locks.Acquire(context.Background(), "dom_001", "other", 4, now, now.Add(time.Minute))
	if err != nil || !lockHeld {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(Config{Store: store, Locks: locks, Keys: ReferenceKeySource{Keys: map[string][]byte{"master/current": bytes32()}}, Issuer: issuer, CAA: MemoryCAA{Result: CAAResult{State: "blocked", FailureCode: "caa_forbidden"}}, Distributor: NewMemoryDistributor(), MasterKeyReference: "master/current", OwnerID: "server-a", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	domain := testDomain("app.example.test", StrategyDelegatedDNS01)
	if _, err := coordinator.Ensure(context.Background(), domain); !errors.Is(err, ErrCAABlocked) {
		t.Fatalf("CAA error = %v", err)
	}
	coordinator.config.CAA = MemoryCAA{Result: CAAResult{State: "ready"}}
	if _, err := coordinator.Ensure(context.Background(), domain); !errors.Is(err, ErrIssuanceLocked) {
		t.Fatalf("lock error = %v", err)
	}
}

func TestMemoryIssuanceLockFencesOlderGenerationsAfterExpiry(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	lock := NewMemoryLock()
	if ok, err := lock.Acquire(context.Background(), "dom_001", "issuer-a", 4, now, now.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("initial lock = %v, %v", ok, err)
	}
	if ok, err := lock.Acquire(context.Background(), "dom_001", "issuer-b", 3, now.Add(2*time.Minute), now.Add(3*time.Minute)); err != nil || ok {
		t.Fatalf("older generation acquired after expiry = %v, %v", ok, err)
	}
	if err := lock.ReleaseGeneration(context.Background(), "dom_001", "issuer-b", 3); err != nil {
		t.Fatal(err)
	}
	if ok, err := lock.Acquire(context.Background(), "dom_001", "issuer-b", 5, now.Add(2*time.Minute), now.Add(3*time.Minute)); err != nil || !ok {
		t.Fatalf("newer generation lock = %v, %v", ok, err)
	}
	// A stale generation-aware release must not remove the newer lease.
	if err := lock.ReleaseGeneration(context.Background(), "dom_001", "issuer-b", 4); err != nil {
		t.Fatal(err)
	}
	if ok, err := lock.Acquire(context.Background(), "dom_001", "issuer-c", 5, now.Add(2*time.Minute), now.Add(3*time.Minute)); err != nil || ok {
		t.Fatalf("stale release removed newer lock = %v, %v", ok, err)
	}
}

func TestCoordinatorOnDemandLeafUsesBoundedExactFallback(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{err: ErrIssuerRateLimited}
	fallback := testFallback{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}
	coordinator, _, _, _ := coordinatorForTest(t, issuer)
	coordinator.config.Fallback = fallback
	coordinator.config.Delegated = MemoryDelegator{Challenge: DNSChallenge{Name: "_acme-challenge.example.test", Type: "TXT", Value: "bounded-token", TTL: 5 * time.Minute}}
	domain := testDomain("*.example.test", StrategyOnDemandLeaf)
	domain.LeafHostname = "app.example.test"
	domain.AllowOnDemandFallback = true
	result, err := coordinator.Ensure(context.Background(), domain)
	if err != nil || !result.Fallback || result.Certificate.State != StateActive {
		t.Fatalf("fallback result = %+v, %v", result, err)
	}
	if result.Certificate.Issuer != "test-ca" {
		t.Fatalf("fallback issuer = %q", result.Certificate.Issuer)
	}
}

func TestCoordinatorReplacementRetiresOldOnlyAfterNewReady(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}
	coordinator, store, distributor, _ := coordinatorForTest(t, issuer)
	domain := testDomain("app.example.test", StrategyDelegatedDNS01)
	first, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	domain.CertificateReference = first.Certificate.Reference
	coordinator.config.Now = func() time.Time { return now.Add(1 * time.Hour) }
	domain.RenewalDue = true
	issuer.bundle = testBundle(t, []string{"app.example.test"}, now.Add(time.Hour), 24*time.Hour)
	second, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if second.Certificate.CertificateGeneration != first.Certificate.CertificateGeneration+1 {
		t.Fatalf("generation = %d, want %d", second.Certificate.CertificateGeneration, first.Certificate.CertificateGeneration+1)
	}
	last := distributor.Events[len(distributor.Events)-1]
	if !strings.HasPrefix(last, "retire:") || !strings.Contains(last, first.Certificate.Reference) {
		t.Fatalf("replacement events = %v", distributor.Events)
	}
	current, ok, err := store.Current(context.Background(), domain.ID)
	if err != nil || !ok || current.CertificateGeneration != second.Certificate.CertificateGeneration {
		t.Fatalf("current = %+v, %v, %v", current, ok, err)
	}
}

func TestCoordinatorRetriesFailedStagedCertificateWithExactBinding(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}
	coordinator, store, distributor, _ := coordinatorForTest(t, issuer)
	domain := testDomain("app.example.test", StrategyDelegatedDNS01)
	distributor.FailAt = "stage"
	if _, err := coordinator.Ensure(context.Background(), domain); !errors.Is(err, ErrDistributionUnavailable) {
		t.Fatalf("first issuance error = %v", err)
	}
	distributor.FailAt = ""
	result, err := coordinator.Ensure(context.Background(), domain)
	if err != nil || result.Certificate.State != StateActive {
		t.Fatalf("retry result = %+v, %v", result, err)
	}
	stored, found, err := store.Current(context.Background(), domain.ID)
	if err != nil || !found || stored.State != StateActive || stored.CertificateGeneration != 2 {
		t.Fatalf("retry stored = %+v found=%v err=%v", stored, found, err)
	}
}

func TestCoordinatorGenerationSourceSkipsFailedStagedGeneration(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}
	coordinator, store, _, _ := coordinatorForTest(t, issuer)
	domain := testDomain("app.example.test", StrategyDelegatedDNS01)
	first, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}

	active, found, err := store.Current(context.Background(), domain.ID)
	if err != nil || !found {
		t.Fatalf("active certificate = %+v found=%v err=%v", active, found, err)
	}
	failed := active
	failed.ID = "tcert_dom_001_failed_2"
	failed.CertificateReference = "ref_failed_2"
	failed.CertificateGeneration = 2
	failed.State = StateStaged
	failed.UpdatedAt = now
	if err := store.PutStaged(context.Background(), failed); err != nil {
		t.Fatalf("put staged generation 2 = %v", err)
	}
	if err := store.MarkFailed(context.Background(), failed.ID, "edge_stage_failed", now); err != nil {
		t.Fatalf("mark generation 2 failed = %v", err)
	}

	issuer.bundle = testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)
	domain.CertificateReference = first.Certificate.Reference
	domain.RenewalDue = true
	retry, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if !retry.Issued || retry.Certificate.CertificateGeneration != 3 {
		t.Fatalf("retry generation = %+v, want issued generation 3", retry)
	}
	if retry.Certificate.Reference == failed.CertificateReference {
		t.Fatal("retry reused failed generation 2 certificate reference")
	}
}

type stagedFailureDistributor struct {
	mu          sync.Mutex
	stageCount  int
	readyCount  int
	failStageAt int
	failReadyAt int
	rollbackErr error
	staged      map[string]bool
	rolledBack  []string
}

func newStagedFailureDistributor() *stagedFailureDistributor {
	return &stagedFailureDistributor{staged: make(map[string]bool)}
}

func (d *stagedFailureDistributor) Stage(_ context.Context, request DistributionRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stageCount++
	if d.failStageAt > 0 && d.stageCount == d.failStageAt {
		return ErrDistributionUnavailable
	}
	d.staged[request.Target.NodeID] = true
	return nil
}

func (d *stagedFailureDistributor) WaitReady(_ context.Context, request DistributionRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.readyCount++
	if d.failReadyAt > 0 && d.readyCount == d.failReadyAt {
		return ErrCertificateNotReady
	}
	return nil
}

func (d *stagedFailureDistributor) Activate(_ context.Context, request DistributionRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.staged[request.Target.NodeID] {
		return ErrCertificateNotReady
	}
	return nil
}

func (d *stagedFailureDistributor) Retire(_ context.Context, _ StoredCertificate, target DistributionTarget) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.staged, target.NodeID)
	return nil
}

func (d *stagedFailureDistributor) Revoke(_ context.Context, _ StoredCertificate, target DistributionTarget) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rolledBack = append(d.rolledBack, target.NodeID)
	delete(d.staged, target.NodeID)
	return d.rollbackErr
}

func TestCoordinatorCleansEverySuccessfullyStagedEdgeBeforeActivation(t *testing.T) {
	for _, test := range []struct {
		name         string
		failStageAt  int
		failReadyAt  int
		wantRollback []string
	}{
		{name: "second stage", failStageAt: 2, wantRollback: []string{"edge_a"}},
		{name: "second readiness", failReadyAt: 2, wantRollback: []string{"edge_a", "edge_b"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
			issuer := &testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}
			coordinator, store, _, _ := coordinatorForTest(t, issuer)
			distributor := newStagedFailureDistributor()
			distributor.failStageAt = test.failStageAt
			distributor.failReadyAt = test.failReadyAt
			coordinator.config.Distributor = distributor
			_, err := coordinator.Ensure(context.Background(), testDomain("app.example.test", StrategyDelegatedDNS01))
			if err == nil {
				t.Fatal("failed pre-activation transition unexpectedly succeeded")
			}
			distributor.mu.Lock()
			gotRollback := append([]string(nil), distributor.rolledBack...)
			remaining := len(distributor.staged)
			distributor.mu.Unlock()
			if strings.Join(gotRollback, ",") != strings.Join(test.wantRollback, ",") {
				t.Fatalf("rollback targets = %v, want %v (err=%v)", gotRollback, test.wantRollback, err)
			}
			if remaining != 0 {
				t.Fatalf("staged targets remain after failure: %d", remaining)
			}
			store.mu.Lock()
			var stored StoredCertificate
			found := false
			for _, candidate := range store.all {
				stored, found = candidate, true
				break
			}
			store.mu.Unlock()
			if !found || stored.State != StateFailed {
				t.Fatalf("failed certificate state = %+v found=%v", stored, found)
			}
		})
	}
}

func TestCoordinatorJoinsPreActivationCompensationFailure(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}
	coordinator, _, _, _ := coordinatorForTest(t, issuer)
	distributor := newStagedFailureDistributor()
	distributor.failReadyAt = 2
	distributor.rollbackErr = errors.New("edge cleanup unavailable")
	coordinator.config.Distributor = distributor
	_, err := coordinator.Ensure(context.Background(), testDomain("app.example.test", StrategyDelegatedDNS01))
	if err == nil || !errors.Is(err, ErrCertificateNotReady) || !errors.Is(err, ErrDistributionUnavailable) || !strings.Contains(err.Error(), "edge cleanup unavailable") {
		t.Fatalf("compensation error was not joined: %v", err)
	}
}

func TestCoordinatorRevokesAuthorityAndRetriesDurably(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &revokingTestIssuer{testIssuer: testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}}
	coordinator, baseStore, _, _ := coordinatorForTest(t, &issuer.testIssuer)
	// The issuer is swapped after construction so Ensure still uses the
	// ordinary issue implementation while Revoke sees the authority method.
	coordinator.config.Issuer = issuer
	result, err := coordinator.Ensure(context.Background(), testDomain("app.example.test", StrategyDelegatedDNS01))
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryRevocationStore{MemoryStore: baseStore}
	coordinator.config.Store = store
	issuer.revokeErr = errors.New("authority unavailable")
	if _, err := coordinator.Revoke(context.Background(), "dom_001", "operator_requested"); !errors.Is(err, ErrCertificateRevocationUnavailable) {
		t.Fatalf("revocation error = %v", err)
	}
	if issuer.revoked != 1 {
		t.Fatalf("authority revoke calls = %d, want 1", issuer.revoked)
	}
	store.mu.Lock()
	if got := store.all[result.Certificate.Reference[len("tcert_"):]].FailureCode; got != "ca_revocation_pending" {
		t.Fatalf("pending marker = %q", got)
	}
	store.mu.Unlock()
	issuer.revokeErr = nil
	completed, err := coordinator.ReconcileRevocations(context.Background(), 10)
	if err != nil || completed != 1 {
		t.Fatalf("revocation retry = completed %d err %v", completed, err)
	}
	if issuer.revoked != 2 {
		t.Fatalf("authority retry calls = %d, want 2", issuer.revoked)
	}
}

type failingMarkStore struct {
	*MemoryStore
	err error
}

func (s failingMarkStore) MarkFailed(context.Context, string, string, time.Time) error { return s.err }

func TestCoordinatorDoesNotHideFailurePersistenceErrors(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"app.example.test"}, now, 24*time.Hour)}
	coordinator, store, distributor, _ := coordinatorForTest(t, issuer)
	persistenceErr := errors.New("failure journal unavailable")
	coordinator.config.Store = failingMarkStore{MemoryStore: store, err: persistenceErr}
	distributor.FailAt = "stage"
	_, err := coordinator.Ensure(context.Background(), testDomain("app.example.test", StrategyDelegatedDNS01))
	if !errors.Is(err, ErrDistributionUnavailable) || !errors.Is(err, persistenceErr) {
		t.Fatalf("failure persistence error = %v", err)
	}
}

func TestCoordinatorExpiryAlertsAreIdempotentPerCertificate(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	coordinator, _, _, _ := coordinatorForTest(t, &testIssuer{})
	alerts := &MemoryAlerts{}
	coordinator.config.Alerts = alerts
	coordinator.config.ExpiryAlertWindow = 24 * time.Hour
	domain := testDomain("app.example.test", StrategyDelegatedDNS01)
	certificate := StoredCertificate{DomainID: domain.ID, Hostname: domain.Hostname, State: StateActive, CertificateReference: "tcert_alert_01", CertificateGeneration: 3, ExpiresAt: now.Add(time.Hour)}
	if err := coordinator.alertExpiry(context.Background(), domain, certificate, now); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.alertExpiry(context.Background(), domain, certificate, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	alerts.mu.Lock()
	count := len(alerts.Alerts)
	alerts.mu.Unlock()
	if count != 1 {
		t.Fatalf("expiry alert count = %d, want 1", count)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
