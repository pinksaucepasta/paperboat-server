package previewdomain

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
)

type reconcilerDNSCall struct {
	hostname, recordType, target, challenge string
}

type reconcilerDNSResolverFake struct {
	mu          sync.Mutex
	observation tunnelv1.DNSObservation
	err         error
	block       <-chan struct{}
	started     chan struct{}
	startOnce   sync.Once
	calls       []reconcilerDNSCall
}

func (f *reconcilerDNSResolverFake) Observe(ctx context.Context, hostname, recordType, target, challenge string) (tunnelv1.DNSObservation, error) {
	f.mu.Lock()
	f.calls = append(f.calls, reconcilerDNSCall{hostname: hostname, recordType: recordType, target: target, challenge: challenge})
	f.mu.Unlock()
	if f.started != nil {
		f.startOnce.Do(func() { close(f.started) })
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return tunnelv1.DNSObservation{}, ctx.Err()
		}
	}
	return f.observation, f.err
}

func (f *reconcilerDNSResolverFake) Calls() []reconcilerDNSCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]reconcilerDNSCall(nil), f.calls...)
}

type reconcilerRepositoryFake struct {
	mu              sync.Mutex
	rows            []dbsqlc.PreviewDomain
	applied         []DNSReconciliationObservation
	listCalls       int
	quarantineCalls int
	applyErr        error
	leaseErr        error
}

func (f *reconcilerRepositoryFake) ListDue(ctx context.Context, _ time.Time, limit int) ([]dbsqlc.PreviewDomain, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if limit > len(f.rows) {
		limit = len(f.rows)
	}
	rows := append([]dbsqlc.PreviewDomain(nil), f.rows[:limit]...)
	for i := range rows {
		rows[i].ObservedRecords = append([]byte(nil), rows[i].ObservedRecords...)
	}
	return rows, nil
}

func (f *reconcilerRepositoryFake) ApplyDNSObservationForReconciliation(ctx context.Context, input DNSReconciliationObservation) (dbsqlc.PreviewDomain, error) {
	if err := ctx.Err(); err != nil {
		return dbsqlc.PreviewDomain{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.leaseErr != nil {
		return dbsqlc.PreviewDomain{}, f.leaseErr
	}
	if f.applyErr != nil {
		return dbsqlc.PreviewDomain{}, f.applyErr
	}
	f.applied = append(f.applied, input)
	for index := range f.rows {
		row := &f.rows[index]
		if row.ID != input.DomainID || row.AccountID != input.AccountID || row.PreviewID != input.PreviewID {
			continue
		}
		if row.PreviewGeneration != input.PreviewGeneration || row.Generation != input.ExpectedGeneration {
			return dbsqlc.PreviewDomain{}, ErrGenerationConflict
		}
		row.ObservedRecords = append([]byte(nil), input.ObservedRecords...)
		row.OwnershipState = input.OwnershipState
		row.ConflictState = input.ConflictState
		row.DnsLastCheckedAt = sql.NullTime{Time: input.Now, Valid: true}
		row.DnsNextCheckAt = input.NextCheckAt
		row.DnsTtlSeconds = sql.NullInt32{Int32: input.TTLSeconds, Valid: input.TTLSeconds > 0}
		if input.Verified {
			row.VerificationAttempts = 0
			row.LastVerifiedAt = sql.NullTime{Time: input.Now, Valid: true}
		} else {
			row.VerificationAttempts++
		}
		row.Generation++
		return *row, nil
	}
	return dbsqlc.PreviewDomain{}, ErrGenerationConflict
}

func (f *reconcilerRepositoryFake) ReleaseExpiredPreviewDomainQuarantines(ctx context.Context, _ time.Time) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	f.mu.Lock()
	f.quarantineCalls++
	f.mu.Unlock()
	return 0, nil
}

func (f *reconcilerRepositoryFake) Applied() []DNSReconciliationObservation {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := append([]DNSReconciliationObservation(nil), f.applied...)
	for index := range result {
		result[index].ObservedRecords = append([]byte(nil), result[index].ObservedRecords...)
	}
	return result
}

type reconcilerEventSinkFake struct {
	mu     sync.Mutex
	events []DNSReconcileEvent
}

func (f *reconcilerEventSinkFake) EmitDNSReconcileEvent(_ context.Context, event DNSReconcileEvent) {
	f.mu.Lock()
	f.events = append(f.events, event)
	f.mu.Unlock()
}

func (f *reconcilerEventSinkFake) Events() []DNSReconcileEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]DNSReconcileEvent(nil), f.events...)
}

func TestReconcilerVerifiesExactApexAndWildcardWithProviderAwareTypes(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	repository := &reconcilerRepositoryFake{rows: []dbsqlc.PreviewDomain{
		reconcilerDomainRow("exact", "app.example.com", "exact", "generic", now),
		reconcilerDomainRow("apex", "example.com", "exact", "cloudflare", now),
		reconcilerDomainRow("wildcard", "*.apps.example.com", "one_label_wildcard", "generic", now),
	}}
	resolver := &reconcilerDNSResolverFake{observation: tunnelv1.DNSObservation{
		Records: []string{"CNAME stable.edge.example"}, TTL: 10 * time.Minute,
	}}
	events := &reconcilerEventSinkFake{}
	reconciler, err := NewReconciler(repository, resolver, ReconcilerConfig{
		Now: func() time.Time { return now }, EventSink: events,
	})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := reconciler.Reconcile(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if processed != 3 {
		t.Fatalf("processed = %d, want 3", processed)
	}
	calls := resolver.Calls()
	if len(calls) != 3 {
		t.Fatalf("resolver calls = %d, want 3", len(calls))
	}
	wantTypes := map[string]string{
		"app.example.com":    "CNAME",
		"example.com":        "ALIAS",
		"*.apps.example.com": "CNAME",
	}
	for _, call := range calls {
		if got := wantTypes[call.hostname]; got == "" || call.recordType != got {
			t.Fatalf("DNS call = %#v, want record type %q", call, got)
		}
		if call.target != "stable.edge.example" || call.challenge == "" {
			t.Fatalf("DNS call leaked or lost binding = %#v", call)
		}
	}
	for _, input := range repository.Applied() {
		if !input.Verified || input.OwnershipState != "verified" || input.ConflictState != "clear" {
			t.Fatalf("DNS input = %#v, want authoritative verified state", input)
		}
		if input.NextCheckAt.Before(now.Add(9*time.Minute)) || input.NextCheckAt.After(now.Add(11*time.Minute)) {
			t.Fatalf("TTL next check = %s, want bounded around 10m", input.NextCheckAt.Sub(now))
		}
	}
	for _, event := range events.Events() {
		if event.Code != "dns_verified" || !event.Verified || event.OwnershipState != "verified" || event.ConflictState != "clear" {
			t.Fatalf("event = %#v, want verified event", event)
		}
		encoded, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		for _, secret := range []string{"app.example.com", "stable.edge.example", "dns-challenge"} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("event contains unsafe DNS detail %q: %s", secret, encoded)
			}
		}
	}
}

func TestReconcilerTransientGracePreservesLKGAndWrongRecordWithdraws(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	row := reconcilerDomainRow("domain-1", "app.example.com", "exact", "generic", now)
	row.ObservedRecords = []byte(`["CNAME stable.edge.example"]`)
	row.OwnershipState = "verified"
	row.ConflictState = "clear"
	repository := &reconcilerRepositoryFake{rows: []dbsqlc.PreviewDomain{row}}
	resolver := &reconcilerDNSResolverFake{observation: tunnelv1.DNSObservation{FailureCode: "dns_unavailable"}, err: errors.New("resolver unavailable")}
	events := &reconcilerEventSinkFake{}
	reconciler, err := NewReconciler(repository, resolver, ReconcilerConfig{Now: func() time.Time { return now }, EventSink: events})
	if err != nil {
		t.Fatal(err)
	}
	if processed, reconcileErr := reconciler.Reconcile(context.Background(), 1); reconcileErr != nil || processed != 1 {
		t.Fatalf("first transient reconcile = %d, %v", processed, reconcileErr)
	}
	applied := repository.Applied()
	if len(applied) != 1 || applied[0].Verified || applied[0].OwnershipState != "verified" || string(applied[0].ObservedRecords) != string(row.ObservedRecords) {
		t.Fatalf("first transient input = %#v, want preserved LKG", applied)
	}
	if repository.rows[0].VerificationAttempts != 1 {
		t.Fatalf("transient attempts = %d, want 1", repository.rows[0].VerificationAttempts)
	}

	// After the bounded grace window the same transient failure withdraws DNS
	// readiness instead of indefinitely serving an answer that is no longer
	// authoritative.
	repository.rows[0].VerificationAttempts = 2
	if processed, reconcileErr := reconciler.Reconcile(context.Background(), 1); reconcileErr != nil || processed != 1 {
		t.Fatalf("grace exhaustion reconcile = %d, %v", processed, reconcileErr)
	}
	applied = repository.Applied()
	last := applied[len(applied)-1]
	if last.OwnershipState != "failed" || last.ConflictState != "clear" || last.Verified {
		t.Fatalf("grace exhaustion input = %#v, want failed/unverified", last)
	}

	// A conclusive wrong record withdraws immediately and is marked as a
	// conflict. This prevents the edge alias projection from treating a ready
	// certificate as routable after ownership changes.
	wrong := &reconcilerRepositoryFake{rows: []dbsqlc.PreviewDomain{row}}
	wrongResolver := &reconcilerDNSResolverFake{observation: tunnelv1.DNSObservation{Records: []string{"CNAME attacker.example"}, TTL: time.Minute}}
	wrongReconciler, err := NewReconciler(wrong, wrongResolver, ReconcilerConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongReconciler.Reconcile(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	wrongInput := wrong.Applied()[0]
	if wrongInput.OwnershipState != "failed" || wrongInput.ConflictState != "conflicted" || wrongInput.Verified {
		t.Fatalf("wrong-record input = %#v, want failed/conflicted", wrongInput)
	}
}

func TestReconcilerFencesGenerationBatchAndCancellation(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	rows := []dbsqlc.PreviewDomain{
		reconcilerDomainRow("domain-1", "one.example.com", "exact", "generic", now),
		reconcilerDomainRow("domain-2", "two.example.com", "exact", "generic", now),
	}
	resolver := &reconcilerDNSResolverFake{observation: tunnelv1.DNSObservation{Records: []string{"CNAME stable.edge.example"}}}
	repository := &reconcilerRepositoryFake{rows: rows}
	reconciler, err := NewReconciler(repository, resolver, ReconcilerConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := reconciler.Reconcile(context.Background(), 1)
	if err != nil || processed != 1 {
		t.Fatalf("bounded batch = %d, %v", processed, err)
	}
	inputs := repository.Applied()
	if len(inputs) != 1 || inputs[0].PreviewGeneration != rows[0].PreviewGeneration || inputs[0].ExpectedGeneration != 1 {
		t.Fatalf("fence input = %#v, want current preview/domain generations", inputs)
	}

	// The SQL repository returns a typed conflict when the lease generation or
	// domain CAS no longer matches. Reconciliation treats it as stale work and
	// continues without publishing an error or a false event.
	staleRepository := &reconcilerRepositoryFake{rows: []dbsqlc.PreviewDomain{rows[0]}, applyErr: ErrGenerationConflict}
	stale, err := NewReconciler(staleRepository, resolver, ReconcilerConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := stale.Reconcile(context.Background(), 1); err != nil || processed != 0 {
		t.Fatalf("stale reconcile = %d, %v, want skipped", processed, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	block := make(chan struct{})
	started := make(chan struct{})
	blockedResolver := &reconcilerDNSResolverFake{block: block, started: started}
	blockedRepository := &reconcilerRepositoryFake{rows: []dbsqlc.PreviewDomain{rows[0]}}
	blocked, err := NewReconciler(blockedRepository, blockedResolver, ReconcilerConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, reconcileErr := blocked.Reconcile(ctx, 1)
		result <- reconcileErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DNS observation did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled reconcile error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled DNS observation did not return")
	}
	close(block)
}

func TestReconcilerRetryJitterAndWorkerPolicyAreBounded(t *testing.T) {
	base := 10 * time.Minute
	first := deterministicDNSJitter("domain-1", 4, base)
	second := deterministicDNSJitter("domain-1", 4, base)
	if first != second || first < 9*time.Minute || first > 11*time.Minute {
		t.Fatalf("deterministic jitter = %s/%s, want equal and bounded", first, second)
	}
	if deterministicDNSJitter("domain-1", 4, time.Second/2) != time.Second/2 {
		t.Fatal("sub-second jitter changed the base delay")
	}
	bounded, err := NewReconciler(&reconcilerRepositoryFake{}, &reconcilerDNSResolverFake{}, ReconcilerConfig{
		Jitter: func(_ string, _ int32, base time.Duration) time.Duration { return base + time.Hour },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := bounded.retryDelay("domain-1", 99, 0, false); got != 30*time.Minute {
		t.Fatalf("failure retry delay = %s, want 30m cap", got)
	}

	repository := &reconcilerRepositoryFake{}
	resolver := &reconcilerDNSResolverFake{}
	reconciler, err := NewReconciler(repository, resolver, ReconcilerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Worker(0, 1)(context.Background()); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid worker policy error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := reconciler.Worker(time.Hour, 1)(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled worker error = %v", err)
	}
	if _, err := NewReconciler(repository, resolver, ReconcilerConfig{MinimumRetry: time.Second, MaximumRetry: 500 * time.Millisecond}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid retry policy error = %v", err)
	}
	if _, err := NewReconciler(repository, resolver, ReconcilerConfig{MinimumRetry: time.Hour, MaximumRetry: 2 * time.Hour, DefaultTTL: 2 * time.Hour, MaximumTTL: 90 * time.Minute}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("retry larger than TTL policy error = %v", err)
	}
}

func reconcilerDomainRow(id, hostname, matchType, provider string, now time.Time) dbsqlc.PreviewDomain {
	return dbsqlc.PreviewDomain{
		ID: id, AccountID: "account-1", PreviewID: "preview-1", PreviewGeneration: 7,
		Hostname: hostname, MatchType: matchType, OwnershipChallengeReference: "dns-challenge://challenge-" + id,
		OwnershipState: "pending", DnsTarget: "stable.edge.example", ObservedRecords: []byte(`[]`),
		DnsProvider: provider, ExpectedRecords: []byte(`[]`), DnsNextCheckAt: now.Add(-time.Minute),
		CertificateStrategy: "managed", CertificateState: "pending", ConflictState: "clear",
		Generation: 1, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Minute),
	}
}
