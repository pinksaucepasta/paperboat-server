package tunnelcert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

type fakeAddressProvider struct {
	records             []AddressRecord
	creates, deletes    int
	uncertainFirstWrite bool
}

func (p *fakeAddressProvider) ListAddressRecords(context.Context, string, string) ([]AddressRecord, error) {
	return append([]AddressRecord(nil), p.records...), nil
}
func (p *fakeAddressProvider) CreateAddressRecord(_ context.Context, record AddressRecord, _ bool) (AddressRecord, error) {
	p.creates++
	record.ProviderID = fmt.Sprintf("new_%d", p.creates)
	p.records = append(p.records, record)
	if p.uncertainFirstWrite && p.creates == 1 {
		return AddressRecord{}, addressError(AddressPublicationPending, "provider outcome is uncertain")
	}
	return record, nil
}
func (p *fakeAddressProvider) DeleteAddressRecord(_ context.Context, record AddressRecord) error {
	p.deletes++
	for index, existing := range p.records {
		if existing.ProviderID == record.ProviderID {
			p.records = append(p.records[:index], p.records[index+1:]...)
			break
		}
	}
	return nil
}

type fakeAddressResolver struct {
	values []string
	err    error
}

func (r *fakeAddressResolver) LookupHost(context.Context, string) ([]string, error) {
	return append([]string(nil), r.values...), r.err
}

func TestDesiredAddressPublicationValidationAndRecordMatching(t *testing.T) {
	now := time.Now()
	desired := DesiredAddressPublication{Owner: "tunnel_1", Hostname: "*.Example.Test", ResourceGeneration: 4, ReadinessVersion: "ready-v1", ObservedAt: now, ValidUntil: now.Add(time.Minute), Addresses: []string{"8.8.8.8", "8.8.8.8", "2606:4700:4700::1111"}, IPv6ReachabilityVerified: true}
	host, addresses, err := validateDesiredAddressPublication(desired)
	if err != nil || host != "*.example.test" || len(addresses) != 2 {
		t.Fatalf("host=%q addresses=%v error=%v", host, addresses, err)
	}
	wanted := stringSet(addresses)
	records := []AddressRecord{{ProviderID: "old_a", Hostname: host, Address: addresses[0], Owner: desired.Owner, Generation: 1}, {ProviderID: "old_b", Hostname: host, Address: addresses[1], Owner: desired.Owner, Generation: 3}}
	if !addressRecordsMatch(records, desired.Owner, 4, wanted) {
		t.Fatal("healthy records from earlier publication generations were rejected")
	}
	if addressRecordsMatch(records, desired.Owner, 2, wanted) {
		t.Fatal("future provider generation was accepted")
	}
	duplicate := append(append([]AddressRecord(nil), records...), records[0])
	if addressRecordsMatch(duplicate, desired.Owner, 4, wanted) {
		t.Fatal("duplicate provider address was accepted")
	}
	desired.IPv6ReachabilityVerified = false
	if _, _, err := validateDesiredAddressPublication(desired); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unverified IPv6 error=%v", err)
	}
}

func TestAddressLookupHostnameUsesOneLabelWildcardProbe(t *testing.T) {
	host := addressLookupHostname("*.example.test")
	if !strings.HasPrefix(host, "pb-") || !strings.HasSuffix(host, ".example.test") || strings.Count(host, ".") != 2 {
		t.Fatalf("lookup hostname=%q", host)
	}
	if !isDNSNotFound(&net.DNSError{IsNotFound: true}) {
		t.Fatal("NXDOMAIN was not recognized")
	}
}

func TestAddressReconcilerPersistsUncertainWriteAndRetainsHealthyRecordOnPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run address publication PostgreSQL acceptance")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(dsn), "_test") {
		t.Fatal("PAPERBOAT_TEST_DATABASE_DSN must name an isolated *_test database")
	}
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(context.Background(), database); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	host, owner := "dns-"+suffix+".example.test", "tunnel_"+suffix
	t.Cleanup(func() {
		_, _ = database.Pool().Exec(context.Background(), `DELETE FROM edge_dns_publications WHERE hostname=$1`, host)
	})
	provider := &fakeAddressProvider{uncertainFirstWrite: true}
	resolver := &fakeAddressResolver{values: []string{"8.8.8.8"}}
	reconciler, err := NewAddressReconciler(database, provider, resolver)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	desired := DesiredAddressPublication{Owner: owner, Hostname: host, ResourceGeneration: 1, ReadinessVersion: "ready_1", ObservedAt: now, ValidUntil: now.Add(time.Minute), Addresses: []string{"8.8.8.8"}}
	if err := reconciler.Reconcile(context.Background(), desired); err == nil {
		t.Fatal("uncertain creation was reported ready")
	}
	if err := reconciler.Reconcile(context.Background(), desired); err != nil {
		t.Fatalf("uncertain creation did not reconcile by list: %v", err)
	}
	if provider.creates != 1 {
		t.Fatalf("uncertain POST replayed: creates=%d", provider.creates)
	}
	desired.ReadinessVersion, desired.ObservedAt = "ready_2", now.Add(time.Second)
	if err := reconciler.Reconcile(context.Background(), desired); err != nil {
		t.Fatalf("healthy record was not retained: %v", err)
	}
	if provider.creates != 1 || provider.deletes != 0 {
		t.Fatalf("healthy address churned: creates=%d deletes=%d", provider.creates, provider.deletes)
	}
	var state string
	if err := database.Pool().QueryRow(context.Background(), `SELECT state FROM edge_dns_publications WHERE hostname=$1`, host).Scan(&state); err != nil || state != "verified" {
		t.Fatalf("state=%q error=%v", state, err)
	}
	stale := desired
	stale.ReadinessVersion, stale.ObservedAt = "stale", now.Add(-time.Second)
	if err := reconciler.Reconcile(context.Background(), stale); !isAddressErrorKind(err, AddressPublicationConflict) {
		t.Fatalf("stale observation error=%v", err)
	}
	stale.ResourceGeneration, stale.ObservedAt = 0, now.Add(2*time.Second)
	if err := reconciler.Reconcile(context.Background(), stale); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid resource generation error=%v", err)
	}

	withdraw := DesiredAddressPublication{Owner: owner, Hostname: host, ResourceGeneration: 2, ObservedAt: now.Add(2 * time.Second)}
	if err := reconciler.Reconcile(context.Background(), withdraw); !isAddressErrorKind(err, AddressPublicationPending) {
		t.Fatalf("withdraw mutation error=%v", err)
	}
	resolver.values, resolver.err = nil, &net.DNSError{IsNotFound: true}
	if err := reconciler.Reconcile(context.Background(), withdraw); err != nil {
		t.Fatalf("NXDOMAIN withdrawal verification: %v", err)
	}
	staleGeneration := desired
	staleGeneration.ObservedAt = now.Add(4 * time.Second)
	if err := reconciler.Reconcile(context.Background(), staleGeneration); !isAddressErrorKind(err, AddressPublicationConflict) {
		t.Fatalf("stale resource generation error=%v", err)
	}
	hostnames, err := reconciler.OwnedHostnames(context.Background(), owner)
	if err != nil || len(hostnames) != 1 || hostnames[0] != host {
		t.Fatalf("owned hostnames=%v error=%v", hostnames, err)
	}

	recoverDesired := DesiredAddressPublication{Owner: owner, Hostname: host, ResourceGeneration: 3, ReadinessVersion: "ready_3", ObservedAt: now.Add(3 * time.Second), ValidUntil: now.Add(time.Minute), Addresses: []string{"8.8.8.8"}}
	resolver.values, resolver.err = []string{"8.8.8.8"}, nil
	if err := reconciler.Reconcile(context.Background(), recoverDesired); !isAddressErrorKind(err, AddressPublicationPending) {
		t.Fatalf("recovery mutation error=%v", err)
	}
	if err := reconciler.Reconcile(context.Background(), recoverDesired); err != nil {
		t.Fatalf("recovery verification error=%v", err)
	}
}

func TestDatabaseCloudflareAddressAdmissionSharedOnPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run shared DNS admission PostgreSQL acceptance")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(context.Background(), database); err != nil {
		t.Fatal(err)
	}
	zone := fmt.Sprintf("zone_%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = database.Pool().Exec(context.Background(), `DELETE FROM edge_dns_provider_budgets WHERE zone_id=$1`, zone)
	})
	first, err := NewDatabaseCloudflareAddressAdmission(database, zone)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDatabaseCloudflareAddressAdmission(database, zone)
	if err != nil {
		t.Fatal(err)
	}
	releaseFirst, err := first.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var firstTokens float64
	var firstRefilled time.Time
	if err := database.Pool().QueryRow(context.Background(), `SELECT tokens,refilled_at FROM edge_dns_provider_budgets WHERE zone_id=$1`, zone).Scan(&firstTokens, &firstRefilled); err != nil {
		releaseFirst()
		t.Fatal(err)
	}
	releaseSecond, err := second.Acquire(context.Background())
	if err != nil {
		releaseFirst()
		t.Fatal(err)
	}
	third := make(chan error, 1)
	thirdCtx, thirdCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer thirdCancel()
	go func() {
		release, err := first.Acquire(thirdCtx)
		if err == nil {
			release()
		}
		third <- err
	}()
	select {
	case err := <-third:
		releaseFirst()
		releaseSecond()
		t.Fatalf("third call passed two shared slots: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	releaseFirst()
	select {
	case err := <-third:
		if err != nil {
			releaseSecond()
			t.Fatalf("third call did not recover after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseSecond()
		t.Fatal("third call stayed blocked after a slot was released")
	}
	releaseSecond()
	var tokens float64
	var lastRefilled time.Time
	if err := database.Pool().QueryRow(context.Background(), `SELECT tokens,refilled_at FROM edge_dns_provider_budgets WHERE zone_id=$1`, zone).Scan(&tokens, &lastRefilled); err != nil {
		t.Fatal(err)
	}
	// Include database-clock refill during remote round trips. Exactly two
	// further admissions must consume the same persisted bucket.
	wantTokens := firstTokens - 2 + lastRefilled.Sub(firstRefilled).Seconds()/6
	if math.Abs(tokens-wantTokens) > 0.00001 {
		t.Fatalf("shared tokens=%v want=%v", tokens, wantTokens)
	}

	if _, err := database.Pool().Exec(context.Background(), `UPDATE edge_dns_provider_budgets SET tokens=0,refilled_at=statement_timestamp()-interval '6 seconds',blocked_until=statement_timestamp() WHERE zone_id=$1`, zone); err != nil {
		t.Fatal(err)
	}
	refillCtx, refillCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer refillCancel()
	refillRelease, err := second.Acquire(refillCtx)
	if err != nil {
		t.Fatalf("shared refill did not recover: %v", err)
	}
	refillRelease()

	first.Block(context.Background(), "5")
	var blockedFor float64
	if err := database.Pool().QueryRow(context.Background(), `SELECT EXTRACT(EPOCH FROM (blocked_until-statement_timestamp())) FROM edge_dns_provider_budgets WHERE zone_id=$1`, zone).Scan(&blockedFor); err != nil || blockedFor <= 0 {
		t.Fatalf("Retry-After was not persisted: seconds=%v error=%v", blockedFor, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if release, err := second.Acquire(ctx); err == nil {
		release()
		t.Fatal("second instance ignored shared Retry-After")
	}
	if _, err := database.Pool().Exec(context.Background(), `UPDATE edge_dns_provider_budgets SET tokens=1,refilled_at=statement_timestamp(),blocked_until=statement_timestamp() WHERE zone_id=$1`, zone); err != nil {
		t.Fatal(err)
	}
	recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer recoveryCancel()
	recoveryRelease, err := second.Acquire(recoveryCtx)
	if err != nil {
		t.Fatalf("Retry-After recovery failed: %v", err)
	}
	recoveryRelease()
}

func isAddressErrorKind(err error, kind AddressPublicationErrorKind) bool {
	var typed *AddressPublicationError
	return errors.As(err, &typed) && typed.Kind == kind
}

func TestAddressReconcilerReservedWithdrawalOnPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	host, owner, zone := "withdraw-"+suffix+".example.test", "owner_"+suffix, "zone_"+suffix
	defer func() {
		_, _ = database.Pool().Exec(context.Background(), `DELETE FROM edge_dns_publications WHERE hostname=$1`, host)
		_, _ = database.Pool().Exec(context.Background(), `DELETE FROM edge_dns_provider_budgets WHERE zone_id=$1`, zone)
	}()
	var calls, deletes atomic.Int32
	var exists atomic.Bool
	exists.Store(true)
	record := cloudflareAddressRecord{ID: "record_123", Type: "A", Name: host, Content: "8.8.8.8", TTL: 60, Comment: addressComment(owner, 1)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			exists.Store(false)
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		if strings.Contains(r.URL.Path, "record_123") {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": record})
			return
		}
		records := []cloudflareAddressRecord{}
		if exists.Load() {
			records = append(records, record)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": records})
	}))
	defer server.Close()
	provider := newAddressProvider(t, server, "token")
	provider.addressAdmission, err = NewDatabaseCloudflareAddressAdmission(database, zone)
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := NewAddressReconciler(database, provider, &fakeAddressResolver{})
	if err != nil {
		t.Fatal(err)
	}
	desired := DesiredAddressPublication{Owner: owner, Hostname: host, ResourceGeneration: 1, ObservedAt: time.Now().UTC()}
	var creditedAt time.Time
	credit := func(n int) {
		t.Helper()
		err := database.Pool().QueryRow(context.Background(), `INSERT INTO edge_dns_provider_budgets(zone_id,tokens,refilled_at,blocked_until) VALUES($1,$2,statement_timestamp(),statement_timestamp()) ON CONFLICT(zone_id) DO UPDATE SET tokens=$2,refilled_at=statement_timestamp(),blocked_until=statement_timestamp() RETURNING refilled_at`, zone, n).Scan(&creditedAt)
		if err != nil {
			t.Fatal(err)
		}
	}
	for n := 0; n < 3; n++ {
		credit(n)
		if err := reconciler.Reconcile(context.Background(), desired); !isAddressErrorKind(err, AddressPublicationPending) {
			t.Fatalf("partial budget result: %v", err)
		}
		if calls.Load() != 0 {
			t.Fatal("partial budget was consumed by restarting reads")
		}
	}
	credit(3)
	if err := reconciler.Reconcile(context.Background(), desired); !isAddressErrorKind(err, AddressPublicationPending) {
		t.Fatalf("mutation must await readback: %v", err)
	}
	if deletes.Load() != 1 || calls.Load() != 3 {
		t.Fatalf("withdrawal never progressed: calls=%d deletes=%d", calls.Load(), deletes.Load())
	}
	credit(3)
	if err := reconciler.Reconcile(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	if err := reconciler.Reconcile(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before {
		t.Fatal("unchanged verified publication consumed another provider call")
	}
	var tokens float64
	var refilledAt time.Time
	if err := database.Pool().QueryRow(context.Background(), `SELECT tokens,refilled_at FROM edge_dns_provider_budgets WHERE zone_id=$1`, zone).Scan(&tokens, &refilledAt); err != nil {
		t.Fatal(err)
	}
	if math.Abs(tokens-(2+refilledAt.Sub(creditedAt).Seconds()/6)) > 0.00001 {
		t.Fatalf("unused reservation credits not returned: %f", tokens)
	}
}
