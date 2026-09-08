package tunnelcert

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

const maxDesiredAddressRecords = 4

type AddressRecordProvider interface {
	ListAddressRecords(context.Context, string, string) ([]AddressRecord, error)
	CreateAddressRecord(context.Context, AddressRecord, bool) (AddressRecord, error)
	DeleteAddressRecord(context.Context, AddressRecord) error
}

type AddressResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}

type DesiredAddressPublication struct {
	Owner                    string
	Hostname                 string
	ResourceGeneration       uint64
	ReadinessVersion         string
	ObservedAt               time.Time
	ValidUntil               time.Time
	Addresses                []string
	IPv6ReachabilityVerified bool
}

type AddressReconciler struct {
	database *db.DB
	provider AddressRecordProvider
	resolver AddressResolver
	now      func() time.Time
}

type databaseCloudflareAddressAdmission struct {
	database *db.DB
	zoneID   string
}

// NewDatabaseCloudflareAddressAdmission creates the shared per-zone provider
// budget used by every server replica configured with the same database.
func NewDatabaseCloudflareAddressAdmission(database *db.DB, zoneID string) (CloudflareAddressAdmission, error) {
	if database == nil || database.Pool() == nil || !validMetadata(zoneID, 128) {
		return nil, fmt.Errorf("%w: Cloudflare address admission database and zone are required", ErrInvalid)
	}
	return &databaseCloudflareAddressAdmission{database: database, zoneID: zoneID}, nil
}

func (a *databaseCloudflareAddressAdmission) Acquire(ctx context.Context) (func(), error) {
	if reservation, ok := ctx.Value(addressReservationKey{}).(*addressReservation); ok && reservation.owner == a {
		return reservation.acquire(ctx)
	}
	for {
		conn, err := a.database.Pool().Acquire(ctx)
		if err != nil {
			return nil, err
		}
		slot := -1
		for candidate := 0; candidate < 2; candidate++ {
			var locked bool
			if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,173)+$2)`, a.zoneID, candidate).Scan(&locked); err != nil {
				conn.Release()
				return nil, err
			}
			if locked {
				slot = candidate
				break
			}
		}
		if slot < 0 {
			conn.Release()
			if err := waitContext(ctx, 25*time.Millisecond); err != nil {
				return nil, err
			}
			continue
		}
		release := databaseAdmissionRelease(conn, a.zoneID, slot)
		var remaining float64
		err = conn.QueryRow(ctx, `INSERT INTO edge_dns_provider_budgets(zone_id,tokens,refilled_at,blocked_until)
VALUES($1,4,statement_timestamp(),statement_timestamp())
ON CONFLICT(zone_id) DO UPDATE SET
tokens=LEAST(5,edge_dns_provider_budgets.tokens+EXTRACT(EPOCH FROM (statement_timestamp()-edge_dns_provider_budgets.refilled_at))/6)-1,
refilled_at=statement_timestamp()
WHERE edge_dns_provider_budgets.blocked_until<=statement_timestamp()
  AND LEAST(5,edge_dns_provider_budgets.tokens+EXTRACT(EPOCH FROM (statement_timestamp()-edge_dns_provider_budgets.refilled_at))/6)>=1
RETURNING tokens`, a.zoneID).Scan(&remaining)
		if err == nil {
			return release, nil
		}
		release()
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		var waitSeconds float64
		if err := a.database.Pool().QueryRow(ctx, `SELECT GREATEST(0,EXTRACT(EPOCH FROM (blocked_until-statement_timestamp())),(1-tokens)*6-EXTRACT(EPOCH FROM (statement_timestamp()-refilled_at))) FROM edge_dns_provider_budgets WHERE zone_id=$1`, a.zoneID).Scan(&waitSeconds); err != nil {
			return nil, err
		}
		wait := time.Duration(waitSeconds * float64(time.Second))
		if wait < 25*time.Millisecond {
			wait = 25 * time.Millisecond
		}
		if err := waitContext(ctx, wait); err != nil {
			return nil, err
		}
	}
}

func (a *databaseCloudflareAddressAdmission) Reserve(ctx context.Context, count int) (context.Context, func(), error) {
	if count < 1 || count > cloudflareAddressBurst {
		return nil, nil, ErrInvalid
	}
	conn, err := a.database.Pool().Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	slot := -1
	for candidate := 0; candidate < 2; candidate++ {
		var locked bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,173)+$2)`, a.zoneID, candidate).Scan(&locked); err != nil {
			conn.Release()
			return nil, nil, err
		}
		if locked {
			slot = candidate
			break
		}
	}
	if slot < 0 {
		conn.Release()
		return nil, nil, addressError(AddressPublicationPending, "provider concurrency unavailable")
	}
	release := databaseAdmissionRelease(conn, a.zoneID, slot)
	var remaining float64
	err = conn.QueryRow(ctx, `INSERT INTO edge_dns_provider_budgets(zone_id,tokens,refilled_at,blocked_until)
VALUES($1,5-$2,statement_timestamp(),statement_timestamp())
ON CONFLICT(zone_id) DO UPDATE SET
 tokens=LEAST(5,edge_dns_provider_budgets.tokens+EXTRACT(EPOCH FROM(statement_timestamp()-edge_dns_provider_budgets.refilled_at))/6)-$2,
 refilled_at=statement_timestamp()
WHERE edge_dns_provider_budgets.blocked_until<=statement_timestamp()
 AND LEAST(5,edge_dns_provider_budgets.tokens+EXTRACT(EPOCH FROM(statement_timestamp()-edge_dns_provider_budgets.refilled_at))/6)>=$2
RETURNING tokens`, a.zoneID, count).Scan(&remaining)
	if err != nil {
		release()
		if errors.Is(err, pgx.ErrNoRows) {
			err = addressError(AddressPublicationPending, "provider step budget unavailable")
		}
		return nil, nil, err
	}
	reservation := &addressReservation{owner: a, remaining: count, concurrent: make(chan struct{}, 1)}
	reservation.check = func(ctx context.Context) error {
		var blocked bool
		err := conn.QueryRow(ctx, `SELECT blocked_until>statement_timestamp() FROM edge_dns_provider_budgets WHERE zone_id=$1`, a.zoneID).Scan(&blocked)
		if err != nil {
			return err
		}
		if blocked {
			return addressError(AddressPublicationPending, "provider retry after active")
		}
		return nil
	}
	reservation.refund = func(unused int) {
		if unused > 0 {
			refundCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _ = conn.Exec(refundCtx, `UPDATE edge_dns_provider_budgets SET tokens=LEAST(5,tokens+$2) WHERE zone_id=$1`, a.zoneID, unused)
		}
		release()
	}
	return context.WithValue(ctx, addressReservationKey{}, reservation), reservation.close, nil
}

func databaseAdmissionRelease(conn *pgxpool.Conn, zoneID string, slot int) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var unlocked bool
			if err := conn.QueryRow(ctx, `SELECT pg_advisory_unlock(hashtextextended($1,173)+$2)`, zoneID, slot).Scan(&unlocked); err != nil || !unlocked {
				_ = conn.Conn().Close(ctx)
			}
			conn.Release()
		})
	}
}

func (a *databaseCloudflareAddressAdmission) Block(_ context.Context, retryAfter string) {
	delay := parseRetryAfter(retryAfter, time.Now().UTC())
	if delay <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = a.database.Pool().Exec(ctx, `INSERT INTO edge_dns_provider_budgets(zone_id,tokens,refilled_at,blocked_until)
VALUES($1,5,statement_timestamp(),statement_timestamp()+$2::interval) ON CONFLICT(zone_id) DO UPDATE SET blocked_until=GREATEST(edge_dns_provider_budgets.blocked_until,EXCLUDED.blocked_until)`, a.zoneID, delay.String())
}

func NewAddressReconciler(database *db.DB, provider AddressRecordProvider, resolver AddressResolver) (*AddressReconciler, error) {
	if database == nil || database.Pool() == nil || provider == nil || resolver == nil {
		return nil, fmt.Errorf("%w: address reconciler dependencies are required", ErrInvalid)
	}
	return &AddressReconciler{database: database, provider: provider, resolver: resolver, now: time.Now}, nil
}

func (r *AddressReconciler) OwnedHostnames(ctx context.Context, owner string) ([]string, error) {
	if r == nil || r.database == nil || !validMetadata(owner, 128) {
		return nil, fmt.Errorf("%w: publication owner is invalid", ErrInvalid)
	}
	hostnames, err := r.database.Queries().ListEdgeDNSPublicationHostnamesByOwner(ctx, owner)
	if err != nil {
		return nil, err
	}
	if len(hostnames) > 128 {
		return nil, addressError(AddressPublicationConflict, "publication hostname ownership exceeds bounds")
	}
	return hostnames, nil
}

// Reconcile serializes one hostname from durable desired state through
// provider mutation and resolver verification. Provider errors are returned
// unchanged so pending publication is never mistaken for readiness.
func (r *AddressReconciler) Reconcile(ctx context.Context, desired DesiredAddressPublication) error {
	if r == nil || r.database == nil || r.provider == nil || r.resolver == nil {
		return fmt.Errorf("%w: address reconciler is unavailable", ErrInvalid)
	}
	host, addresses, err := validateDesiredAddressPublication(desired)
	if err != nil {
		return err
	}
	desired.Hostname, desired.Addresses = host, addresses

	conn, err := r.database.Pool().Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 172))`, host); err != nil {
		return err
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var unlocked bool
		if err := conn.QueryRow(unlockCtx, `SELECT pg_advisory_unlock(hashtextextended($1, 172))`, host).Scan(&unlocked); err != nil || !unlocked {
			_ = conn.Conn().Close(unlockCtx)
		}
	}()

	generation, err := r.persistDesired(ctx, conn.Conn(), desired)
	if err != nil {
		return err
	}
	// Reuse unchanged verified publication for one DNS TTL. Fresh resource
	// authority is persisted above; any changed tuple clears verified state.
	current, readErr := dbsqlc.New(conn.Conn()).GetEdgeDNSPublication(ctx, host)
	if readErr != nil {
		return readErr
	}
	if current.State == "verified" && current.VerifiedAt.Valid && r.now().Sub(current.VerifiedAt.Time) < 60*time.Second {
		return nil
	}
	if provider, ok := r.provider.(interface {
		ReserveAddressStep(context.Context) (context.Context, func(), error)
	}); ok {
		reserved, release, reserveErr := provider.ReserveAddressStep(ctx)
		if reserveErr != nil {
			return reserveErr
		}
		defer release()
		ctx = reserved
	}
	records, err := r.provider.ListAddressRecords(ctx, host, desired.Owner)
	if err != nil {
		r.recordFailure(ctx, conn.Conn(), desired, generation, nil, err)
		return err
	}
	wanted := stringSet(addresses)
	mutated := false
	retained := make(map[string]bool, len(records))
	kept := records[:0]
	for _, record := range records {
		if record.Generation > generation {
			err := addressError(AddressPublicationConflict, "provider record has a future publication generation")
			r.recordFailure(ctx, conn.Conn(), desired, generation, records, err)
			return err
		}
		_, wantedAddress := wanted[record.Address]
		if wantedAddress && !retained[record.Address] {
			kept = append(kept, record)
			retained[record.Address] = true
			continue
		}
		if mutated {
			kept = append(kept, record)
			continue
		}
		writeCtx, cancel, deadlineErr := publicationWriteContext(ctx, desired)
		if deadlineErr != nil {
			return deadlineErr
		}
		deleteErr := r.provider.DeleteAddressRecord(writeCtx, record)
		cancel()
		if deleteErr != nil {
			r.recordFailure(ctx, conn.Conn(), desired, generation, records, deleteErr)
			return deleteErr
		}
		mutated = true
	}
	records = kept
	present := make(map[string]bool, len(records))
	for _, record := range records {
		present[record.Address] = true
	}
	for _, address := range addresses {
		if mutated {
			break
		}
		if present[address] {
			continue
		}
		writeCtx, cancel, deadlineErr := publicationWriteContext(ctx, desired)
		if deadlineErr != nil {
			return deadlineErr
		}
		created, createErr := r.provider.CreateAddressRecord(writeCtx, AddressRecord{Hostname: host, Address: address, Owner: desired.Owner, Generation: generation}, desired.IPv6ReachabilityVerified)
		cancel()
		if createErr != nil {
			r.recordFailure(ctx, conn.Conn(), desired, generation, records, createErr)
			return createErr
		}
		records = append(records, created)
		mutated = true
	}
	if !addressRecordsMatch(records, desired.Owner, generation, wanted) {
		err = addressError(AddressPublicationPending, "provider records have not converged")
		r.recordFailure(ctx, conn.Conn(), desired, generation, records, err)
		return err
	}
	if err := r.markState(ctx, conn.Conn(), desired, generation, records, "submitted", ""); err != nil {
		return err
	}
	if mutated {
		return addressError(AddressPublicationPending, "provider changes require independent readback")
	}
	resolved, lookupErr := r.resolver.LookupHost(ctx, addressLookupHostname(host))
	if lookupErr != nil && !(len(wanted) == 0 && isDNSNotFound(lookupErr)) || !resolvedAddressesMatch(resolved, wanted) {
		return addressError(AddressPublicationPending, "authoritative address results have not converged")
	}
	return r.markState(ctx, conn.Conn(), desired, generation, records, "verified", "")
}

func (r *AddressReconciler) persistDesired(ctx context.Context, conn *pgx.Conn, desired DesiredAddressPublication) (uint64, error) {
	encoded, _ := json.Marshal(desired.Addresses)
	row, err := dbsqlc.New(conn).UpsertEdgeDNSPublicationDesired(ctx, dbsqlc.UpsertEdgeDNSPublicationDesiredParams{
		Hostname: desired.Hostname, OwnerID: desired.Owner, ResourceGeneration: int64(desired.ResourceGeneration),
		ReadinessVersion: desired.ReadinessVersion, ObservedAt: desired.ObservedAt.UTC(),
		ValidUntil:       sql.NullTime{Time: desired.ValidUntil.UTC(), Valid: !desired.ValidUntil.IsZero()},
		DesiredAddresses: encoded, Now: r.now().UTC(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, addressError(AddressPublicationConflict, "hostname is owned by another resource or newer generation")
	}
	if err != nil {
		return 0, err
	}
	return uint64(row.PublicationGeneration), nil
}

func (r *AddressReconciler) recordFailure(ctx context.Context, conn *pgx.Conn, desired DesiredAddressPublication, generation uint64, records []AddressRecord, cause error) {
	kind := "provider_failure"
	var publicationError *AddressPublicationError
	if errors.As(cause, &publicationError) {
		kind = string(publicationError.Kind)
	}
	_ = r.markState(ctx, conn, desired, generation, records, "failed", kind)
}

func (r *AddressReconciler) markState(ctx context.Context, conn *pgx.Conn, desired DesiredAddressPublication, generation uint64, records []AddressRecord, state, failure string) error {
	if records == nil {
		records = []AddressRecord{}
	}
	encoded, _ := json.Marshal(records)
	now := r.now().UTC()
	queries := dbsqlc.New(conn)
	var rows int64
	var err error
	switch state {
	case "submitted":
		rows, err = queries.MarkEdgeDNSPublicationSubmitted(ctx, dbsqlc.MarkEdgeDNSPublicationSubmittedParams{ProviderRecords: encoded, Now: now, Hostname: desired.Hostname, OwnerID: desired.Owner, PublicationGeneration: int64(generation)})
	case "verified":
		rows, err = queries.MarkEdgeDNSPublicationVerified(ctx, dbsqlc.MarkEdgeDNSPublicationVerifiedParams{ProviderRecords: encoded, Now: sql.NullTime{Time: now, Valid: true}, Hostname: desired.Hostname, OwnerID: desired.Owner, PublicationGeneration: int64(generation)})
	case "failed":
		rows, err = queries.MarkEdgeDNSPublicationFailed(ctx, dbsqlc.MarkEdgeDNSPublicationFailedParams{ProviderRecords: encoded, FailureCode: sql.NullString{String: failure, Valid: failure != ""}, Now: now, Hostname: desired.Hostname, OwnerID: desired.Owner, PublicationGeneration: int64(generation)})
	default:
		return fmt.Errorf("%w: publication state is invalid", ErrInvalid)
	}
	if err != nil {
		return err
	}
	if rows != 1 {
		return addressError(AddressPublicationConflict, "publication generation changed")
	}
	return nil
}

func validateDesiredAddressPublication(desired DesiredAddressPublication) (string, []string, error) {
	host, _, err := normalizeHostname(desired.Hostname)
	if err != nil || !validMetadata(desired.Owner, 128) || desired.ResourceGeneration == 0 || desired.ResourceGeneration > maxPlatformGeneration || desired.ObservedAt.IsZero() || len(desired.Addresses) > maxDesiredAddressRecords {
		return "", nil, fmt.Errorf("%w: desired address publication is invalid", ErrInvalid)
	}
	set := make(map[string]struct{}, len(desired.Addresses))
	addresses := make([]string, 0, len(desired.Addresses))
	for _, raw := range desired.Addresses {
		ip, parseErr := netip.ParseAddr(raw)
		if parseErr != nil || !publicAddress(ip) || ip.Is6() && !desired.IPv6ReachabilityVerified {
			return "", nil, fmt.Errorf("%w: desired address is invalid", ErrInvalid)
		}
		canonical := ip.Unmap().String()
		if _, exists := set[canonical]; exists {
			continue
		}
		set[canonical] = struct{}{}
		addresses = append(addresses, canonical)
	}
	sort.Strings(addresses)
	if len(addresses) > 0 && (!validMetadata(desired.ReadinessVersion, 256) || desired.ValidUntil.IsZero() || !desired.ValidUntil.After(time.Now())) {
		return "", nil, fmt.Errorf("%w: ready address authority is invalid or expired", ErrInvalid)
	}
	return host, addresses, nil
}

func publicationWriteContext(parent context.Context, desired DesiredAddressPublication) (context.Context, context.CancelFunc, error) {
	if len(desired.Addresses) == 0 {
		ctx, cancel := context.WithCancel(parent)
		return ctx, cancel, nil
	}
	if !desired.ValidUntil.After(time.Now()) {
		return nil, nil, addressError(AddressPublicationPending, "ready address authority expired before provider write")
	}
	ctx, cancel := context.WithDeadline(parent, desired.ValidUntil)
	return ctx, cancel, nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func addressRecordsMatch(records []AddressRecord, owner string, generation uint64, wanted map[string]struct{}) bool {
	if len(records) != len(wanted) {
		return false
	}
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.Owner != owner || record.Generation == 0 || record.Generation > generation {
			return false
		}
		if _, ok := wanted[record.Address]; !ok {
			return false
		}
		seen[record.Address] = struct{}{}
	}
	return len(seen) == len(wanted)
}

func addressLookupHostname(host string) string {
	if !strings.HasPrefix(host, "*.") {
		return host
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "pb-verify." + strings.TrimPrefix(host, "*.")
	}
	return "pb-" + hex.EncodeToString(random) + "." + strings.TrimPrefix(host, "*.")
}

func isDNSNotFound(err error) bool {
	var dnsError *net.DNSError
	return errors.As(err, &dnsError) && dnsError.IsNotFound
}

func resolvedAddressesMatch(values []string, wanted map[string]struct{}) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ip, err := netip.ParseAddr(value)
		if err != nil {
			return false
		}
		address := ip.Unmap().String()
		if _, ok := wanted[address]; !ok {
			return false
		}
		seen[address] = struct{}{}
	}
	return len(seen) == len(wanted)
}
