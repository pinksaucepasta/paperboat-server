package tunnelv1

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/workers"
	"golang.org/x/net/publicsuffix"
)

const (
	domainDNSMinimumRetry          = 30 * time.Second
	domainDNSMaximumRetry          = 30 * time.Minute
	domainDNSDefaultTTL            = 300 * time.Second
	domainDNSTransientFailureGrace = 3
)

type DNSObservation struct {
	Records     []string
	TTL         time.Duration
	FailureCode string
}

type DomainDNSResolver interface {
	Observe(context.Context, string, string, string, string) (DNSObservation, error)
}

type NetDomainDNSResolver struct {
	Servers []string
	Timeout time.Duration
}

func (r NetDomainDNSResolver) Observe(ctx context.Context, hostname, recordType, target, challengeReference string) (DNSObservation, error) {
	servers, err := r.servers()
	if err != nil {
		return DNSObservation{FailureCode: "dns_unavailable"}, err
	}
	name := strings.TrimPrefix(hostname, "*.")
	if strings.HasPrefix(hostname, "*.") {
		digest := sha256.Sum256([]byte(challengeReference))
		name = fmt.Sprintf("paperboat-%x.%s", digest[:6], name)
	}
	observation := DNSObservation{}
	if recordType == "CNAME" {
		records, ttl, err := r.lookup(ctx, servers, name, dns.TypeCNAME)
		if err != nil {
			observation.FailureCode = classifyDNSError(err)
			return observation, err
		}
		observation.Records, observation.TTL = records, ttl
		want := "CNAME " + normalizeObservedDNSValue(target)
		if len(records) != 1 || !strings.EqualFold(records[0], want) {
			observation.FailureCode = "wrong_record"
		}
		return observation, nil
	}
	addresses, ttlA, errA := r.lookupAddresses(ctx, servers, name)
	if errA != nil {
		observation.FailureCode = classifyDNSError(errA)
		return observation, errA
	}
	targetAddresses, _, err := r.lookupAddresses(ctx, servers, target)
	if err != nil {
		observation.FailureCode = "target_dns_error"
		return observation, err
	}
	observation.Records, observation.TTL = addresses, ttlA
	if !sameDNSAddressSet(addresses, targetAddresses) {
		observation.FailureCode = "wrong_record"
	}
	return observation, nil
}

func (r NetDomainDNSResolver) servers() ([]string, error) {
	if len(r.Servers) > 0 {
		return append([]string(nil), r.Servers...), nil
	}
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		return nil, errors.New("DNS resolver configuration is unavailable")
	}
	servers := make([]string, 0, len(config.Servers))
	for _, server := range config.Servers {
		servers = append(servers, net.JoinHostPort(server, config.Port))
	}
	return servers, nil
}

func (r NetDomainDNSResolver) lookup(ctx context.Context, servers []string, name string, qtype uint16) ([]string, time.Duration, error) {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), qtype)
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := &dns.Client{Timeout: timeout}
	var lastErr error
	for _, server := range servers {
		response, _, err := client.ExchangeContext(ctx, message, server)
		if err != nil {
			lastErr = err
			continue
		}
		if response.Truncated {
			client.Net = "tcp"
			response, _, err = client.ExchangeContext(ctx, message, server)
			client.Net = ""
			if err != nil {
				lastErr = err
				continue
			}
		}
		if response.Rcode != dns.RcodeSuccess {
			return nil, 0, &net.DNSError{Err: dns.RcodeToString[response.Rcode], Name: name, IsNotFound: response.Rcode == dns.RcodeNameError}
		}
		records := make([]string, 0, len(response.Answer))
		var ttl uint32
		for _, answer := range response.Answer {
			if answer.Header().Rrtype != qtype {
				continue
			}
			if qtype == dns.TypeCNAME && !strings.EqualFold(answer.Header().Name, message.Question[0].Name) {
				continue
			}
			if ttl == 0 || answer.Header().Ttl < ttl {
				ttl = answer.Header().Ttl
			}
			switch value := answer.(type) {
			case *dns.CNAME:
				records = append(records, "CNAME "+normalizeObservedDNSValue(value.Target))
			case *dns.A:
				records = append(records, "A "+value.A.String())
			case *dns.AAAA:
				records = append(records, "AAAA "+value.AAAA.String())
			}
		}
		if len(records) == 0 {
			return nil, 0, &net.DNSError{Err: "record not found", Name: name, IsNotFound: true}
		}
		sort.Strings(records)
		return records, time.Duration(ttl) * time.Second, nil
	}
	if lastErr == nil {
		lastErr = errors.New("DNS query failed")
	}
	return nil, 0, lastErr
}

func (r NetDomainDNSResolver) lookupAddresses(ctx context.Context, servers []string, name string) ([]string, time.Duration, error) {
	var result []string
	var ttl time.Duration
	var firstErr error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		records, recordTTL, err := r.lookup(ctx, servers, name, qtype)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		result = append(result, records...)
		if ttl == 0 || recordTTL < ttl {
			ttl = recordTTL
		}
	}
	if len(result) == 0 {
		return nil, 0, firstErr
	}
	sort.Strings(result)
	return result, ttl, nil
}

func classifyDNSError(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "dns_not_found"
		}
		if dnsErr.IsTimeout || dnsErr.IsTemporary {
			return "dns_unavailable"
		}
	}
	return "dns_error"
}

func normalizeObservedDNSValue(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func sameDNSAddressSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]struct{}, len(right))
	for _, value := range right {
		values[value] = struct{}{}
	}
	for _, value := range left {
		if _, ok := values[value]; !ok {
			return false
		}
	}
	return true
}

type DomainReconciler struct {
	db       *db.DB
	resolver DomainDNSResolver
	now      func() time.Time
	observe  func(context.Context, DomainDNSReconcileEvent)
}

type DomainDNSReconcileEvent struct {
	DomainID      string
	Code          string
	Verified      bool
	ConflictState string
	NextCheckAt   time.Time
}

// SetTelemetryObserver installs the process-owned adapter before Worker is
// started. The event is deliberately hostname- and record-free.
func (r *DomainReconciler) SetTelemetryObserver(observer func(context.Context, DomainDNSReconcileEvent)) error {
	if r == nil || observer == nil {
		return ErrInvalidInput
	}
	r.observe = observer
	return nil
}

func NewDomainReconciler(store *db.DB, resolver DomainDNSResolver, now func() time.Time) (*DomainReconciler, error) {
	if store == nil || resolver == nil {
		return nil, errors.New("domain reconciler database and resolver are required")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &DomainReconciler{db: store, resolver: resolver, now: now}, nil
}

func (r *DomainReconciler) Reconcile(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 500 {
		return 0, ErrInvalidInput
	}
	now := r.now().UTC()
	if _, err := r.db.Queries().ReleaseExpiredTunnelDomainQuarantinesV1(ctx, now); err != nil {
		return 0, err
	}
	rows, err := r.db.Queries().ListDueTunnelDomainsV1(ctx, dbsqlc.ListDueTunnelDomainsV1Params{Now: now, RowLimit: int32(limit)})
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return changed, err
		}
		if err := r.reconcileOne(ctx, row, now); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

func (r *DomainReconciler) reconcileOne(ctx context.Context, row dbsqlc.TunnelDomain, now time.Time) error {
	recordType := dnsVerificationRecordType(row)
	observation, lookupErr := r.resolver.Observe(ctx, row.Hostname, recordType, row.DnsTarget, row.OwnershipChallengeReference)
	observed, err := json.Marshal(observation.Records)
	if err != nil {
		return err
	}
	state, conflict, observationVerified := domainDNSObservationState(row, observation, recordType, lookupErr)
	if state == "verified" && !observationVerified {
		// A transient lookup failure inside the bounded grace window must not
		// erase the last authoritative record set or masquerade as new proof.
		observed = append([]byte(nil), row.ObservedRecords...)
	}
	ttl := boundedDNSTTL(observation.TTL)
	retryTTL := observation.TTL
	if retryTTL > 0 {
		retryTTL = boundedDNSTTL(retryTTL)
	}
	next := now.Add(domainDNSBackoff(row.VerificationAttempts, retryTTL, observationVerified))
	err = r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		updated, err := tx.Queries().ApplyTunnelDomainDNSObservationV1(ctx, dbsqlc.ApplyTunnelDomainDNSObservationV1Params{
			ObservedRecords: observed, OwnershipState: state, ConflictState: conflict,
			Now: sql.NullTime{Time: now, Valid: true}, NextCheckAt: next, TtlSeconds: sql.NullInt32{Int32: int32(ttl / time.Second), Valid: true},
			ObservationVerified: observationVerified, DomainID: row.ID, ExpectedGeneration: row.Generation,
		})
		if err != nil {
			return err
		}
		if !observationVerified || updated.OwnershipState != "verified" {
			return nil
		}
		_, err = tx.Queries().CompleteTunnelDomainVerificationOperationsV1(ctx, dbsqlc.CompleteTunnelDomainVerificationOperationsV1Params{
			Now: sql.NullTime{Time: now, Valid: true}, AccountID: row.AccountID,
			DomainID: sql.NullString{String: row.ID, Valid: true},
		})
		if err != nil {
			return err
		}
		_, err = tx.Queries().AdvanceTunnelDomainCreateOperationsV1(ctx, dbsqlc.AdvanceTunnelDomainCreateOperationsV1Params{
			Now: now, AccountID: row.AccountID,
			DomainID: sql.NullString{String: row.ID, Valid: true},
		})
		return err
	})
	if err != nil {
		return err
	}
	if r.observe != nil {
		code := "dns_verification_waiting"
		if observationVerified {
			code = "dns_verified"
		} else if conflict != "" && conflict != "clear" {
			code = "dns_conflict"
		} else if state == "failed" {
			code = "dns_verification_failed"
		}
		r.observe(ctx, DomainDNSReconcileEvent{DomainID: row.ID, Code: code, Verified: observationVerified, ConflictState: conflict, NextCheckAt: next})
	}
	return nil
}

func domainDNSObservationState(row dbsqlc.TunnelDomain, observation DNSObservation, recordType string, lookupErr error) (string, string, bool) {
	if lookupErr == nil && dnsObservationMatches(row, observation, recordType) {
		return "verified", "clear", true
	}
	switch observation.FailureCode {
	case "wrong_record":
		return "failed", "conflicted", false
	case "dns_not_found":
		return "failed", "clear", false
	}
	if row.OwnershipState == "verified" && row.VerificationAttempts+1 < domainDNSTransientFailureGrace {
		return "verified", "clear", false
	}
	if row.OwnershipState == "failed" || row.OwnershipState == "verified" || row.VerificationAttempts >= 7 {
		return "failed", "clear", false
	}
	return "pending", "clear", false
}

func expectedDNSRecordType(raw []byte) string {
	var records []DNSRecordInstruction
	if json.Unmarshal(raw, &records) == nil && len(records) == 1 {
		return strings.ToUpper(records[0].Type)
	}
	return "CNAME"
}

func dnsVerificationRecordType(row dbsqlc.TunnelDomain) string {
	recordType := expectedDNSRecordType(row.ExpectedRecords)
	registrable, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimPrefix(row.Hostname, "*."))
	if err == nil && registrable == row.Hostname && row.DnsProvider == "cloudflare" {
		return "ALIAS"
	}
	return recordType
}

func dnsObservationMatches(row dbsqlc.TunnelDomain, observation DNSObservation, recordType string) bool {
	if observation.FailureCode != "" || len(observation.Records) == 0 {
		return false
	}
	if recordType != "CNAME" {
		return true // The production resolver already compares flattened addresses with the stable target.
	}
	want := "CNAME " + normalizeObservedDNSValue(row.DnsTarget)
	for _, record := range observation.Records {
		if strings.EqualFold(strings.TrimSpace(record), want) {
			return true
		}
	}
	return false
}

func boundedDNSTTL(value time.Duration) time.Duration {
	if value < domainDNSMinimumRetry {
		return domainDNSDefaultTTL
	}
	if value > 24*time.Hour {
		return 24 * time.Hour
	}
	return value
}

func domainDNSBackoff(attempt int32, ttl time.Duration, verified bool) time.Duration {
	if verified {
		return ttl
	}
	delay := domainDNSMinimumRetry
	for i := int32(0); i < attempt && delay < domainDNSMaximumRetry; i++ {
		delay *= 2
	}
	if delay > domainDNSMaximumRetry {
		delay = domainDNSMaximumRetry
	}
	if delay < ttl {
		delay = ttl
	}
	return delay
}

func (r *DomainReconciler) Worker(interval time.Duration, limit int) workers.Worker {
	return workers.Worker(func(ctx context.Context) error {
		if interval <= 0 {
			return fmt.Errorf("domain reconciliation interval must be positive")
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if _, err := r.Reconcile(ctx, limit); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	})
}
