package tunnelv1

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestDomainDNSObservationRequiresExactStableTarget(t *testing.T) {
	row := dbsqlc.TunnelDomain{DnsTarget: "stable.edge.paperboat.example"}
	for _, test := range []struct {
		name        string
		recordType  string
		observation DNSObservation
		want        bool
	}{
		{name: "exact cname", recordType: "CNAME", observation: DNSObservation{Records: []string{"CNAME stable.edge.paperboat.example"}}, want: true},
		{name: "terminal dot normalized", recordType: "CNAME", observation: DNSObservation{Records: []string{"cname STABLE.EDGE.PAPERBOAT.EXAMPLE"}}, want: true},
		{name: "wrong cname", recordType: "CNAME", observation: DNSObservation{Records: []string{"CNAME attacker.example"}}},
		{name: "resolver failure", recordType: "CNAME", observation: DNSObservation{Records: []string{"CNAME stable.edge.paperboat.example"}, FailureCode: "dnssec_error"}},
		{name: "flattened compared by resolver", recordType: "ALIAS", observation: DNSObservation{Records: []string{"A 192.0.2.1"}}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := dnsObservationMatches(row, test.observation, test.recordType); got != test.want {
				t.Fatalf("match = %v, want %v", got, test.want)
			}
		})
	}
}

func TestNetDomainDNSResolverUsesWildcardProbeAndAuthoritativeTTL(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		question := request.Question[0]
		if strings.HasPrefix(question.Name, "paperboat-") && strings.HasSuffix(question.Name, ".example.com.") && question.Qtype == dns.TypeCNAME {
			response.Answer = append(response.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 900}, Target: "stable.paperboat.example."})
		} else {
			response.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(response)
	})
	server := &dns.Server{PacketConn: packet, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	resolver := NetDomainDNSResolver{Servers: []string{packet.LocalAddr().String()}, Timeout: time.Second}
	observation, err := resolver.Observe(context.Background(), "*.example.com", "CNAME", "stable.paperboat.example", "dns-challenge://test")
	if err != nil || observation.FailureCode != "" || observation.TTL != 15*time.Minute || len(observation.Records) != 1 {
		t.Fatalf("observation = %+v, %v", observation, err)
	}
}

func TestDomainDNSBackoffRespectsTTLAndCaps(t *testing.T) {
	if got := domainDNSBackoff(0, 5*time.Minute, false); got != 5*time.Minute {
		t.Fatalf("TTL delay = %v", got)
	}
	if got := domainDNSBackoff(30, 30*time.Second, false); got != 30*time.Minute {
		t.Fatalf("capped delay = %v", got)
	}
	if got := domainDNSBackoff(30, 2*time.Hour, true); got != 2*time.Hour {
		t.Fatalf("verified recheck = %v", got)
	}
}

func TestVerifiedDomainDNSDriftAndTransientGrace(t *testing.T) {
	row := dbsqlc.TunnelDomain{OwnershipState: "verified", ConflictState: "clear", DnsTarget: "stable.edge.paperboat.example"}
	state, conflict, verified := domainDNSObservationState(row, DNSObservation{FailureCode: "dns_unavailable"}, "CNAME", context.DeadlineExceeded)
	if state != "verified" || conflict != "clear" || verified {
		t.Fatalf("first transient = %q %q %v", state, conflict, verified)
	}
	row.VerificationAttempts = domainDNSTransientFailureGrace - 1
	state, conflict, verified = domainDNSObservationState(row, DNSObservation{FailureCode: "dns_unavailable"}, "CNAME", context.DeadlineExceeded)
	if state != "failed" || conflict != "clear" || verified {
		t.Fatalf("expired grace = %q %q %v", state, conflict, verified)
	}
	row.VerificationAttempts = 0
	state, conflict, verified = domainDNSObservationState(row, DNSObservation{FailureCode: "wrong_record", Records: []string{"CNAME attacker.example"}}, "CNAME", nil)
	if state != "failed" || conflict != "conflicted" || verified {
		t.Fatalf("wrong target = %q %q %v", state, conflict, verified)
	}
	state, conflict, verified = domainDNSObservationState(row, DNSObservation{FailureCode: "dns_not_found"}, "CNAME", &net.DNSError{IsNotFound: true})
	if state != "failed" || conflict != "clear" || verified {
		t.Fatalf("removed record = %q %q %v", state, conflict, verified)
	}
}

func TestDomainLifecycleReportsIssuingTLSAfterDNSVerification(t *testing.T) {
	row := dbsqlc.TunnelDomain{OwnershipState: "verified", ConflictState: "clear", CertificateState: "issuing"}
	if got := wireDomainLifecycleState(row); got != "issuing_tls" {
		t.Fatalf("state = %q", got)
	}
	row.OwnershipState = "failed"
	if got := wireDomainLifecycleState(row); got != "dns_error" {
		t.Fatalf("drifted state = %q", got)
	}
}

func TestDomainDNSInstructionsAreProviderAwareAndOriginOpaque(t *testing.T) {
	for _, test := range []struct {
		host, provider, wantType string
	}{
		{host: "app.example.com", provider: "generic", wantType: "CNAME"},
		{host: "*.example.com", provider: "cloudflare", wantType: "CNAME"},
		{host: "example.com", provider: "cloudflare", wantType: "CNAME"},
		{host: "example.com", provider: "route53", wantType: "ALIAS"},
		{host: "example.com", provider: "generic", wantType: "ANAME"},
	} {
		recordType, note := dnsRecordTypeAndNote(test.host, test.provider)
		if recordType != test.wantType || note == "" {
			t.Fatalf("%s/%s = %s %q", test.host, test.provider, recordType, note)
		}
	}
	records, err := json.Marshal([]DNSRecordInstruction{{Name: "*.example.com", Type: "CNAME", Value: "stable.paperboat.example", TTL: 300}})
	if err != nil || expectedDNSRecordType(records) != "CNAME" {
		t.Fatalf("expected record = %s, %v", records, err)
	}
}

func TestDNSProviderValidationFailsClosed(t *testing.T) {
	for _, provider := range []string{"", "generic", "cloudflare", "route53", "google_cloud_dns", "digitalocean", "namecheap"} {
		if _, err := validateDNSProvider(provider); err != nil {
			t.Fatalf("provider %q: %v", provider, err)
		}
	}
	if _, err := validateDNSProvider("unknown-provider"); err == nil {
		t.Fatal("unknown provider was accepted")
	}
}

func TestOneLabelWildcardDoesNotCaptureApexOrMultipleLabels(t *testing.T) {
	hostname, matchType, err := normalizeBindingHostname("*.Example.COM.")
	if err != nil || hostname != "*.example.com" || matchType != "one_label_wildcard" {
		t.Fatalf("normalization = %q %q %v", hostname, matchType, err)
	}
	match := func(candidate string) bool {
		suffix := strings.TrimPrefix(hostname, "*.")
		prefix, ok := strings.CutSuffix(candidate, "."+suffix)
		return ok && prefix != "" && !strings.Contains(prefix, ".")
	}
	if !match("app.example.com") || match("example.com") || match("a.b.example.com") {
		t.Fatal("wildcard did not preserve one-label semantics")
	}
}

func TestDomainClaimQuarantineIsBoundedAndLiveClaimsStayExclusive(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	if !domainClaimBlocked(dbsqlc.TunnelDomain{}, now) {
		t.Fatal("live claim must remain exclusive across accounts")
	}
	deleted := dbsqlc.TunnelDomain{DeletedAt: sql.NullTime{Time: now.Add(-time.Hour), Valid: true}, QuarantineUntil: sql.NullTime{Time: now.Add(time.Hour), Valid: true}}
	if !domainClaimBlocked(deleted, now) {
		t.Fatal("active quarantine must block reuse")
	}
	deleted.QuarantineUntil.Time = now
	if domainClaimBlocked(deleted, now) {
		t.Fatal("expired quarantine must allow a fresh independently verified claim")
	}
}
