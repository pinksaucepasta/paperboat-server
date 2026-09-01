package tunnelcert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type testSecretSource struct {
	value []byte
}

func (s testSecretSource) Resolve(context.Context, string) ([]byte, error) {
	return append([]byte(nil), s.value...), nil
}

type testTXTResolver struct {
	mu     sync.Mutex
	values [][]string
}

func (r *testTXTResolver) LookupTXT(context.Context, string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.values) == 0 {
		return nil, nil
	}
	value := r.values[0]
	if len(r.values) > 1 {
		r.values = r.values[1:]
	}
	return value, nil
}

func TestCloudflareDNSProviderUsesWriteOnlyReferenceAndCleansUp(t *testing.T) {
	const token = "cloudflare-secret-token"
	var gotAuth string
	var gotBody struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
		Proxied bool   `json:"proxied"`
	}
	var deletePath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"record_123"}}`))
			return
		}
		deletePath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":null}`))
	}))
	defer server.Close()
	resolver := &testTXTResolver{values: [][]string{nil, {"expected-value"}}}
	provider, err := NewCloudflareDNSProvider(CloudflareDNSConfig{BaseURL: server.URL + "/client/v4/", ZoneID: "zone_123", TokenReference: "secret/cloudflare", TokenSource: testSecretSource{value: []byte(token)}, Resolver: resolver, PropagationWait: 100 * time.Millisecond, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	record, err := provider.Present(context.Background(), DNS01Record{Domain: "preview.example.test", Name: "_acme-challenge.preview.example.test", Value: "expected-value", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if record.ProviderID != "record_123" || gotAuth != "Bearer "+token || gotBody.Type != "TXT" || gotBody.Name != "_acme-challenge.preview.example.test" || gotBody.Content != "expected-value" || gotBody.TTL != 60 || gotBody.Proxied {
		t.Fatalf("record=%+v auth=%q body=%+v", record, gotAuth, gotBody)
	}
	if err := provider.Wait(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := provider.Cleanup(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if deletePath != "/client/v4/zones/zone_123/dns_records/record_123" {
		t.Fatalf("delete path=%q", deletePath)
	}
}

func TestCloudflareDNSProviderNeverReturnsCredentialOrResponseBody(t *testing.T) {
	const token = "sensitive-cloudflare-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"` + token + `"}]}`))
	}))
	defer server.Close()
	provider, err := NewCloudflareDNSProvider(CloudflareDNSConfig{BaseURL: server.URL, ZoneID: "zone_123", TokenReference: "secret/cloudflare", TokenSource: testSecretSource{value: []byte(token)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Present(context.Background(), DNS01Record{Domain: "preview.example.test", Name: "_acme-challenge.preview.example.test", Value: "value", TTL: time.Minute})
	if err == nil || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "success") {
		t.Fatalf("unsafe provider error=%v", err)
	}
}

func TestDNSCAAInspectorUsesClosestPolicyAndWildcardTag(t *testing.T) {
	queryer := &testCAAQueryer{answers: map[string][]*dns.CAA{
		"_example.test.": {{Hdr: dns.RR_Header{Name: "_example.test.", Rrtype: dns.TypeCAA, Class: dns.ClassINET}, Tag: "issue", Value: "other-ca.example"}},
		"example.test.":  {{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeCAA, Class: dns.ClassINET}, Tag: "issue", Value: "letsencrypt.org"}, {Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeCAA, Class: dns.ClassINET}, Tag: "issuewild", Value: "other-ca.example"}},
	}}
	inspector, err := NewDNSCAAInspector(DNSCAAInspectorConfig{Server: "127.0.0.1:53", Queryer: queryer, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := inspector.Check(context.Background(), "www.example.test", "letsencrypt.org")
	if err != nil || ordinary.State != "ready" {
		t.Fatalf("ordinary=%+v err=%v", ordinary, err)
	}
	wildcard, err := inspector.Check(context.Background(), "*.example.test", "letsencrypt.org")
	// The policy result is intentionally a typed state rather than a Go
	// error, so callers can expose a stable CAA diagnostic.
	if err != nil || wildcard.State != "blocked" {
		t.Fatalf("wildcard=%+v err=%v", wildcard, err)
	}
}

func TestDNSCAAInspectorAllowsUnrestrictedAndHonorsCriticalPolicies(t *testing.T) {
	tests := []struct {
		name       string
		records    []*dns.CAA
		hostname   string
		wantState  string
		wantReason string
	}{
		{name: "iodef only ordinary", records: []*dns.CAA{{Tag: "iodef", Value: "mailto:security@example.test"}}, hostname: "www.example.test", wantState: "ready"},
		{name: "iodef only wildcard", records: []*dns.CAA{{Tag: "iodef", Value: "mailto:security@example.test"}}, hostname: "*.example.test", wantState: "ready"},
		{name: "wildcard falls back to issue", records: []*dns.CAA{{Tag: "issue", Value: "letsencrypt.org"}}, hostname: "*.example.test", wantState: "ready"},
		{name: "wildcard issuewild wins", records: []*dns.CAA{{Tag: "issue", Value: "letsencrypt.org"}, {Tag: "issuewild", Value: "other-ca.example"}}, hostname: "*.example.test", wantState: "blocked", wantReason: "caa_issuer_not_authorized"},
		{name: "empty issue denies", records: []*dns.CAA{{Tag: "issue", Value: "; accounturi=https://example.test"}}, hostname: "www.example.test", wantState: "blocked", wantReason: "caa_issuance_forbidden"},
		{name: "unknown noncritical ignored", records: []*dns.CAA{{Flag: 0, Tag: "accounturi", Value: "opaque"}}, hostname: "www.example.test", wantState: "ready"},
		{name: "unknown critical blocks", records: []*dns.CAA{{Flag: 128, Tag: "accounturi", Value: "opaque"}}, hostname: "www.example.test", wantState: "blocked", wantReason: "caa_unsupported_critical_tag"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			queryer := &testCAAQueryer{answers: map[string][]*dns.CAA{"example.test.": test.records}}
			inspector, err := NewDNSCAAInspector(DNSCAAInspectorConfig{Server: "127.0.0.1:53", Queryer: queryer, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			result, err := inspector.Check(context.Background(), test.hostname, "letsencrypt.org")
			if err != nil || result.State != test.wantState || result.FailureCode != test.wantReason {
				t.Fatalf("result=%+v err=%v, want state=%s reason=%s", result, err, test.wantState, test.wantReason)
			}
		})
	}
}

type testCAAQueryer struct {
	answers map[string][]*dns.CAA
}

func (q *testCAAQueryer) ExchangeContext(_ context.Context, request *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
	name := request.Question[0].Name
	answers, ok := q.answers[name]
	if !ok {
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}, 0, nil
	}
	message := new(dns.Msg)
	message.SetReply(request)
	for _, answer := range answers {
		message.Answer = append(message.Answer, answer)
	}
	return message, 0, nil
}
