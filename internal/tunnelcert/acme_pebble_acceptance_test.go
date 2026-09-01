package tunnelcert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestACMEIssuerPebbleWildcard is deliberately opt-in. It runs the complete
// RFC 8555 DNS-01 exchange against an isolated Pebble/challtestsrv pair and
// therefore proves the production ACME client without contacting a public CA
// or using provider credentials.
func TestACMEIssuerPebbleWildcard(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_ACME_DIRECTORY_URL"))
	management := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_ACME_DNS_MANAGEMENT_URL"))
	caPath := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_ACME_CA_FILE"))
	if directory == "" || management == "" || caPath == "" {
		t.Skip("set PAPERBOAT_TEST_ACME_DIRECTORY_URL, PAPERBOAT_TEST_ACME_DNS_MANAGEMENT_URL, and PAPERBOAT_TEST_ACME_CA_FILE")
	}
	caPEM, err := os.ReadFile(filepath.Clean(caPath))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("Pebble CA did not contain a certificate")
	}
	if certificateCAPath := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_ACME_CERT_CA_FILE")); certificateCAPath != "" {
		certificateCAPEM, err := os.ReadFile(filepath.Clean(certificateCAPath))
		if err != nil {
			t.Fatal(err)
		}
		if !roots.AppendCertsFromPEM(certificateCAPEM) {
			t.Fatal("Pebble certificate CA did not contain a certificate")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newPebbleDNSProvider(management, client, &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "udp", "127.0.0.1:8053")
	}})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewACMEIssuer(ACMEIssuerConfig{DirectoryURL: directory, AccountKey: accountKey, DNS: provider, HTTPClient: client, Timeout: 90 * time.Second, PropagationTimeout: 20 * time.Second, CleanupTimeout: 10 * time.Second, PollInterval: 100 * time.Millisecond, RetryBase: 100 * time.Millisecond, RetryMax: time.Second, Issuer: "pebble", ChallengeZone: "challenge.paperboat.test"})
	if err != nil {
		t.Fatal(err)
	}
	challengeHost := "_acme-challenge.example.test"
	challengeTarget, err := DelegatedChallengeTarget("domain_pebble_1", "account_pebble_1", "tunnel_pebble_1", "dns-challenge://domain_pebble_1", "challenge.paperboat.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.SetCNAME(context.Background(), challengeHost, challengeTarget); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := provider.ClearCNAME(cleanupCtx, challengeHost, challengeTarget); err != nil {
			t.Errorf("clear delegated challenge CNAME: %v", err)
		}
	}()
	cnameCtx, cancelCNAME := context.WithTimeout(context.Background(), 5*time.Second)
	if err := provider.WaitCNAME(cnameCtx, challengeHost, challengeTarget); err != nil {
		cancelCNAME()
		t.Fatal(err)
	}
	cancelCNAME()
	bundle, err := issuer.IssueDNS01(context.Background(), Domain{ID: "domain_pebble_1", AccountID: "account_pebble_1", TunnelID: "tunnel_pebble_1", Hostname: "*.example.test", ChallengeReference: "dns-challenge://domain_pebble_1", Generation: 1, Strategy: StrategyWildcard, OwnershipState: "verified", CAAState: "not_applicable"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := bundle.Validate("*.example.test", time.Now().UTC(), 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !identity.Wildcard || identity.Hostname != "*.example.test" {
		t.Fatalf("unexpected Pebble certificate identity: %+v", identity)
	}
	assertPebbleTLSHandshake(t, bundle, roots)

	// A second order for the same identity exercises the renewal path and
	// proves that a replacement certificate gets a distinct key/fingerprint.
	renewed, err := issuer.IssueDNS01(context.Background(), Domain{ID: "domain_pebble_1", AccountID: "account_pebble_1", TunnelID: "tunnel_pebble_1", Hostname: "*.example.test", ChallengeReference: "dns-challenge://domain_pebble_1", Generation: 2, Strategy: StrategyWildcard, OwnershipState: "verified", CAAState: "not_applicable"})
	if err != nil {
		t.Fatal(err)
	}
	renewedIdentity, err := renewed.Validate("*.example.test", time.Now().UTC(), 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if renewedIdentity.Fingerprint == identity.Fingerprint {
		t.Fatal("renewal reused the prior certificate")
	}
	if err := issuer.RevokeBundle(context.Background(), renewed); err != nil {
		t.Fatal(err)
	}

	// Platform wildcards are server-owned Cloudflare records. Their TXT is
	// written directly at _acme-challenge.<base>, so this order deliberately has
	// no delegated CNAME configured in challtestsrv.
	platformDomain := Domain{
		ID: PlatformPreviewTargetID, AccountID: PlatformAccountID,
		TargetKind: TargetPlatformWildcard, Hostname: "*.platform.example.test",
		ChallengeReference: PlatformPreviewChallengeReference, Generation: 1,
		Strategy: StrategyPlatformDNS01, OwnershipState: "verified", CAAState: "not_applicable",
	}
	platformBundle, err := issuer.IssueDNS01(context.Background(), platformDomain)
	if err != nil {
		t.Fatal(err)
	}
	platformIdentity, err := platformBundle.Validate(platformDomain.Hostname, time.Now().UTC(), 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !platformIdentity.Wildcard || platformIdentity.Hostname != platformDomain.Hostname {
		t.Fatalf("unexpected direct platform certificate identity: %+v", platformIdentity)
	}
	provider.mu.Lock()
	var directRecordFound bool
	presented := append([]DNS01Record(nil), provider.presented...)
	for _, record := range provider.presented {
		if record.Name == "_acme-challenge.platform.example.test" && record.TargetName == record.Name {
			directRecordFound = true
			break
		}
	}
	provider.mu.Unlock()
	if !directRecordFound {
		t.Fatalf("platform ACME order did not write direct TXT: %+v", presented)
	}
	if err := issuer.RevokeBundle(context.Background(), platformBundle); err != nil {
		t.Fatal(err)
	}
}

func assertPebbleTLSHandshake(t *testing.T, bundle CertificateBundle, roots *x509.CertPool) {
	t.Helper()
	certificate, err := tls.X509KeyPair(bundle.CertificatePEM, bundle.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- acceptErr
			return
		}
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok {
			connection.Close()
			result <- errors.New("Pebble handshake accepted non-TLS connection")
			return
		}
		err := tlsConnection.Handshake()
		connection.Close()
		result <- err
	}()
	client, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "preview.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Handshake(); err != nil {
		client.Close()
		t.Fatal(err)
	}
	client.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Pebble TLS handshake")
	}
}

type pebbleDNSProvider struct {
	base      string
	client    *http.Client
	resolver  *net.Resolver
	mu        sync.Mutex
	presented []DNS01Record
}

func newPebbleDNSProvider(base string, client *http.Client, resolver *net.Resolver) (*pebbleDNSProvider, error) {
	parsed := strings.TrimRight(strings.TrimSpace(base), "/")
	if parsed == "" || client == nil || resolver == nil || !strings.HasPrefix(parsed, "http://") && !strings.HasPrefix(parsed, "https://") {
		return nil, errors.New("invalid Pebble DNS management endpoint")
	}
	return &pebbleDNSProvider{base: parsed, client: client, resolver: resolver}, nil
}

func (p *pebbleDNSProvider) Present(ctx context.Context, record DNS01Record) (DNS01Record, error) {
	if p == nil || record.Name == "" || record.Value == "" {
		return DNS01Record{}, errors.New("invalid DNS record")
	}
	if err := p.post(ctx, "/set-txt", map[string]string{"host": ensureFQDN(record.Name), "value": record.Value}); err != nil {
		return DNS01Record{}, err
	}
	record.ProviderID = strings.TrimPrefix(strings.ReplaceAll(record.Name, ".", "_"), "_")
	p.mu.Lock()
	p.presented = append(p.presented, record)
	p.mu.Unlock()
	return record, nil
}

func (p *pebbleDNSProvider) Wait(ctx context.Context, record DNS01Record) error {
	if p == nil || p.resolver == nil {
		return errors.New("DNS resolver is unavailable")
	}
	for {
		values, err := p.resolver.LookupTXT(ctx, strings.TrimSuffix(record.Name, "."))
		if err == nil {
			for _, value := range values {
				if value == record.Value {
					return nil
				}
			}
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (p *pebbleDNSProvider) Cleanup(ctx context.Context, record DNS01Record) error {
	if p == nil || record.Name == "" {
		return errors.New("invalid DNS record")
	}
	return p.post(ctx, "/clear-txt", map[string]string{"host": ensureFQDN(record.Name)})
}

func (p *pebbleDNSProvider) SetCNAME(ctx context.Context, host, target string) error {
	if p == nil || host == "" || target == "" {
		return errors.New("invalid DNS CNAME")
	}
	return p.post(ctx, "/set-cname", map[string]string{"host": ensureFQDN(host), "target": ensureFQDN(target)})
}

func (p *pebbleDNSProvider) ClearCNAME(ctx context.Context, host, target string) error {
	if p == nil || host == "" || target == "" {
		return errors.New("invalid DNS CNAME")
	}
	return p.post(ctx, "/clear-cname", map[string]string{"host": ensureFQDN(host), "target": ensureFQDN(target)})
}

func (p *pebbleDNSProvider) WaitCNAME(ctx context.Context, host, target string) error {
	if p == nil || p.resolver == nil || host == "" || target == "" {
		return errors.New("DNS resolver is unavailable")
	}
	want := strings.ToLower(ensureFQDN(target))
	for {
		got, err := p.resolver.LookupCNAME(ctx, strings.TrimSuffix(host, "."))
		if err == nil && strings.ToLower(ensureFQDN(got)) == want {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("wait for delegated CNAME %s: %w", host, ctx.Err())
		case <-timer.C:
		}
	}
}

func (p *pebbleDNSProvider) post(ctx context.Context, path string, payload map[string]string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Pebble DNS management returned HTTP %d", response.StatusCode)
	}
	return nil
}

func ensureFQDN(value string) string {
	if strings.HasSuffix(value, ".") {
		return value
	}
	return value + "."
}
