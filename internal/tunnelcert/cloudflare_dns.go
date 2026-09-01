package tunnelcert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	cloudflareAPIBase       = "https://api.cloudflare.com/client/v4/"
	maxCloudflareResponse   = 1 << 20
	maxCloudflareTokenBytes = 512
	defaultCloudflarePoll   = 2 * time.Second
	defaultCloudflareWait   = 2 * time.Minute
	defaultCloudflareTries  = 4
)

// DNSSecretSource resolves a write-only provider credential by reference.
// The returned bytes are used for one request and must not be persisted by an
// implementation or included in an error.
type DNSSecretSource interface {
	Resolve(context.Context, string) ([]byte, error)
}

type TXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type CloudflareDNSConfig struct {
	BaseURL         string
	ZoneID          string
	TokenReference  string
	TokenSource     DNSSecretSource
	HTTPClient      *http.Client
	Resolver        TXTResolver
	PropagationWait time.Duration
	PollInterval    time.Duration
	MaxAttempts     int
}

// CloudflareDNSProvider is deliberately record-scoped. It never accepts a
// raw token in its public constructor and never returns the token or an API
// response body to callers.
type CloudflareDNSProvider struct {
	baseURL         *url.URL
	zoneID          string
	tokenReference  string
	tokens          DNSSecretSource
	httpClient      *http.Client
	resolver        TXTResolver
	propagationWait time.Duration
	pollInterval    time.Duration
	maxAttempts     int
}

func NewCloudflareDNSProvider(config CloudflareDNSConfig) (*CloudflareDNSProvider, error) {
	base := config.BaseURL
	if base == "" {
		base = cloudflareAPIBase
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: Cloudflare API endpoint is invalid", ErrInvalid)
	}
	if parsed.Scheme == "http" {
		if ip := net.ParseIP(parsed.Hostname()); ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("%w: insecure Cloudflare API endpoint must be loopback", ErrInvalid)
		}
	}
	if !validKeyReference(config.TokenReference) || config.TokenSource == nil || !validMetadata(config.ZoneID, 128) {
		return nil, fmt.Errorf("%w: Cloudflare token reference and zone are required", ErrInvalid)
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{}
	} else {
		clone := *client
		client = &clone
	}
	client.Timeout = 30 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrDNSChallengeUnavailable }
	propagationWait := config.PropagationWait
	if propagationWait <= 0 || propagationWait > 10*time.Minute {
		propagationWait = defaultCloudflareWait
	}
	pollInterval := config.PollInterval
	if pollInterval <= 0 || pollInterval > time.Minute {
		pollInterval = defaultCloudflarePoll
	}
	maxAttempts := config.MaxAttempts
	if maxAttempts <= 0 || maxAttempts > 8 {
		maxAttempts = defaultCloudflareTries
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &CloudflareDNSProvider{baseURL: parsed, zoneID: config.ZoneID, tokenReference: config.TokenReference, tokens: config.TokenSource, httpClient: client, resolver: resolver, propagationWait: propagationWait, pollInterval: pollInterval, maxAttempts: maxAttempts}, nil
}

func (p *CloudflareDNSProvider) Present(ctx context.Context, record DNS01Record) (DNS01Record, error) {
	ctx = certificateContext(ctx)
	if p == nil || p.tokens == nil || p.baseURL == nil || !validDNS01Record(record) {
		return DNS01Record{}, ErrDNSChallengeUnavailable
	}
	token, err := p.tokens.Resolve(ctx, p.tokenReference)
	if err != nil || len(token) == 0 || len(token) > maxCloudflareTokenBytes || strings.ContainsAny(string(token), "\r\n\x00") {
		return DNS01Record{}, fmt.Errorf("%w: Cloudflare credential resolution failed", ErrDNSChallengeUnavailable)
	}
	defer clearBytes(token)
	payload, err := json.Marshal(struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
		Proxied bool   `json:"proxied"`
	}{Type: "TXT", Name: strings.TrimSuffix(record.Name, "."), Content: record.Value, TTL: int(record.TTL / time.Second), Proxied: false})
	if err != nil {
		return DNS01Record{}, ErrDNSChallengeUnavailable
	}
	path := "zones/" + url.PathEscape(p.zoneID) + "/dns_records"
	var result cloudflareRecordResult
	if err := p.request(ctx, http.MethodPost, path, token, payload, &result); err != nil {
		return DNS01Record{}, err
	}
	if !result.Success || !validProviderID(result.Result.ID) {
		return DNS01Record{}, ErrDNSChallengeUnavailable
	}
	record.ProviderID = result.Result.ID
	record.Name = strings.TrimSuffix(record.Name, ".")
	return record, nil
}

func (p *CloudflareDNSProvider) Wait(ctx context.Context, record DNS01Record) error {
	ctx = certificateContext(ctx)
	if p == nil || !validDNS01Record(record) || !validProviderID(record.ProviderID) {
		return ErrDNSChallengeUnavailable
	}
	waitCtx, cancel := context.WithTimeout(ctx, p.propagationWait)
	defer cancel()
	for {
		values, err := p.resolver.LookupTXT(waitCtx, record.Name)
		if err == nil {
			for _, value := range values {
				if value == record.Value {
					return nil
				}
			}
		}
		timer := time.NewTimer(p.pollInterval)
		select {
		case <-waitCtx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if errors.Is(waitCtx.Err(), context.Canceled) || errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("%w: DNS TXT record did not propagate", ErrDNSChallengePending)
			}
			return ErrDNSChallengePending
		case <-timer.C:
		}
	}
}

func (p *CloudflareDNSProvider) Cleanup(ctx context.Context, record DNS01Record) error {
	ctx = certificateContext(ctx)
	if p == nil || p.baseURL == nil || !validProviderID(record.ProviderID) {
		return ErrDNSChallengeUnavailable
	}
	token, err := p.tokens.Resolve(ctx, p.tokenReference)
	if err != nil || len(token) == 0 || len(token) > maxCloudflareTokenBytes || strings.ContainsAny(string(token), "\r\n\x00") {
		return fmt.Errorf("%w: Cloudflare credential resolution failed", ErrDNSChallengeUnavailable)
	}
	defer clearBytes(token)
	path := "zones/" + url.PathEscape(p.zoneID) + "/dns_records/" + url.PathEscape(record.ProviderID)
	return p.request(ctx, http.MethodDelete, path, token, nil, nil)
}

type cloudflareRecordResult struct {
	Success bool `json:"success"`
	Result  struct {
		ID string `json:"id"`
	} `json:"result"`
}

func (p *CloudflareDNSProvider) request(ctx context.Context, method, path string, token, body []byte, output any) error {
	ctx = certificateContext(ctx)
	endpoint := p.baseURL.ResolveReference(&url.URL{Path: strings.TrimSuffix(p.baseURL.Path, "/") + "/" + strings.TrimPrefix(path, "/")})
	for attempt := 1; attempt <= p.maxAttempts; attempt++ {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
		if err != nil {
			return ErrDNSChallengeUnavailable
		}
		request.Header.Set("Authorization", "Bearer "+string(token))
		request.Header.Set("Accept", "application/json")
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
			fingerprint := sha256.Sum256(body)
			request.Header.Set("X-Paperboat-Idempotency-Key", "dns01_"+hex.EncodeToString(fingerprint[:]))
		}
		response, err := p.httpClient.Do(request)
		if err != nil {
			if attempt == p.maxAttempts {
				return ErrDNSChallengeUnavailable
			}
			if err := waitContext(ctx, dnsRetryDelay(attempt, "")); err != nil {
				return err
			}
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxCloudflareResponse+1))
		response.Body.Close()
		if readErr != nil || len(data) > maxCloudflareResponse {
			return ErrDNSChallengeUnavailable
		}
		if response.StatusCode == http.StatusNotFound && method == http.MethodDelete {
			return nil
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			if output == nil {
				return nil
			}
			if err := json.Unmarshal(data, output); err != nil {
				return ErrDNSChallengeUnavailable
			}
			return nil
		}
		if attempt < p.maxAttempts && (response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500) {
			if err := waitContext(ctx, dnsRetryDelay(attempt, response.Header.Get("Retry-After"))); err != nil {
				return err
			}
			continue
		}
		return ErrDNSChallengeUnavailable
	}
	return ErrDNSChallengeUnavailable
}

func dnsRetryDelay(attempt int, retryAfter string) time.Duration {
	if value := parseRetryAfter(retryAfter, time.Now().UTC()); value > 0 && value <= 30*time.Second {
		return value
	}
	delay := 250 * time.Millisecond
	for step := 1; step < attempt; step++ {
		delay *= 2
	}
	if delay > 5*time.Second {
		return 5 * time.Second
	}
	return delay
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validDNS01Record(record DNS01Record) bool {
	if !validMetadata(record.Domain, 253) || !validMetadata(record.Name, 253) || record.Value == "" || len(record.Value) > maxACMEDNSRecordValueLength || record.TTL < 30*time.Second || record.TTL > 24*time.Hour {
		return false
	}
	host, wildcard, err := normalizeHostname(record.Domain)
	if err != nil {
		return false
	}
	authorizationName := record.AuthorizationName
	if authorizationName == "" {
		authorizationName = "_acme-challenge." + strings.TrimPrefix(host, "*.")
	}
	want := "_acme-challenge." + strings.TrimPrefix(host, "*.")
	if !strings.EqualFold(strings.TrimSuffix(authorizationName, "."), want) {
		return false
	}
	targetName := record.TargetName
	if targetName == "" {
		targetName = record.Name
	}
	if !strings.EqualFold(strings.TrimSuffix(targetName, "."), strings.TrimSuffix(record.Name, ".")) {
		return false
	}
	if wildcard && strings.HasPrefix(targetName, "*.") {
		return false
	}
	return strings.TrimSpace(record.Value) == record.Value && !strings.ContainsAny(record.Value, "\r\n\x00")
}

func validProviderID(value string) bool {
	if len(value) < 1 || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, char := range value {
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ DNS01Provider = (*CloudflareDNSProvider)(nil)
