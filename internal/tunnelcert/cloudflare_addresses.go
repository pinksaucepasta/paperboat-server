package tunnelcert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cloudflareAddressCallTimeout = 5 * time.Second
	cloudflareAddressBurst       = 5
	cloudflareAddressResultLimit = 100
)

// AddressRecord is the complete identity of a Paperboat-owned provider record.
// ProviderID is empty before creation and required for deletion.
type AddressRecord struct {
	ProviderID string
	Hostname   string
	Address    string
	Owner      string
	Generation uint64
}

type AddressPublicationErrorKind string

const (
	AddressPublicationPending     AddressPublicationErrorKind = "pending"
	AddressPublicationConflict    AddressPublicationErrorKind = "conflict"
	AddressPublicationUnsupported AddressPublicationErrorKind = "unsupported"
)

// AddressPublicationError lets the reconciler branch without parsing provider
// text. Detail is deliberately a stable, non-secret Paperboat description.
type AddressPublicationError struct {
	Kind   AddressPublicationErrorKind
	Detail string
}

func (e *AddressPublicationError) Error() string {
	return "address publication " + string(e.Kind) + ": " + e.Detail
}

func addressError(kind AddressPublicationErrorKind, detail string) error {
	return &AddressPublicationError{Kind: kind, Detail: detail}
}

type cloudflareAddressAdmission struct {
	concurrent chan struct{}
	mu         sync.Mutex
	tokens     float64
	updated    time.Time
	blocked    time.Time
}

// CloudflareAddressAdmission bounds provider calls. Production uses the
// database-backed implementation so replicas share one per-zone budget.
type CloudflareAddressAdmission interface {
	Acquire(context.Context) (func(), error)
	Reserve(context.Context, int) (context.Context, func(), error)
	Block(context.Context, string)
}

func newCloudflareAddressAdmission() *cloudflareAddressAdmission {
	return &cloudflareAddressAdmission{concurrent: make(chan struct{}, 2), tokens: cloudflareAddressBurst, updated: time.Now()}
}

func (a *cloudflareAddressAdmission) Acquire(ctx context.Context) (func(), error) {
	if reservation, ok := ctx.Value(addressReservationKey{}).(*addressReservation); ok && reservation.owner == a {
		return reservation.acquire(ctx)
	}
	for {
		a.mu.Lock()
		now := time.Now()
		if now.Before(a.blocked) {
			wait := time.Until(a.blocked)
			a.mu.Unlock()
			if err := waitContext(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}
		elapsed := now.Sub(a.updated).Seconds()
		a.tokens += elapsed / 6 // ten calls per minute
		if a.tokens > cloudflareAddressBurst {
			a.tokens = cloudflareAddressBurst
		}
		a.updated = now
		if a.tokens >= 1 {
			a.tokens--
			a.mu.Unlock()
			break
		}
		wait := time.Duration((1 - a.tokens) * 6 * float64(time.Second))
		a.mu.Unlock()
		if err := waitContext(ctx, wait); err != nil {
			return nil, err
		}
	}
	select {
	case a.concurrent <- struct{}{}:
		return func() { <-a.concurrent }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type addressReservationKey struct{}
type addressReservation struct {
	owner      CloudflareAddressAdmission
	mu         sync.Mutex
	remaining  int
	closed     bool
	concurrent chan struct{}
	check      func(context.Context) error
	refund     func(int)
}

func (r *addressReservation) acquire(ctx context.Context) (func(), error) {
	select {
	case r.concurrent <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release := func() { <-r.concurrent }
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.remaining == 0 {
		release()
		return nil, addressError(AddressPublicationPending, "reserved provider step exhausted")
	}
	if err := r.check(ctx); err != nil {
		release()
		return nil, err
	}
	r.remaining--
	return release, nil
}
func (r *addressReservation) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	r.refund(r.remaining)
	r.remaining = 0
}
func (a *cloudflareAddressAdmission) Reserve(ctx context.Context, count int) (context.Context, func(), error) {
	if count < 1 || count > cloudflareAddressBurst {
		return nil, nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	select {
	case a.concurrent <- struct{}{}:
	default:
		return nil, nil, addressError(AddressPublicationPending, "provider concurrency unavailable")
	}
	a.mu.Lock()
	now := time.Now()
	a.tokens = min(float64(cloudflareAddressBurst), a.tokens+now.Sub(a.updated).Seconds()/6)
	a.updated = now
	if now.Before(a.blocked) || a.tokens < float64(count) {
		a.mu.Unlock()
		<-a.concurrent
		return nil, nil, addressError(AddressPublicationPending, "provider step budget unavailable")
	}
	a.tokens -= float64(count)
	a.mu.Unlock()
	reservation := &addressReservation{owner: a, remaining: count, concurrent: make(chan struct{}, 1)}
	reservation.check = func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if time.Now().Before(a.blocked) {
			return addressError(AddressPublicationPending, "provider retry after active")
		}
		return nil
	}
	reservation.refund = func(unused int) {
		a.mu.Lock()
		a.tokens = min(float64(cloudflareAddressBurst), a.tokens+float64(unused))
		a.mu.Unlock()
		<-a.concurrent
	}
	return context.WithValue(ctx, addressReservationKey{}, reservation), reservation.close, nil
}

// ReserveAddressStep funds LIST plus one identity-checked deletion before any
// provider reads. A pending reservation consumes no tokens or provider calls.
func (p *CloudflareDNSProvider) ReserveAddressStep(ctx context.Context) (context.Context, func(), error) {
	if p.addressAdmission == nil {
		return nil, nil, addressError(AddressPublicationPending, "provider admission unavailable")
	}
	return p.addressAdmission.Reserve(ctx, 3)
}

func (a *cloudflareAddressAdmission) Block(_ context.Context, retryAfter string) {
	delay := parseRetryAfter(retryAfter, time.Now().UTC())
	if delay <= 0 {
		return
	}
	a.mu.Lock()
	until := time.Now().Add(delay)
	if until.After(a.blocked) {
		a.blocked = until
	}
	a.mu.Unlock()
}

type cloudflareAddressRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}

type cloudflareAddressList struct {
	Success    bool                      `json:"success"`
	Result     []cloudflareAddressRecord `json:"result"`
	ResultInfo struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

// ListAddressRecords returns only exact-name Paperboat-owned A/AAAA records.
func (p *CloudflareDNSProvider) ListAddressRecords(ctx context.Context, hostname, owner string) ([]AddressRecord, error) {
	host, err := validAddressIdentity(hostname, owner, 1)
	if err != nil {
		return nil, err
	}
	var response cloudflareAddressList
	path := "zones/" + url.PathEscape(p.zoneID) + "/dns_records?name=" + url.QueryEscape(host) + "&per_page=" + strconv.Itoa(cloudflareAddressResultLimit)
	if err := p.addressRequest(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	if !response.Success || len(response.Result) > cloudflareAddressResultLimit || response.ResultInfo.TotalPages > 1 {
		return nil, addressError(AddressPublicationPending, "provider response is incomplete")
	}
	result := make([]AddressRecord, 0, len(response.Result))
	for _, item := range response.Result {
		if !strings.EqualFold(strings.TrimSuffix(item.Name, "."), host) {
			continue
		}
		if item.Type == "CNAME" {
			return nil, addressError(AddressPublicationConflict, "exact hostname has a CNAME record")
		}
		if item.Type != "A" && item.Type != "AAAA" {
			continue
		}
		itemOwner, generation, ok := parseAddressComment(item.Comment)
		if !ok || itemOwner != owner {
			return nil, addressError(AddressPublicationConflict, "exact hostname has an address record owned by another writer")
		}
		ip, err := netip.ParseAddr(item.Content)
		if !validProviderID(item.ID) || err != nil || !publicAddress(ip) || item.TTL != 60 || item.Proxied {
			return nil, addressError(AddressPublicationConflict, "owned address record does not match the publication contract")
		}
		result = append(result, AddressRecord{ProviderID: item.ID, Hostname: host, Address: ip.Unmap().String(), Owner: itemOwner, Generation: generation})
	}
	return result, nil
}

// CreateAddressRecord performs one write attempt. A request error is pending:
// callers must list and reconcile before deciding whether to try another POST.
func (p *CloudflareDNSProvider) CreateAddressRecord(ctx context.Context, record AddressRecord, ipv6ReachabilityVerified bool) (AddressRecord, error) {
	host, ip, err := validateAddressRecord(record, false)
	if err != nil {
		return AddressRecord{}, err
	}
	recordType := "A"
	if ip.Is6() {
		if !ipv6ReachabilityVerified {
			return AddressRecord{}, addressError(AddressPublicationUnsupported, "AAAA requires verified public IPv6 reachability")
		}
		recordType = "AAAA"
	}
	payload, _ := json.Marshal(struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
		Proxied bool   `json:"proxied"`
		Comment string `json:"comment"`
	}{Type: recordType, Name: host, Content: ip.String(), TTL: 60, Proxied: false, Comment: addressComment(record.Owner, record.Generation)})
	var response struct {
		Success bool                    `json:"success"`
		Result  cloudflareAddressRecord `json:"result"`
	}
	path := "zones/" + url.PathEscape(p.zoneID) + "/dns_records"
	if err := p.addressRequest(ctx, http.MethodPost, path, payload, &response); err != nil {
		return AddressRecord{}, err
	}
	if !response.Success || !validProviderID(response.Result.ID) {
		return AddressRecord{}, addressError(AddressPublicationPending, "provider did not confirm creation")
	}
	record.ProviderID, record.Hostname, record.Address = response.Result.ID, host, ip.String()
	return record, nil
}

// DeleteAddressRecord reads the provider record by ID and deletes only when
// every supplied identity field still matches. A missing record is complete.
func (p *CloudflareDNSProvider) DeleteAddressRecord(ctx context.Context, record AddressRecord) error {
	host, ip, err := validateAddressRecord(record, true)
	if err != nil {
		return err
	}
	path := "zones/" + url.PathEscape(p.zoneID) + "/dns_records/" + url.PathEscape(record.ProviderID)
	var response struct {
		Success bool                    `json:"success"`
		Result  cloudflareAddressRecord `json:"result"`
	}
	err = p.addressRequest(ctx, http.MethodGet, path, nil, &response)
	if errors.Is(err, errAddressRecordMissing) {
		return nil
	}
	if err != nil {
		return err
	}
	owner, generation, ok := parseAddressComment(response.Result.Comment)
	if !response.Success || response.Result.ID != record.ProviderID || !strings.EqualFold(strings.TrimSuffix(response.Result.Name, "."), host) || response.Result.Content != ip.String() || owner != record.Owner || generation != record.Generation || !ok {
		return addressError(AddressPublicationConflict, "provider record identity changed")
	}
	return p.addressRequest(ctx, http.MethodDelete, path, nil, nil)
}

var errAddressRecordMissing = errors.New("address record missing")

func (p *CloudflareDNSProvider) addressRequest(parent context.Context, method, path string, body []byte, output any) error {
	if p == nil || p.baseURL == nil || p.tokens == nil {
		return addressError(AddressPublicationPending, "provider is unavailable")
	}
	if p.addressAdmission == nil {
		return addressError(AddressPublicationPending, "provider admission is unavailable")
	}
	release, err := p.addressAdmission.Acquire(parent)
	if err != nil {
		return addressError(AddressPublicationPending, "provider admission deadline exceeded")
	}
	defer release()
	ctx, cancel := context.WithTimeout(parent, cloudflareAddressCallTimeout)
	defer cancel()
	token, err := p.tokens.Resolve(ctx, p.tokenReference)
	if err != nil || len(token) == 0 || len(token) > maxCloudflareTokenBytes || strings.ContainsAny(string(token), "\r\n\x00") {
		return addressError(AddressPublicationPending, "credential resolution failed")
	}
	defer clearBytes(token)
	pathPart, rawQuery, _ := strings.Cut(path, "?")
	endpoint := p.baseURL.ResolveReference(&url.URL{Path: strings.TrimSuffix(p.baseURL.Path, "/") + "/" + strings.TrimPrefix(pathPart, "/"), RawQuery: rawQuery})
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return addressError(AddressPublicationPending, "request construction failed")
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := p.httpClient.Do(request)
	if err != nil {
		return addressError(AddressPublicationPending, "provider outcome is uncertain")
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxCloudflareResponse+1))
	if readErr != nil || len(data) > maxCloudflareResponse {
		return addressError(AddressPublicationPending, "provider response exceeded bounds")
	}
	if response.StatusCode == http.StatusTooManyRequests {
		p.addressAdmission.Block(ctx, response.Header.Get("Retry-After"))
	}
	if response.StatusCode == http.StatusNotFound && method == http.MethodGet {
		return errAddressRecordMissing
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return addressError(AddressPublicationPending, "provider rejected request")
	}
	if output != nil && json.Unmarshal(data, output) != nil {
		return addressError(AddressPublicationPending, "provider response was invalid")
	}
	return nil
}

func validAddressIdentity(hostname, owner string, generation uint64) (string, error) {
	host, _, err := normalizeHostname(hostname)
	if err != nil || !validMetadata(owner, 128) || generation == 0 || strings.ContainsAny(owner, "=\r\n\x00") {
		return "", fmt.Errorf("%w: address record identity is invalid", ErrInvalid)
	}
	return host, nil
}

func validateAddressRecord(record AddressRecord, requireID bool) (string, netip.Addr, error) {
	host, err := validAddressIdentity(record.Hostname, record.Owner, record.Generation)
	ip, parseErr := netip.ParseAddr(record.Address)
	if err != nil || parseErr != nil || !publicAddress(ip) || requireID && !validProviderID(record.ProviderID) || !requireID && record.ProviderID != "" {
		return "", netip.Addr{}, fmt.Errorf("%w: address record is invalid", ErrInvalid)
	}
	return host, ip.Unmap(), nil
}

var nonPublicAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2001:2::/48"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:10::/28"), netip.MustParsePrefix("2001:20::/28"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

func publicAddress(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range nonPublicAddressPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func addressComment(owner string, generation uint64) string {
	return "paperboat owner=" + owner + " generation=" + strconv.FormatUint(generation, 10)
}

func parseAddressComment(comment string) (string, uint64, bool) {
	const prefix = "paperboat owner="
	if !strings.HasPrefix(comment, prefix) {
		return "", 0, false
	}
	parts := strings.Split(strings.TrimPrefix(comment, prefix), " generation=")
	if len(parts) != 2 {
		return "", 0, false
	}
	generation, err := strconv.ParseUint(parts[1], 10, 64)
	return parts[0], generation, err == nil && generation > 0 && parts[0] != ""
}
