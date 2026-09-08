package tunnelcert

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newAddressProvider(t *testing.T, server *httptest.Server, token string) *CloudflareDNSProvider {
	t.Helper()
	provider, err := NewCloudflareDNSProvider(CloudflareDNSConfig{BaseURL: server.URL + "/client/v4/", ZoneID: "zone_123", TokenReference: "secret/cloudflare", TokenSource: testSecretSource{value: []byte(token)}, AddressAdmission: newCloudflareAddressAdmission()})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestCloudflareAddressCreateIsBoundedDNSOnly(t *testing.T) {
	var body cloudflareAddressRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"record_123"}}`))
	}))
	defer server.Close()
	record, err := newAddressProvider(t, server, "token").CreateAddressRecord(context.Background(), AddressRecord{Hostname: "Edge.Example.Test.", Address: "8.8.8.8", Owner: "route_1", Generation: 7}, false)
	if err != nil {
		t.Fatal(err)
	}
	if record.ProviderID != "record_123" || record.Hostname != "edge.example.test" || body.Type != "A" || body.TTL != 60 || body.Proxied || body.Comment != "paperboat owner=route_1 generation=7" {
		t.Fatalf("record=%+v body=%+v", record, body)
	}
	for _, address := range []string{"10.0.0.1", "192.0.2.1", "2001:db8::1"} {
		if _, err := newAddressProvider(t, server, "token").CreateAddressRecord(context.Background(), AddressRecord{Hostname: "edge.example.test", Address: address, Owner: "route_1", Generation: 7}, true); !errors.Is(err, ErrInvalid) {
			t.Fatalf("address %s accepted: %v", address, err)
		}
	}
	_, err = newAddressProvider(t, server, "token").CreateAddressRecord(context.Background(), AddressRecord{Hostname: "edge.example.test", Address: "2606:4700:4700::1111", Owner: "route_1", Generation: 7}, false)
	var typed *AddressPublicationError
	if !errors.As(err, &typed) || typed.Kind != AddressPublicationUnsupported {
		t.Fatalf("unverified AAAA error=%v", err)
	}
}

func TestCloudflareAddressDeleteRejectsWrongOwner(t *testing.T) {
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
		}
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"record_123","type":"A","name":"edge.example.test","content":"8.8.8.8","comment":"paperboat owner=another_route generation=7"}}`))
	}))
	defer server.Close()
	err := newAddressProvider(t, server, "token").DeleteAddressRecord(context.Background(), AddressRecord{ProviderID: "record_123", Hostname: "edge.example.test", Address: "8.8.8.8", Owner: "route_1", Generation: 7})
	var typed *AddressPublicationError
	if !errors.As(err, &typed) || typed.Kind != AddressPublicationConflict || deletes.Load() != 0 {
		t.Fatalf("error=%v deletes=%d", err, deletes.Load())
	}
}

func TestCloudflareAddressListRejectsConflictingExactRecords(t *testing.T) {
	tests := []struct{ name, record string }{
		{"foreign owner", `{"id":"record_1","type":"A","name":"edge.example.test","content":"8.8.8.8","ttl":60,"proxied":false,"comment":"paperboat owner=other generation=1"}`},
		{"cname", `{"id":"record_1","type":"CNAME","name":"edge.example.test","content":"other.example.test","ttl":60,"proxied":false}`},
		{"proxied owned", `{"id":"record_1","type":"A","name":"edge.example.test","content":"8.8.8.8","ttl":60,"proxied":true,"comment":"paperboat owner=route_1 generation=1"}`},
		{"wrong ttl", `{"id":"record_1","type":"A","name":"edge.example.test","content":"8.8.8.8","ttl":120,"proxied":false,"comment":"paperboat owner=route_1 generation=1"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"success":true,"result":[` + test.record + `],"result_info":{"total_pages":1}}`))
			}))
			defer server.Close()
			_, err := newAddressProvider(t, server, "token").ListAddressRecords(context.Background(), "edge.example.test", "route_1")
			var typed *AddressPublicationError
			if !errors.As(err, &typed) || typed.Kind != AddressPublicationConflict {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCloudflareAddressUncertainPostIsNotReplayedOrLeaked(t *testing.T) {
	const token = "sensitive-address-token"
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		hijacker := w.(http.Hijacker)
		connection, _, err := hijacker.Hijack()
		if err == nil {
			_ = connection.Close()
		}
	}))
	defer server.Close()
	_, err := newAddressProvider(t, server, token).CreateAddressRecord(context.Background(), AddressRecord{Hostname: "edge.example.test", Address: "8.8.4.4", Owner: "route_1", Generation: 1}, false)
	if posts.Load() != 1 || err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("posts=%d error=%v", posts.Load(), err)
	}
}

func TestCloudflareAddressAdmissionHonorsCancellation(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
	}))
	defer server.Close()
	provider := newAddressProvider(t, server, "token")
	for i := 0; i < 2; i++ {
		go provider.ListAddressRecords(context.Background(), "edge.example.test", "route_1")
	}
	<-started
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := provider.ListAddressRecords(ctx, "edge.example.test", "route_1")
	close(release)
	var typed *AddressPublicationError
	if !errors.As(err, &typed) || typed.Kind != AddressPublicationPending {
		t.Fatalf("error=%v", err)
	}
}

func TestCloudflareAddressAdmissionEnforcesBurstAndRetryAfter(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
	}))
	defer server.Close()
	provider := newAddressProvider(t, server, "token")
	_, _ = provider.ListAddressRecords(context.Background(), "edge.example.test", "route_1")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := provider.ListAddressRecords(ctx, "edge.example.test", "route_1")
	var typed *AddressPublicationError
	if !errors.As(err, &typed) || typed.Kind != AddressPublicationPending || calls.Load() != 1 {
		t.Fatalf("error=%v calls=%d", err, calls.Load())
	}
}

func TestCloudflareAddressReservedStepPreventsReadStarvation(t *testing.T) {
	var calls, deletes atomic.Int32
	record := cloudflareAddressRecord{ID: "record_123", Type: "A", Name: "edge.example.test", Content: "8.8.8.8", TTL: 60, Comment: addressComment("route_1", 7)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		if strings.Contains(r.URL.Path, "record_123") {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": record})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []cloudflareAddressRecord{record}})
	}))
	defer server.Close()
	provider := newAddressProvider(t, server, "token")
	admission := provider.addressAdmission.(*cloudflareAddressAdmission)
	// Model each replenished credit without waiting six seconds per token.
	for credits := 0; credits < 3; credits++ {
		admission.mu.Lock()
		admission.tokens = float64(credits)
		admission.updated = time.Now()
		admission.mu.Unlock()
		for range 3 {
			_, _, err := provider.ReserveAddressStep(context.Background())
			if !isAddressErrorKind(err, AddressPublicationPending) {
				t.Fatalf("partial budget admitted a step: %v", err)
			}
		}
		admission.mu.Lock()
		remaining := admission.tokens
		admission.mu.Unlock()
		if remaining < float64(credits) || calls.Load() != 0 {
			t.Fatalf("failed passes consumed reads or credits: remaining=%f calls=%d", remaining, calls.Load())
		}
	}
	admission.mu.Lock()
	admission.tokens = 3
	admission.updated = time.Now()
	admission.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reserved, release, err := provider.ReserveAddressStep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	records, err := provider.ListAddressRecords(reserved, "edge.example.test", "route_1")
	if err != nil {
		release()
		t.Fatal(err)
	}
	if err := provider.DeleteAddressRecord(reserved, records[0]); err != nil {
		release()
		t.Fatal(err)
	}
	release()
	if calls.Load() != 3 || deletes.Load() != 1 {
		t.Fatalf("withdrawal failed to progress: calls=%d deletes=%d", calls.Load(), deletes.Load())
	}
}

func TestCloudflareAddressReservationRefundAndRetryAfter(t *testing.T) {
	admission := newCloudflareAddressAdmission()
	reserved, closeReservation, err := admission.Reserve(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	release, err := admission.Acquire(reserved)
	if err != nil {
		t.Fatal(err)
	}
	release()
	admission.Block(context.Background(), "1")
	if _, err := admission.Acquire(reserved); !isAddressErrorKind(err, AddressPublicationPending) {
		t.Fatalf("reserved request ignored Retry-After: %v", err)
	}
	closeReservation()
	closeReservation()
	admission.mu.Lock()
	remaining := admission.tokens
	admission.mu.Unlock()
	if remaining != 4 {
		t.Fatalf("unused credits not refunded exactly once: %f", remaining)
	}
	if len(admission.concurrent) != 0 {
		t.Fatal("reservation leaked concurrency permit")
	}
}
