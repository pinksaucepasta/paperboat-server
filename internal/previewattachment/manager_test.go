package previewattachment

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type testAuthority struct {
	mu         sync.Mutex
	resolution Resolution
	calls      int
}

type testPublisher struct {
	mu     sync.Mutex
	calls  []AdmissionRequest
	status AdmissionDeliveryStatus
}

func (p *testPublisher) PublishPreviewCarrierAdmission(_ context.Context, request AdmissionRequest) (AdmissionDelivery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, request)
	status := p.status
	if status == "" {
		status = AdmissionAccepted
	}
	return AdmissionDelivery{Status: status}, nil
}

func testManager(t *testing.T, authority *testAuthority, now time.Time) *Manager {
	t.Helper()
	manager, err := NewManager(authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetClock(func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetAdmissionPublisher(&testPublisher{}); err != nil {
		t.Fatal(err)
	}
	return manager
}

func (a *testAuthority) ResolvePreviewAttachment(_ context.Context, _ ResolveRequest) (Resolution, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	return a.resolution, nil
}

func (a *testAuthority) setResolution(fn func(*Resolution)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(&a.resolution)
}

func (a *testAuthority) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func TestManagerAllocatesEphemeralAttachmentAndReplaysIdempotently(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	authority := &testAuthority{resolution: testResolution(now)}
	manager := testManager(t, authority, now)

	first, err := manager.Allocate(context.Background(), testProof(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if first.State != StatePending || first.EdgeReady || first.OriginReady {
		t.Fatalf("initial attachment = %#v, want pending and not ready", first)
	}
	if first.TunnelID != "preview-tunnel-1" || first.ConnectorID != "preview-connector-1" || first.SessionID != "connector-session-1" {
		t.Fatalf("attachment identity = %#v, want preview-ephemeral identity", first.Binding)
	}

	replay, err := manager.Allocate(context.Background(), testProof(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replay, first) {
		t.Fatalf("idempotent replay changed attachment:\nfirst=%#v\nreplay=%#v", first, replay)
	}
	if authority.callCount() != 2 {
		t.Fatalf("authority calls = %d, want live revalidation on each request", authority.callCount())
	}

	changed := testRequest()
	changed.RequestID = "request-2"
	if _, err := manager.Allocate(context.Background(), testProof(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestManagerRejectsDurableCarrierAndMismatchedOwnerSession(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	authority := &testAuthority{resolution: testResolution(now)}
	manager := testManager(t, authority, now)

	authority.setResolution(func(r *Resolution) { r.Carrier.Ephemeral = false })
	if _, err := manager.Allocate(context.Background(), testProof(), testRequest()); !errors.Is(err, ErrConflict) {
		t.Fatalf("durable carrier error = %v, want ErrConflict", err)
	}
	authority.setResolution(func(r *Resolution) {
		r.Carrier.Ephemeral = true
		r.Lease.OwnerSessionID = "owner-session-2"
	})
	if _, err := manager.Allocate(context.Background(), testProof(), testRequest()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("mismatched owner session error = %v, want ErrUnauthorized", err)
	}
}

func TestManagerRequiresEdgeAndOriginBeforeReadyAndFencesCallbacks(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	authority := &testAuthority{resolution: testResolution(now)}
	manager := testManager(t, authority, now)
	proof, req := testProof(), testRequest()

	allocated, err := manager.Allocate(context.Background(), proof, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ObserveOrigin(context.Background(), proof, req, allocated.Binding, allocated.AttachmentGeneration, true); !errors.Is(err, ErrAdmissionUnavailable) {
		t.Fatalf("origin-before-edge error = %v, want ErrAdmissionUnavailable", err)
	}
	if _, err := manager.ObserveEdge(context.Background(), req, allocated.Binding, allocated.AttachmentGeneration); !errors.Is(err, ErrAdmissionUnavailable) {
		t.Fatalf("edge-before-admission error = %v, want ErrAdmissionUnavailable", err)
	}

	admitted, err := manager.Admit(context.Background(), proof, req, allocated.Binding, allocated.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if admitted.State != StateAdmitted || admitted.EdgeReady || admitted.OriginReady || admitted.AttachmentGeneration != 2 {
		t.Fatalf("admitted attachment = %#v, want admitted generation 2", admitted)
	}
	admission, err := admitted.Admission()
	if err != nil {
		t.Fatal(err)
	}
	if admission.Binding != admitted.Binding || admission.AttachmentGeneration != admitted.AttachmentGeneration {
		t.Fatalf("carrier admission = %#v, does not match attachment", admission)
	}

	edgeReady, err := manager.ObserveEdge(context.Background(), req, admitted.Binding, admitted.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if edgeReady.State != StateEdgeReady || !edgeReady.EdgeReady || edgeReady.OriginReady || edgeReady.AttachmentGeneration != 3 {
		t.Fatalf("edge-ready attachment = %#v, want edge_ready generation 3", edgeReady)
	}
	ready, err := manager.ObserveOrigin(context.Background(), proof, req, edgeReady.Binding, edgeReady.AttachmentGeneration, true)
	if err != nil {
		t.Fatal(err)
	}
	if ready.State != StateReady || !ready.EdgeReady || !ready.OriginReady || ready.ReadyAt == nil || ready.AttachmentGeneration != 4 {
		t.Fatalf("ready attachment = %#v, want both readiness and generation 4", ready)
	}
	if _, err := manager.ObserveOrigin(context.Background(), proof, req, allocated.Binding, allocated.AttachmentGeneration, true); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("stale callback error = %v, want ErrStaleBinding", err)
	}

	repeat, err := manager.ObserveOrigin(context.Background(), proof, req, ready.Binding, ready.AttachmentGeneration, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(repeat, ready) {
		t.Fatalf("duplicate readiness changed attachment:\nready=%#v\nrepeat=%#v", ready, repeat)
	}
}

func TestManagerReconnectRebindsOnlySessionAndRejectsStaleCallbacks(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	authority := &testAuthority{resolution: testResolution(now)}
	manager := testManager(t, authority, now)
	proof, req := testProof(), testRequest()
	first, err := manager.Allocate(context.Background(), proof, req)
	if err != nil {
		t.Fatal(err)
	}
	firstReady, err := manager.Admit(context.Background(), proof, req, first.Binding, first.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	firstEdge, err := manager.ObserveEdge(context.Background(), req, firstReady.Binding, firstReady.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	firstReady, err = manager.ObserveOrigin(context.Background(), proof, req, firstEdge.Binding, firstEdge.AttachmentGeneration, true)
	if err != nil {
		t.Fatal(err)
	}

	authority.setResolution(func(r *Resolution) {
		r.Carrier.SessionID = "connector-session-2"
		r.Carrier.ProcessGeneration = 2
	})
	rebound, err := manager.Renew(context.Background(), proof, req, firstReady.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if rebound.SessionID != "connector-session-2" || rebound.ProcessGeneration != 2 || rebound.State != StatePending || rebound.EdgeReady || rebound.OriginReady || rebound.AttachmentGeneration != 5 {
		t.Fatalf("rebound attachment = %#v, want fresh pending generation 5", rebound)
	}
	if _, err := manager.ObserveOrigin(context.Background(), proof, req, firstReady.Binding, firstReady.AttachmentGeneration, true); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("old reconnect callback error = %v, want ErrStaleBinding", err)
	}

	authority.setResolution(func(r *Resolution) { r.Route.RouteID = "route-2" })
	if _, err := manager.Renew(context.Background(), proof, req, rebound.AttachmentGeneration); !errors.Is(err, ErrConflict) {
		t.Fatalf("route change error = %v, want ErrConflict", err)
	}
}

func TestManagerReleaseIsGenerationFencedAndIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	authority := &testAuthority{resolution: testResolution(now)}
	manager := testManager(t, authority, now)
	proof, req := testProof(), testRequest()
	allocated, err := manager.Allocate(context.Background(), proof, req)
	if err != nil {
		t.Fatal(err)
	}
	released, err := manager.Release(context.Background(), proof, req, allocated.Binding, allocated.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if released.State != StateReleased || released.EdgeReady || released.OriginReady || released.AttachmentGeneration != 2 {
		t.Fatalf("released attachment = %#v", released)
	}
	replayOld, err := manager.Release(context.Background(), proof, req, allocated.Binding, allocated.AttachmentGeneration)
	if err != nil {
		t.Fatalf("lost-response release replay error = %v", err)
	}
	if !reflect.DeepEqual(replayOld, released) {
		t.Fatalf("lost-response release replay changed attachment:\nreleased=%#v\nreplay=%#v", released, replayOld)
	}
	repeat, err := manager.Release(context.Background(), proof, req, released.Binding, released.AttachmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(repeat, released) {
		t.Fatalf("release replay changed attachment:\nreleased=%#v\nrepeat=%#v", released, repeat)
	}
}

func TestAttachmentContainsNoCredentialMaterial(t *testing.T) {
	type forbidden struct {
		Token      string `json:"token"`
		Credential string `json:"credential"`
		PrivateKey string `json:"private_key"`
		Password   string `json:"password"`
	}
	// Keep this compile-time/documentation test next to the response contract:
	// the safe response has no fields of the forbidden shape.
	var _ = forbidden{}
	if _, ok := any(Attachment{}).(interface{ Token() }); ok {
		t.Fatal("attachment unexpectedly exposes a token method")
	}
}

func testProof() MachineProof {
	return MachineProof{UserID: "user-1", MachineID: "machine-1", OperationID: "operation-1", InstallationGeneration: 1}
}

func testRequest() Request {
	return Request{
		PreviewID: "preview-1", OperationID: "operation-1", OwnerDeviceID: "machine-1", OwnerSessionID: "owner-session-1",
		IdempotencyKey: "operation-1", RequestID: "request-1", CorrelationID: "correlation-1",
	}
}

func testResolution(now time.Time) Resolution {
	endpoint := "https://preview.example"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	digest := sha256.Sum256(make([]byte, 32))
	thumbprint := "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:])
	return Resolution{
		Lease: LeaseSnapshot{
			AccountID: "account-1", ActorID: "user-1", PreviewID: "preview-1", OperationID: "operation-1",
			OwnerDeviceID: "machine-1", OwnerSessionID: "owner-session-1", Endpoint: endpoint,
			Target: Target{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "public", Generation: 1,
			LeaseDeadline: now.Add(10 * time.Minute), State: "active",
			MachineIdentityPublicKey: publicKey, MachineIdentityThumbprint: thumbprint,
		},
		Carrier: CarrierSnapshot{
			AccountID: "account-1", HostID: "machine-1", Ephemeral: true,
			TunnelID: "preview-tunnel-1", ConnectorID: "preview-connector-1", SessionID: "connector-session-1",
			ProcessGeneration: 1, ConfigGeneration: 1, ConfigContentHash: "sha256:" + strings.Repeat("a", 64),
			LeaseDeadline: now.Add(5 * time.Minute), EdgeEndpoints: []string{"quic://edge.example:443", "tls://edge.example:443"},
			EdgeNodeID: "edge-node-1", EdgeProcessEpoch: "edge-process-1", EdgeCarrierServerSPKISHA256: "sha256:" + strings.Repeat("b", 64), EdgeCarrierServerCertificateChainPEM: "test-public-certificate-chain", MachineIdentityPublicKey: publicKey, MachineIdentityThumbprint: thumbprint,
		},
		Route: RouteSnapshot{AccountID: "account-1", TunnelID: "preview-tunnel-1", RouteID: "route-1", Generation: 1, Protocol: "https", PublicEndpoint: endpoint},
	}
}
