package tunnelv1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

type fakeTunnelRepository struct {
	verifyErr     error
	createErr     error
	patchErr      error
	transitionErr error
	getErr        error
	listErr       error
	create        CreateRecord
	patch         PatchRecord
	transition    StateRecord
	tunnel        dbsqlc.Tunnel
	list          []dbsqlc.Tunnel
	createResult  MutationRecord
	patchResult   MutationRecord
	stateResult   MutationRecord
}

func (f *fakeTunnelRepository) VerifyHost(_ context.Context, accountID, hostID string) error {
	if f.verifyErr != nil {
		return f.verifyErr
	}
	if accountID != "acct_1" || hostID != "host_1" {
		return ErrHostNotFound
	}
	return nil
}

func (f *fakeTunnelRepository) Create(_ context.Context, input CreateRecord) (MutationRecord, error) {
	f.create = input
	if f.createErr != nil {
		return MutationRecord{}, f.createErr
	}
	if f.createResult.Tunnel.ID == "" {
		f.createResult = MutationRecord{
			Tunnel: dbsqlc.Tunnel{
				ID: input.TunnelID, AccountID: input.AccountID, Name: input.Name,
				DesiredState: DesiredActive, AccessMode: input.AccessMode, Generation: 1,
				StableEndpointID: input.StableEndpointID, StableEndpoint: input.StableEndpoint,
				CreatedByHostID: input.HostID, CreatedByActorID: input.ActorID,
				ExpiresAt: input.ExpiresAt, SummaryCode: "pending",
				SummaryTransitionedAt: testNow, CreatedAt: testNow, UpdatedAt: testNow,
			},
			Operation: testOperation(input.OperationID, input.TunnelID, "connecting", "running", "changed"),
			Changed:   true,
		}
	}
	return f.createResult, nil
}

func (f *fakeTunnelRepository) Get(_ context.Context, _, _ string) (dbsqlc.Tunnel, error) {
	if f.getErr != nil {
		return dbsqlc.Tunnel{}, f.getErr
	}
	return f.tunnel, nil
}

func (f *fakeTunnelRepository) List(_ context.Context, _ string, _ *ListPosition, _ int) ([]dbsqlc.Tunnel, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.list, nil
}

func (f *fakeTunnelRepository) Patch(_ context.Context, input PatchRecord) (MutationRecord, error) {
	f.patch = input
	if f.patchErr != nil {
		return MutationRecord{}, f.patchErr
	}
	return f.patchResult, nil
}

func (f *fakeTunnelRepository) Transition(_ context.Context, input StateRecord) (MutationRecord, error) {
	f.transition = input
	if f.transitionErr != nil {
		return MutationRecord{}, f.transitionErr
	}
	return f.stateResult, nil
}

func (f *fakeTunnelRepository) ReconcileExpired(context.Context, ExpiryRecord) ([]MutationRecord, error) {
	return nil, nil
}

var testNow = time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)

func testRequest(host bool) previewtunnelapi.RequestContext {
	actor := previewtunnelapi.Actor{
		AccountID: "acct_1", ActorID: "user_1", Role: "user",
		Scopes: []string{"tunnels:read", "tunnels:write"},
	}
	if host {
		actor.DeviceID = "host_1"
		actor.HostID = "host_1"
	}
	return previewtunnelapi.RequestContext{Actor: actor, RequestID: "req_1", CorrelationID: "corr_1"}
}

func testHash() [sha256.Size]byte {
	var hash [sha256.Size]byte
	hash[0] = 1
	return hash
}

func testOperation(id, resourceID, phase, state, outcome string) dbsqlc.Operation {
	return dbsqlc.Operation{
		ID: id, AccountID: "acct_1", ResourceID: sql.NullString{String: resourceID, Valid: resourceID != ""},
		OperationType: "tunnel.create", ResourceKind: "tunnel", Phase: phase, State: state,
		Progress: 40, Outcome: outcome, CorrelationID: "corr_1", CreatedAt: testNow, UpdatedAt: testNow,
	}
}

func testService(t *testing.T, repository *fakeTunnelRepository, newID func(string) (string, error)) *Service {
	t.Helper()
	service, err := NewService(repository, Config{
		EndpointBuilder: func(name, endpointID string) (string, error) {
			return fmt.Sprintf("https://%s.tunnels.example.test", endpointID), nil
		},
		CursorKey: bytes.Repeat([]byte{7}, 32), Now: func() time.Time { return testNow }, NewID: newID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func sequentialID() func(string) (string, error) {
	var n int
	return func(prefix string) (string, error) {
		n++
		return fmt.Sprintf("%s_%d", prefix, n), nil
	}
}

func TestCreateTunnelRequiresVerifiedHostAndPersistsInitialOrigin(t *testing.T) {
	repository := &fakeTunnelRepository{}
	service := testService(t, repository, sequentialID())
	result, err := service.CreateTunnel(context.Background(), testRequest(true), CreateTunnelRequest{
		Name: "demo", Origin: OriginRequest{Scheme: "http", Address: "127.0.0.1:3000"},
		MutationInput: MutationInput{IdempotencyKey: "op_create_1", RequestHash: testHash()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if repository.create.HostID != "host_1" || repository.create.ActorID != "user_1" || repository.create.AuditActorID != "host_1" || repository.create.ActorType != "host" || repository.create.Origin.Address != "127.0.0.1:3000" {
		t.Fatalf("create record lost verified host or origin: %+v", repository.create)
	}
	if repository.create.AccessMode != AccessPublic || result.Tunnel.AccessMode != AccessPublic {
		t.Fatalf("access mode = %q, want public", result.Tunnel.AccessMode)
	}
	if result.Tunnel.StableEndpoint == "" || result.Operation.State != "running" || result.Operation.Phase != "connecting" {
		t.Fatalf("create readiness = tunnel=%+v operation=%+v", result.Tunnel, result.Operation)
	}
}

func TestCreateTunnelRejectsMissingOrForgedHost(t *testing.T) {
	service := testService(t, &fakeTunnelRepository{}, sequentialID())
	input := CreateTunnelRequest{
		Name: "demo", Origin: OriginRequest{Scheme: "http", Address: "127.0.0.1:3000"},
		MutationInput: MutationInput{IdempotencyKey: "op_create_1", RequestHash: testHash()},
	}
	if _, err := service.CreateTunnel(context.Background(), testRequest(false), input); !errors.Is(err, previewtunnelapi.ErrHostActorRequired) {
		t.Fatalf("missing host error = %v", err)
	}
	repository := &fakeTunnelRepository{verifyErr: ErrHostNotFound}
	service = testService(t, repository, sequentialID())
	if _, err := service.CreateTunnel(context.Background(), testRequest(true), input); !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("forged/unowned host error = %v", err)
	}
	mismatched := testRequest(true)
	mismatched.Actor.DeviceID = "different-device"
	service = testService(t, &fakeTunnelRepository{}, sequentialID())
	if _, err := service.CreateTunnel(context.Background(), mismatched, input); !errors.Is(err, previewtunnelapi.ErrHostActorRequired) {
		t.Fatalf("mismatched host/device error = %v", err)
	}
}

func TestCreateTunnelPropagatesIdempotencyConflict(t *testing.T) {
	repository := &fakeTunnelRepository{createErr: ErrIdempotencyConflict}
	service := testService(t, repository, sequentialID())
	_, err := service.CreateTunnel(context.Background(), testRequest(true), CreateTunnelRequest{
		Name: "demo", Origin: OriginRequest{Scheme: "https", Address: "origin.test:443"},
		MutationInput: MutationInput{IdempotencyKey: "op_create_1", RequestHash: testHash()},
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency error = %v", err)
	}
}

func TestMutationRejectsIDGenerationFailure(t *testing.T) {
	newID := func(string) (string, error) { return "", errors.New("entropy unavailable") }
	service := testService(t, &fakeTunnelRepository{}, newID)
	name := "renamed"
	request := testRequest(false)
	request.RequestID = ""
	request.CorrelationID = ""
	_, err := service.PatchTunnel(context.Background(), request, "tun_1", PatchTunnelRequest{
		Name: &name, MutationInput: MutationInput{ExpectedGeneration: 1, IdempotencyKey: "op_patch_1", RequestHash: testHash()},
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("ID allocation error = %v", err)
	}
}

func TestStatusProjectsExpiryWithoutChangingDesiredIdentity(t *testing.T) {
	expires := testNow.Add(-time.Minute)
	repository := &fakeTunnelRepository{tunnel: dbsqlc.Tunnel{
		ID: "tun_1", AccountID: "acct_1", DesiredState: DesiredActive, AccessMode: AccessPrivate,
		Generation: 4, StableEndpointID: "11111111-1111-4111-8111-111111111111", StableEndpoint: "https://11111111-1111-4111-8111-111111111111.tunnels.example.test",
		ExpiresAt: sql.NullTime{Time: expires, Valid: true}, SummaryCode: "pending",
		SummaryTransitionedAt: testNow.Add(-time.Hour), CreatedAt: testNow.Add(-time.Hour), UpdatedAt: testNow.Add(-time.Hour),
	}}
	service := testService(t, repository, sequentialID())
	status, err := service.Status(context.Background(), testRequest(false), "tun_1")
	if err != nil {
		t.Fatal(err)
	}
	if status.OverallCode != "tunnel_expired" || status.Dimensions.Route.Code != "route_expired" || status.Retrying {
		t.Fatalf("expiry status = %+v", status)
	}
	if repository.tunnel.DesiredState != DesiredActive || repository.tunnel.StableEndpointID != "11111111-1111-4111-8111-111111111111" {
		t.Fatal("status projection changed durable desired identity")
	}
}

func TestTunnelAdmissionGateUsesDurableExpiryAndDesiredState(t *testing.T) {
	if !TunnelAdmissionAllowed(dbsqlc.Tunnel{DesiredState: DesiredActive, ExpiresAt: sql.NullTime{Time: testNow.Add(time.Minute), Valid: true}}, testNow) {
		t.Fatal("active unexpired tunnel was rejected")
	}
	for _, tunnel := range []dbsqlc.Tunnel{
		{DesiredState: DesiredPaused},
		{DesiredState: DesiredDeleted},
		{DesiredState: DesiredActive, ExpiresAt: sql.NullTime{Time: testNow, Valid: true}},
	} {
		if TunnelAdmissionAllowed(tunnel, testNow) {
			t.Fatalf("admitted tunnel outside durable gate: %+v", tunnel)
		}
	}
}

func TestOperationViewMapsUncertainToCanonicalFailure(t *testing.T) {
	operation := testOperation("op_1", "tun_1", "connecting", "uncertain", "uncertain")
	view := previewtunnelapi.OperationView(operation, "req_1")
	if view.State != "failed" || view.Error == nil || view.Error.Code != "operation_outcome_uncertain" || view.Error.Outcome != "uncertain" {
		t.Fatalf("uncertain operation = %+v", view)
	}
}

func TestOriginValidationAcceptsPrivateLoopbackAndIPv6(t *testing.T) {
	for _, address := range []string{"127.0.0.1:3000", "localhost:80", "origin.example.test:443", "[::1]:8080"} {
		if err := validateOriginRequest(OriginRequest{Scheme: "http", Address: address}); err != nil {
			t.Errorf("address %q rejected: %v", address, err)
		}
	}
	for _, host := range []string{"example.test", "localhost", "::1"} {
		if err := validateOriginRequest(OriginRequest{Scheme: "http", Address: "127.0.0.1:3000", HostOverride: &host}); err != nil {
			t.Errorf("host override %q rejected: %v", host, err)
		}
	}
}

func TestOriginValidationAcceptsH2CAndUnixSchemes(t *testing.T) {
	if err := validateOriginRequest(OriginRequest{Scheme: "h2c", Address: "127.0.0.1:3000"}); err != nil {
		t.Fatalf("h2c origin rejected: %v", err)
	}
	if err := validateOriginRequest(OriginRequest{Scheme: "unix", Address: "/tmp/paperboat.sock"}); err != nil {
		t.Fatalf("unix origin rejected: %v", err)
	}
}

func TestOriginValidationRejectsURLsMalformedPortsAndHeaderInjection(t *testing.T) {
	for _, address := range []string{
		"http://origin.test:3000", "origin.test", "origin.test:0", "origin.test:65536",
		"origin.test:080", "origin.test:not-a-port", "origin.test:3000/path", "user:pass@origin.test:3000",
		"origin.test:3000\r\nX-Injected: yes", ":3000", "[::1]",
	} {
		if err := validateOriginRequest(OriginRequest{Scheme: "http", Address: address}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("address %q error = %v, want ErrInvalidInput", address, err)
		}
	}
	for _, host := range []string{"example.test:443", "https://example.test", "example.test/path", "example.test\r\nX-Test: yes", "-bad.test", "bad_.test"} {
		if err := validateOriginRequest(OriginRequest{Scheme: "http", Address: "127.0.0.1:3000", HostOverride: &host}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("host override %q error = %v, want ErrInvalidInput", host, err)
		}
	}
}

func TestCreateTunnelRejectsPublicTCPButAllowsPrivateTCP(t *testing.T) {
	input := CreateTunnelRequest{
		Name: "tcp-demo", Origin: OriginRequest{Scheme: "tcp", Address: "127.0.0.1:5432"},
		MutationInput: MutationInput{IdempotencyKey: "op_tcp_1", RequestHash: testHash()},
	}
	service := testService(t, &fakeTunnelRepository{}, sequentialID())
	if _, err := service.CreateTunnel(context.Background(), testRequest(true), input); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("public TCP error = %v, want ErrInvalidInput", err)
	}
	input.AccessMode = AccessPrivate
	result, err := service.CreateTunnel(context.Background(), testRequest(true), input)
	if err != nil || result.Tunnel.AccessMode != AccessPrivate {
		t.Fatalf("private TCP create = %#v, %v", result, err)
	}
}

func TestEndpointBuilderUsesCanonicalUUIDAndIgnoresName(t *testing.T) {
	builder, err := NewEndpointBuilder("https://tunnels.example.test")
	if err != nil {
		t.Fatal(err)
	}
	endpointID := "11111111-1111-4111-8111-111111111111"
	longName := "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk"
	first, err := builder(longName, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := builder("renamed", endpointID)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://" + endpointID + ".tunnels.example.test"
	if first != want || second != want {
		t.Fatalf("endpoints = %q/%q, want %q", first, second, want)
	}
	if err := validateStableEndpoint(first); err != nil {
		t.Fatalf("canonical endpoint %q rejected: %v", first, err)
	}
	for _, invalidID := range []string{"tep_0123456789012345678901", "11111111-1111-4111-0111-111111111111", "11111111-1111-4111-8111-11111111111A"} {
		if _, err := builder("demo", invalidID); err == nil {
			t.Fatalf("accepted non-canonical endpoint identity %q", invalidID)
		}
	}
	if _, err := NewEndpointBuilder("https://" + strings.Repeat("a", 64) + ".example.test"); err == nil {
		t.Fatal("accepted an overlong endpoint base label")
	}
}

func TestCreateTunnelEndpointUUIDIsStableAcrossIdempotentReplay(t *testing.T) {
	repository := &fakeTunnelRepository{}
	endpointIDs := []string{
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
	}
	var endpointIndex int
	builder, err := NewEndpointBuilder("https://tunnels.example.test")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository, Config{
		EndpointBuilder: builder,
		CursorKey:       bytes.Repeat([]byte{7}, 32),
		Now:             func() time.Time { return testNow },
		NewID:           sequentialID(),
		NewEndpointID: func() (string, error) {
			value := endpointIDs[endpointIndex]
			endpointIndex++
			return value, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := CreateTunnelRequest{
		Name: "original", Origin: OriginRequest{Scheme: "http", Address: "127.0.0.1:3000"},
		MutationInput: MutationInput{IdempotencyKey: "create-replay", RequestHash: testHash()},
	}
	first, err := service.CreateTunnel(context.Background(), testRequest(true), input)
	if err != nil {
		t.Fatal(err)
	}
	input.Name = "renamed"
	second, err := service.CreateTunnel(context.Background(), testRequest(true), input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Tunnel.StableEndpointID != endpointIDs[0] || first.Tunnel.StableEndpoint != "https://"+endpointIDs[0]+".tunnels.example.test" {
		t.Fatalf("first endpoint = %+v", first.Tunnel)
	}
	if second.Tunnel.StableEndpointID != first.Tunnel.StableEndpointID || second.Tunnel.StableEndpoint != first.Tunnel.StableEndpoint {
		t.Fatalf("replay changed durable endpoint: first=%+v second=%+v", first.Tunnel, second.Tunnel)
	}
	if repository.create.StableEndpointID != endpointIDs[1] {
		t.Fatalf("second attempt did not allocate a fresh candidate before repository replay: %q", repository.create.StableEndpointID)
	}
}
