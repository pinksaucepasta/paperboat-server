package previewv1

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewdomain"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
)

type previewLeaseFake struct {
	owners         map[string]bool
	leases         map[string]previewtunnelstore.PreviewLeaseRecord
	operations     map[string]dbsqlc.Operation
	createKeys     map[string]string
	createHashes   map[string]string
	renewKeys      map[string]previewtunnelstore.RenewPreviewLeaseV1Result
	readyCalls     int
	uncertainCalls int
	readyInputs    []previewtunnelstore.MarkPreviewLeaseReadyV1Input
	reconcile      previewtunnelstore.ReconcilePreviewLeasesV1Result
	createInput    []previewtunnelstore.CreatePreviewLeaseV1Input
	createErrors   []error
}

func newPreviewLeaseFake() *previewLeaseFake {
	return &previewLeaseFake{
		owners: make(map[string]bool), leases: make(map[string]previewtunnelstore.PreviewLeaseRecord),
		operations: make(map[string]dbsqlc.Operation), createKeys: make(map[string]string), createHashes: make(map[string]string),
		renewKeys: make(map[string]previewtunnelstore.RenewPreviewLeaseV1Result),
	}
}

func (f *previewLeaseFake) VerifyPreviewLeaseOwnerV1(_ context.Context, accountID, ownerDeviceID string) error {
	if len(f.owners) > 0 && !f.owners[accountID+":"+ownerDeviceID] {
		return previewtunnelstore.ErrOwnerNotFound
	}
	return nil
}

func (f *previewLeaseFake) GetPreviewLeaseV1(_ context.Context, accountID, previewID string) (previewtunnelstore.PreviewLeaseRecord, error) {
	lease, ok := f.leases[accountID+":"+previewID]
	if !ok {
		return previewtunnelstore.PreviewLeaseRecord{}, previewtunnelstore.ErrNotFound
	}
	return lease, nil
}

func (f *previewLeaseFake) GetPreviewLeaseCreateOperationV1(_ context.Context, accountID, previewID string) (dbsqlc.Operation, error) {
	for _, operation := range f.operations {
		if operation.AccountID == accountID && operation.OperationType == "preview.create" && operation.ResourceID.Valid && operation.ResourceID.String == previewID {
			return operation, nil
		}
	}
	return dbsqlc.Operation{}, previewtunnelstore.ErrNotFound
}

func (f *previewLeaseFake) ListPreviewLeasesV1(_ context.Context, input previewtunnelstore.ListPreviewLeasesV1Input) ([]previewtunnelstore.PreviewLeaseRecord, error) {
	items := make([]previewtunnelstore.PreviewLeaseRecord, 0)
	for key, lease := range f.leases {
		if strings.HasPrefix(key, input.AccountID+":") {
			items = append(items, lease)
		}
	}
	return items, nil
}

func (f *previewLeaseFake) CreatePreviewLeaseV1(_ context.Context, input previewtunnelstore.CreatePreviewLeaseV1Input) (previewtunnelstore.CreatePreviewLeaseV1Result, error) {
	f.createInput = append(f.createInput, input)
	if len(f.createErrors) > 0 {
		err := f.createErrors[0]
		f.createErrors = f.createErrors[1:]
		return previewtunnelstore.CreatePreviewLeaseV1Result{}, err
	}
	if existingID := f.createKeys[input.AccountID+":"+input.IdempotencyKey]; existingID != "" {
		if f.createHashes[input.AccountID+":"+input.IdempotencyKey] != string(input.RequestHash) {
			return previewtunnelstore.CreatePreviewLeaseV1Result{}, previewtunnelstore.ErrIdempotencyConflict
		}
		return previewtunnelstore.CreatePreviewLeaseV1Result{
			Lease: f.leases[input.AccountID+":"+existingID], Operation: f.operations[input.AccountID+":"+input.IdempotencyKey], Replayed: true,
		}, nil
	}
	lease := previewtunnelstore.PreviewLeaseRecord{PreviewLease: dbsqlc.PreviewLease{
		ID: input.LeaseID, EndpointID: input.EndpointID, Endpoint: input.Endpoint, AccountID: input.AccountID,
		ActorID: input.ActorID, OwnerDeviceID: input.OwnerDeviceID, OwnerSessionID: input.OwnerSessionID,
		TargetScheme: input.TargetScheme, TargetAddress: input.TargetAddress, AccessMode: input.AccessMode,
		LeaseDeadline: input.LeaseDeadline, UserDeadline: input.UserDeadline, AllocationState: "pending",
		EdgeState: "pending", OriginState: "unknown", TerminalState: "active", CreatedAt: input.Now,
		LastRenewedAt: input.Now, Generation: 1, OwnerLastSeenAt: input.Now,
	}}
	op := dbsqlc.Operation{ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
		RequestHash: input.RequestHash, OperationType: "preview.create", ResourceKind: "preview_lease",
		ResourceID: sql.NullString{String: input.LeaseID, Valid: true}, Phase: "connecting", State: "running", Progress: 60,
		Outcome: "changed", CorrelationID: input.CorrelationID, CreatedAt: input.Now, UpdatedAt: input.Now}
	f.leases[input.AccountID+":"+lease.ID] = lease
	f.operations[input.AccountID+":"+input.IdempotencyKey] = op
	f.createKeys[input.AccountID+":"+input.IdempotencyKey] = lease.ID
	f.createHashes[input.AccountID+":"+input.IdempotencyKey] = string(input.RequestHash)
	return previewtunnelstore.CreatePreviewLeaseV1Result{Lease: lease, Operation: op}, nil
}

func (f *previewLeaseFake) RenewPreviewLeaseV1(_ context.Context, input previewtunnelstore.RenewPreviewLeaseV1Input) (previewtunnelstore.RenewPreviewLeaseV1Result, error) {
	if result, ok := f.renewKeys[input.AccountID+":"+input.IdempotencyKey]; ok {
		result.Replayed = true
		return result, nil
	}
	key := input.AccountID + ":" + input.PreviewID
	lease, ok := f.leases[key]
	if !ok {
		return previewtunnelstore.RenewPreviewLeaseV1Result{}, previewtunnelstore.ErrNotFound
	}
	if lease.Generation != input.ExpectedGeneration {
		return previewtunnelstore.RenewPreviewLeaseV1Result{}, previewtunnelstore.ErrGenerationConflict
	}
	if lease.TerminalState != "active" {
		return previewtunnelstore.RenewPreviewLeaseV1Result{}, previewtunnelstore.ErrPreviewLeaseTerminal
	}
	lease.LeaseDeadline, lease.LastRenewedAt, lease.OwnerLastSeenAt = input.LeaseDeadline, input.Now, input.Now
	lease.Generation++
	f.leases[key] = lease
	op := dbsqlc.Operation{ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
		RequestHash: input.RequestHash, OperationType: "preview.renew", ResourceKind: "preview_lease",
		ResourceID: sql.NullString{String: input.PreviewID, Valid: true}, Phase: "ready", State: "succeeded", Progress: 100,
		Outcome: "changed", CorrelationID: input.CorrelationID, CreatedAt: input.Now, UpdatedAt: input.Now, CompletedAt: sql.NullTime{Time: input.Now, Valid: true}}
	result := previewtunnelstore.RenewPreviewLeaseV1Result{Lease: lease, Operation: op}
	f.renewKeys[input.AccountID+":"+input.IdempotencyKey] = result
	return result, nil
}

func (f *previewLeaseFake) StopPreviewLeaseV1(_ context.Context, input previewtunnelstore.StopPreviewLeaseV1Input) (previewtunnelstore.StopPreviewLeaseV1Result, error) {
	key := input.AccountID + ":" + input.PreviewID
	lease, ok := f.leases[key]
	if !ok {
		return previewtunnelstore.StopPreviewLeaseV1Result{}, previewtunnelstore.ErrNotFound
	}
	if lease.TerminalState != "active" {
		return previewtunnelstore.StopPreviewLeaseV1Result{Lease: lease, Replayed: true}, nil
	}
	if lease.Generation != input.ExpectedGeneration {
		return previewtunnelstore.StopPreviewLeaseV1Result{}, previewtunnelstore.ErrGenerationConflict
	}
	lease.AllocationState, lease.EdgeState, lease.TerminalState = "released", "released", "stopped"
	lease.StoppedAt = sql.NullTime{Time: input.Now, Valid: true}
	lease.Generation++
	f.leases[key] = lease
	return previewtunnelstore.StopPreviewLeaseV1Result{Lease: lease}, nil
}

func (f *previewLeaseFake) MarkPreviewLeaseReadyV1(_ context.Context, input previewtunnelstore.MarkPreviewLeaseReadyV1Input) (previewtunnelstore.PreviewLeaseRecord, error) {
	f.readyCalls++
	f.readyInputs = append(f.readyInputs, input)
	key := input.AccountID + ":" + input.PreviewID
	lease, ok := f.leases[key]
	if !ok {
		return previewtunnelstore.PreviewLeaseRecord{}, previewtunnelstore.ErrNotFound
	}
	if lease.Generation != input.ExpectedGeneration {
		return previewtunnelstore.PreviewLeaseRecord{}, previewtunnelstore.ErrGenerationConflict
	}
	lease.AllocationState, lease.EdgeState, lease.OriginState = input.AllocationState, input.EdgeState, input.OriginState
	if input.AllocationState == "failed" {
		lease.TerminalState = "failed"
		lease.StoppedAt = sql.NullTime{Time: input.Now, Valid: true}
	}
	if input.AllocationState == "ready" && input.EdgeState == "ready" && input.OriginState == "ready" && !lease.ReadyAt.Valid {
		lease.ReadyAt = sql.NullTime{Time: input.Now, Valid: true}
	}
	lease.Generation++
	f.leases[key] = lease
	return lease, nil
}

func (f *previewLeaseFake) MarkPreviewLeaseDispatchUncertainV1(_ context.Context, input previewtunnelstore.MarkPreviewLeaseDispatchUncertainV1Input) error {
	f.uncertainCalls++
	for operationID, operation := range f.operations {
		if operation.AccountID == input.AccountID && operation.ResourceID.Valid && operation.ResourceID.String == input.PreviewID {
			operation.State, operation.ErrorCode, operation.Outcome = "uncertain", sql.NullString{String: input.ErrorCode, Valid: true}, "uncertain"
			operation.Retrying = true
			f.operations[operationID] = operation
			return nil
		}
	}
	return nil
}

func (f *previewLeaseFake) ReconcilePreviewLeasesV1(_ context.Context, _ previewtunnelstore.ReconcilePreviewLeasesV1Input) (previewtunnelstore.ReconcilePreviewLeasesV1Result, error) {
	return f.reconcile, nil
}

type incrementingReader struct{ next byte }

type previewDomainProjectionFake struct {
	rows []dbsqlc.PreviewDomain
}

func (f previewDomainProjectionFake) List(context.Context, string, string, *previewdomain.ListPosition, int) ([]dbsqlc.PreviewDomain, error) {
	return append([]dbsqlc.PreviewDomain(nil), f.rows...), nil
}

func (f previewDomainProjectionFake) ListProjection(context.Context, string, string, int) ([]dbsqlc.PreviewDomain, error) {
	return append([]dbsqlc.PreviewDomain(nil), f.rows...), nil
}

type recordingDispatcher struct {
	calls     []DispatchRequest
	sessions  map[string]struct{}
	nextError error
}

func (d *recordingDispatcher) Dispatch(_ context.Context, request DispatchRequest) (DispatchOutcome, error) {
	d.calls = append(d.calls, request)
	if d.sessions == nil {
		d.sessions = make(map[string]struct{})
	}
	d.sessions[request.OperationID] = struct{}{}
	if d.nextError != nil {
		err := d.nextError
		d.nextError = nil
		return DispatchOutcome{}, err
	}
	return DispatchOutcome{Schema: Schema, Kind: PreviewDispatchKind, PreviewID: request.PreviewID, OperationID: request.OperationID, State: "accepted", Generation: request.ExpectedGeneration}, nil
}

type uncertainDispatchError struct{}

func (uncertainDispatchError) Error() string          { return "dispatch outcome is uncertain" }
func (uncertainDispatchError) UncertainOutcome() bool { return true }

type attachmentReadinessFake struct {
	err   error
	calls int
}

func (f *attachmentReadinessFake) RequirePreviewAttachmentReady(_ context.Context, accountID, previewID, operationID, ownerDeviceID, ownerSessionID string) error {
	f.calls++
	if accountID == "" || previewID == "" || operationID == "" || ownerDeviceID == "" || ownerSessionID == "" {
		return errors.New("incomplete attachment binding")
	}
	return f.err
}

func (r *incrementingReader) Read(dst []byte) (int, error) {
	for index := range dst {
		dst[index] = r.next
		r.next++
	}
	return len(dst), nil
}

func testPreviewLeaseService(t *testing.T, fake *previewLeaseFake, now time.Time) *Service {
	t.Helper()
	counter := 0
	service, err := NewService(fake, Config{
		EndpointDomain: "preview.example.test", CursorKey: []byte(strings.Repeat("k", 32)),
		LeaseDuration: 30 * time.Minute, MaxLease: 2 * time.Hour, OwnerGrace: 20 * time.Second,
		AttachmentReadiness: &attachmentReadinessFake{},
		Now:                 func() time.Time { return now }, Random: &incrementingReader{},
		NewID: func(prefix string) (string, error) { counter++; return fmt.Sprintf("%s_%03d", prefix, counter), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func browserRequest() previewtunnelapi.RequestContext {
	return previewtunnelapi.RequestContext{Actor: previewtunnelapi.Actor{AccountID: "acct_1", ActorID: "user_1", Role: "user"}, RequestID: "req_1", CorrelationID: "cor_1"}
}

func deviceRequest(device string) previewtunnelapi.RequestContext {
	request := browserRequest()
	request.Actor.DeviceID = device
	return request
}

func createInput(owner string) CreateRequest {
	return CreateRequest{OwnerDeviceID: owner, OwnerSessionID: "session_1", Target: Target{Scheme: "http", Address: "127.0.0.1:3000"}, IdempotencyKey: "create_1"}
}

func TestCreateDefaultsPublicAndAllocatesRandomEndpoint(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	service := testPreviewLeaseService(t, fake, now)
	result, err := service.Create(context.Background(), browserRequest(), createInput("machine_1"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Preview.AccessMode != "public" || result.Preview.Persistent {
		t.Fatalf("default preview policy = %#v", result.Preview)
	}
	if !strings.HasPrefix(result.Preview.Endpoint, "https://") || strings.HasPrefix(result.Preview.Endpoint, "https://preview-") || !strings.HasSuffix(result.Preview.Endpoint, ".preview.example.test") {
		t.Fatalf("endpoint = %q", result.Preview.Endpoint)
	}
	if result.Preview.State != "allocating" || result.Operation.State != "running" {
		t.Fatalf("initial lifecycle = %#v operation=%#v", result.Preview, result.Operation)
	}
	if result.ETag == "" || strings.Contains(result.ETag, "machine") {
		t.Fatalf("etag leaked unexpected data: %q", result.ETag)
	}
	if len(fake.createInput) != 1 || fake.createInput[0].Endpoint == "" {
		t.Fatalf("create input missing endpoint: %#v", fake.createInput)
	}
}

func TestCreatePersistsNormalizedPreviewDomainsInLeaseTransaction(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	service := testPreviewLeaseService(t, fake, now)
	input := createInput("machine_1")
	input.Domains = []string{"*.Apps.Example.COM", "demo.example.com"}
	if _, err := service.Create(context.Background(), browserRequest(), input); err != nil {
		t.Fatal(err)
	}
	if len(fake.createInput) != 1 || len(fake.createInput[0].Domains) != 2 {
		t.Fatalf("domain create input = %+v", fake.createInput)
	}
	if got := []string{fake.createInput[0].Domains[0].Hostname, fake.createInput[0].Domains[1].Hostname}; !slices.Equal(got, []string{"*.apps.example.com", "demo.example.com"}) {
		t.Fatalf("normalized domains = %v", got)
	}
	duplicate := createInput("machine_1")
	duplicate.IdempotencyKey = "create_duplicate"
	duplicate.Domains = []string{"DEMO.example.com", "demo.example.com"}
	if _, err := service.Create(context.Background(), browserRequest(), duplicate); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate domain error = %v", err)
	}
	if len(fake.createInput) != 1 {
		t.Fatalf("duplicate domains reached persistence: %d", len(fake.createInput))
	}
}

func TestPreviewResourceProjectsReleasedDomainSummaryWithoutTunnelFields(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.leases["acct_1:prv_1"] = previewtunnelstore.PreviewLeaseRecord{PreviewLease: dbsqlc.PreviewLease{
		ID: "prv_1", AccountID: "acct_1", ActorID: "user_1", OwnerDeviceID: "machine_1", OwnerSessionID: "owner_1",
		TargetScheme: "http", TargetAddress: "127.0.0.1:3000", AccessMode: "public", EndpointID: "pep_1",
		Endpoint: "https://a.preview.example.test", LeaseDeadline: now, AllocationState: "released",
		EdgeState: "released", OriginState: "down", TerminalState: "stopped", Generation: 3, CreatedAt: now.Add(-time.Hour), LastRenewedAt: now,
	}}
	service, err := NewService(fake, Config{
		EndpointDomain: "preview.example.test", CursorKey: []byte(strings.Repeat("k", 32)), PreviewDomains: previewDomainProjectionFake{rows: []dbsqlc.PreviewDomain{{
			ID: "pdom_1", AccountID: "acct_1", PreviewID: "prv_1", PreviewGeneration: 2, Hostname: "*.apps.example.test",
			MatchType: "one_label_wildcard", OwnershipState: "expired", DnsTarget: "a.preview.example.test",
			ObservedRecords: []byte(`[]`), DnsProvider: "generic", ExpectedRecords: []byte(`[]`), DnsNextCheckAt: now,
			CertificateStrategy: "managed", CertificateState: "revoked", CaaState: "ready", ConflictState: "quarantined",
			Generation: 5, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		}}}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Get(context.Background(), browserRequest(), "prv_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Preview.Domains) != 1 || result.Preview.Domains[0].State != "quarantined" || result.Preview.Domains[0].WildcardLabels == nil || *result.Preview.Domains[0].WildcardLabels != 1 {
		t.Fatalf("domain summaries = %#v", result.Preview.Domains)
	}
	encoded, err := json.Marshal(result.Preview)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	domain := wire["domains"].([]any)[0].(map[string]any)
	for _, forbidden := range []string{"schema", "kind", "account_id", "tunnel_id", "route_id"} {
		if _, exists := domain[forbidden]; exists {
			t.Fatalf("preview domain summary exposed %s: %s", forbidden, encoded)
		}
	}
}

func TestCreateBindsSignedDeviceAndAllowsBrowserDeviceSelection(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:device_a"] = true
	fake.owners["acct_1:device_b"] = true
	service := testPreviewLeaseService(t, fake, now)
	if _, err := service.Create(context.Background(), deviceRequest("device_a"), createInput("device_b")); !errors.Is(err, ErrOwnerDenied) {
		t.Fatalf("device reassignment error = %v", err)
	}
	if _, err := service.Create(context.Background(), deviceRequest("device_a"), createInput("device_a")); err != nil {
		t.Fatalf("matching device create: %v", err)
	}
	if _, err := service.Create(context.Background(), browserRequest(), CreateRequest{OwnerDeviceID: "device_b", OwnerSessionID: "session_2", Target: Target{Scheme: "https", Address: "localhost:8443"}, IdempotencyKey: "create_2", AccessMode: "private"}); err != nil {
		t.Fatalf("browser device selection: %v", err)
	}
	if fake.createInput[1].AccessMode != "private" || fake.createInput[1].TargetScheme != "https" {
		t.Fatalf("private create input = %#v", fake.createInput[1])
	}
}

func TestCreateRejectsLiveCLIClientSessionAsPreviewOwnerMachine(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	// The fake models the production owner query: only an eligible online
	// user_machines ID is present. A live CLI session ID is deliberately not a
	// preview owner, even when it belongs to the same account.
	fake.owners["acct_1:machine_1"] = true
	service := testPreviewLeaseService(t, fake, now)
	if _, err := service.Create(context.Background(), browserRequest(), createInput("cli_session_1")); !errors.Is(err, previewtunnelstore.ErrOwnerNotFound) {
		t.Fatalf("live CLI session owner error = %v, want owner not found", err)
	}
	if len(fake.createInput) != 0 {
		t.Fatalf("rejected CLI session was persisted: %d create calls", len(fake.createInput))
	}
}

func TestBrowserCannotRenewAnOwnerSessionLease(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	service := testPreviewLeaseService(t, fake, now)
	created, err := service.Create(context.Background(), browserRequest(), createInput("machine_1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Renew(context.Background(), browserRequest(), created.Preview.ID, MutationRequest{ExpectedGeneration: 1, OwnerSessionID: "session_1", IdempotencyKey: "renew_browser"}); !errors.Is(err, ErrOwnerDenied) {
		t.Fatalf("browser renewal error = %v, want ownership denial", err)
	}
	if got := fake.leases["acct_1:"+created.Preview.ID].Generation; got != 1 {
		t.Fatalf("browser renewal changed lease generation to %d", got)
	}
	if stopped, err := service.Stop(context.Background(), browserRequest(), created.Preview.ID, MutationRequest{ExpectedGeneration: 1, IdempotencyKey: "stop_browser"}); err != nil || stopped.Preview.State != "stopped" {
		t.Fatalf("same-account browser stop = %#v, %v", stopped, err)
	}
}

func TestCreateDeadlineIsMaximumAndRenewStopUseGeneration(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	service := testPreviewLeaseService(t, fake, now)
	input := createInput("machine_1")
	deadline := now.Add(45 * time.Minute)
	input.ExpiresAt = &deadline
	created, err := service.Create(context.Background(), browserRequest(), input)
	if err != nil {
		t.Fatal(err)
	}
	if created.Preview.UserDeadline == nil || !created.Preview.UserDeadline.Equal(deadline) || !created.Preview.LeaseDeadline.Equal(deadline) {
		t.Fatalf("deadline projection = %#v", created.Preview)
	}
	renewed, err := service.Renew(context.Background(), deviceRequest("machine_1"), created.Preview.ID, MutationRequest{ExpectedGeneration: 1, OwnerSessionID: "session_1", IdempotencyKey: "renew_1"})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Preview.LeaseDeadline.After(deadline) || renewed.Preview.State != "allocating" {
		t.Fatalf("renewal exceeded deadline: %#v", renewed.Preview)
	}
	stopped, err := service.Stop(context.Background(), deviceRequest("machine_1"), created.Preview.ID, MutationRequest{ExpectedGeneration: 2, IdempotencyKey: "stop_1"})
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Preview.State != "stopped" || stopped.Preview.EdgeState != "down" || stopped.Preview.AllocationState != "released" {
		t.Fatalf("stop projection = %#v", stopped.Preview)
	}
	replayed, err := service.Stop(context.Background(), deviceRequest("machine_1"), created.Preview.ID, MutationRequest{ExpectedGeneration: 3, IdempotencyKey: "stop_2"})
	if err != nil || !replayed.Replayed {
		t.Fatalf("idempotent terminal stop = %#v, %v", replayed, err)
	}
}

func TestCreateIdempotencyReplaysSamePreview(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	service := testPreviewLeaseService(t, fake, now)
	input := createInput("machine_1")
	first, err := service.Create(context.Background(), browserRequest(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Create(context.Background(), browserRequest(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || first.Preview.ID != second.Preview.ID || first.Preview.Endpoint != second.Preview.Endpoint || len(fake.createInput) != 2 {
		t.Fatalf("replay = %#v create calls=%d", second, len(fake.createInput))
	}
}

func TestCreateDispatchesBrowserOnceAndReplayDoesNotDuplicateHostSession(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	dispatcher := &recordingDispatcher{}
	service := testPreviewLeaseService(t, fake, now)
	service.ConfigureDispatcher(dispatcher)
	input := createInput("machine_1")
	first, err := service.Create(context.Background(), browserRequest(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Create(context.Background(), browserRequest(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || first.Preview.ID != second.Preview.ID || first.Operation.ID != second.Operation.ID {
		t.Fatalf("replay changed durable identity: first=%#v second=%#v", first, second)
	}
	if len(dispatcher.calls) != 2 || len(dispatcher.sessions) != 1 {
		t.Fatalf("dispatch calls=%d host sessions=%d, want two idempotent deliveries and one session", len(dispatcher.calls), len(dispatcher.sessions))
	}
	if dispatcher.calls[0].RequestHash != dispatcher.calls[1].RequestHash || dispatcher.calls[0].OperationID != dispatcher.calls[1].OperationID {
		t.Fatalf("replay changed dispatch binding: first=%#v second=%#v", dispatcher.calls[0], dispatcher.calls[1])
	}
}

func TestCreateDispatchesOwnerDeviceRequestToStableHostRuntime(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	dispatcher := &recordingDispatcher{}
	service := testPreviewLeaseService(t, fake, now)
	service.ConfigureDispatcher(dispatcher)
	created, err := service.Create(context.Background(), deviceRequest("machine_1"), createInput("machine_1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dispatcher.calls) != 1 || len(dispatcher.sessions) != 1 {
		t.Fatalf("owner device dispatch calls=%d host sessions=%d, want one stable-host delivery", len(dispatcher.calls), len(dispatcher.sessions))
	}
	if dispatcher.calls[0].PreviewID != created.Preview.ID || dispatcher.calls[0].OperationID != created.Operation.ID || dispatcher.calls[0].OwnerDeviceID != "machine_1" {
		t.Fatalf("owner device dispatch binding = %#v", dispatcher.calls[0])
	}
}

func TestCreateRetriesSameLeaseAfterUncertainDispatchAndRejectsHashMismatch(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	dispatcher := &recordingDispatcher{nextError: uncertainDispatchError{}}
	service := testPreviewLeaseService(t, fake, now)
	service.ConfigureDispatcher(dispatcher)
	input := createInput("machine_1")
	_, err := service.Create(context.Background(), browserRequest(), input)
	if err == nil || !dispatchErrorUncertain(err) {
		t.Fatalf("first dispatch error = %v, want uncertain outcome", err)
	}
	if fake.uncertainCalls != 1 || len(dispatcher.calls) != 1 {
		t.Fatalf("uncertain bookkeeping calls=%d dispatches=%d", fake.uncertainCalls, len(dispatcher.calls))
	}
	previewID, operationID := dispatcher.calls[0].PreviewID, dispatcher.calls[0].OperationID
	retry, err := service.Create(context.Background(), browserRequest(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !retry.Replayed || retry.Preview.ID != previewID || retry.Operation.ID != operationID || len(dispatcher.calls) != 2 {
		t.Fatalf("uncertain retry = %#v dispatches=%d", retry, len(dispatcher.calls))
	}
	input.Target.Address = "127.0.0.1:4000"
	if _, err := service.Create(context.Background(), browserRequest(), input); !errors.Is(err, previewtunnelstore.ErrIdempotencyConflict) {
		t.Fatalf("mismatched replay = %v, want idempotency conflict", err)
	}
}

func TestCreateKnownDispatchFailureUsesPersistedOriginDownState(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	dispatcher := &recordingDispatcher{nextError: errors.New("remote_invalid_response")}
	service := testPreviewLeaseService(t, fake, now)
	service.ConfigureDispatcher(dispatcher)

	if _, err := service.Create(context.Background(), browserRequest(), createInput("machine_1")); err == nil {
		t.Fatal("known dispatch failure returned nil")
	}
	if len(fake.readyInputs) != 1 {
		t.Fatalf("known dispatch failure readiness updates = %d, want one", len(fake.readyInputs))
	}
	if got := fake.readyInputs[0].OriginState; got != "down" {
		t.Fatalf("persisted origin state = %q, want internal down state", got)
	}
}

func TestCreateRetriesOnlyTypedEndpointConflict(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	fake.createErrors = []error{previewtunnelstore.ErrEndpointConflict}
	service := testPreviewLeaseService(t, fake, now)
	if _, err := service.Create(context.Background(), browserRequest(), createInput("machine_1")); err != nil {
		t.Fatalf("typed endpoint conflict should retry: %v", err)
	}
	if len(fake.createInput) != 2 || fake.createInput[0].Endpoint == fake.createInput[1].Endpoint {
		t.Fatalf("retry inputs = %#v", fake.createInput)
	}

	fake = newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	fake.createErrors = []error{fmt.Errorf("wrapped unrelated conflict: %w", previewtunnelstore.ErrConflict)}
	service = testPreviewLeaseService(t, fake, now)
	if _, err := service.Create(context.Background(), browserRequest(), createInput("machine_1")); !errors.Is(err, previewtunnelstore.ErrConflict) {
		t.Fatalf("unrelated conflict = %v", err)
	}
	if len(fake.createInput) != 1 {
		t.Fatalf("unrelated conflict retried, inputs = %d", len(fake.createInput))
	}
}

func TestCreateRejectsNonLoopbackAndNonCanonicalTargets(t *testing.T) {
	cases := []string{
		"localhost", "http://localhost:3000", "http://user@127.0.0.1:3000", "127.0.0.1:bad",
		"127.0.0.1:0", "127.0.0.1:65536", "192.168.1.10:3000", "127.0.0.1:3000/path", "127.0.0.1:3000?x=1",
	}
	for _, address := range cases {
		t.Run(address, func(t *testing.T) {
			if validLocalTarget(address) {
				t.Fatalf("accepted invalid target %q", address)
			}
		})
	}
	for _, address := range []string{"127.0.0.1:3000", "[::1]:8443", "localhost:3000"} {
		if !validLocalTarget(address) {
			t.Fatalf("rejected local target %q", address)
		}
	}
}

func TestCreateValidatesPreviewTargetSchemesAndPrivateTCP(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	service := testPreviewLeaseService(t, fake, now)
	valid := []struct {
		name, scheme, address, access, key string
	}{
		{"h2c", "h2c", "127.0.0.1:5000", "public", "create_h2c"},
		{"unix", "unix", "/run/paperboat.sock", "public", "create_unix"},
		{"private tcp", "tcp", "10.0.0.4:5432", "private", "create_tcp"},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			input := createInput("machine_1")
			input.Target = Target{Scheme: test.scheme, Address: test.address}
			input.AccessMode, input.IdempotencyKey = test.access, test.key
			if _, err := service.Create(context.Background(), browserRequest(), input); err != nil {
				t.Fatalf("create %s: %v", test.name, err)
			}
		})
	}
	invalid := []struct {
		name, scheme, address, access string
	}{
		{"public tcp", "tcp", "10.0.0.4:5432", "public"},
		{"remote http", "http", "10.0.0.4:80", "public"},
		{"relative unix", "unix", "app.sock", "private"},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			input := createInput("machine_1")
			input.Target = Target{Scheme: test.scheme, Address: test.address}
			input.AccessMode, input.IdempotencyKey = test.access, "invalid_"+test.name
			if _, err := service.Create(context.Background(), browserRequest(), input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("create %s error = %v", test.name, err)
			}
		})
	}
}

func TestObserveReadinessCompletesProjectionAndReconcileMapsTerminalStates(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	service := testPreviewLeaseService(t, fake, now)
	created, err := service.Create(context.Background(), browserRequest(), createInput("machine_1"))
	if err != nil {
		t.Fatal(err)
	}
	ready, err := service.ObserveReadiness(context.Background(), browserRequest(), created.Preview.ID, 1, "ready", "ready", "ready")
	if err != nil {
		t.Fatal(err)
	}
	if ready.Preview.State != "ready" || ready.Preview.OriginState != "ready" || fake.readyCalls != 1 {
		t.Fatalf("ready projection = %#v calls=%d", ready.Preview, fake.readyCalls)
	}
	fake.reconcile = previewtunnelstore.ReconcilePreviewLeasesV1Result{
		Expired:   []previewtunnelstore.PreviewLeaseRecord{{PreviewLease: dbsqlc.PreviewLease{ID: "prv_exp", AccountID: "acct_1", ActorID: "user_1", OwnerDeviceID: "m", OwnerSessionID: "s", TargetScheme: "http", TargetAddress: "127.0.0.1:3000", AccessMode: "public", Endpoint: "https://exp.preview.example.test", LeaseDeadline: now.Add(-time.Minute), AllocationState: "released", EdgeState: "released", OriginState: "unknown", TerminalState: "expired", CreatedAt: now.Add(-time.Hour), LastRenewedAt: now.Add(-time.Hour), Generation: 2, OwnerLastSeenAt: now.Add(-time.Hour)}}},
		OwnerLost: []previewtunnelstore.PreviewLeaseRecord{{PreviewLease: dbsqlc.PreviewLease{ID: "prv_lost", AccountID: "acct_1", ActorID: "user_1", OwnerDeviceID: "m", OwnerSessionID: "s", TargetScheme: "http", TargetAddress: "127.0.0.1:3000", AccessMode: "private", Endpoint: "https://lost.preview.example.test", LeaseDeadline: now.Add(time.Hour), AllocationState: "released", EdgeState: "released", OriginState: "down", TerminalState: "owner_lost", CreatedAt: now.Add(-time.Hour), LastRenewedAt: now.Add(-time.Hour), Generation: 3, OwnerLastSeenAt: now.Add(-time.Hour)}}},
	}
	reconciled, err := service.Reconcile(context.Background(), "worker_1", "cor_reconcile", "req_reconcile")
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Expired[0].State != "expired" || reconciled.Expired[0].EdgeState != "down" || reconciled.OwnerLost[0].State != "owner_disconnected" || reconciled.OwnerLost[0].OriginState != "unavailable" {
		t.Fatalf("reconciliation projection = %#v", reconciled)
	}
}

func TestObserveDeviceReadinessRequiresOwnerAndReplaysAfterUncertainResponse(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := newPreviewLeaseFake()
	fake.owners["acct_1:machine_1"] = true
	service := testPreviewLeaseService(t, fake, now)
	created, err := service.Create(context.Background(), browserRequest(), createInput("machine_1"))
	if err != nil {
		t.Fatal(err)
	}
	blocked := &attachmentReadinessFake{err: errors.New("edge is not ready")}
	service.attachmentReadiness = blocked
	if _, err := service.ObserveDeviceReadiness(context.Background(), deviceRequest("machine_1"), created.Preview.ID, created.Operation.ID, "machine_1", "session_1", created.ETag, 1, "ready", "ready", "ready"); !errors.Is(err, ErrAttachmentNotReady) || blocked.calls != 1 || fake.readyCalls != 0 {
		t.Fatalf("attachment readiness gate error=%v calls=%d lease_mutations=%d", err, blocked.calls, fake.readyCalls)
	}
	service.attachmentReadiness = &attachmentReadinessFake{}
	ready, err := service.ObserveDeviceReadiness(context.Background(), deviceRequest("machine_1"), created.Preview.ID, created.Operation.ID, "machine_1", "session_1", created.ETag, 1, "ready", "ready", "ready")
	if err != nil {
		t.Fatal(err)
	}
	if ready.Preview.State != "ready" || ready.ETag == created.ETag || fake.readyCalls != 1 {
		t.Fatalf("first readiness = %#v calls=%d", ready, fake.readyCalls)
	}
	// The host may not know whether the first response reached it. Reusing the
	// same operation/body with the old strong ETag returns the already-ready
	// projection rather than incorrectly producing a generation conflict.
	replayed, err := service.ObserveDeviceReadiness(context.Background(), deviceRequest("machine_1"), created.Preview.ID, created.Operation.ID, "machine_1", "session_1", created.ETag, 1, "ready", "ready", "ready")
	if err != nil || replayed.ETag != ready.ETag || fake.readyCalls != 1 {
		t.Fatalf("readiness replay = %#v err=%v calls=%d", replayed, err, fake.readyCalls)
	}
	if _, err := service.ObserveDeviceReadiness(context.Background(), deviceRequest("machine_2"), created.Preview.ID, created.Operation.ID, "machine_1", "session_1", created.ETag, 1, "ready", "ready", "ready"); !errors.Is(err, ErrOwnerDenied) {
		t.Fatalf("different owner device error = %v", err)
	}
	if _, err := service.ObserveDeviceReadiness(context.Background(), deviceRequest("machine_1"), created.Preview.ID, created.Operation.ID, "machine_1", "other_session", created.ETag, 1, "ready", "ready", "ready"); !errors.Is(err, ErrOwnerDenied) {
		t.Fatalf("different owner session error = %v", err)
	}
	if _, err := service.ObserveDeviceReadiness(context.Background(), deviceRequest("machine_1"), created.Preview.ID, created.Operation.ID, "machine_1", "session_1", created.ETag, 1, "ready", "ready", "unavailable"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("non-ready lifecycle error = %v", err)
	}
}

func TestNewServiceRejectsInvalidEndpointDomainAndCursorKey(t *testing.T) {
	fake := newPreviewLeaseFake()
	_, err := NewService(fake, Config{EndpointDomain: "https://bad.example", CursorKey: []byte(strings.Repeat("k", 32))})
	if err == nil {
		t.Fatal("accepted endpoint URL instead of host")
	}
	_, err = NewService(fake, Config{EndpointDomain: "preview.example", CursorKey: []byte("short")})
	if err == nil {
		t.Fatal("accepted short cursor key")
	}
}

func TestPreviewCursorIsBounded(t *testing.T) {
	codec, err := newCursorCodec([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Encode(previewCursor{AccountID: "acct_1", ID: strings.Repeat("x", 2000), CreatedAt: time.Now().UTC()}); !errors.Is(err, previewtunnelapi.ErrInvalidCursor) {
		t.Fatalf("oversized cursor payload error = %v", err)
	}
	if _, err := codec.Decode(strings.Repeat("x", maxPreviewCursorEncoded+1), "acct_1"); !errors.Is(err, previewtunnelapi.ErrInvalidCursor) {
		t.Fatalf("oversized cursor error = %v", err)
	}
}

func TestPreviewCursorRejectsTunnelCursorAndUnknownFields(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	codec, err := newCursorCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	// tunnelv1 signs the same account/time/id tuple with version=1 but no
	// resource kind. A preview cursor must not accept that other family.
	tunnelPayload, err := json.Marshal(struct {
		Version   int       `json:"version"`
		AccountID string    `json:"account_id"`
		CreatedAt time.Time `json:"created_at"`
		ID        string    `json:"id"`
	}{1, "acct_1", now, "prv_1"})
	if err != nil {
		t.Fatal(err)
	}
	tunnelMAC := hmac.New(sha256.New, key)
	_, _ = tunnelMAC.Write(tunnelPayload)
	tunnelCursor := base64.RawURLEncoding.EncodeToString(tunnelPayload) + "." + base64.RawURLEncoding.EncodeToString(tunnelMAC.Sum(nil))
	if _, err := codec.Decode(tunnelCursor, "acct_1"); !errors.Is(err, previewtunnelapi.ErrInvalidCursor) {
		t.Fatalf("accepted tunnel cursor: %v", err)
	}

	previewPayload, err := json.Marshal(struct {
		Version   int       `json:"version"`
		Kind      string    `json:"kind"`
		AccountID string    `json:"account_id"`
		CreatedAt time.Time `json:"created_at"`
		ID        string    `json:"id"`
		Extra     string    `json:"extra"`
	}{1, Kind, "acct_1", now, "prv_1", "reject"})
	if err != nil {
		t.Fatal(err)
	}
	previewMAC := hmac.New(sha256.New, key)
	_, _ = previewMAC.Write(previewPayload)
	unknownFieldCursor := base64.RawURLEncoding.EncodeToString(previewPayload) + "." + base64.RawURLEncoding.EncodeToString(previewMAC.Sum(nil))
	if _, err := codec.Decode(unknownFieldCursor, "acct_1"); !errors.Is(err, previewtunnelapi.ErrInvalidCursor) {
		t.Fatalf("accepted preview cursor with unknown field: %v", err)
	}
}

var _ io.Reader = (*incrementingReader)(nil)
