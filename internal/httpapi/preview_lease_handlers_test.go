package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
)

type fakePreviewLeaseAPI struct {
	create        previewv1.CreateResult
	get           previewv1.PreviewResult
	list          previewv1.PreviewPage
	renew         previewv1.RenewResult
	stop          previewv1.StopResult
	err           error
	createRequest previewv1.CreateRequest
	mutation      previewv1.MutationRequest
}

func (f *fakePreviewLeaseAPI) Create(_ context.Context, _ previewtunnelapi.RequestContext, request previewv1.CreateRequest) (previewv1.CreateResult, error) {
	f.createRequest = request
	return f.create, f.err
}

func (f *fakePreviewLeaseAPI) Get(context.Context, previewtunnelapi.RequestContext, string) (previewv1.PreviewResult, error) {
	return f.get, f.err
}

func (f *fakePreviewLeaseAPI) List(context.Context, previewtunnelapi.RequestContext, string, int) (previewv1.PreviewPage, error) {
	return f.list, f.err
}

func (f *fakePreviewLeaseAPI) Renew(_ context.Context, _ previewtunnelapi.RequestContext, _ string, mutation previewv1.MutationRequest) (previewv1.RenewResult, error) {
	f.mutation = mutation
	return f.renew, f.err
}

func (f *fakePreviewLeaseAPI) Stop(_ context.Context, _ previewtunnelapi.RequestContext, _ string, mutation previewv1.MutationRequest) (previewv1.StopResult, error) {
	f.mutation = mutation
	return f.stop, f.err
}

type fakePreviewReadinessAPI struct {
	result                                                           previewv1.PreviewResult
	err                                                              error
	called                                                           bool
	request                                                          previewtunnelapi.RequestContext
	previewID, operationID, ownerDeviceID, ownerSessionID, leaseETag string
	expectedGeneration                                               int64
	allocationState, edgeState, originState                          string
}

func (f *fakePreviewReadinessAPI) ObserveDeviceReadiness(_ context.Context, request previewtunnelapi.RequestContext, previewID, operationID, ownerDeviceID, ownerSessionID, leaseETag string, expectedGeneration int64, allocationState, edgeState, originState string) (previewv1.PreviewResult, error) {
	f.called = true
	f.request = request
	f.previewID, f.operationID, f.ownerDeviceID, f.ownerSessionID, f.leaseETag = previewID, operationID, ownerDeviceID, ownerSessionID, leaseETag
	f.expectedGeneration = expectedGeneration
	f.allocationState, f.edgeState, f.originState = allocationState, edgeState, originState
	return f.result, f.err
}

type fakePreviewMachineVerifier struct {
	claims       controlplane.MachineRequestClaims
	err          error
	method, path string
	body         []byte
}

func (f *fakePreviewMachineVerifier) VerifyMachineRequest(_ context.Context, _ string, _ []byte, method, path string, body []byte) (controlplane.MachineRequestClaims, error) {
	f.method, f.path, f.body = method, path, append([]byte(nil), body...)
	if f.err != nil {
		return controlplane.MachineRequestClaims{}, f.err
	}
	return f.claims, nil
}

func previewLeaseHandlerRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.SetPathValue("preview_id", "prv_1")
	ctx := context.WithValue(request.Context(), authContextKey{}, principal{
		User:   auth.User{ID: "acct_1", Role: auth.RoleUser},
		Client: &auth.ClientPrincipal{SessionID: "device_1", Scopes: []string{"previews:read", "previews:write"}},
	})
	ctx = observability.WithRequestID(ctx, "req_1")
	ctx = observability.WithCorrelationID(ctx, "cor_1")
	return request.WithContext(ctx)
}

func previewReadinessHandlerRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/previews/prv_1/readiness", strings.NewReader(body))
	request.SetPathValue("preview_id", "prv_1")
	request.Header.Set("Authorization", "Bearer machine-identity")
	request.Header.Set("X-Paperboat-Machine-Identity", "machine-identity")
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("proof")))
	request.Header.Set("Idempotency-Key", "op_1")
	request.Header.Set("If-Match", previewtunnelapi.ETag(previewv1.Kind, "prv_1", 1))
	ctx := observability.WithRequestID(request.Context(), "req_1")
	ctx = observability.WithCorrelationID(ctx, "cor_1")
	return request.WithContext(ctx)
}

func validPreviewMachineVerifier() *fakePreviewMachineVerifier {
	return &fakePreviewMachineVerifier{claims: controlplane.MachineRequestClaims{
		UserID: "acct_1", MachineID: "machine_1", InstallationGeneration: 1, OperationID: "op_1",
	}}
}

func TestPreviewLeaseCreateHandlerReturnsCanonicalOperationForPendingWork(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service := &fakePreviewLeaseAPI{create: previewv1.CreateResult{
		Preview:   previewv1.Preview{Schema: previewv1.Schema, Kind: previewv1.Kind, ID: "prv_1", AccountID: "acct_1", ActorID: "user_1", OwnerDeviceID: "device_1", OwnerSessionID: "session_1", Target: previewv1.Target{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "public", Persistent: false, Endpoint: "https://abc.preview.example.test", LeaseDeadline: now.Add(time.Hour), State: "allocating", AllocationState: "pending", EdgeState: "pending", OriginState: "unknown", CreatedAt: now, LastRenewedAt: now},
		Operation: previewtunnelapi.Operation{Schema: previewv1.Schema, Kind: "operation", ID: "op_1", ResourceKind: "preview_lease", ResourceID: "prv_1", Phase: "connecting", State: "running", Progress: 60, CorrelationID: "cor_1", CreatedAt: now, UpdatedAt: now}, ETag: `"ptv1:preview_lease:prHZMQ:1"`,
	}}
	request := previewLeaseHandlerRequest(http.MethodPost, "/v1/previews", `{"owner_device_id":"device_1","owner_session_id":"session_1","target":{"scheme":"http","address":"127.0.0.1:3000"},"domains":[]}`)
	request.Header.Set("Idempotency-Key", "create_1")
	recorder := httptest.NewRecorder()
	previewLeaseCreate(service).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("ETag") == "" || recorder.Header().Get("If-Match") != "" {
		t.Fatalf("response concurrency headers = %#v", recorder.Header())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store, no-transform" {
		t.Fatalf("cache control = %q", got)
	}
	if recorder.Header().Get("Location") != "/v1/operations/op_1" {
		t.Fatalf("location = %q", recorder.Header().Get("Location"))
	}
	if recorder.Header().Get("X-Paperboat-Operation-ID") != "op_1" {
		t.Fatalf("operation header = %q", recorder.Header().Get("X-Paperboat-Operation-ID"))
	}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data["kind"] != "operation" || envelope.Data["resource_kind"] != "preview_lease" || envelope.Data["preview"] != nil {
		t.Fatalf("non-canonical pending response = %#v", envelope.Data)
	}
	if service.createRequest.AccessMode != "" || service.createRequest.RequestHash == ([32]byte{}) {
		t.Fatalf("request normalization/hash = %#v", service.createRequest)
	}
}

func TestPreviewLeaseCreateHandlerRequiresExplicitDomainsArray(t *testing.T) {
	service := &fakePreviewLeaseAPI{}
	request := previewLeaseHandlerRequest(http.MethodPost, "/v1/previews", `{"owner_device_id":"device_1","owner_session_id":"session_1","target":{"scheme":"http","address":"127.0.0.1:3000"}}`)
	request.Header.Set("Idempotency-Key", "create_1")
	recorder := httptest.NewRecorder()
	previewLeaseCreate(service).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if service.createRequest.OwnerDeviceID != "" {
		t.Fatal("service was called without the canonical domains array")
	}
}

func TestPreviewLeaseCreateHandlerReturnsOperationHeaderForReadyReplay(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service := &fakePreviewLeaseAPI{create: previewv1.CreateResult{
		Preview:   previewv1.Preview{Schema: previewv1.Schema, Kind: previewv1.Kind, ID: "prv_1", AccountID: "acct_1", ActorID: "user_1", OwnerDeviceID: "device_1", OwnerSessionID: "session_1", Target: previewv1.Target{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "public", Persistent: false, Endpoint: "https://abc.preview.example.test", LeaseDeadline: now.Add(time.Hour), State: "ready", AllocationState: "ready", EdgeState: "ready", OriginState: "ready", CreatedAt: now, LastRenewedAt: now},
		Operation: previewtunnelapi.Operation{Schema: previewv1.Schema, Kind: "operation", ID: "op_1", ResourceKind: "preview_lease", ResourceID: "prv_1", Phase: "ready", State: "succeeded", Progress: 100, CorrelationID: "cor_1", CreatedAt: now, UpdatedAt: now}, ETag: `"ptv1:preview_lease:prHZMQ:2"`,
	}}
	request := previewLeaseHandlerRequest(http.MethodPost, "/v1/previews", `{"owner_device_id":"device_1","owner_session_id":"session_1","target":{"scheme":"http","address":"127.0.0.1:3000"},"domains":[]}`)
	request.Header.Set("Idempotency-Key", "create_1")
	recorder := httptest.NewRecorder()
	previewLeaseCreate(service).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("X-Paperboat-Operation-ID") != "op_1" {
		t.Fatalf("operation header = %q", recorder.Header().Get("X-Paperboat-Operation-ID"))
	}
	if strings.Contains(recorder.Body.String(), `"operation_id"`) {
		t.Fatal("ready preview response leaked operation_id into the resource")
	}
}

func TestPreviewLeaseReadinessRequiresMachineProofAndBindsOwner(t *testing.T) {
	body := `{"owner_device_id":"machine_1","owner_session_id":"session_1","allocation_state":"ready","edge_state":"ready","origin_state":"ready"}`
	service := &fakePreviewReadinessAPI{result: previewv1.PreviewResult{Preview: previewv1.Preview{ID: "prv_1", State: "ready"}, ETag: previewtunnelapi.ETag(previewv1.Kind, "prv_1", 2)}}
	verifier := validPreviewMachineVerifier()
	recorder := httptest.NewRecorder()
	previewLeaseReadiness(service, verifier).ServeHTTP(recorder, previewReadinessHandlerRequest(body))
	if recorder.Code != http.StatusOK || !service.called {
		t.Fatalf("valid readiness status=%d called=%v body=%s", recorder.Code, service.called, recorder.Body.String())
	}
	if service.request.Actor.AccountID != "acct_1" || service.request.Actor.ActorID != "acct_1" || service.request.Actor.DeviceID != "machine_1" || service.request.Actor.HostID != "machine_1" {
		t.Fatalf("readiness actor = %#v", service.request.Actor)
	}
	if service.previewID != "prv_1" || service.operationID != "op_1" || service.ownerDeviceID != "machine_1" || service.ownerSessionID != "session_1" || service.expectedGeneration != 1 || service.leaseETag != previewtunnelapi.ETag(previewv1.Kind, "prv_1", 1) {
		t.Fatalf("readiness binding = preview=%q operation=%q device=%q session=%q generation=%d etag=%q", service.previewID, service.operationID, service.ownerDeviceID, service.ownerSessionID, service.expectedGeneration, service.leaseETag)
	}
	if verifier.method != http.MethodPost || verifier.path != "/v1/previews/prv_1/readiness" || string(verifier.body) != body {
		t.Fatalf("proof binding = method=%q path=%q body=%q", verifier.method, verifier.path, verifier.body)
	}
}

func TestPreviewLeaseReadinessRejectsBrowserAndMachineBindingMismatches(t *testing.T) {
	body := `{"owner_device_id":"machine_1","owner_session_id":"session_1","allocation_state":"ready","edge_state":"ready","origin_state":"ready"}`
	t.Run("browser", func(t *testing.T) {
		service := &fakePreviewReadinessAPI{}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/previews/prv_1/readiness", strings.NewReader(body))
		request.SetPathValue("preview_id", "prv_1")
		request.Header.Set("Idempotency-Key", "op_1")
		request.Header.Set("If-Match", previewtunnelapi.ETag(previewv1.Kind, "prv_1", 1))
		previewLeaseReadiness(service, validPreviewMachineVerifier()).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized || service.called {
			t.Fatalf("browser status=%d called=%v body=%s", recorder.Code, service.called, recorder.Body.String())
		}
	})
	t.Run("different machine in same account", func(t *testing.T) {
		service := &fakePreviewReadinessAPI{}
		verifier := validPreviewMachineVerifier()
		verifier.claims.MachineID = "machine_2"
		recorder := httptest.NewRecorder()
		previewLeaseReadiness(service, verifier).ServeHTTP(recorder, previewReadinessHandlerRequest(body))
		if recorder.Code != http.StatusForbidden || service.called {
			t.Fatalf("machine mismatch status=%d called=%v body=%s", recorder.Code, service.called, recorder.Body.String())
		}
	})
	t.Run("wrong proof or body", func(t *testing.T) {
		service := &fakePreviewReadinessAPI{}
		verifier := validPreviewMachineVerifier()
		verifier.err = errors.New("proof does not match request")
		recorder := httptest.NewRecorder()
		previewLeaseReadiness(service, verifier).ServeHTTP(recorder, previewReadinessHandlerRequest(body))
		if recorder.Code != http.StatusUnauthorized || service.called {
			t.Fatalf("proof mismatch status=%d called=%v body=%s", recorder.Code, service.called, recorder.Body.String())
		}
	})
	t.Run("identity and bearer mismatch", func(t *testing.T) {
		service := &fakePreviewReadinessAPI{}
		request := previewReadinessHandlerRequest(body)
		request.Header.Set("Authorization", "Bearer another-machine-identity")
		recorder := httptest.NewRecorder()
		previewLeaseReadiness(service, validPreviewMachineVerifier()).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized || service.called {
			t.Fatalf("credential mismatch status=%d called=%v body=%s", recorder.Code, service.called, recorder.Body.String())
		}
	})
}

func TestPreviewLeaseReadinessMapsGenerationAndSessionFailures(t *testing.T) {
	body := `{"owner_device_id":"machine_1","owner_session_id":"session_1","allocation_state":"ready","edge_state":"ready","origin_state":"ready"}`
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{name: "session", err: previewv1.ErrOwnerDenied, want: http.StatusForbidden},
		{name: "generation", err: previewtunnelstore.ErrGenerationConflict, want: http.StatusPreconditionFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &fakePreviewReadinessAPI{err: test.err}
			recorder := httptest.NewRecorder()
			previewLeaseReadiness(service, validPreviewMachineVerifier()).ServeHTTP(recorder, previewReadinessHandlerRequest(body))
			if recorder.Code != test.want || !service.called {
				t.Fatalf("status=%d want=%d called=%v body=%s", recorder.Code, test.want, service.called, recorder.Body.String())
			}
		})
	}
}

func TestPreviewLeaseCreateHandlerRejectsVanityAndUnknownFields(t *testing.T) {
	service := &fakePreviewLeaseAPI{}
	request := previewLeaseHandlerRequest(http.MethodPost, "/v1/previews", `{"owner_device_id":"device_1","owner_session_id":"session_1","endpoint":"https://custom.preview.example.test","target":{"scheme":"http","address":"127.0.0.1:3000"},"domains":[]}`)
	request.Header.Set("Idempotency-Key", "create_1")
	recorder := httptest.NewRecorder()
	previewLeaseCreate(service).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if service.createRequest.OwnerDeviceID != "" {
		t.Fatal("service called for rejected unknown endpoint field")
	}
	for _, body := range []string{"null", `{} {}`} {
		service = &fakePreviewLeaseAPI{}
		request = previewLeaseHandlerRequest(http.MethodPost, "/v1/previews", body)
		request.Header.Set("Idempotency-Key", "create_1")
		recorder = httptest.NewRecorder()
		previewLeaseCreate(service).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("body %q status = %d, body = %s", body, recorder.Code, recorder.Body.String())
		}
	}
}

func TestPreviewLeaseMutationHandlerParsesStrongETagAndIdempotency(t *testing.T) {
	service := &fakePreviewLeaseAPI{renew: previewv1.RenewResult{Preview: previewv1.Preview{ID: "prv_1"}, ETag: `"ptv1:preview_lease:prHZMQ:2"`}}
	request := previewLeaseHandlerRequest(http.MethodPost, "/v1/previews/prv_1/lease/renew", `{}`)
	request.Header.Set("If-Match", `"ptv1:preview_lease: cHJ2XzE:1"`)
	request.Header.Set("Idempotency-Key", "renew_1")
	// The value above intentionally contains a space and must be rejected.
	recorder := httptest.NewRecorder()
	previewLeaseRenew(service).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || service.mutation.ExpectedGeneration != 0 {
		t.Fatalf("invalid ETag status=%d mutation=%#v", recorder.Code, service.mutation)
	}

	request = previewLeaseHandlerRequest(http.MethodPost, "/v1/previews/prv_1/lease/renew", `{"owner_session_id":"session_1"}`)
	request.Header.Set("If-Match", `"ptv1:preview_lease:cHJ2XzE:1"`)
	request.Header.Set("Idempotency-Key", "renew_1")
	recorder = httptest.NewRecorder()
	previewLeaseRenew(service).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || service.mutation.ExpectedGeneration != 1 || service.mutation.OwnerSessionID != "session_1" || recorder.Header().Get("ETag") == "" {
		t.Fatalf("valid ETag status=%d mutation=%#v body=%s", recorder.Code, service.mutation, recorder.Body.String())
	}
}

func machinePreviewMutationRequest(method, target, body string) *http.Request {
	request := previewLeaseHandlerRequest(method, target, body)
	request.Header.Set("Authorization", "Bearer machine-identity")
	request.Header.Set("X-Paperboat-Machine-Identity", "machine-identity")
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("proof")))
	request.Header.Set("If-Match", `"ptv1:preview_lease:cHJ2XzE:1"`)
	request.Header.Set("Idempotency-Key", "op_1")
	return request
}

func TestPreviewLeaseRenewAndStopAcceptMachineProof(t *testing.T) {
	service := &fakePreviewLeaseAPI{
		renew: previewv1.RenewResult{Preview: previewv1.Preview{ID: "prv_1"}, ETag: `"ptv1:preview_lease:cHJ2XzE:2"`},
		stop:  previewv1.StopResult{Preview: previewv1.Preview{ID: "prv_1"}, ETag: `"ptv1:preview_lease:cHJ2XzE:2"`},
	}
	verifier := validPreviewMachineVerifier()

	renewRequest := machinePreviewMutationRequest(http.MethodPost, "/v1/previews/prv_1/lease/renew", `{"owner_session_id":"session_1"}`)
	renewResponse := httptest.NewRecorder()
	previewLeaseRenew(service, verifier).ServeHTTP(renewResponse, renewRequest)
	if renewResponse.Code != http.StatusOK {
		t.Fatalf("machine renew status = %d, body = %s", renewResponse.Code, renewResponse.Body.String())
	}
	if verifier.method != http.MethodPost || verifier.path != "/v1/previews/prv_1/lease/renew" || string(verifier.body) != `{"owner_session_id":"session_1"}` {
		t.Fatalf("machine renew proof binding = method %q path %q body %q", verifier.method, verifier.path, verifier.body)
	}
	if service.mutation.ExpectedGeneration != 1 || service.mutation.OwnerSessionID != "session_1" {
		t.Fatalf("machine renew mutation = %#v", service.mutation)
	}

	verifier.method, verifier.path, verifier.body = "", "", nil
	stopRequest := machinePreviewMutationRequest(http.MethodDelete, "/v1/previews/prv_1", "")
	stopResponse := httptest.NewRecorder()
	previewLeaseStop(service, verifier).ServeHTTP(stopResponse, stopRequest)
	if stopResponse.Code != http.StatusOK {
		t.Fatalf("machine stop status = %d, body = %s", stopResponse.Code, stopResponse.Body.String())
	}
	if verifier.method != http.MethodDelete || verifier.path != "/v1/previews/prv_1" || len(verifier.body) != 0 {
		t.Fatalf("machine stop proof binding = method %q path %q body %q", verifier.method, verifier.path, verifier.body)
	}
}

func TestPreviewLeaseMachineMutationRejectsInvalidProofBeforeService(t *testing.T) {
	for _, test := range []struct {
		name    string
		method  string
		handler func(*fakePreviewLeaseAPI, machineRequestVerifier) http.Handler
		target  string
		body    string
	}{
		{name: "renew", method: http.MethodPost, handler: func(service *fakePreviewLeaseAPI, verifier machineRequestVerifier) http.Handler {
			return previewLeaseRenew(service, verifier)
		}, target: "/v1/previews/prv_1/lease/renew", body: `{"owner_session_id":"session_1"}`},
		{name: "stop", method: http.MethodDelete, handler: func(service *fakePreviewLeaseAPI, verifier machineRequestVerifier) http.Handler {
			return previewLeaseStop(service, verifier)
		}, target: "/v1/previews/prv_1", body: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, invalid := range []struct {
				name     string
				mutate   func(*http.Request)
				verifier *fakePreviewMachineVerifier
			}{
				{name: "malformed", mutate: func(request *http.Request) {
					request.Header.Set("X-Paperboat-Machine-Proof", "not-base64")
				}, verifier: validPreviewMachineVerifier()},
				{name: "wrong-operation", mutate: func(*http.Request) {}, verifier: &fakePreviewMachineVerifier{claims: controlplane.MachineRequestClaims{
					UserID: "acct_1", MachineID: "machine_1", InstallationGeneration: 1, OperationID: "other-operation",
				}}},
			} {
				t.Run(invalid.name, func(t *testing.T) {
					service := &fakePreviewLeaseAPI{}
					request := machinePreviewMutationRequest(test.method, test.target, test.body)
					invalid.mutate(request)
					recorder := httptest.NewRecorder()
					test.handler(service, invalid.verifier).ServeHTTP(recorder, request)
					if recorder.Code != http.StatusUnauthorized {
						t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
					}
					if service.mutation.RequestHash != ([32]byte{}) {
						t.Fatal("service was called for invalid machine proof")
					}
				})
			}
		})
	}
}

func TestPreviewLeaseMutationAuthBypassesClientAuthForMachineProof(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodDelete, "/v1/previews/prv_1", strings.NewReader("{}"))
	request.Header.Set("X-Paperboat-Machine-Identity", "machine-identity")
	request.Header.Set("X-Paperboat-Machine-Proof", "proof")
	recorder := httptest.NewRecorder()
	previewLeaseMutationAuth(nil, nil, nil, next).ServeHTTP(recorder, request)
	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("machine mutation wrapper status=%d called=%v", recorder.Code, called)
	}
}

func TestPreviewLeaseStopEmptyAndObjectBodiesShareRequestHash(t *testing.T) {
	service := &fakePreviewLeaseAPI{stop: previewv1.StopResult{Preview: previewv1.Preview{ID: "prv_1"}, ETag: `"ptv1:preview_lease:cHJ2XzE:2"`}}
	newRequest := func(body string) *http.Request {
		request := previewLeaseHandlerRequest(http.MethodPost, "/v1/previews/prv_1/lease/stop", body)
		request.Header.Set("If-Match", `"ptv1:preview_lease:cHJ2XzE:1"`)
		request.Header.Set("Idempotency-Key", "stop_1")
		return request
	}
	first := httptest.NewRecorder()
	previewLeaseStop(service).ServeHTTP(first, newRequest(""))
	if first.Code != http.StatusOK {
		t.Fatalf("empty stop status = %d, body = %s", first.Code, first.Body.String())
	}
	firstHash := service.mutation.RequestHash
	second := httptest.NewRecorder()
	previewLeaseStop(service).ServeHTTP(second, newRequest("{}"))
	if second.Code != http.StatusOK {
		t.Fatalf("object stop status = %d, body = %s", second.Code, second.Body.String())
	}
	if service.mutation.RequestHash != firstHash || firstHash == ([32]byte{}) {
		t.Fatalf("empty and object stop hashes differ: first=%x second=%x", firstHash, service.mutation.RequestHash)
	}
}

func TestPreviewLeaseListMapsInvalidCursorSeparatelyFromPrecondition(t *testing.T) {
	service := &fakePreviewLeaseAPI{err: previewtunnelapi.ErrInvalidCursor}
	request := previewLeaseHandlerRequest(http.MethodGet, "/v1/previews?cursor=bad", "")
	recorder := httptest.NewRecorder()
	previewLeaseList(service).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"code":"invalid_cursor"`) || !strings.Contains(recorder.Body.String(), `"repair_action":"restart_pagination"`) {
		t.Fatalf("invalid cursor response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestPreviewLeaseReadinessMapsAttachmentGateAsRetryable(t *testing.T) {
	request := previewLeaseHandlerRequest(http.MethodPost, "/v1/previews/prv_1/readiness", "{}")
	recorder := httptest.NewRecorder()
	writePreviewLeaseError(recorder, request, errors.Join(previewv1.ErrAttachmentNotReady, errors.New("edge pending")))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"code":"preview_attachment_not_ready"`) || !strings.Contains(recorder.Body.String(), `"retryable":true`) || !strings.Contains(recorder.Body.String(), `"repair_action":"retry_readiness"`) {
		t.Fatalf("attachment readiness response = %d %s", recorder.Code, recorder.Body.String())
	}
}
