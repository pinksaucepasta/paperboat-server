package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/previewdomain"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

type previewDomainAPIStub struct {
	page       previewdomain.Page
	view       previewdomain.DomainView
	result     previewdomain.MutationResult
	instr      previewdomain.DNSInstructions
	err        error
	createBody previewdomain.Request
	mutation   previewdomain.MutationInput
}

func (f *previewDomainAPIStub) List(context.Context, previewtunnelapi.RequestContext, string, string, int) (previewdomain.Page, error) {
	return f.page, f.err
}

func (f *previewDomainAPIStub) Get(context.Context, previewtunnelapi.RequestContext, string, string) (previewdomain.DomainView, error) {
	return f.view, f.err
}

func (f *previewDomainAPIStub) Create(_ context.Context, _ previewtunnelapi.RequestContext, _ string, body previewdomain.Request) (previewdomain.MutationResult, error) {
	f.createBody = body
	return f.result, f.err
}

func (f *previewDomainAPIStub) Verify(_ context.Context, _ previewtunnelapi.RequestContext, _ string, _ string, mutation previewdomain.MutationInput) (previewdomain.MutationResult, error) {
	f.mutation = mutation
	return f.result, f.err
}

func (f *previewDomainAPIStub) Delete(_ context.Context, _ previewtunnelapi.RequestContext, _ string, _ string, mutation previewdomain.MutationInput) (previewdomain.MutationResult, error) {
	f.mutation = mutation
	return f.result, f.err
}

func (f *previewDomainAPIStub) Instructions(context.Context, previewtunnelapi.RequestContext, string, string) (previewdomain.DNSInstructions, error) {
	return f.instr, f.err
}

func (f *previewDomainAPIStub) ReadyAliases(context.Context, previewtunnelapi.RequestContext, string) ([]previewdomain.ReadyAlias, error) {
	return nil, f.err
}

func TestPreviewDomainCreateHandlerStrictAndOperationResponse(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	stub := &previewDomainAPIStub{result: previewdomain.MutationResult{
		Domain:    previewdomain.DomainView{Schema: previewdomain.Schema, Kind: previewdomain.Kind, ID: "domain-1", Hostname: "alias.example", Generation: 1, ETag: previewtunnelapi.ETag(previewdomain.Kind, "domain-1", 1)},
		Operation: previewtunnelapi.Operation{Schema: previewdomain.Schema, Kind: "operation", ID: "op-1", State: "running", Progress: 35, CreatedAt: now, UpdatedAt: now},
	}}
	request := previewLeaseHandlerRequest(http.MethodPost, "/v1/previews/preview-1/domains", `{"hostname":"Alias.Example.","provider":"generic"}`)
	request.Header.Set(previewtunnelapi.IdempotencyHeader, "domain-create-1")
	recorder := httptest.NewRecorder()
	PreviewDomainCreateHandler(stub).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if stub.createBody.Hostname != "Alias.Example." || stub.createBody.Provider != "generic" || stub.createBody.Mutation.IdempotencyKey != "domain-create-1" {
		t.Fatalf("create request = %#v", stub.createBody)
	}
	if recorder.Header().Get("ETag") != stub.result.Domain.ETag || !strings.Contains(recorder.Header().Get("Location"), "op-1") {
		t.Fatalf("headers = %#v", recorder.Header())
	}

	request = previewLeaseHandlerRequest(http.MethodPost, "/v1/previews/preview-1/domains", `{"hostname":"alias.example","unknown":true}`)
	request.Header.Set(previewtunnelapi.IdempotencyHeader, "domain-create-2")
	recorder = httptest.NewRecorder()
	PreviewDomainCreateHandler(stub).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestPreviewDomainMutationHandlerETagAndTypedErrors(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	stub := &previewDomainAPIStub{result: previewdomain.MutationResult{
		Domain:    previewdomain.DomainView{Schema: previewdomain.Schema, Kind: previewdomain.Kind, ID: "domain-1", Generation: 2, ETag: previewtunnelapi.ETag(previewdomain.Kind, "domain-1", 2)},
		Operation: previewtunnelapi.Operation{Schema: previewdomain.Schema, Kind: "operation", ID: "op-delete", State: "succeeded", Progress: 100, CreatedAt: now, UpdatedAt: now},
	}}
	request := previewLeaseHandlerRequest(http.MethodDelete, "/v1/previews/preview-1/domains/domain-1", `{}`)
	request.SetPathValue("domain_id", "domain-1")
	request.Header.Set(previewtunnelapi.IdempotencyHeader, "domain-delete-1")
	request.Header.Set(previewtunnelapi.IfMatchHeader, stub.result.Domain.ETag)
	recorder := httptest.NewRecorder()
	PreviewDomainDeleteHandler(stub).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || stub.mutation.ExpectedGeneration != 2 {
		t.Fatalf("delete status=%d mutation=%#v body=%s", recorder.Code, stub.mutation, recorder.Body.String())
	}

	stub.err = previewdomain.ErrDomainConflict
	request = previewLeaseHandlerRequest(http.MethodDelete, "/v1/previews/preview-1/domains/domain-1", `{}`)
	request.SetPathValue("domain_id", "domain-1")
	request.Header.Set(previewtunnelapi.IdempotencyHeader, "domain-delete-2")
	request.Header.Set(previewtunnelapi.IfMatchHeader, stub.result.Domain.ETag)
	recorder = httptest.NewRecorder()
	PreviewDomainDeleteHandler(stub).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"code":"domain_conflict"`) {
		t.Fatalf("conflict status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	stub.err = previewdomain.ErrDNSUnavailable
	request = previewLeaseHandlerRequest(http.MethodGet, "/v1/previews/preview-1/domains/domain-1/instructions", "")
	request.SetPathValue("domain_id", "domain-1")
	recorder = httptest.NewRecorder()
	PreviewDomainInstructionsHandler(stub).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"code":"dns_unavailable"`) {
		t.Fatalf("dns status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPreviewDomainHandlersRequireAuthenticatedPrincipal(t *testing.T) {
	stub := &previewDomainAPIStub{}
	request := httptest.NewRequest(http.MethodGet, "/v1/previews/preview-1/domains", nil)
	request.SetPathValue("preview_id", "preview-1")
	recorder := httptest.NewRecorder()
	PreviewDomainListHandler(stub).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}
