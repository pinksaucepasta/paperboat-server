package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/diagnosticuploads"
)

type diagnosticRepositoryStub struct{ intent diagnosticuploads.Intent }

func (s *diagnosticRepositoryStub) Reserve(_ context.Context, request diagnosticuploads.CreateRequest, hash [32]byte, proposed diagnosticuploads.Intent) (diagnosticuploads.Intent, error) {
	if request.UserID != "usr_test" || request.CLIClientSessionID != "cli_test" {
		return diagnosticuploads.Intent{}, diagnosticuploads.ErrNotFound
	}
	if s.intent.ID == "" {
		s.intent = proposed
	}
	if s.intent.RequestHash != hash {
		return diagnosticuploads.Intent{}, diagnosticuploads.ErrIdempotencyConflict
	}
	return s.intent, nil
}
func (s *diagnosticRepositoryStub) Get(_ context.Context, userID, intentID string) (diagnosticuploads.Intent, error) {
	if userID != s.intent.UserID || intentID != s.intent.ID {
		return diagnosticuploads.Intent{}, diagnosticuploads.ErrNotFound
	}
	return s.intent, nil
}
func (s *diagnosticRepositoryStub) Complete(_ context.Context, userID, intentID string, metadata diagnosticuploads.ObjectMetadata, now time.Time) (diagnosticuploads.Intent, error) {
	if userID != s.intent.UserID || intentID != s.intent.ID || metadata.Bytes != s.intent.Bytes || metadata.SHA256 != s.intent.SHA256 {
		return diagnosticuploads.Intent{}, diagnosticuploads.ErrUploadMismatch
	}
	s.intent.State, s.intent.UploadedAt, s.intent.ObjectETag = "uploaded", now, metadata.ETag
	return s.intent, nil
}

type diagnosticObjectsStub struct {
	metadata diagnosticuploads.ObjectMetadata
}

func (s *diagnosticObjectsStub) AuthorizePut(_ context.Context, _ string, _ int64, _ [32]byte, _ time.Time) (diagnosticuploads.UploadAuthority, error) {
	return diagnosticuploads.UploadAuthority{URL: "https://objects.example.test/upload", Headers: map[string]string{"X-Amz-Checksum-Sha256": "checksum", "If-None-Match": "*"}}, nil
}
func (s *diagnosticObjectsStub) Stat(_ context.Context, _ string) (diagnosticuploads.ObjectMetadata, error) {
	return s.metadata, nil
}

func TestDiagnosticUploadHandlerLifecycle(t *testing.T) {
	repository, objects := &diagnosticRepositoryStub{}, &diagnosticObjectsStub{}
	service, err := diagnosticuploads.New(repository, objects)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"schema":"paperboat.diagnostic-upload-intent-request/v1","correlation_id":"pb-0123456789abcdef0123456789abcdef","bytes":1024,"sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","categories":["manifest","recent_events","redacted_events","status"]}`)
	request := authenticatedDiagnosticRequest(http.MethodPost, "/v1/diagnostic-upload-intents", body)
	request.Header.Set("Idempotency-Key", "diagnostic-operation-0001")
	response := httptest.NewRecorder()
	diagnosticUploadIntentCreate(service).ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data diagnosticUploadIntentResponse `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Schema != "paperboat.diagnostic-upload-intent/v1" || envelope.Data.State != "pending" || envelope.Data.UploadMethod != http.MethodPut || envelope.Data.UploadHeaders["If-None-Match"] != "*" {
		t.Fatalf("response=%#v", envelope.Data)
	}
	copy(objects.metadata.SHA256[:], repository.intent.SHA256[:])
	objects.metadata.Bytes, objects.metadata.ETag = repository.intent.Bytes, "etag"
	completeBody := []byte(`{}`)
	complete := authenticatedDiagnosticRequest(http.MethodPost, "/v1/diagnostic-upload-intents/"+repository.intent.ID+"/complete", completeBody)
	complete.SetPathValue("intent_id", repository.intent.ID)
	completed := httptest.NewRecorder()
	diagnosticUploadIntentComplete(service).ServeHTTP(completed, complete)
	if completed.Code != http.StatusOK {
		t.Fatalf("complete status=%d body=%s", completed.Code, completed.Body.String())
	}
	if !bytes.Contains(completed.Body.Bytes(), []byte(`"state":"uploaded"`)) || !bytes.Contains(completed.Body.Bytes(), []byte(repository.intent.CorrelationID)) {
		t.Fatalf("completion=%s", completed.Body.String())
	}
}

func TestDiagnosticUploadHandlerRejectsLooseInput(t *testing.T) {
	service, _ := diagnosticuploads.New(&diagnosticRepositoryStub{}, &diagnosticObjectsStub{})
	valid := []byte(`{"schema":"paperboat.diagnostic-upload-intent-request/v1","correlation_id":"pb-0123456789abcdef0123456789abcdef","bytes":1024,"sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","categories":["manifest","recent_events","redacted_events","status"]}`)
	for name, mutate := range map[string]func(*http.Request){
		"content type": func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		"query":        func(r *http.Request) { r.URL.RawQuery = "debug=true" },
		"unknown field": func(r *http.Request) {
			changed := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"token":"secret"}`)...)
			r.Body = io.NopCloser(bytes.NewReader(changed))
			r.ContentLength = int64(len(changed))
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := authenticatedDiagnosticRequest(http.MethodPost, "/v1/diagnostic-upload-intents", valid)
			request.Header.Set("Idempotency-Key", "diagnostic-operation-0001")
			mutate(request)
			response := httptest.NewRecorder()
			diagnosticUploadIntentCreate(service).ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func authenticatedDiagnosticRequest(method, target string, body []byte) *http.Request {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	client := &auth.ClientPrincipal{SessionID: "cli_test", Scopes: []string{"diagnostics:upload"}}
	ctx := context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "usr_test"}, Client: client})
	return request.WithContext(ctx)
}
