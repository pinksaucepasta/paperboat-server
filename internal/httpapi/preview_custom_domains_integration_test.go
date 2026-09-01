package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/previewdomain"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
)

// TestPreviewCustomDomainsHTTPIntegration exercises the production preview
// and preview-domain services through their HTTP handlers without requiring a
// database or a network listener. The repository below models the transaction
// boundary explicitly: a preview and every requested alias are prepared first,
// then committed together.
func TestPreviewCustomDomainsHTTPIntegration(t *testing.T) {
	const (
		account      = "acct_preview_http"
		otherAccount = "acct_preview_other"
		device       = "device_preview_http"
	)
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	harness := newPreviewCustomDomainsHTTPHarness(t, now, account, otherAccount, device)

	fullScopes := []string{"previews:read", "previews:write"}
	readScopes := []string{"previews:read"}

	missingDomains := `{"owner_device_id":"` + device + `","owner_session_id":"session_preview_http","target":{"scheme":"http","address":"127.0.0.1:3000"}}`
	response := harness.do(t, http.MethodPost, "/v1/previews", missingDomains, account, fullScopes, "preview-missing-domains", "")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"validation_failed"`) {
		t.Fatalf("missing domains status=%d body=%s", response.Code, response.Body.String())
	}
	if harness.repository.previewCreateCalls() != 0 {
		t.Fatalf("missing domains reached persistence: %d create calls", harness.repository.previewCreateCalls())
	}

	// Validation happens before the repository transaction. A malformed alias
	// therefore cannot leave a preview or a prefix of its aliases behind.
	invalidBatch := `{"owner_device_id":"` + device + `","owner_session_id":"session_preview_http","target":{"scheme":"http","address":"127.0.0.1:3000"},"domains":["valid.example.com","not-a-host"]}`
	response = harness.do(t, http.MethodPost, "/v1/previews", invalidBatch, account, fullScopes, "preview-invalid-batch", "")
	if response.Code != http.StatusBadRequest || harness.repository.previewCreateCalls() != 0 {
		t.Fatalf("invalid alias batch status=%d creates=%d body=%s", response.Code, harness.repository.previewCreateCalls(), response.Body.String())
	}

	createBody := `{"owner_device_id":"` + device + `","owner_session_id":"session_preview_http","target":{"scheme":"http","address":"127.0.0.1:3000"},"domains":["WWW.Example.COM.","Example.COM.","*.Apps.Example.COM."]}`
	response = harness.do(t, http.MethodPost, "/v1/previews", createBody, account, fullScopes, "preview-create-1", "")
	if response.Code != http.StatusAccepted {
		t.Fatalf("preview create status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Location") != "/v1/operations/op_1" {
		t.Fatalf("preview create location=%q body=%s", response.Header().Get("Location"), response.Body.String())
	}
	var createOperation previewtunnelapi.Operation
	decodePreviewCustomDomainJSON(t, response, &createOperation)
	if createOperation.Kind != "operation" || createOperation.ResourceKind != previewv1.Kind || createOperation.ResourceID == "" {
		t.Fatalf("preview create operation=%#v", createOperation)
	}

	previewID := harness.repository.latestPreviewID(account)
	if previewID != "prv_1" {
		t.Fatalf("preview id=%q", previewID)
	}
	if got := harness.repository.previewCreateCalls(); got != 1 {
		t.Fatalf("preview create calls=%d want 1", got)
	}
	if got := harness.repository.previewDomainHostnames(account, previewID); !equalPreviewCustomDomainStrings(got, []string{"*.apps.example.com", "example.com", "www.example.com"}) {
		t.Fatalf("canonical alias hostnames=%v", got)
	}
	if got := harness.repository.previewDomainCount(account, previewID); got != 3 {
		t.Fatalf("committed alias count=%d want 3", got)
	}
	for _, row := range harness.repository.previewDomainRows(account, previewID) {
		if row.PreviewGeneration != 1 || row.Generation != 1 || row.DeletedAt.Valid {
			t.Fatalf("initial alias row was not committed as a live generation-1 binding: %#v", row)
		}
	}

	// An exact replay reuses the same preview and its complete alias batch.
	replay := harness.do(t, http.MethodPost, "/v1/previews", createBody, account, fullScopes, "preview-create-1", "")
	if replay.Code != http.StatusAccepted || harness.repository.previewCreateCalls() != 1 || harness.repository.previewDomainCount(account, previewID) != 3 {
		t.Fatalf("create replay status=%d calls=%d aliases=%d body=%s", replay.Code, harness.repository.previewCreateCalls(), harness.repository.previewDomainCount(account, previewID), replay.Body.String())
	}

	// The managed Paperboat endpoint is available from the preview resource
	// while custom DNS aliases are still waiting for ownership proof.
	response = harness.do(t, http.MethodGet, "/v1/previews/"+previewID, "", account, readScopes, "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("preview get status=%d body=%s", response.Code, response.Body.String())
	}
	var previewResource previewv1.Preview
	decodePreviewCustomDomainJSON(t, response, &previewResource)
	if !strings.HasPrefix(previewResource.Endpoint, "https://") || strings.HasPrefix(previewResource.Endpoint, "https://preview-") || previewResource.Endpoint == "https://www.example.com" || previewResource.Target.Address != "127.0.0.1:3000" {
		t.Fatalf("managed preview endpoint=%q target=%#v", previewResource.Endpoint, previewResource.Target)
	}
	if previewResource.State != "allocating" || len(previewResource.Domains) != 3 {
		t.Fatalf("preview state/domains=%q/%d", previewResource.State, len(previewResource.Domains))
	}
	assertPreviewCustomDomainSummarySafety(t, response.Body.Bytes(), 3)

	// Nested reads are account-scoped and require an authenticated actor with
	// the appropriate resource scope.
	response = harness.do(t, http.MethodGet, "/v1/previews/"+previewID+"/domains", "", "", nil, "", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated nested list status=%d body=%s", response.Code, response.Body.String())
	}
	response = harness.do(t, http.MethodGet, "/v1/previews/"+previewID+"/domains", "", account, []string{"previews:write"}, "", "")
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"forbidden"`) {
		t.Fatalf("missing read scope status=%d body=%s", response.Code, response.Body.String())
	}
	response = harness.do(t, http.MethodGet, "/v1/previews/"+previewID+"/domains", "", otherAccount, readScopes, "", "")
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "example.com") {
		t.Fatalf("cross-account nested list status=%d body=%s", response.Code, response.Body.String())
	}

	response = harness.do(t, http.MethodGet, "/v1/previews/"+previewID+"/domains", "", account, readScopes, "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("nested list status=%d body=%s", response.Code, response.Body.String())
	}
	var domainPage previewdomain.Page
	decodePreviewCustomDomainJSON(t, response, &domainPage)
	if len(domainPage.Items) != 3 {
		t.Fatalf("nested list items=%d want 3", len(domainPage.Items))
	}
	wildcardID := ""
	apexID := ""
	exactID := ""
	for _, item := range domainPage.Items {
		switch item.Hostname {
		case "*.apps.example.com":
			wildcardID = item.ID
			if item.MatchType != "one_label_wildcard" || item.WildcardLabels == nil || *item.WildcardLabels != 1 {
				t.Fatalf("wildcard projection=%#v", item)
			}
		case "example.com":
			apexID = item.ID
		case "www.example.com":
			exactID = item.ID
		}
	}
	if wildcardID == "" || apexID == "" || exactID == "" {
		t.Fatalf("nested aliases missing wildcard=%q apex=%q exact=%q", wildcardID, apexID, exactID)
	}

	response = harness.do(t, http.MethodGet, "/v1/previews/"+previewID+"/domains/"+wildcardID, "", account, readScopes, "", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"match_type":"one_label_wildcard"`) {
		t.Fatalf("nested get status=%d body=%s", response.Code, response.Body.String())
	}
	response = harness.do(t, http.MethodGet, "/v1/previews/"+previewID+"/domains/"+wildcardID, "", otherAccount, readScopes, "", "")
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "apps.example.com") {
		t.Fatalf("cross-account nested get status=%d body=%s", response.Code, response.Body.String())
	}

	response = harness.do(t, http.MethodGet, "/v1/previews/"+previewID+"/domains/"+apexID+"/instructions", "", account, readScopes, "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("domain instructions status=%d body=%s", response.Code, response.Body.String())
	}
	var instructions previewdomain.DNSInstructions
	decodePreviewCustomDomainJSON(t, response, &instructions)
	if instructions.Hostname != "example.com" || len(instructions.Records) < 2 || instructions.Records[0].Type != "ANAME" {
		t.Fatalf("apex instructions=%#v", instructions)
	}
	if strings.Contains(response.Body.String(), "super-secret") || strings.Contains(response.Body.String(), "route_id") || strings.Contains(response.Body.String(), "tunnel_id") {
		t.Fatalf("instructions leaked internal metadata: %s", response.Body.String())
	}

	// Verify is a generation and idempotency mutation. A replay with the
	// original If-Match succeeds, while a different mutation with that stale
	// ETag is rejected before persistence.
	exact := harness.repository.previewDomain(account, previewID, exactID)
	oldExactETag := previewtunnelapi.ETag(previewdomain.Kind, exactID, exact.Generation)
	response = harness.do(t, http.MethodPost, "/v1/previews/"+previewID+"/domains/"+exactID+"/verify", "{}", account, fullScopes, "verify-exact-1", oldExactETag)
	if response.Code != http.StatusAccepted || response.Header().Get("ETag") == oldExactETag {
		t.Fatalf("verify status=%d old_etag=%q new_etag=%q body=%s", response.Code, oldExactETag, response.Header().Get("ETag"), response.Body.String())
	}
	verifiedETag := response.Header().Get("ETag")
	verifyCalls := harness.repository.domainMutationCalls("verify")
	replay = harness.do(t, http.MethodPost, "/v1/previews/"+previewID+"/domains/"+exactID+"/verify", "{}", account, fullScopes, "verify-exact-1", oldExactETag)
	if replay.Code != http.StatusAccepted || replay.Header().Get("ETag") != verifiedETag || harness.repository.domainMutationCalls("verify") != verifyCalls {
		t.Fatalf("verify replay status=%d etag=%q calls=%d/%d body=%s", replay.Code, replay.Header().Get("ETag"), harness.repository.domainMutationCalls("verify"), verifyCalls, replay.Body.String())
	}

	response = harness.do(t, http.MethodDelete, "/v1/previews/"+previewID+"/domains/"+exactID, "{}", account, fullScopes, "delete-stale-1", oldExactETag)
	if response.Code != http.StatusPreconditionFailed || !strings.Contains(response.Body.String(), `"code":"generation_conflict"`) {
		t.Fatalf("stale delete status=%d body=%s", response.Code, response.Body.String())
	}
	response = harness.do(t, http.MethodDelete, "/v1/previews/"+previewID+"/domains/"+exactID, "{}", account, fullScopes, "", verifiedETag)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"idempotency_key_required"`) {
		t.Fatalf("missing delete idempotency status=%d body=%s", response.Code, response.Body.String())
	}
	response = harness.do(t, http.MethodDelete, "/v1/previews/"+previewID+"/domains/"+exactID, "{}", account, fullScopes, "delete-exact-1", verifiedETag)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"quarantined"`) {
		t.Fatalf("domain delete status=%d body=%s", response.Code, response.Body.String())
	}
	deletedETag := response.Header().Get("ETag")
	deleteCalls := harness.repository.domainMutationCalls("delete")
	replay = harness.do(t, http.MethodDelete, "/v1/previews/"+previewID+"/domains/"+exactID, "{}", account, fullScopes, "delete-exact-1", verifiedETag)
	if replay.Code != http.StatusOK || replay.Header().Get("ETag") != deletedETag || harness.repository.domainMutationCalls("delete") != deleteCalls {
		t.Fatalf("delete replay status=%d etag=%q calls=%d/%d body=%s", replay.Code, replay.Header().Get("ETag"), harness.repository.domainMutationCalls("delete"), deleteCalls, replay.Body.String())
	}

	// Stopping the terminal lease withdraws every still-live alias in the same
	// lifecycle transition. The preview resource keeps the managed endpoint as
	// historical context and projects all aliases as quarantined, but no
	// nested live-domain read remains available.
	leaseETag := previewtunnelapi.ETag(previewv1.Kind, previewID, 1)
	response = harness.do(t, http.MethodDelete, "/v1/previews/"+previewID, "{}", account, fullScopes, "preview-stop-1", leaseETag)
	if response.Code != http.StatusOK {
		t.Fatalf("preview stop status=%d body=%s", response.Code, response.Body.String())
	}
	var stoppedPreview previewv1.Preview
	decodePreviewCustomDomainJSON(t, response, &stoppedPreview)
	if stoppedPreview.State != "stopped" || !strings.HasPrefix(stoppedPreview.Endpoint, "https://") || strings.HasPrefix(stoppedPreview.Endpoint, "https://preview-") || len(stoppedPreview.Domains) != 3 {
		t.Fatalf("stopped preview=%#v", stoppedPreview)
	}
	for _, summary := range stoppedPreview.Domains {
		if summary.State != "quarantined" {
			t.Fatalf("terminal alias summary=%#v", summary)
		}
	}
	assertPreviewCustomDomainSummarySafety(t, response.Body.Bytes(), 3)
	if !harness.repository.allPreviewDomainsWithdrawn(account, previewID) {
		t.Fatal("terminal preview left a live alias")
	}

	response = harness.do(t, http.MethodGet, "/v1/previews/"+previewID+"/domains", "", account, readScopes, "", "")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"preview_not_active"`) {
		t.Fatalf("terminal nested list status=%d body=%s", response.Code, response.Body.String())
	}
}

type previewCustomDomainsHTTPHarness struct {
	repository *previewCustomDomainsRepository
	router     http.Handler
}

func newPreviewCustomDomainsHTTPHarness(t *testing.T, now time.Time, account, otherAccount, device string) *previewCustomDomainsHTTPHarness {
	t.Helper()
	repository := newPreviewCustomDomainsRepository(now, account, otherAccount, device)
	previewService, err := previewv1.NewService(repository, previewv1.Config{
		EndpointDomain: "preview.example.test",
		CursorKey:      bytes.Repeat([]byte("p"), 32),
		LeaseDuration:  30 * time.Minute,
		MaxLease:       2 * time.Hour,
		OwnerGrace:     20 * time.Second,
		Now:            func() time.Time { return now },
		NewID:          previewCustomDomainIDFactory(),
		Random:         previewCustomDomainRandomReader{},
		PreviewDomains: repository,
	})
	if err != nil {
		t.Fatal(err)
	}
	domainService, err := previewdomain.NewService(repository, previewdomain.Config{
		CursorKey:     bytes.Repeat([]byte("d"), 32),
		ChallengeZone: "challenge.paperboat.test",
		Now:           func() time.Time { return now },
		NewID:         previewCustomDomainIDFactory(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &previewCustomDomainsHTTPHarness{
		repository: repository,
		router:     newPreviewCustomDomainsHTTPRouter(previewService, domainService),
	}
}

func newPreviewCustomDomainsHTTPRouter(previewAPI PreviewLeaseAPI, domainAPI previewdomain.API) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /v1/previews", previewLeaseCreate(previewAPI))
	mux.Handle("GET /v1/previews", previewLeaseList(previewAPI))
	mux.Handle("GET /v1/previews/{preview_id}", previewLeaseGet(previewAPI))
	mux.Handle("DELETE /v1/previews/{preview_id}", previewLeaseStop(previewAPI))
	mux.Handle("POST /v1/previews/{preview_id}/domains", PreviewDomainCreate(domainAPI))
	mux.Handle("GET /v1/previews/{preview_id}/domains", PreviewDomainList(domainAPI))
	mux.Handle("GET /v1/previews/{preview_id}/domains/{domain_id}", PreviewDomainGet(domainAPI))
	mux.Handle("DELETE /v1/previews/{preview_id}/domains/{domain_id}", PreviewDomainDelete(domainAPI))
	mux.Handle("POST /v1/previews/{preview_id}/domains/{domain_id}/verify", PreviewDomainVerify(domainAPI))
	mux.Handle("GET /v1/previews/{preview_id}/domains/{domain_id}/instructions", PreviewDomainInstructions(domainAPI))
	return mux
}

func (h *previewCustomDomainsHTTPHarness) do(t *testing.T, method, path, body, account string, scopes []string, idempotencyKey, etag string) *httptest.ResponseRecorder {
	t.Helper()
	request := previewCustomDomainHTTPRequest(method, path, body, account, scopes)
	if idempotencyKey != "" {
		request.Header.Set(previewtunnelapi.IdempotencyHeader, idempotencyKey)
	}
	if etag != "" {
		request.Header.Set(previewtunnelapi.IfMatchHeader, etag)
	}
	response := httptest.NewRecorder()
	h.router.ServeHTTP(response, request)
	return response
}

// A nil scopes slice represents a browser principal. A non-nil slice creates
// the same scoped client principal that the production bearer middleware
// places in the request context. This keeps auth behavior deterministic while
// avoiding a database-backed auth service in this focused integration test.
func previewCustomDomainHTTPRequest(method, path, body, account string, scopes []string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	ctx := observability.WithRequestID(request.Context(), "req_preview_custom_domains")
	ctx = observability.WithCorrelationID(ctx, "cor_preview_custom_domains")
	if account != "" {
		user := auth.User{ID: account, Role: auth.RoleUser, Status: "active"}
		var client *auth.ClientPrincipal
		if scopes != nil {
			client = &auth.ClientPrincipal{SessionID: "device_preview_http", User: user, Scopes: append([]string(nil), scopes...)}
		}
		ctx = context.WithValue(ctx, authContextKey{}, principal{User: user, Client: client})
	}
	return request.WithContext(ctx)
}

func decodePreviewCustomDomainJSON(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("response is not JSON: %v body=%s", err, response.Body.String())
	}
	if len(envelope.Data) == 0 {
		t.Fatalf("response does not contain data: %s", response.Body.String())
	}
	if err := json.Unmarshal(envelope.Data, target); err != nil {
		t.Fatalf("response data decode: %v body=%s", err, response.Body.String())
	}
}

func assertPreviewCustomDomainSummarySafety(t *testing.T, body []byte, wantCount int) {
	t.Helper()
	var envelope struct {
		Data struct {
			Domains []map[string]json.RawMessage `json:"domains"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("summary response is not JSON: %v body=%s", err, body)
	}
	if len(envelope.Data.Domains) != wantCount {
		t.Fatalf("summary count=%d want %d body=%s", len(envelope.Data.Domains), wantCount, body)
	}
	allowed := map[string]bool{
		"id": true, "target_kind": true, "preview_id": true, "hostname": true,
		"match_type": true, "wildcard_labels": true, "state": true, "dns": true,
		"certificate": true, "generation": true, "etag": true,
	}
	for _, summary := range envelope.Data.Domains {
		for key := range summary {
			if !allowed[key] {
				t.Fatalf("preview domain summary exposed %q: %s", key, body)
			}
		}
		for _, forbidden := range []string{"schema", "kind", "account_id", "tunnel_id", "route_id", "secret"} {
			if _, exists := summary[forbidden]; exists {
				t.Fatalf("preview domain summary exposed %q: %s", forbidden, body)
			}
		}
	}
	for _, forbidden := range []string{"super-secret", "route_secret", "tunnel_secret"} {
		if bytes.Contains(bytes.ToLower(body), []byte(forbidden)) {
			t.Fatalf("preview response leaked %q: %s", forbidden, body)
		}
	}
	if bytes.Contains(body, []byte(`"tunnel_id"`)) || bytes.Contains(body, []byte(`"route_id"`)) {
		t.Fatalf("preview response leaked tunnel/route identity: %s", body)
	}
}

func previewCustomDomainIDFactory() func(string) (string, error) {
	counts := make(map[string]int)
	return func(prefix string) (string, error) {
		counts[prefix]++
		return prefix + "_" + strconv.Itoa(counts[prefix]), nil
	}
}

type previewCustomDomainRandomReader struct{}

func (previewCustomDomainRandomReader) Read(dst []byte) (int, error) {
	for index := range dst {
		dst[index] = byte(index + 1)
	}
	return len(dst), nil
}

type previewCustomDomainsRepository struct {
	mu  sync.Mutex
	now time.Time

	owners map[string]bool
	leases map[string]previewtunnelstore.PreviewLeaseRecord
	create map[string]previewCustomLeaseCreateRecord
	ops    map[string]dbsqlc.Operation

	renewResults map[string]previewtunnelstore.RenewPreviewLeaseV1Result
	renewHashes  map[string][]byte
	stopResults  map[string]previewtunnelstore.StopPreviewLeaseV1Result
	stopHashes   map[string][]byte

	domains                  map[string]dbsqlc.PreviewDomain
	domainOps                map[string]previewCustomDomainMutationRecord
	domainCreateCalls        int
	previewCreateCallsValue  int
	domainMutationCallsValue map[string]int
}

type previewCustomLeaseCreateRecord struct {
	hash   []byte
	result previewtunnelstore.CreatePreviewLeaseV1Result
}

type previewCustomDomainMutationRecord struct {
	hash   [32]byte
	result previewdomain.RepositoryMutation
}

func newPreviewCustomDomainsRepository(now time.Time, account, otherAccount, device string) *previewCustomDomainsRepository {
	return &previewCustomDomainsRepository{
		now:                      now,
		owners:                   map[string]bool{account + ":" + device: true, otherAccount + ":" + device: true},
		leases:                   make(map[string]previewtunnelstore.PreviewLeaseRecord),
		create:                   make(map[string]previewCustomLeaseCreateRecord),
		ops:                      make(map[string]dbsqlc.Operation),
		renewResults:             make(map[string]previewtunnelstore.RenewPreviewLeaseV1Result),
		renewHashes:              make(map[string][]byte),
		stopResults:              make(map[string]previewtunnelstore.StopPreviewLeaseV1Result),
		stopHashes:               make(map[string][]byte),
		domains:                  make(map[string]dbsqlc.PreviewDomain),
		domainOps:                make(map[string]previewCustomDomainMutationRecord),
		domainMutationCallsValue: make(map[string]int),
	}
}

func (f *previewCustomDomainsRepository) VerifyPreviewLeaseOwnerV1(_ context.Context, accountID, ownerDeviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.owners[accountID+":"+ownerDeviceID] {
		return previewtunnelstore.ErrOwnerNotFound
	}
	return nil
}

func (f *previewCustomDomainsRepository) GetPreviewLeaseV1(_ context.Context, accountID, previewID string) (previewtunnelstore.PreviewLeaseRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	lease, ok := f.leases[previewCustomDomainScope(accountID, previewID)]
	if !ok {
		return previewtunnelstore.PreviewLeaseRecord{}, previewtunnelstore.ErrNotFound
	}
	return lease, nil
}

func (f *previewCustomDomainsRepository) GetPreviewLeaseCreateOperationV1(_ context.Context, accountID, previewID string) (dbsqlc.Operation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, operation := range f.ops {
		if operation.AccountID == accountID && operation.OperationType == "preview.create" && operation.ResourceID.Valid && operation.ResourceID.String == previewID {
			return operation, nil
		}
	}
	return dbsqlc.Operation{}, previewtunnelstore.ErrNotFound
}

func (f *previewCustomDomainsRepository) ListPreviewLeasesV1(_ context.Context, input previewtunnelstore.ListPreviewLeasesV1Input) ([]previewtunnelstore.PreviewLeaseRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := make([]previewtunnelstore.PreviewLeaseRecord, 0)
	for _, lease := range f.leases {
		if lease.AccountID == input.AccountID {
			rows = append(rows, lease)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].CreatedAt.Before(rows[j].CreatedAt)
	})
	if len(rows) > int(input.Limit) {
		rows = rows[:input.Limit]
	}
	return rows, nil
}

func (f *previewCustomDomainsRepository) CreatePreviewLeaseV1(_ context.Context, input previewtunnelstore.CreatePreviewLeaseV1Input) (previewtunnelstore.CreatePreviewLeaseV1Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	createKey := previewCustomDomainScope(input.AccountID, input.IdempotencyKey)
	if previous, ok := f.create[createKey]; ok {
		if !bytes.Equal(previous.hash, input.RequestHash) {
			return previewtunnelstore.CreatePreviewLeaseV1Result{}, previewtunnelstore.ErrIdempotencyConflict
		}
		result := previous.result
		result.Replayed = true
		return result, nil
	}

	// Preflight the complete alias set before mutating either map. This models
	// the SQL transaction's all-or-nothing preview/domain insertion.
	seen := make(map[string]bool, len(input.Domains))
	prepared := make([]dbsqlc.PreviewDomain, 0, len(input.Domains))
	stableTarget, err := previewdomain.StableTargetHostname(input.Endpoint)
	if err != nil {
		return previewtunnelstore.CreatePreviewLeaseV1Result{}, err
	}
	for index, requested := range input.Domains {
		hostname, matchType, normalizeErr := previewdomain.NormalizeHostname(requested.Hostname)
		if normalizeErr != nil {
			return previewtunnelstore.CreatePreviewLeaseV1Result{}, normalizeErr
		}
		if seen[hostname] {
			return previewtunnelstore.CreatePreviewLeaseV1Result{}, previewdomain.ErrDomainConflict
		}
		seen[hostname] = true
		if err := f.previewDomainConflictLocked(input.AccountID, hostname, input.Now); err != nil {
			return previewtunnelstore.CreatePreviewLeaseV1Result{}, err
		}
		provider, providerErr := previewdomain.ValidateProvider(requested.Provider)
		if providerErr != nil {
			return previewtunnelstore.CreatePreviewLeaseV1Result{}, providerErr
		}
		strategy, strategyErr := previewdomain.ValidateCertificateStrategy(requested.CertificateStrategy, matchType)
		if strategyErr != nil {
			return previewtunnelstore.CreatePreviewLeaseV1Result{}, strategyErr
		}
		recordType := previewdomain.DNSRecordType(hostname, provider)
		expected, marshalErr := json.Marshal([]previewdomain.DNSRecord{{Name: hostname, Type: recordType, Value: stableTarget, TTL: 300}})
		if marshalErr != nil {
			return previewtunnelstore.CreatePreviewLeaseV1Result{}, marshalErr
		}
		certificateState, caaState := "pending", "unknown"
		if strategy == "none" {
			certificateState, caaState = "not_applicable", "not_applicable"
		}
		prepared = append(prepared, dbsqlc.PreviewDomain{
			ID: "pdom_" + strconv.Itoa(index+1), AccountID: input.AccountID, PreviewID: input.LeaseID,
			PreviewGeneration: 1, Hostname: hostname, MatchType: matchType,
			OwnershipChallengeReference: "dns-challenge://super-secret-" + strconv.Itoa(index+1),
			OwnershipState:              "pending", DnsTarget: stableTarget, ObservedRecords: []byte(`[]`), DnsProvider: provider,
			ExpectedRecords: expected, DnsNextCheckAt: input.Now, CertificateStrategy: strategy,
			CertificateState: certificateState, CaaState: caaState, ConflictState: "clear", Generation: 1,
			CreatedAt: input.Now, UpdatedAt: input.Now,
		})
	}

	lease := previewtunnelstore.PreviewLeaseRecord{PreviewLease: dbsqlc.PreviewLease{
		ID: input.LeaseID, EndpointID: input.EndpointID, Endpoint: input.Endpoint, AccountID: input.AccountID,
		ActorID: input.ActorID, OwnerDeviceID: input.OwnerDeviceID, OwnerSessionID: input.OwnerSessionID,
		TargetScheme: input.TargetScheme, TargetAddress: input.TargetAddress, AccessMode: input.AccessMode,
		LeaseDeadline: input.LeaseDeadline, UserDeadline: input.UserDeadline, AllocationState: "pending",
		EdgeState: "pending", OriginState: "unknown", TerminalState: "active", CreatedAt: input.Now,
		LastRenewedAt: input.Now, Generation: 1, OwnerLastSeenAt: input.Now,
	}}
	operation := previewCustomDomainOperation(input.OperationID, input.AccountID, input.IdempotencyKey, "preview.create", input.LeaseID, "connecting", "running", 60, input.Now)
	result := previewtunnelstore.CreatePreviewLeaseV1Result{Lease: lease, Operation: operation}
	f.leases[previewCustomDomainScope(input.AccountID, input.LeaseID)] = lease
	f.ops[input.AccountID+":"+input.OperationID] = operation
	f.create[createKey] = previewCustomLeaseCreateRecord{hash: append([]byte(nil), input.RequestHash...), result: result}
	for _, row := range prepared {
		f.domains[previewCustomDomainScope(row.AccountID, row.PreviewID, row.ID)] = row
	}
	f.previewCreateCallsValue++
	f.domainCreateCalls++
	return result, nil
}

func (f *previewCustomDomainsRepository) RenewPreviewLeaseV1(_ context.Context, input previewtunnelstore.RenewPreviewLeaseV1Input) (previewtunnelstore.RenewPreviewLeaseV1Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := previewCustomDomainScope(input.AccountID, input.IdempotencyKey)
	if previous, ok := f.renewResults[key]; ok {
		if !bytes.Equal(f.renewHashes[key], input.RequestHash) {
			return previewtunnelstore.RenewPreviewLeaseV1Result{}, previewtunnelstore.ErrIdempotencyConflict
		}
		previous.Replayed = true
		return previous, nil
	}
	leaseKey := previewCustomDomainScope(input.AccountID, input.PreviewID)
	lease, ok := f.leases[leaseKey]
	if !ok {
		return previewtunnelstore.RenewPreviewLeaseV1Result{}, previewtunnelstore.ErrNotFound
	}
	if lease.TerminalState != "active" {
		return previewtunnelstore.RenewPreviewLeaseV1Result{}, previewtunnelstore.ErrPreviewLeaseTerminal
	}
	if lease.Generation != input.ExpectedGeneration {
		return previewtunnelstore.RenewPreviewLeaseV1Result{}, previewtunnelstore.ErrGenerationConflict
	}
	previousGeneration := lease.Generation
	lease.Generation++
	lease.LeaseDeadline, lease.LastRenewedAt, lease.OwnerLastSeenAt = input.LeaseDeadline, input.Now, input.Now
	f.leases[leaseKey] = lease
	for key, row := range f.domains {
		if row.AccountID == input.AccountID && row.PreviewID == input.PreviewID && !row.DeletedAt.Valid && row.PreviewGeneration == previousGeneration {
			row.PreviewGeneration = lease.Generation
			row.UpdatedAt = input.Now
			f.domains[key] = row
		}
	}
	operation := previewCustomDomainOperation(input.OperationID, input.AccountID, input.IdempotencyKey, "preview.renew", input.PreviewID, "ready", "succeeded", 100, input.Now)
	result := previewtunnelstore.RenewPreviewLeaseV1Result{Lease: lease, Operation: operation}
	f.renewResults[key], f.renewHashes[key] = result, append([]byte(nil), input.RequestHash...)
	f.ops[input.AccountID+":"+input.OperationID] = operation
	return result, nil
}

func (f *previewCustomDomainsRepository) StopPreviewLeaseV1(_ context.Context, input previewtunnelstore.StopPreviewLeaseV1Input) (previewtunnelstore.StopPreviewLeaseV1Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := previewCustomDomainScope(input.AccountID, input.IdempotencyKey)
	if previous, ok := f.stopResults[key]; ok {
		if !bytes.Equal(f.stopHashes[key], input.RequestHash) {
			return previewtunnelstore.StopPreviewLeaseV1Result{}, previewtunnelstore.ErrIdempotencyConflict
		}
		previous.Replayed = true
		return previous, nil
	}
	leaseKey := previewCustomDomainScope(input.AccountID, input.PreviewID)
	lease, ok := f.leases[leaseKey]
	if !ok {
		return previewtunnelstore.StopPreviewLeaseV1Result{}, previewtunnelstore.ErrNotFound
	}
	if lease.TerminalState != "active" {
		return previewtunnelstore.StopPreviewLeaseV1Result{}, previewtunnelstore.ErrPreviewLeaseTerminal
	}
	if lease.Generation != input.ExpectedGeneration {
		return previewtunnelstore.StopPreviewLeaseV1Result{}, previewtunnelstore.ErrGenerationConflict
	}
	terminalGeneration := lease.Generation
	lease.Generation++
	lease.AllocationState, lease.EdgeState, lease.OriginState, lease.TerminalState = "released", "released", "down", "stopped"
	lease.StoppedAt = sql.NullTime{Time: input.Now, Valid: true}
	f.leases[leaseKey] = lease
	for key, row := range f.domains {
		if row.AccountID != input.AccountID || row.PreviewID != input.PreviewID || row.PreviewGeneration > terminalGeneration || row.DeletedAt.Valid {
			continue
		}
		row.OwnershipState, row.CertificateState, row.ConflictState = "expired", "revoked", "quarantined"
		row.QuarantineUntil = sql.NullTime{Time: input.Now.Add(previewdomain.Quarantine), Valid: true}
		row.DeletedAt = sql.NullTime{Time: input.Now, Valid: true}
		row.Generation++
		row.UpdatedAt = input.Now
		f.domains[key] = row
	}
	result := previewtunnelstore.StopPreviewLeaseV1Result{Lease: lease}
	f.stopResults[key], f.stopHashes[key] = result, append([]byte(nil), input.RequestHash...)
	return result, nil
}

func (f *previewCustomDomainsRepository) MarkPreviewLeaseReadyV1(_ context.Context, input previewtunnelstore.MarkPreviewLeaseReadyV1Input) (previewtunnelstore.PreviewLeaseRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := previewCustomDomainScope(input.AccountID, input.PreviewID)
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
	}
	lease.Generation++
	f.leases[key] = lease
	return lease, nil
}

func (f *previewCustomDomainsRepository) ReconcilePreviewLeasesV1(context.Context, previewtunnelstore.ReconcilePreviewLeasesV1Input) (previewtunnelstore.ReconcilePreviewLeasesV1Result, error) {
	return previewtunnelstore.ReconcilePreviewLeasesV1Result{}, nil
}

func (f *previewCustomDomainsRepository) MarkPreviewLeaseDispatchUncertainV1(context.Context, previewtunnelstore.MarkPreviewLeaseDispatchUncertainV1Input) error {
	return nil
}

func (f *previewCustomDomainsRepository) List(_ context.Context, accountID, previewID string, after *previewdomain.ListPosition, limit int) ([]dbsqlc.PreviewDomain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.domainRowsLocked(accountID, previewID, false)
	if after != nil {
		filtered := rows[:0]
		for _, row := range rows {
			if row.CreatedAt.After(after.CreatedAt) || (row.CreatedAt.Equal(after.CreatedAt) && row.ID > after.ID) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return clonePreviewCustomDomainRows(rows), nil
}

func (f *previewCustomDomainsRepository) ListProjection(_ context.Context, accountID, previewID string, limit int) ([]dbsqlc.PreviewDomain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.domainRowsLocked(accountID, previewID, true)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return clonePreviewCustomDomainRows(rows), nil
}

func (f *previewCustomDomainsRepository) Get(_ context.Context, accountID, previewID, domainID string) (dbsqlc.PreviewDomain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.domains[previewCustomDomainScope(accountID, previewID, domainID)]
	if !ok || row.DeletedAt.Valid {
		return dbsqlc.PreviewDomain{}, previewdomain.ErrNotFound
	}
	return clonePreviewCustomDomainRow(row), nil
}

func (f *previewCustomDomainsRepository) Lease(_ context.Context, accountID, previewID string) (previewdomain.LeaseContext, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	lease, ok := f.leases[previewCustomDomainScope(accountID, previewID)]
	if !ok {
		return previewdomain.LeaseContext{}, previewdomain.ErrNotFound
	}
	return previewdomain.LeaseContext{ID: lease.ID, AccountID: lease.AccountID, Generation: lease.Generation, LeaseDeadline: lease.LeaseDeadline, UserDeadline: lease.UserDeadline, AllocationState: lease.AllocationState, EdgeState: lease.EdgeState, OriginState: lease.OriginState, TerminalState: lease.TerminalState, OwnerDeviceID: lease.OwnerDeviceID, OwnerSessionID: lease.OwnerSessionID, Endpoint: lease.Endpoint}, nil
}

func (f *previewCustomDomainsRepository) Create(_ context.Context, input previewdomain.CreateRecord) (previewdomain.RepositoryMutation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := "create:" + previewCustomDomainScope(input.AccountID, input.IdempotencyKey)
	if previous, ok := f.domainOps[key]; ok {
		if previous.hash != input.RequestHash {
			return previewdomain.RepositoryMutation{}, previewdomain.ErrIdempotencyConflict
		}
		result := previous.result
		result.Replayed = true
		return result, nil
	}
	if err := f.previewDomainConflictLocked(input.AccountID, input.Hostname, input.Now); err != nil {
		return previewdomain.RepositoryMutation{}, err
	}
	row := dbsqlc.PreviewDomain{ID: input.DomainID, AccountID: input.AccountID, PreviewID: input.PreviewID, PreviewGeneration: input.PreviewGeneration, Hostname: input.Hostname, MatchType: input.MatchType, OwnershipChallengeReference: input.ChallengeReference, OwnershipState: "pending", DnsTarget: input.DNSTarget, DnsProvider: input.DNSProvider, ExpectedRecords: append([]byte(nil), input.ExpectedRecords...), DnsNextCheckAt: input.Now, CertificateStrategy: input.CertificateStrategy, CertificateState: "pending", CaaState: "unknown", ConflictState: "clear", Generation: 1, CreatedAt: input.Now, UpdatedAt: input.Now}
	f.domains[previewCustomDomainScope(input.AccountID, input.PreviewID, input.DomainID)] = row
	op := previewCustomDomainOperation(input.OperationID, input.AccountID, input.IdempotencyKey, "preview.domain.create", input.DomainID, "waiting_for_dns", "running", 35, input.Now)
	result := previewdomain.RepositoryMutation{Domain: row, Operation: op, Changed: true}
	f.domainOps[key] = previewCustomDomainMutationRecord{hash: input.RequestHash, result: result}
	f.domainCreateCalls++
	return result, nil
}

func (f *previewCustomDomainsRepository) Verify(_ context.Context, input previewdomain.MutationRecord) (previewdomain.RepositoryMutation, error) {
	return f.mutateDomain(input, true)
}

func (f *previewCustomDomainsRepository) Delete(_ context.Context, input previewdomain.MutationRecord) (previewdomain.RepositoryMutation, error) {
	return f.mutateDomain(input, false)
}

func (f *previewCustomDomainsRepository) ApplyDNSObservation(_ context.Context, input previewdomain.DNSObservationRecord) (previewdomain.RepositoryMutation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := previewCustomDomainScope(input.AccountID, input.PreviewID, input.DomainID)
	row, ok := f.domains[key]
	if !ok || row.DeletedAt.Valid || row.Generation != input.ExpectedGeneration {
		return previewdomain.RepositoryMutation{}, previewdomain.ErrGenerationConflict
	}
	row.ObservedRecords, row.OwnershipState, row.ConflictState = append([]byte(nil), input.ObservedRecords...), input.OwnershipState, input.ConflictState
	row.Generation++
	row.UpdatedAt = input.Now
	f.domains[key] = row
	return previewdomain.RepositoryMutation{Domain: row, Changed: true}, nil
}

func (f *previewCustomDomainsRepository) ApplyCertificateObservation(_ context.Context, input previewdomain.CertificateObservationRecord) (previewdomain.RepositoryMutation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := previewCustomDomainScope(input.AccountID, input.PreviewID, input.DomainID)
	row, ok := f.domains[key]
	if !ok || row.DeletedAt.Valid || row.Generation != input.ExpectedGeneration {
		return previewdomain.RepositoryMutation{}, previewdomain.ErrGenerationConflict
	}
	row.CertificateState, row.CaaState = input.CertificateState, input.CAAState
	if input.CertificateReference != nil {
		row.CertificateReference = sql.NullString{String: *input.CertificateReference, Valid: true}
	}
	row.Generation++
	row.UpdatedAt = input.Now
	f.domains[key] = row
	return previewdomain.RepositoryMutation{Domain: row, Changed: true}, nil
}

func (f *previewCustomDomainsRepository) ReadyAliases(_ context.Context, accountID, previewID string, _ time.Time) ([]previewdomain.ReadyAliasRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.domainRowsLocked(accountID, previewID, false)
	result := make([]previewdomain.ReadyAliasRecord, 0, len(rows))
	for _, row := range rows {
		if row.OwnershipState == "verified" && row.CertificateState == "ready" && row.ConflictState == "clear" {
			result = append(result, previewdomain.ReadyAliasRecord{Domain: row, CertificateReference: "cert-ref", CertificateGeneration: row.Generation})
		}
	}
	return result, nil
}

func (f *previewCustomDomainsRepository) mutateDomain(input previewdomain.MutationRecord, verify bool) (previewdomain.RepositoryMutation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	opType := "delete"
	if verify {
		opType = "verify"
	}
	key := opType + ":" + previewCustomDomainScope(input.AccountID, input.IdempotencyKey)
	if previous, ok := f.domainOps[key]; ok {
		if previous.hash != input.RequestHash {
			return previewdomain.RepositoryMutation{}, previewdomain.ErrIdempotencyConflict
		}
		result := previous.result
		result.Replayed = true
		return result, nil
	}
	domainKey := previewCustomDomainScope(input.AccountID, input.PreviewID, input.DomainID)
	row, ok := f.domains[domainKey]
	if !ok || row.DeletedAt.Valid {
		return previewdomain.RepositoryMutation{}, previewdomain.ErrNotFound
	}
	lease, ok := f.leases[previewCustomDomainScope(input.AccountID, input.PreviewID)]
	if !ok {
		return previewdomain.RepositoryMutation{}, previewdomain.ErrNotFound
	}
	if row.PreviewGeneration != lease.Generation || row.Generation != input.ExpectedGeneration {
		return previewdomain.RepositoryMutation{}, previewdomain.ErrGenerationConflict
	}
	row.Generation++
	row.UpdatedAt = input.Now
	phase, state, progress := "waiting_for_dns", "running", int16(35)
	if verify {
		row.OwnershipState, row.ConflictState = "pending", "clear"
		row.VerificationAttempts = 0
	} else {
		row.OwnershipState, row.CertificateState, row.ConflictState = "revoked", "revoked", "quarantined"
		row.DeletedAt = sql.NullTime{Time: input.Now, Valid: true}
		row.QuarantineUntil = sql.NullTime{Time: input.Now.Add(previewdomain.Quarantine), Valid: true}
		phase, state, progress = "ready", "succeeded", 100
	}
	f.domains[domainKey] = row
	op := previewCustomDomainOperation(input.OperationID, input.AccountID, input.IdempotencyKey, "preview.domain."+opType, input.DomainID, phase, state, progress, input.Now)
	result := previewdomain.RepositoryMutation{Domain: row, Operation: op, Changed: true}
	f.domainOps[key] = previewCustomDomainMutationRecord{hash: input.RequestHash, result: result}
	f.domainMutationCallsValue[opType]++
	return result, nil
}

func (f *previewCustomDomainsRepository) previewDomainConflictLocked(accountID, hostname string, now time.Time) error {
	for _, row := range f.domains {
		if row.Hostname != hostname {
			continue
		}
		if !row.DeletedAt.Valid {
			return previewdomain.ErrDomainConflict
		}
		if row.AccountID != accountID && row.QuarantineUntil.Valid && now.Before(row.QuarantineUntil.Time) {
			return previewdomain.ErrDomainConflict
		}
	}
	return nil
}

func (f *previewCustomDomainsRepository) domainRowsLocked(accountID, previewID string, includeDeleted bool) []dbsqlc.PreviewDomain {
	rows := make([]dbsqlc.PreviewDomain, 0)
	for _, row := range f.domains {
		if row.AccountID == accountID && row.PreviewID == previewID && (includeDeleted || !row.DeletedAt.Valid) {
			rows = append(rows, clonePreviewCustomDomainRow(row))
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].CreatedAt.Before(rows[j].CreatedAt)
	})
	return rows
}

func (f *previewCustomDomainsRepository) latestPreviewID(accountID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var latest previewtunnelstore.PreviewLeaseRecord
	for _, lease := range f.leases {
		if lease.AccountID == accountID && (latest.ID == "" || lease.CreatedAt.After(latest.CreatedAt)) {
			latest = lease
		}
	}
	return latest.ID
}

func (f *previewCustomDomainsRepository) previewCreateCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.previewCreateCallsValue
}

func (f *previewCustomDomainsRepository) previewDomainCount(accountID, previewID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.domainRowsLocked(accountID, previewID, true))
}

func (f *previewCustomDomainsRepository) previewDomainHostnames(accountID, previewID string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.domainRowsLocked(accountID, previewID, true)
	hostnames := make([]string, 0, len(rows))
	for _, row := range rows {
		hostnames = append(hostnames, row.Hostname)
	}
	sort.Strings(hostnames)
	return hostnames
}

func (f *previewCustomDomainsRepository) previewDomainRows(accountID, previewID string) []dbsqlc.PreviewDomain {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.domainRowsLocked(accountID, previewID, true)
}

func (f *previewCustomDomainsRepository) previewDomain(accountID, previewID, domainID string) dbsqlc.PreviewDomain {
	f.mu.Lock()
	defer f.mu.Unlock()
	return clonePreviewCustomDomainRow(f.domains[previewCustomDomainScope(accountID, previewID, domainID)])
}

func (f *previewCustomDomainsRepository) domainMutationCalls(kind string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.domainMutationCallsValue[kind]
}

func (f *previewCustomDomainsRepository) allPreviewDomainsWithdrawn(accountID, previewID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.domainRowsLocked(accountID, previewID, true)
	if len(rows) == 0 {
		return false
	}
	for _, row := range rows {
		if !row.DeletedAt.Valid || row.ConflictState != "quarantined" {
			return false
		}
	}
	return true
}

func clonePreviewCustomDomainRows(rows []dbsqlc.PreviewDomain) []dbsqlc.PreviewDomain {
	cloned := make([]dbsqlc.PreviewDomain, len(rows))
	for index, row := range rows {
		cloned[index] = clonePreviewCustomDomainRow(row)
	}
	return cloned
}

func clonePreviewCustomDomainRow(row dbsqlc.PreviewDomain) dbsqlc.PreviewDomain {
	row.ObservedRecords = append([]byte(nil), row.ObservedRecords...)
	row.ExpectedRecords = append([]byte(nil), row.ExpectedRecords...)
	return row
}

func previewCustomDomainOperation(id, account, idempotencyKey, operationType, resourceID, phase, state string, progress int16, now time.Time) dbsqlc.Operation {
	resourceKind := previewdomain.Kind
	if operationType == "preview.create" || operationType == "preview.renew" {
		resourceKind = previewv1.Kind
	}
	return dbsqlc.Operation{ID: id, AccountID: account, IdempotencyKey: idempotencyKey, OperationType: operationType, ResourceKind: resourceKind, ResourceID: sql.NullString{String: resourceID, Valid: resourceID != ""}, Phase: phase, State: state, Progress: progress, Outcome: "changed", CorrelationID: "cor_preview_custom_domains", CreatedAt: now, UpdatedAt: now}
}

func previewCustomDomainScope(parts ...string) string {
	return strings.Join(parts, ":")
}

func equalPreviewCustomDomainStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var _ previewv1.Repository = (*previewCustomDomainsRepository)(nil)
var _ previewdomain.PreviewDomainRepository = (*previewCustomDomainsRepository)(nil)
