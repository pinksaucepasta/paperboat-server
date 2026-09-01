package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/environment"
)

type environmentScopesAPI struct {
	environmentVariableAPI
	accountID string
	calls     int
}

func (a *environmentScopesAPI) ListScopes(_ context.Context, accountID string) (environment.ScopeInventory, error) {
	a.accountID = accountID
	a.calls++
	return environment.ScopeInventory{
		Schema: "paperboat.environment-scope-inventory/v1",
		Scopes: []environment.ScopeInventoryItem{
			{Scope: "global", ScopeState: "active", Version: 7, KeyEpoch: 3, ManifestID: "sha256:" + strings.Repeat("1", 64), Names: []string{"APP_LOG_LEVEL", "APP_REGION"}},
			{Scope: "machine", MachineID: "machine_01", ScopeState: "active", Version: 4, KeyEpoch: 2, ManifestID: "sha256:" + strings.Repeat("2", 64), Names: []string{"APP_REGION"}},
			{Scope: "machine", MachineID: "machine_retired", ScopeState: "retired", Version: 9, KeyEpoch: 5, ManifestID: "sha256:" + strings.Repeat("3", 64), Names: []string{}},
		},
	}, nil
}

func TestEnvironmentScopesRequiresAccountPrincipal(t *testing.T) {
	api := &environmentScopesAPI{}
	request := httptest.NewRequest(http.MethodGet, "/v1/environment-scopes", nil)
	response := httptest.NewRecorder()

	environmentScopesList(api).ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || api.calls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, api.calls, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control=%q", response.Header().Get("Cache-Control"))
	}
}

func TestEnvironmentScopesReturnsStrictMetadataOnlyInventory(t *testing.T) {
	api := &environmentScopesAPI{}
	request := httptest.NewRequest(http.MethodGet, "/v1/environment-scopes", nil)
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}}))
	response := httptest.NewRecorder()

	environmentScopesList(api).ServeHTTP(response, request)

	if response.Code != http.StatusOK || api.calls != 1 || api.accountID != "account_01" {
		t.Fatalf("status=%d calls=%d account=%q body=%s", response.Code, api.calls, api.accountID, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control=%q", response.Header().Get("Cache-Control"))
	}
	var responseDocument struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &responseDocument); err != nil {
		t.Fatal(err)
	}
	var inventory environment.ScopeInventory
	if err := json.Unmarshal(responseDocument.Data, &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Schema != "paperboat.environment-scope-inventory/v1" || len(inventory.Scopes) != 3 || inventory.Scopes[2].ScopeState != "retired" || inventory.Scopes[2].Names == nil {
		t.Fatalf("inventory=%+v", inventory)
	}
	for _, forbidden := range []string{"envelope", "ciphertext", "content_hash", "wrapped_key", "value"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("response leaked forbidden field %q: %s", forbidden, response.Body.String())
		}
	}
}
