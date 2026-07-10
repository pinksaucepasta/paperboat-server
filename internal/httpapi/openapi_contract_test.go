package httpapi

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestOpenAPIDocumentCoversPublicAndFrozenTargetPaths(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenAPI string                    `json:"openapi"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("openapi json is invalid: %v", err)
	}
	if doc.OpenAPI == "" {
		t.Fatal("missing openapi version")
	}
	required := map[string][]string{
		"/.well-known/jwks.json":                {"get"},
		"/healthz":                              {"get"},
		"/readyz":                               {"get"},
		"/api/me":                               {"get"},
		"/api/auth/workos/state":                {"get"},
		"/api/auth/workos/callback":             {"post"},
		"/api/auth/logout":                      {"post"},
		"/api/auth/csrf":                        {"get"},
		"/api/auth/device/authorize":            {"post"},
		"/api/auth/device/token":                {"post"},
		"/api/auth/device/requests/{user_code}": {"get"},
		"/api/auth/device/requests/{user_code}/approve": {"post"},
		"/api/auth/device/requests/{user_code}/deny":    {"post"},
		"/api/auth/token/refresh":                       {"post"},
		"/api/auth/token/revoke":                        {"post"},
		"/api/auth/clients":                             {"get"},
		"/api/auth/clients/{client_session_id}":         {"delete"},
		"/api/billing/entitlement":                      {"get"},
		"/api/billing/usage":                            {"get"},
		"/api/billing/plan-products":                    {"get"},
		"/api/billing/checkout":                         {"post"},
		"/api/billing/customer-portal":                  {"post"},
		"/api/webhooks/polar":                           {"post"},
		"/api/catalog/plans":                            {"get"},
		"/api/catalog/machine-types":                    {"get"},
		"/api/catalog/presets":                          {"get"},
		"/api/catalog/idle-timeouts":                    {"get"},
		"/api/catalog/regions":                          {"get"},
		"/api/github/status":                            {"get"},
		"/api/github/oauth/start":                       {"post"},
		"/api/github/oauth/callback":                    {"get", "post"},
		"/api/github/config-repo/provision":             {"post"},
		"/api/dashboard/usage-summary":                  {"get"},
		"/api/projects":                                 {"get", "post"},
		"/api/projects/{project_id}":                    {"get", "patch", "delete"},
		"/api/projects/{project_id}/start":              {"post"},
		"/api/projects/{project_id}/stop":               {"post"},
		"/api/projects/{project_id}/restart":            {"post"},
		"/api/projects/{project_id}/keep-alive":         {"post"},
		"/api/projects/{project_id}/activity":           {"post"},
		"/api/projects/{project_id}/events":             {"get"},
		"/api/projects/{project_id}/connect":            {"post"},
		"/api/projects/{project_id}/cli-connect":        {"post"},
		"/api/projects/{project_id}/papercode-connect":  {"post"},
		"/api/projects/{project_id}/connection-status":  {"get"},
		"/api/machine/activity-heartbeat":               {"post"},
		"/api/admin/users/{user_id}/adjust-credits":     {"post"},
		"/api/admin/users/{user_id}/adjust-storage":     {"post"},
	}
	for path, methods := range required {
		operations, ok := doc.Paths[path]
		if !ok {
			t.Fatalf("openapi missing path %s", path)
		}
		for _, method := range methods {
			if _, ok := operations[method]; !ok {
				t.Fatalf("openapi missing %s %s", method, path)
			}
		}
	}
}

func TestOpenAPIFreezesCLIContractSchemas(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("openapi json is invalid: %v", err)
	}

	client := doc.Components.Schemas["AuthorizedClient"]
	assertExactCLIScopes(t, doc.Components.Schemas["DeviceAuthorizationRequest"], "DeviceAuthorizationRequest")
	assertExactCLIScopes(t, doc.Components.Schemas["DeviceRequest"], "DeviceRequest")
	assertExactCLIScopes(t, client, "AuthorizedClient")
	tokenSetProperties := objectValue(t, doc.Components.Schemas["TokenSet"]["properties"], "TokenSet.properties")
	scope := objectValue(t, tokenSetProperties["scope"], "TokenSet.scope")
	if scope["const"] != "account:read clients:revoke projects:read projects:connect session:refresh" {
		t.Fatalf("TokenSet.scope const = %v", scope["const"])
	}
	descriptor := doc.Components.Schemas["CLIConnectDescriptor"]
	descriptorRequired := stringSet(t, descriptor["required"], "CLIConnectDescriptor.required")
	for _, field := range []string{"status", "reason", "retry_after_seconds"} {
		if !descriptorRequired[field] {
			t.Fatalf("CLIConnectDescriptor does not require %q", field)
		}
	}
	descriptorProperties := objectValue(t, descriptor["properties"], "CLIConnectDescriptor.properties")
	for field, expected := range map[string]any{"status": "ready", "reason": "ready", "retry_after_seconds": float64(0)} {
		property := objectValue(t, descriptorProperties[field], "CLIConnectDescriptor."+field)
		if property["const"] != expected {
			t.Fatalf("CLIConnectDescriptor.%s const = %v", field, property["const"])
		}
	}
	terminalAuthProperties := objectValue(t, doc.Components.Schemas["TerminalAuth"]["properties"], "TerminalAuth.properties")
	assertSingletonConstScope(t, terminalAuthProperties["scopes"], "terminal:operate", "TerminalAuth.scopes")
	stagedUploadProperties := objectValue(t, doc.Components.Schemas["StagedImageUpload"]["properties"], "StagedImageUpload.properties")
	uploadAuth := objectValue(t, stagedUploadProperties["auth"], "StagedImageUpload.auth")
	uploadAuthProperties := objectValue(t, uploadAuth["properties"], "StagedImageUpload.auth.properties")
	assertSingletonConstScope(t, uploadAuthProperties["scopes"], "file:stage", "StagedImageUpload.auth.scopes")
	required := stringSet(t, client["required"], "AuthorizedClient.required")
	for _, field := range []string{
		"client_session_id", "client_id", "client_label", "device_type", "os", "scopes",
		"state", "created_at", "approved_at", "last_used_at", "revoked_at",
		"revocation_reason", "current",
	} {
		if !required[field] {
			t.Fatalf("AuthorizedClient does not require %q", field)
		}
	}

	list := doc.Components.Schemas["AuthorizedClientList"]
	listProperties := objectValue(t, list["properties"], "AuthorizedClientList.properties")
	items := objectValue(t, listProperties["items"], "AuthorizedClientList.items")
	itemSchema := objectValue(t, items["items"], "AuthorizedClientList.items.items")
	if itemSchema["$ref"] != "#/components/schemas/AuthorizedClient" {
		t.Fatalf("authorized-client item ref = %v", itemSchema["$ref"])
	}
	pagination := objectValue(t, listProperties["pagination"], "AuthorizedClientList.pagination")
	paginationRequired := stringSet(t, pagination["required"], "AuthorizedClientList.pagination.required")
	if !reflect.DeepEqual(paginationRequired, map[string]bool{
		"limit": true, "offset": true, "total": true, "next_offset": true,
	}) {
		t.Fatalf("pagination required fields = %#v", paginationRequired)
	}

	get := objectValue(t, doc.Paths["/api/auth/clients"]["get"], "GET /api/auth/clients")
	assertRequiredBearerScope(t, get, "account:read", "GET /api/auth/clients")
	responses := objectValue(t, get["responses"], "authorized-client responses")
	okResponse := objectValue(t, responses["200"], "authorized-client 200")
	content := objectValue(t, okResponse["content"], "authorized-client content")
	jsonContent := objectValue(t, content["application/json"], "authorized-client JSON")
	responseSchema := objectValue(t, jsonContent["schema"], "authorized-client response schema")
	properties := objectValue(t, responseSchema["properties"], "authorized-client response properties")
	data := objectValue(t, properties["data"], "authorized-client response data")
	if data["$ref"] != "#/components/schemas/AuthorizedClientList" {
		t.Fatalf("authorized-client response ref = %v", data["$ref"])
	}
	deleteClient := objectValue(t, doc.Paths["/api/auth/clients/{client_session_id}"]["delete"], "DELETE /api/auth/clients/{client_session_id}")
	assertRequiredBearerScope(t, deleteClient, "clients:revoke", "DELETE /api/auth/clients/{client_session_id}")
	listProjects := objectValue(t, doc.Paths["/api/projects"]["get"], "GET /api/projects")
	assertRequiredBearerScope(t, listProjects, "projects:read", "GET /api/projects")
	cliConnect := objectValue(t, doc.Paths["/api/projects/{project_id}/cli-connect"]["post"], "POST /api/projects/{project_id}/cli-connect")
	assertRequiredBearerScope(t, cliConnect, "projects:connect", "POST /api/projects/{project_id}/cli-connect")
	connectionStatus := objectValue(t, doc.Paths["/api/projects/{project_id}/connection-status"]["get"], "GET /api/projects/{project_id}/connection-status")
	assertRequiredBearerScope(t, connectionStatus, "projects:connect", "GET /api/projects/{project_id}/connection-status")

	variants := arrayValue(t, doc.Components.Schemas["ConnectionStatus"]["oneOf"], "ConnectionStatus.oneOf")
	got := make(map[string]struct{})
	for i, rawVariant := range variants {
		variant := objectValue(t, rawVariant, "ConnectionStatus variant")
		variantProperties := objectValue(t, variant["properties"], "ConnectionStatus variant properties")
		status := objectValue(t, variantProperties["status"], "ConnectionStatus status")["const"]
		connectable := objectValue(t, variantProperties["connectable"], "ConnectionStatus connectable")["const"]
		retry := objectValue(t, variantProperties["retry_after_seconds"], "ConnectionStatus retry")
		reasonSchema := objectValue(t, variantProperties["reason"], "ConnectionStatus reason")
		reasons := []any{reasonSchema["const"]}
		if enum, ok := reasonSchema["enum"]; ok {
			reasons = arrayValue(t, enum, "ConnectionStatus reason enum")
		}
		for _, reason := range reasons {
			got[status.(string)+"/"+reason.(string)] = struct{}{}
		}
		if status == "ready" {
			if connectable != true || retry["const"] != float64(0) {
				t.Fatalf("ready variant %d has invalid connectable/retry: %v/%v", i, connectable, retry)
			}
		} else if connectable != false || retry["minimum"] != float64(1) {
			t.Fatalf("pending variant %d has invalid connectable/retry: %v/%v", i, connectable, retry)
		}
	}
	want := map[string]struct{}{
		"ready/ready":                            {},
		"machine_starting/machine_start_queued":  {},
		"machine_starting/machine_not_running":   {},
		"tunnel_connecting/tunnel_offline":       {},
		"papercode_starting/papercode_unhealthy": {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readiness combinations = %#v, want %#v", got, want)
	}
}

func assertExactCLIScopes(t *testing.T, schema map[string]any, name string) {
	t.Helper()
	properties := objectValue(t, schema["properties"], name+".properties")
	scopes := objectValue(t, properties["scopes"], name+".scopes")
	if scopes["minItems"] != float64(5) || scopes["maxItems"] != float64(5) || scopes["uniqueItems"] != true {
		t.Fatalf("%s does not require exactly five unique scopes: %#v", name, scopes)
	}
	items := objectValue(t, scopes["items"], name+".scopes.items")
	actual := stringSet(t, items["enum"], name+".scopes.items.enum")
	expected := map[string]bool{
		"account:read": true, "clients:revoke": true, "projects:read": true,
		"projects:connect": true, "session:refresh": true,
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("%s scopes = %#v", name, actual)
	}
}

func assertRequiredBearerScope(t *testing.T, operation map[string]any, expected, name string) {
	t.Helper()
	actual := stringSet(t, operation["x-required-bearer-scopes"], name+".x-required-bearer-scopes")
	if !reflect.DeepEqual(actual, map[string]bool{expected: true}) {
		t.Fatalf("%s bearer scopes = %#v", name, actual)
	}
}

func assertSingletonConstScope(t *testing.T, raw any, expected, name string) {
	t.Helper()
	scopes := objectValue(t, raw, name)
	if scopes["minItems"] != float64(1) || scopes["maxItems"] != float64(1) || scopes["items"] != false {
		t.Fatalf("%s does not require exactly one scope: %#v", name, scopes)
	}
	prefixItems := arrayValue(t, scopes["prefixItems"], name+".prefixItems")
	if len(prefixItems) != 1 || objectValue(t, prefixItems[0], name+".prefixItems[0]")["const"] != expected {
		t.Fatalf("%s does not require %q: %#v", name, expected, scopes)
	}
}

func objectValue(t *testing.T, value any, label string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, want object", label, value)
	}
	return object
}

func arrayValue(t *testing.T, value any, label string) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("%s is %T, want array", label, value)
	}
	return array
}

func stringSet(t *testing.T, value any, label string) map[string]bool {
	t.Helper()
	set := make(map[string]bool)
	for _, item := range arrayValue(t, value, label) {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("%s contains %T, want string", label, item)
		}
		set[text] = true
	}
	return set
}
