package httpapi

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOpenAPIDocumentCoversPublicRouterPaths(t *testing.T) {
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
		"/healthz":                                      {"get"},
		"/readyz":                                      {"get"},
		"/api/me":                                      {"get"},
		"/api/auth/workos/state":                       {"get"},
		"/api/auth/workos/callback":                    {"post"},
		"/api/auth/logout":                             {"post"},
		"/api/auth/csrf":                               {"get"},
		"/api/billing/entitlement":                     {"get"},
		"/api/billing/usage":                           {"get"},
		"/api/billing/plan-products":                   {"get"},
		"/api/billing/checkout":                        {"post"},
		"/api/billing/customer-portal":                 {"post"},
		"/api/webhooks/polar":                          {"post"},
		"/api/catalog/plans":                           {"get"},
		"/api/catalog/machine-types":                   {"get"},
		"/api/catalog/presets":                         {"get"},
		"/api/catalog/idle-timeouts":                   {"get"},
		"/api/catalog/regions":                         {"get"},
		"/api/github/status":                           {"get"},
		"/api/github/oauth/start":                      {"post"},
		"/api/github/oauth/callback":                   {"post"},
		"/api/github/config-repo/provision":            {"post"},
		"/api/projects":                                {"get", "post"},
		"/api/projects/{project_id}":                   {"get", "patch", "delete"},
		"/api/projects/{project_id}/start":             {"post"},
		"/api/projects/{project_id}/stop":              {"post"},
		"/api/projects/{project_id}/restart":           {"post"},
		"/api/projects/{project_id}/keep-alive":        {"post"},
		"/api/projects/{project_id}/activity":          {"post"},
		"/api/projects/{project_id}/events":            {"get"},
		"/api/projects/{project_id}/connect":           {"post"},
		"/api/projects/{project_id}/cli-connect":       {"post"},
		"/api/projects/{project_id}/papercode-connect": {"post"},
		"/api/projects/{project_id}/connection-status": {"get"},
		"/api/machine/activity-heartbeat":              {"post"},
		"/api/admin/users/{user_id}/adjust-credits":    {"post"},
		"/api/admin/users/{user_id}/adjust-storage":    {"post"},
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
