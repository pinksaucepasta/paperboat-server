package httpapi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var registeredRoutePattern = regexp.MustCompile(`mux\.Handle(?:Func)?\("(GET|POST|PUT|PATCH|DELETE) ([^"]+)"`)
var operationIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func TestOpenAPIMatchesRegisteredRoutes(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("openapi json is invalid: %v", err)
	}

	router, err := os.Open("router.go")
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	registered := make(map[string]map[string]bool)
	scanner := bufio.NewScanner(router)
	for scanner.Scan() {
		match := registeredRoutePattern.FindStringSubmatch(scanner.Text())
		if match == nil {
			continue
		}
		method, path := strings.ToLower(match[1]), match[2]
		if strings.HasPrefix(path, "/api/") {
			t.Errorf("registered route is not versioned: %s %s", match[1], path)
		}
		if strings.HasPrefix(path, "/v1/") {
			for _, segment := range strings.Split(strings.TrimPrefix(path, "/v1/"), "/") {
				if strings.HasPrefix(segment, "{") {
					continue
				}
				if strings.Contains(segment, "_") {
					t.Errorf("route segment must use kebab-case: %s %s", match[1], path)
				}
			}
		}
		if registered[path] == nil {
			registered[path] = make(map[string]bool)
		}
		registered[path][method] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	for path, methods := range registered {
		operations, ok := doc.Paths[path]
		if !ok {
			t.Errorf("openapi missing registered path %s", path)
			continue
		}
		for method := range methods {
			if operations[method] == nil {
				t.Errorf("openapi missing registered operation %s %s", strings.ToUpper(method), path)
			}
		}
	}
	operationIDs := make(map[string]string)
	for path, pathItem := range doc.Paths {
		if strings.HasPrefix(path, "/api/") {
			t.Errorf("openapi path is not versioned: %s", path)
		}
		for _, method := range []string{"get", "post", "put", "patch", "delete"} {
			operation, ok := pathItem[method].(map[string]any)
			if !ok {
				continue
			}
			operationID, ok := operation["operationId"].(string)
			if !ok || !operationIDPattern.MatchString(operationID) {
				t.Errorf("%s %s has invalid operationId %q", strings.ToUpper(method), path, operationID)
				continue
			}
			if previous := operationIDs[operationID]; previous != "" {
				t.Errorf("duplicate operationId %q on %s and %s %s", operationID, previous, strings.ToUpper(method), path)
			}
			operationIDs[operationID] = strings.ToUpper(method) + " " + path
		}
	}
}

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
		"/.well-known/jwks.json":                                             {"get"},
		"/v1/client-configuration":                                           {"get"},
		"/healthz":                                                           {"get"},
		"/metrics":                                                           {"get"},
		"/network-check/v1":                                                  {"get"},
		"/network-check/regions/v1":                                          {"get"},
		"/readyz":                                                            {"get"},
		"/v1/config/credentials":                                             {"post"},
		"/v1/config/leases/acquire":                                          {"post"},
		"/v1/config/leases/renew":                                            {"post"},
		"/v1/config/leases/release":                                          {"post"},
		"/v1/config/status":                                                  {"post"},
		"/v1/config/repository-access":                                       {"post"},
		"/v1/config/runtime":                                                 {"post"},
		"/v1/config/conflict-resolutions/pending":                            {"post"},
		"/v1/config/conflict-resolutions/acknowledge":                        {"post"},
		"/v1/edge/assignments/current":                                       {"post"},
		"/v1/nodes/register":                                                 {"post"},
		"/v1/nodes/heartbeat":                                                {"post"},
		"/v1/edge/routes/desired-state":                                      {"post"},
		"/v1/edge/usage-reports":                                             {"post"},
		"/v1/connectors/admission":                                           {"post"},
		"/v1/helper-enrollments":                                             {"post"},
		"/v1/hosted-helper-enrollments":                                      {"post"},
		"/v1/hosted-helper-bootstrap":                                        {"post"},
		"/v1/helper-identity-renewals":                                       {"post"},
		"/v1/machine-installation-failures":                                  {"post"},
		"/v1/previews/credentials":                                           {"post"},
		"/v1/tls/authorizations/previews":                                    {"get"},
		"/v1/tls/authorizations/routes":                                      {"get"},
		"/v1/edge/routes/observations":                                       {"post"},
		"/v1/previews/operations":                                            {"post"},
		"/v1/previews/observations":                                          {"post"},
		"/v1/trust/revocations":                                              {"get"},
		"/v1/me":                                                             {"get"},
		"/v1/favorites":                                                      {"get", "put"},
		"/v1/config-repositories":                                            {"get", "post"},
		"/v1/config-repositories/candidates":                                 {"get"},
		"/v1/config-repositories/{repository_id}":                            {"delete"},
		"/v1/machines/{machine_id}/config-assignment":                        {"get", "put", "delete"},
		"/v1/machines/{machine_id}/config-assignment/consent":                {"post", "delete"},
		"/v1/machines/{machine_id}/config-assignment/warning":                {"get"},
		"/v1/previews":                                                       {"get"},
		"/v1/previews/{preview_id}":                                          {"delete"},
		"/v1/environments/{environment_id}/routes":                           {"post"},
		"/v1/routes/{route_id}":                                              {"patch"},
		"/v1/admin/mint/signing-keys/{key_id}/revoke":                        {"post"},
		"/v1/admin/edge/usage-keys":                                          {"post"},
		"/v1/admin/edge/usage-keys/{key_id}/revoke":                          {"post"},
		"/v1/admin/control-operations/{operation_id}/recover":                {"post"},
		"/v1/admin/hosted-provider-operations/{operation_id}/recover":        {"post"},
		"/v1/admin/billing/uncertain/{kind}/{operation_id}/recover":          {"post"},
		"/v1/environments/{environment_id}/helper-enrollments":               {"post"},
		"/v1/environments/{environment_id}/helpers/{helper_id}/replace":      {"post"},
		"/v1/config-sync/status":                                             {"get"},
		"/v1/config-sync/environments/{environment_id}/conflict-resolutions": {"post"},
		"/v1/auth/workos/state":                                              {"get"},
		"/v1/auth/workos/callback":                                           {"post"},
		"/v1/auth/logout":                                                    {"post"},
		"/v1/auth/csrf":                                                      {"get"},
		"/v1/auth/device/authorize":                                          {"post"},
		"/v1/auth/device/token":                                              {"post"},
		"/v1/auth/device/requests/{user_code}":                               {"get"},
		"/v1/auth/device/requests/{user_code}/approve":                       {"post"},
		"/v1/auth/device/requests/{user_code}/deny":                          {"post"},
		"/v1/auth/token/refresh":                                             {"post"},
		"/v1/auth/token/revoke":                                              {"post"},
		"/v1/auth/cli-client-sessions":                                       {"get"},
		"/v1/auth/cli-client-sessions/{cli_client_session_id}":               {"delete"},
		"/v1/billing/entitlement":                                            {"get"},
		"/v1/billing/usage":                                                  {"get"},
		"/v1/billing/plan-products":                                          {"get"},
		"/v1/billing/checkout":                                               {"post"},
		"/v1/billing/customer-portal":                                        {"post"},
		"/v1/webhooks/polar":                                                 {"post"},
		"/v1/catalog/plans":                                                  {"get"},
		"/v1/catalog/machine-types":                                          {"get"},
		"/v1/catalog/presets":                                                {"get"},
		"/v1/catalog/regions":                                                {"get"},
		"/v1/github/status":                                                  {"get"},
		"/v1/github/repositories":                                            {"get"},
		"/v1/github/oauth/start":                                             {"post"},
		"/v1/github/oauth/callback":                                          {"get", "post"},
		"/v1/github/config-repositories/provision":                           {"post"},
		"/v1/usage-summary":                                                  {"get"},
		"/v1/projects":                                                       {"get", "post"},
		"/v1/projects/{project_id}":                                          {"get", "patch", "delete"},
		"/v1/projects/{project_id}/start":                                    {"post"},
		"/v1/projects/{project_id}/stop":                                     {"post"},
		"/v1/projects/{project_id}/restart":                                  {"post"},
		"/v1/projects/{project_id}/events":                                   {"get"},
		"/v1/projects/{project_id}/connection-descriptor":                    {"post"},
		"/v1/projects/{project_id}/connection-readiness":                     {"get"},
		"/v1/projects/{project_id}/terminal-sessions":                        {"get", "post"},
		"/v1/projects/{project_id}/terminal-sessions/{session_id}":           {"patch", "delete"},
		"/v1/projects/{project_id}/terminal-sessions/{session_id}/close":     {"post"},
		"/v1/machines":                                                       {"get"},
		"/v1/machines/setup":                                                 {"post"},
		"/v1/machines/{machine_id}/unpair":                                   {"post"},
		"/v1/machine-enrollments":                                            {"post"},
		"/v1/machine-enrollments/{enrollment_id}":                            {"get"},
		"/v1/machine-enrollments/{enrollment_id}/cancel":                     {"post"},
		"/v1/machine-enrollments/{enrollment_id}/retry":                      {"post"},
		"/v1/machines/overview":                                              {"get"},
		"/v1/machines/{machine_id}":                                          {"get", "delete"},
		"/v1/machines/{machine_id}/connection-descriptor":                    {"post"},
		"/v1/machines/{machine_id}/connection-readiness":                     {"get"},
		"/v1/machines/{machine_id}/disconnect":                               {"post"},
		"/v1/machines/{machine_id}/terminal-sessions":                        {"get", "post"},
		"/v1/machines/{machine_id}/terminal-sessions/{session_id}":           {"patch", "delete"},
		"/v1/machines/{machine_id}/terminal-sessions/{session_id}/close":     {"post"},
		"/v1/machines/pairings":                                              {"post"},
		"/v1/machines/pairings/{user_code}/approve":                          {"post"},
		"/v1/machines/pairings/{user_code}/deny":                             {"post"},
		"/v1/runtime-observations":                                           {"post"},
		"/v1/admin/users/{user_id}/adjust-credits":                           {"post"},
		"/v1/admin/users/{user_id}/adjust-storage":                           {"post"},
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

func TestOpenAPIFreezesConfigSyncRuntimeObservationAndStatusSchemas(t *testing.T) {
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
		t.Fatal(err)
	}
	for _, schema := range []string{"ConfigSyncPathSummary", "RuntimeObservation", "ConfigSyncStatus"} {
		if doc.Components.Schemas[schema] == nil {
			t.Fatalf("OpenAPI missing %s", schema)
		}
	}
	runtimeProperties := objectValue(t, doc.Components.Schemas["RuntimeObservation"]["properties"], "RuntimeObservation.properties")
	if runtimeProperties["config_sync"] != nil || doc.Components.Schemas["ConfigSyncHeartbeat"] != nil {
		t.Fatal("runtime observation still exposes the obsolete config status path")
	}
	operation := objectValue(t, doc.Paths["/v1/config-sync/status"]["get"], "GET /v1/config-sync/status")
	if operation["security"] == nil {
		t.Fatal("config sync status endpoint is not authenticated in OpenAPI")
	}
	responses := objectValue(t, operation["responses"], "GET /v1/config-sync/status.responses")
	if responses["402"] == nil {
		t.Fatal("config sync status endpoint does not declare its entitlement requirement")
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

	client := doc.Components.Schemas["CLIClientSession"]
	assertExactCLIScopes(t, doc.Components.Schemas["DeviceAuthorizationRequest"], "DeviceAuthorizationRequest")
	assertExactCLIScopes(t, doc.Components.Schemas["DeviceRequest"], "DeviceRequest")
	assertExactCLIScopes(t, client, "CLIClientSession")
	tokenSetProperties := objectValue(t, doc.Components.Schemas["TokenSet"]["properties"], "TokenSet.properties")
	scope := objectValue(t, tokenSetProperties["scope"], "TokenSet.scope")
	if scope["const"] != "account:read clients:revoke projects:read projects:connect session:refresh" {
		t.Fatalf("TokenSet.scope const = %v", scope["const"])
	}
	descriptor := doc.Components.Schemas["EnvironmentConnectionDescriptor"]
	descriptorRequired := stringSet(t, descriptor["required"], "EnvironmentConnectionDescriptor.required")
	for _, field := range []string{"schema", "issuer", "connectable", "expires_at", "environment", "status", "reason", "retry_after_seconds"} {
		if !descriptorRequired[field] {
			t.Fatalf("EnvironmentConnectionDescriptor does not require %q", field)
		}
	}
	descriptorProperties := objectValue(t, descriptor["properties"], "EnvironmentConnectionDescriptor.properties")
	schema := objectValue(t, descriptorProperties["schema"], "EnvironmentConnectionDescriptor.schema")
	if schema["const"] != "paperboat.environment-connection/v1" {
		t.Fatalf("EnvironmentConnectionDescriptor.schema is not canonical v1")
	}
	for _, field := range []string{"project_id", "project_state"} {
		if _, present := descriptorProperties[field]; present {
			t.Fatalf("EnvironmentConnectionDescriptor retains legacy field %q", field)
		}
	}
	environment := objectValue(t, descriptorProperties["environment"], "EnvironmentConnectionDescriptor.environment")
	environmentProperties := objectValue(t, environment["properties"], "EnvironmentConnectionDescriptor.environment.properties")
	for _, field := range []string{"id", "kind", "resource_id", "display_name", "state"} {
		if _, present := environmentProperties[field]; !present {
			t.Fatalf("EnvironmentConnectionDescriptor.environment lacks canonical field %q", field)
		}
	}
	for _, field := range []string{"environment_id", "project_id", "machine_id", "project_root"} {
		if _, present := environmentProperties[field]; present {
			t.Fatalf("EnvironmentConnectionDescriptor.environment retains legacy field %q", field)
		}
	}
	terminal := objectValue(t, descriptorProperties["terminal"], "EnvironmentConnectionDescriptor.terminal")
	terminalProperties := objectValue(t, terminal["properties"], "EnvironmentConnectionDescriptor.terminal.properties")
	for _, field := range []string{"endpoint", "auth", "session_id", "thread_id", "terminal_id", "cwd"} {
		if _, present := terminalProperties[field]; !present {
			t.Fatalf("EnvironmentConnectionDescriptor.terminal lacks canonical field %q", field)
		}
	}
	for _, field := range []string{"kind", "websocket_base_url", "http_base_url"} {
		if _, present := terminalProperties[field]; present {
			t.Fatalf("EnvironmentConnectionDescriptor.terminal retains legacy field %q", field)
		}
	}
	terminalAuthVariants, ok := doc.Components.Schemas["TerminalAuth"]["oneOf"].([]any)
	if !ok || len(terminalAuthVariants) != 2 {
		t.Fatalf("TerminalAuth.oneOf = %#v, want ticket and bearer variants", doc.Components.Schemas["TerminalAuth"]["oneOf"])
	}
	wantTerminalMethods := map[string]bool{"websocket_ticket": false, "bearer": false}
	for index, raw := range terminalAuthVariants {
		variant := objectValue(t, raw, fmt.Sprintf("TerminalAuth.oneOf[%d]", index))
		properties := objectValue(t, variant["properties"], fmt.Sprintf("TerminalAuth.oneOf[%d].properties", index))
		method := objectValue(t, properties["method"], "TerminalAuth.method")["const"]
		methodString, valid := method.(string)
		_, expected := wantTerminalMethods[methodString]
		if !valid || !expected {
			t.Fatalf("TerminalAuth method = %#v", method)
		}
		wantTerminalMethods[methodString] = true
		assertSingletonConstScope(t, properties["scopes"], "terminal:operate", "TerminalAuth.scopes")
	}
	for method, present := range wantTerminalMethods {
		if !present {
			t.Fatalf("TerminalAuth lacks %q variant", method)
		}
	}
	transferProperties := objectValue(t, doc.Components.Schemas["FileTransfer"]["properties"], "FileTransfer.properties")
	transferAuth := objectValue(t, transferProperties["auth"], "FileTransfer.auth")
	transferAuthProperties := objectValue(t, transferAuth["properties"], "FileTransfer.auth.properties")
	assertSingletonConstScope(t, transferAuthProperties["scopes"], "file:transfer", "FileTransfer.auth.scopes")
	for _, legacy := range []string{"max_bytes", "allowed_mime_types", "mime_type"} {
		if _, present := transferProperties[legacy]; present {
			t.Fatalf("FileTransfer retains legacy field %q", legacy)
		}
	}
	required := stringSet(t, client["required"], "CLIClientSession.required")
	for _, field := range []string{
		"cli_client_session_id", "client_id", "client_label", "device_type", "os", "scopes",
		"state", "created_at", "approved_at", "last_used_at", "revoked_at",
		"revocation_reason", "current",
	} {
		if !required[field] {
			t.Fatalf("CLIClientSession does not require %q", field)
		}
	}

	list := doc.Components.Schemas["CLIClientSessionList"]
	listProperties := objectValue(t, list["properties"], "CLIClientSessionList.properties")
	items := objectValue(t, listProperties["items"], "CLIClientSessionList.items")
	itemSchema := objectValue(t, items["items"], "CLIClientSessionList.items.items")
	if itemSchema["$ref"] != "#/components/schemas/CLIClientSession" {
		t.Fatalf("authorized-client item ref = %v", itemSchema["$ref"])
	}
	pagination := objectValue(t, listProperties["pagination"], "CLIClientSessionList.pagination")
	paginationRequired := stringSet(t, pagination["required"], "CLIClientSessionList.pagination.required")
	if !reflect.DeepEqual(paginationRequired, map[string]bool{
		"limit": true, "offset": true, "total": true, "next_offset": true,
	}) {
		t.Fatalf("pagination required fields = %#v", paginationRequired)
	}

	get := objectValue(t, doc.Paths["/v1/auth/cli-client-sessions"]["get"], "GET /v1/auth/cli-client-sessions")
	assertRequiredBearerScope(t, get, "account:read", "GET /v1/auth/cli-client-sessions")
	configSync := objectValue(t, doc.Paths["/v1/config-sync/status"]["get"], "GET /v1/config-sync/status")
	assertRequiredBearerScope(t, configSync, "account:read", "GET /v1/config-sync/status")
	usageSummary := objectValue(t, doc.Paths["/v1/usage-summary"]["get"], "GET /v1/usage-summary")
	assertRequiredBearerScope(t, usageSummary, "account:read", "GET /v1/usage-summary")
	responses := objectValue(t, get["responses"], "authorized-client responses")
	okResponse := objectValue(t, responses["200"], "authorized-client 200")
	content := objectValue(t, okResponse["content"], "authorized-client content")
	jsonContent := objectValue(t, content["application/json"], "authorized-client JSON")
	responseSchema := objectValue(t, jsonContent["schema"], "authorized-client response schema")
	properties := objectValue(t, responseSchema["properties"], "authorized-client response properties")
	data := objectValue(t, properties["data"], "authorized-client response data")
	if data["$ref"] != "#/components/schemas/CLIClientSessionList" {
		t.Fatalf("authorized-client response ref = %v", data["$ref"])
	}
	deleteClient := objectValue(t, doc.Paths["/v1/auth/cli-client-sessions/{cli_client_session_id}"]["delete"], "DELETE /v1/auth/cli-client-sessions/{cli_client_session_id}")
	assertRequiredBearerScope(t, deleteClient, "clients:revoke", "DELETE /v1/auth/cli-client-sessions/{cli_client_session_id}")
	listProjects := objectValue(t, doc.Paths["/v1/projects"]["get"], "GET /v1/projects")
	assertRequiredBearerScope(t, listProjects, "projects:read", "GET /v1/projects")
	createProject := objectValue(t, doc.Paths["/v1/projects"]["post"], "POST /v1/projects")
	assertRequiredBearerScope(t, createProject, "projects:connect", "POST /v1/projects")
	githubRepositories := objectValue(t, doc.Paths["/v1/github/repositories"]["get"], "GET /v1/github/repositories")
	assertRequiredBearerScope(t, githubRepositories, "projects:read", "GET /v1/github/repositories")
	configRepositories := objectValue(t, doc.Paths["/v1/config-repositories"]["get"], "GET /v1/config-repositories")
	assertRequiredBearerScope(t, configRepositories, "projects:read", "GET /v1/config-repositories")
	configAssignment := doc.Paths["/v1/machines/{machine_id}/config-assignment"]
	assertRequiredBearerScope(t, objectValue(t, configAssignment["get"], "GET config assignment"), "projects:read", "GET config assignment")
	assertRequiredBearerScope(t, objectValue(t, configAssignment["put"], "PUT config assignment"), "projects:connect", "PUT config assignment")
	assertRequiredBearerScope(t, objectValue(t, configAssignment["delete"], "DELETE config assignment"), "projects:connect", "DELETE config assignment")
	for _, path := range []string{"/v1/catalog/machine-types", "/v1/catalog/presets", "/v1/catalog/regions"} {
		operation := objectValue(t, doc.Paths[path]["get"], "GET "+path)
		assertRequiredBearerScope(t, operation, "projects:read", "GET "+path)
	}
	cliConnect := objectValue(t, doc.Paths["/v1/projects/{project_id}/connection-descriptor"]["post"], "POST /v1/projects/{project_id}/connection-descriptor")
	assertRequiredBearerScope(t, cliConnect, "projects:connect", "POST /v1/projects/{project_id}/connection-descriptor")
	disconnectMachine := objectValue(t, doc.Paths["/v1/machines/{machine_id}/disconnect"]["post"], "POST machine disconnect")
	assertRequiredBearerScope(t, disconnectMachine, "projects:connect", "POST machine disconnect")
	deleteMachine := objectValue(t, doc.Paths["/v1/machines/{machine_id}"]["delete"], "DELETE machine")
	assertRequiredBearerScope(t, deleteMachine, "projects:connect", "DELETE machine")
	cliConnectionDescriptors := objectValue(t, cliConnect["responses"], "CLI connect responses")
	if _, ok := cliConnectionDescriptors["503"]; !ok {
		t.Fatal("CLI connect must document terminal runtime unavailability")
	}
	deleteSession := objectValue(t, doc.Paths["/v1/projects/{project_id}/terminal-sessions/{session_id}"]["delete"], "DELETE terminal session")
	deleteSessionResponses := objectValue(t, deleteSession["responses"], "delete terminal session responses")
	if _, ok := deleteSessionResponses["200"]; !ok {
		t.Fatal("terminal session deletion must document synchronous purge success")
	}
	connectionStatus := objectValue(t, doc.Paths["/v1/projects/{project_id}/connection-readiness"]["get"], "GET /v1/projects/{project_id}/connection-readiness")
	assertRequiredBearerScope(t, connectionStatus, "projects:connect", "GET /v1/projects/{project_id}/connection-readiness")
	connectionStatusParameters := arrayValue(t, doc.Paths["/v1/projects/{project_id}/connection-readiness"]["parameters"], "connection-readiness parameters")
	if !hasParameter(connectionStatusParameters, "terminal_session_id", "query") {
		t.Fatal("connection-status must document terminal_session_id")
	}

	variants := arrayValue(t, doc.Components.Schemas["ConnectionReadiness"]["oneOf"], "ConnectionReadiness.oneOf")
	got := make(map[string]struct{})
	for i, rawVariant := range variants {
		variant := objectValue(t, rawVariant, "ConnectionReadiness variant")
		variantProperties := objectValue(t, variant["properties"], "ConnectionReadiness variant properties")
		status := objectValue(t, variantProperties["status"], "ConnectionReadiness status")["const"]
		connectable := objectValue(t, variantProperties["connectable"], "ConnectionReadiness connectable")["const"]
		retry := objectValue(t, variantProperties["retry_after_seconds"], "ConnectionReadiness retry")
		reasonSchema := objectValue(t, variantProperties["reason"], "ConnectionReadiness reason")
		reasons := []any{reasonSchema["const"]}
		if enum, ok := reasonSchema["enum"]; ok {
			reasons = arrayValue(t, enum, "ConnectionReadiness reason enum")
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
		"ready/ready":                                        {},
		"machine_starting/machine_start_queued":              {},
		"machine_starting/machine_not_running":               {},
		"tunnel_connecting/tunnel_offline":                   {},
		"helper_starting/helper_unhealthy":                   {},
		"helper_starting/terminal_session_operation_pending": {},
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

func hasParameter(parameters []any, name, location string) bool {
	for _, raw := range parameters {
		parameter, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if parameter["name"] == name && parameter["in"] == location {
			return true
		}
	}
	return false
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
