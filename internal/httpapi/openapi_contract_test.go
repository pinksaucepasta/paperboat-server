package httpapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		t.Fatalf("openapi json contains duplicate object key: %v", err)
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

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decodeOpenAPIValue(decoder, "$"); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func decodeOpenAPIValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("%s has non-string object key", path)
				}
				if _, exists := keys[key]; exists {
					return fmt.Errorf("%s.%s", path, key)
				}
				keys[key] = struct{}{}
				if err := decodeOpenAPIValue(decoder, path+"."+key); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			index := 0
			for decoder.More() {
				if err := decodeOpenAPIValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
					return err
				}
				index++
			}
			_, err := decoder.Token()
			return err
		}
	}
	return nil
}

func TestOpenAPIPrivateAccessSchemasAndOperations(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components map[string]any            `json:"components"`
		Paths      map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("openapi json is invalid: %v", err)
	}
	schemas := objectValue(t, doc.Components["schemas"], "components.schemas")
	for _, name := range []string{"privateAccess", "privateAccessGrantResponse", "privateAccessAuthorize", "privateAccessDecision", "privateAccessCarrierAdmission", "privateAccessCarrierSnapshot"} {
		if _, ok := schemas[name]; !ok {
			t.Errorf("components.schemas.%s is missing", name)
		}
		if _, invalid := doc.Components[name]; invalid {
			t.Errorf("components.%s must not be a top-level component key", name)
		}
	}
	admissionProperties := objectValue(t, objectValue(t, schemas["privateAccessCarrierAdmission"], "privateAccessCarrierAdmission")["properties"], "privateAccessCarrierAdmission.properties")
	for _, name := range []string{"tunnel_name", "route_name"} {
		if _, ok := admissionProperties[name]; !ok {
			t.Errorf("privateAccessCarrierAdmission.properties.%s is missing", name)
		}
	}

	grant := objectValue(t, doc.Paths["/v1/edge/private-access/grants"]["post"], "private grant operation")
	authorize := objectValue(t, doc.Paths["/v1/edge/private-access/authorize"]["post"], "private authorize operation")
	routes := objectValue(t, doc.Paths["/v1/private-access/routes"]["post"], "private routes operation")
	admissions := objectValue(t, doc.Paths["/v1/edge/private-access/carrier-admissions"]["post"], "private admissions operation")
	assertRequestSchema(t, grant, "#/components/schemas/privateAccess")
	assertResponseSchema(t, grant, "200", "#/components/schemas/privateAccessGrantResponse")
	assertRequestSchema(t, authorize, "#/components/schemas/privateAccessAuthorize")
	assertResponseSchema(t, authorize, "200", "#/components/schemas/privateAccessDecision")
	assertResponseSchema(t, routes, "200", "#/components/schemas/privateAccessCarrierSnapshot")
	assertResponseSchema(t, admissions, "200", "#/components/schemas/privateAccessCarrierSnapshot")
	assertPrivateAccessSecurity(t, grant, "bearerMachineControl", "private grant")
	assertPrivateAccessSecurity(t, authorize, "bearerEdgeControl", "private authorize")
	assertPrivateAccessSecurity(t, routes, "bearerMachineControl", "private routes")
	assertPrivateAccessSecurity(t, admissions, "bearerEdgeControl", "private admissions")
	assertParameterRefs(t, grant, "#/components/parameters/MachineIdentity", "#/components/parameters/MachineProof")
	assertParameterRefs(t, authorize, "#/components/parameters/PrivateAccessGrant")
	assertExactResponseStatuses(t, grant, "private grant", "200", "400", "401", "403", "503")
	assertExactResponseStatuses(t, authorize, "private authorize", "200", "400", "401", "403", "409", "503")

	for name, fields := range map[string][]string{
		"privateAccess":              {"resource_kind", "resource_id", "route_id", "audience", "expires_at", "nonce", "carrier_session_id", "route_generation", "session_generation", "process_generation", "config_generation", "assignment_generation", "edge_node_id", "edge_process_epoch", "protocol", "idempotency_key", "request_id", "correlation_id"},
		"privateAccessAuthorize":     {"account_id", "device_id", "session_id", "installation_generation", "resource_kind", "resource_id", "route_id", "carrier_session_id", "route_generation", "session_generation", "process_generation", "config_generation", "assignment_generation", "edge_node_id", "edge_process_epoch"},
		"privateAccessGrantResponse": {"schema", "kind", "grant", "expires_at", "request_id", "correlation_id", "request"},
		"privateAccessDecision":      {"schema", "kind", "decision_id", "allowed", "reason", "expires_at", "request_id", "correlation_id"},
	} {
		required := stringSet(t, objectValue(t, schemas[name], name)["required"], name+".required")
		for _, field := range fields {
			if !required[field] {
				t.Errorf("%s.required is missing %q", name, field)
			}
		}
	}
}

func assertPrivateAccessSecurity(t *testing.T, operation map[string]any, scheme, label string) {
	t.Helper()
	security := arrayValue(t, operation["security"], label+".security")
	if len(security) != 1 {
		t.Fatalf("%s security = %#v, want exactly one scheme", label, security)
	}
	if _, ok := objectValue(t, security[0], label+".security[0]")[scheme]; !ok {
		t.Fatalf("%s does not require %s", label, scheme)
	}
}

func assertExactResponseStatuses(t *testing.T, operation map[string]any, label string, expected ...string) {
	t.Helper()
	responses := objectValue(t, operation["responses"], label+".responses")
	got := make(map[string]bool, len(responses))
	for status := range responses {
		got[status] = true
	}
	want := stringSetFrom(expected)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s response statuses = %#v, want %#v", label, got, want)
	}
}

func TestOpenAPIFreezesPreviewTunnelV1Endpoints(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("openapi json is invalid: %v", err)
	}

	requiredPaths := map[string][]string{
		"/v1/previews":                          {"get", "post"},
		"/v1/previews/{preview_id}":             {"get", "delete"},
		"/v1/previews/{preview_id}/lease/renew": {"post"},
		"/v1/previews/{preview_id}/readiness":   {"post"},
		"/v1/previews/{preview_id}/events":      {"get"},
		"/v1/tunnels":                           {"get", "post"},
		"/v1/tunnels/{tunnel_id}":               {"get", "patch", "delete"},
		"/v1/tunnels/{tunnel_id}/pause":         {"post"},
		"/v1/tunnels/{tunnel_id}/resume":        {"post"},
		"/v1/tunnels/{tunnel_id}/status":        {"get"},
		"/v1/tunnels/{tunnel_id}/events":        {"get"},
	}
	for path, methods := range requiredPaths {
		pathItem, ok := doc.Paths[path]
		if !ok {
			t.Fatalf("preview/tunnel OpenAPI path is missing: %s", path)
		}
		for _, method := range methods {
			if _, ok := pathItem[method]; !ok {
				t.Fatalf("preview/tunnel OpenAPI operation is missing: %s %s", strings.ToUpper(method), path)
			}
		}
	}

	assertCanonicalResourceSchema(t, doc.Components.Schemas, "PreviewLease", "preview_lease", []string{
		"schema", "kind", "id", "account_id", "actor_id", "owner_device_id", "owner_session_id",
		"target", "access_mode", "persistent", "endpoint", "lease_deadline", "state",
		"allocation_state", "edge_state", "origin_state", "domains",
	})
	assertCanonicalResourceSchema(t, doc.Components.Schemas, "Tunnel", "tunnel", []string{
		"schema", "kind", "id", "account_id", "name", "desired_state", "access_mode", "generation",
		"etag", "stable_endpoint_id", "stable_endpoint", "created_by_host_id", "created_by_actor_id",
		"summary_code", "created_at", "updated_at",
	})
	assertCanonicalResourceSchema(t, doc.Components.Schemas, "PreviewTunnelOperation", "operation", []string{
		"schema", "kind", "id", "resource_kind", "resource_id", "phase", "state",
		"progress", "retrying", "correlation_id", "created_at", "updated_at",
	})
	assertCanonicalResourceSchema(t, doc.Components.Schemas, "PreviewTunnelEvent", "event", []string{
		"schema", "kind", "id", "cursor", "event_type", "resource_kind", "resource_id",
		"occurred_at", "actor", "correlation_id", "safe_metadata",
	})
	assertCanonicalResourceSchema(t, doc.Components.Schemas, "PreviewTunnelHealth", "health", []string{
		"schema", "kind", "resource_kind", "resource_id", "overall_code", "dimensions",
		"summary", "since", "retrying", "repair_action", "correlation_id",
	})
	previewCreateSchema := doc.Components.Schemas["PreviewLeaseCreateRequest"]
	previewCreateProperties := objectValue(t, previewCreateSchema["properties"], "PreviewLeaseCreateRequest.properties")
	if !stringSet(t, previewCreateSchema["required"], "PreviewLeaseCreateRequest.required")["domains"] {
		t.Fatal("PreviewLeaseCreateRequest must require domains, including an explicit empty array")
	}
	previewCreateTarget := objectValue(t, previewCreateProperties["target"], "PreviewLeaseCreateRequest.target")
	previewCreateTargetProperties := objectValue(t, previewCreateTarget["properties"], "PreviewLeaseCreateRequest.target.properties")
	previewCreateScheme := objectValue(t, previewCreateTargetProperties["scheme"], "PreviewLeaseCreateRequest.target.scheme")
	wantTargetSchemes := map[string]bool{"http": true, "https": true, "h2c": true, "unix": true, "tcp": true}
	if got := stringSet(t, previewCreateScheme["enum"], "preview create target schemes"); !reflect.DeepEqual(got, wantTargetSchemes) {
		t.Fatalf("preview create target schemes = %#v, want %#v", got, wantTargetSchemes)
	}
	previewCreateDomains := objectValue(t, previewCreateProperties["domains"], "PreviewLeaseCreateRequest.domains")
	if got := int(previewCreateDomains["maxItems"].(float64)); got != 8 {
		t.Fatalf("PreviewLeaseCreateRequest.domains maxItems = %d, want 8", got)
	}
	previewDomain := doc.Components.Schemas["PreviewDomain"]
	previewDomainProperties := objectValue(t, previewDomain["properties"], "PreviewDomain.properties")
	if got := objectValue(t, previewDomainProperties["target_kind"], "PreviewDomain.target_kind")["const"]; got != "preview_lease" {
		t.Fatalf("PreviewDomain target_kind = %v, want preview_lease", got)
	}
	if _, ok := previewDomainProperties["tunnel_id"]; ok {
		t.Fatal("PreviewDomain must not expose tunnel_id")
	}

	previewList := objectValue(t, doc.Paths["/v1/previews"]["get"], "GET /v1/previews")
	assertPreviewTunnelSecurity(t, previewList, "previews:read", false, "GET /v1/previews")
	assertParameterRefs(t, previewList, "#/components/parameters/EventCursor", "#/components/parameters/PageLimit")
	assertResponseSchema(t, previewList, "200", "#/components/schemas/PreviewLeasePageResponse")

	previewCreate := objectValue(t, doc.Paths["/v1/previews"]["post"], "POST /v1/previews")
	assertPreviewTunnelSecurity(t, previewCreate, "previews:write", true, "POST /v1/previews")
	assertParameterRefs(t, previewCreate, "#/components/parameters/IdempotencyKey", "#/components/parameters/MachineIdentityOptional", "#/components/parameters/MachineProofOptional")
	assertRequestSchema(t, previewCreate, "#/components/schemas/PreviewLeaseCreateRequest")
	assertResponseSchema(t, previewCreate, "200", "#/components/schemas/PreviewLeaseResponse")
	assertResponseSchema(t, previewCreate, "202", "#/components/schemas/PreviewTunnelOperationResponse")
	assertResponseHeaderRef(t, previewCreate, "200", "X-Paperboat-Operation-ID", "#/components/headers/OperationID")
	assertResponseHeaderRef(t, previewCreate, "202", "X-Paperboat-Operation-ID", "#/components/headers/OperationID")

	previewItem := doc.Paths["/v1/previews/{preview_id}"]
	assertPathParameterRef(t, previewItem, "#/components/parameters/PreviewID", "preview item")
	previewGet := objectValue(t, previewItem["get"], "GET preview")
	assertPreviewTunnelSecurity(t, previewGet, "previews:read", false, "GET preview")
	assertResponseSchema(t, previewGet, "200", "#/components/schemas/PreviewLeaseResponse")
	previewDelete := objectValue(t, previewItem["delete"], "DELETE preview")
	assertPreviewTunnelSecurity(t, previewDelete, "previews:write", true, "DELETE preview")
	assertParameterRefs(t, previewDelete, "#/components/parameters/IdempotencyKey", "#/components/parameters/IfMatch")
	assertResponseSchema(t, previewDelete, "200", "#/components/schemas/PreviewLeaseResponse")

	previewRenew := objectValue(t, doc.Paths["/v1/previews/{preview_id}/lease/renew"]["post"], "POST preview renew")
	assertPreviewTunnelSecurity(t, previewRenew, "previews:write", true, "POST preview renew")
	assertParameterRefs(t, previewRenew, "#/components/parameters/IdempotencyKey", "#/components/parameters/IfMatch")
	assertResponseSchema(t, previewRenew, "200", "#/components/schemas/PreviewLeaseResponse")

	previewReadiness := objectValue(t, doc.Paths["/v1/previews/{preview_id}/readiness"]["post"], "POST preview readiness")
	assertDevicePreviewTunnelSecurity(t, previewReadiness, "previews:write", "POST preview readiness")
	assertParameterRefs(t, previewReadiness,
		"#/components/parameters/IdempotencyKey",
		"#/components/parameters/IfMatch",
		"#/components/parameters/MachineIdentity",
		"#/components/parameters/MachineProof",
	)
	assertRequestSchema(t, previewReadiness, "#/components/schemas/PreviewLeaseReadinessRequest")
	assertResponseSchema(t, previewReadiness, "200", "#/components/schemas/PreviewLeaseResponse")

	previewEvents := objectValue(t, doc.Paths["/v1/previews/{preview_id}/events"]["get"], "GET preview events")
	assertPreviewTunnelSecurity(t, previewEvents, "previews:read", false, "GET preview events")
	assertParameterRefs(t, previewEvents, "#/components/parameters/EventCursor", "#/components/parameters/PageLimit", "#/components/parameters/LastEventID")
	assertEventResponse(t, previewEvents, "preview events")

	previewDomains := doc.Paths["/v1/previews/{preview_id}/domains"]
	assertPathParameterRef(t, previewDomains, "#/components/parameters/PreviewID", "preview domains")
	previewDomainList := objectValue(t, previewDomains["get"], "GET preview domains")
	assertPreviewTunnelSecurity(t, previewDomainList, "previews:read", false, "GET preview domains")
	assertResponseSchema(t, previewDomainList, "200", "#/components/schemas/PreviewDomainPageResponse")
	previewDomainCreate := objectValue(t, previewDomains["post"], "POST preview domain")
	assertPreviewTunnelSecurity(t, previewDomainCreate, "previews:write", true, "POST preview domain")
	assertParameterRefs(t, previewDomainCreate, "#/components/parameters/IdempotencyKey")
	assertRequestSchema(t, previewDomainCreate, "#/components/schemas/PreviewDomainCreateRequest")

	previewDomainItem := doc.Paths["/v1/previews/{preview_id}/domains/{domain_id}"]
	assertPathParameterRef(t, previewDomainItem, "#/components/parameters/PreviewID", "preview domain item")
	previewDomainGet := objectValue(t, previewDomainItem["get"], "GET preview domain")
	assertPreviewTunnelSecurity(t, previewDomainGet, "previews:read", false, "GET preview domain")
	assertResponseSchema(t, previewDomainGet, "200", "#/components/schemas/PreviewDomainResponse")
	previewDomainDelete := objectValue(t, previewDomainItem["delete"], "DELETE preview domain")
	assertPreviewTunnelSecurity(t, previewDomainDelete, "previews:write", true, "DELETE preview domain")
	assertParameterRefs(t, previewDomainDelete, "#/components/parameters/IdempotencyKey", "#/components/parameters/IfMatch")

	previewDomainVerify := objectValue(t, doc.Paths["/v1/previews/{preview_id}/domains/{domain_id}/verify"]["post"], "POST preview domain verify")
	assertPreviewTunnelSecurity(t, previewDomainVerify, "previews:write", true, "POST preview domain verify")
	assertParameterRefs(t, previewDomainVerify, "#/components/parameters/IdempotencyKey", "#/components/parameters/IfMatch")
	previewDomainInstructions := objectValue(t, doc.Paths["/v1/previews/{preview_id}/domains/{domain_id}/instructions"]["get"], "GET preview domain instructions")
	assertPreviewTunnelSecurity(t, previewDomainInstructions, "previews:read", false, "GET preview domain instructions")
	assertResponseSchema(t, previewDomainInstructions, "200", "#/components/schemas/PreviewDNSInstructionsResponse")

	tunnelList := objectValue(t, doc.Paths["/v1/tunnels"]["get"], "GET /v1/tunnels")
	assertPreviewTunnelSecurity(t, tunnelList, "tunnels:read", false, "GET /v1/tunnels")
	assertParameterRefs(t, tunnelList, "#/components/parameters/EventCursor", "#/components/parameters/PageLimit")
	assertResponseSchema(t, tunnelList, "200", "#/components/schemas/TunnelPageResponse")

	tunnelCreate := objectValue(t, doc.Paths["/v1/tunnels"]["post"], "POST /v1/tunnels")
	assertPreviewTunnelSecurity(t, tunnelCreate, "tunnels:write", true, "POST /v1/tunnels")
	assertParameterRefs(t, tunnelCreate,
		"#/components/parameters/IdempotencyKey",
		"#/components/parameters/MachineIdentity",
		"#/components/parameters/MachineProof",
	)
	assertRequestSchema(t, tunnelCreate, "#/components/schemas/TunnelCreateRequest")
	assertResponseSchema(t, tunnelCreate, "201", "#/components/schemas/TunnelResponse")
	assertResponseSchema(t, tunnelCreate, "202", "#/components/schemas/PreviewTunnelOperationResponse")

	tunnelItem := doc.Paths["/v1/tunnels/{tunnel_id}"]
	assertPathParameterRef(t, tunnelItem, "#/components/parameters/TunnelID", "tunnel item")
	tunnelGet := objectValue(t, tunnelItem["get"], "GET tunnel")
	assertPreviewTunnelSecurity(t, tunnelGet, "tunnels:read", false, "GET tunnel")
	assertResponseSchema(t, tunnelGet, "200", "#/components/schemas/TunnelResponse")
	tunnelPatch := objectValue(t, tunnelItem["patch"], "PATCH tunnel")
	assertPreviewTunnelSecurity(t, tunnelPatch, "tunnels:write", true, "PATCH tunnel")
	assertParameterRefs(t, tunnelPatch, "#/components/parameters/IdempotencyKey", "#/components/parameters/IfMatch")
	assertRequestSchema(t, tunnelPatch, "#/components/schemas/TunnelPatchRequest")
	assertResponseSchema(t, tunnelPatch, "200", "#/components/schemas/TunnelResponse")
	assertResponseSchema(t, tunnelPatch, "202", "#/components/schemas/PreviewTunnelOperationResponse")
	tunnelDelete := objectValue(t, tunnelItem["delete"], "DELETE tunnel")
	assertPreviewTunnelSecurity(t, tunnelDelete, "tunnels:write", true, "DELETE tunnel")
	assertParameterRefs(t, tunnelDelete, "#/components/parameters/IdempotencyKey", "#/components/parameters/IfMatch")
	assertRequestSchema(t, tunnelDelete, "#/components/schemas/TunnelStateMutationRequest")
	assertResponseSchema(t, tunnelDelete, "200", "#/components/schemas/TunnelResponse")
	assertResponseSchema(t, tunnelDelete, "202", "#/components/schemas/PreviewTunnelOperationResponse")

	for path, label := range map[string]string{
		"/v1/tunnels/{tunnel_id}/pause":  "pause",
		"/v1/tunnels/{tunnel_id}/resume": "resume",
	} {
		pathItem := doc.Paths[path]
		assertPathParameterRef(t, pathItem, "#/components/parameters/TunnelID", label)
		operation := objectValue(t, pathItem["post"], "POST "+label)
		assertPreviewTunnelSecurity(t, operation, "tunnels:write", true, "POST "+label)
		assertParameterRefs(t, operation, "#/components/parameters/IdempotencyKey", "#/components/parameters/IfMatch")
		assertRequestSchema(t, operation, "#/components/schemas/TunnelStateMutationRequest")
		assertResponseSchema(t, operation, "200", "#/components/schemas/TunnelResponse")
		assertResponseSchema(t, operation, "202", "#/components/schemas/PreviewTunnelOperationResponse")
	}

	tunnelStatus := objectValue(t, doc.Paths["/v1/tunnels/{tunnel_id}/status"]["get"], "GET tunnel status")
	assertPreviewTunnelSecurity(t, tunnelStatus, "tunnels:read", false, "GET tunnel status")
	assertResponseSchema(t, tunnelStatus, "200", "#/components/schemas/PreviewTunnelHealthResponse")
	tunnelEvents := objectValue(t, doc.Paths["/v1/tunnels/{tunnel_id}/events"]["get"], "GET tunnel events")
	assertPreviewTunnelSecurity(t, tunnelEvents, "tunnels:read", false, "GET tunnel events")
	assertParameterRefs(t, tunnelEvents, "#/components/parameters/EventCursor", "#/components/parameters/PageLimit", "#/components/parameters/LastEventID")
	assertEventResponse(t, tunnelEvents, "tunnel events")
}

func assertCanonicalResourceSchema(t *testing.T, schemas map[string]map[string]any, name, kind string, required []string) {
	t.Helper()
	schema, ok := schemas[name]
	if !ok {
		t.Fatalf("OpenAPI canonical schema %s is missing", name)
	}
	if schema["additionalProperties"] != false {
		t.Fatalf("%s must reject undeclared properties", name)
	}
	properties := objectValue(t, schema["properties"], name+".properties")
	if objectValue(t, properties["schema"], name+".schema")["const"] != "paperboat.preview-tunnel/v1" {
		t.Fatalf("%s.schema is not the canonical v1 identifier", name)
	}
	if objectValue(t, properties["kind"], name+".kind")["const"] != kind {
		t.Fatalf("%s.kind = %v, want %s", name, properties["kind"], kind)
	}
	if got := stringSet(t, schema["required"], name+".required"); !reflect.DeepEqual(got, stringSetFrom(required)) {
		t.Fatalf("%s.required = %#v, want %#v", name, got, required)
	}
}

func assertPreviewTunnelSecurity(t *testing.T, operation map[string]any, scope string, write bool, name string) {
	t.Helper()
	security := arrayValue(t, operation["security"], name+".security")
	if len(security) != 2 {
		t.Fatalf("%s security alternatives = %#v, want cookie and bearer alternatives", name, security)
	}
	cookie := objectValue(t, security[0], name+".security[0]")
	if _, ok := cookie["cookieSession"]; !ok {
		t.Fatalf("%s lacks cookie session authentication", name)
	}
	if write {
		if _, ok := cookie["csrfHeader"]; !ok {
			t.Fatalf("%s cookie writes must require CSRF", name)
		}
	} else if _, ok := cookie["csrfHeader"]; ok {
		t.Fatalf("%s read must not require CSRF", name)
	}
	bearer := objectValue(t, security[1], name+".security[1]")
	if _, ok := bearer["bearerAccess"]; !ok {
		t.Fatalf("%s lacks bearer authentication", name)
	}
	assertRequiredBearerScope(t, operation, scope, name)
}

func assertDevicePreviewTunnelSecurity(t *testing.T, operation map[string]any, scope, name string) {
	t.Helper()
	security := arrayValue(t, operation["security"], name+".security")
	if len(security) != 1 {
		t.Fatalf("%s security must be device-only, got %#v", name, security)
	}
	bearer := objectValue(t, security[0], name+".security[0]")
	if _, ok := bearer["bearerAccess"]; !ok {
		t.Fatalf("%s lacks bearer authentication", name)
	}
	assertRequiredBearerScope(t, operation, scope, name)
}

func assertParameterRefs(t *testing.T, operation map[string]any, expected ...string) {
	t.Helper()
	parameters := arrayValue(t, operation["parameters"], "operation.parameters")
	got := make(map[string]bool, len(parameters))
	for _, raw := range parameters {
		parameter := objectValue(t, raw, "operation parameter")
		if ref, ok := parameter["$ref"].(string); ok {
			got[ref] = true
		}
	}
	want := make(map[string]bool, len(expected))
	for _, ref := range expected {
		want[ref] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("operation parameter refs = %#v, want %#v", got, want)
	}
}

func assertPathParameterRef(t *testing.T, pathItem map[string]any, expected, name string) {
	t.Helper()
	parameters := arrayValue(t, pathItem["parameters"], name+".parameters")
	for _, raw := range parameters {
		if objectValue(t, raw, name+" parameter")["$ref"] == expected {
			return
		}
	}
	t.Fatalf("%s lacks path parameter %s", name, expected)
}

func assertRequestSchema(t *testing.T, operation map[string]any, expected string) {
	t.Helper()
	requestBody := objectValue(t, operation["requestBody"], "requestBody")
	content := objectValue(t, requestBody["content"], "requestBody.content")
	jsonContent := objectValue(t, content["application/json"], "requestBody JSON")
	schema := objectValue(t, jsonContent["schema"], "requestBody schema")
	if schema["$ref"] != expected {
		t.Fatalf("request schema ref = %v, want %s", schema["$ref"], expected)
	}
}

func assertResponseSchema(t *testing.T, operation map[string]any, status, expected string) {
	t.Helper()
	responses := objectValue(t, operation["responses"], "operation.responses")
	response := objectValue(t, responses[status], "response "+status)
	content := objectValue(t, response["content"], "response "+status+".content")
	jsonContent := objectValue(t, content["application/json"], "response "+status+" JSON")
	schema := objectValue(t, jsonContent["schema"], "response "+status+" schema")
	if schema["$ref"] != expected {
		t.Fatalf("response %s schema ref = %v, want %s", status, schema["$ref"], expected)
	}
}

func assertResponseHeaderRef(t *testing.T, operation map[string]any, status, name, expected string) {
	t.Helper()
	responses := objectValue(t, operation["responses"], "operation.responses")
	response := objectValue(t, responses[status], "response "+status)
	headers := objectValue(t, response["headers"], "response "+status+".headers")
	header := objectValue(t, headers[name], "response "+status+" header "+name)
	if header["$ref"] != expected {
		t.Fatalf("response %s header %s ref = %v, want %s", status, name, header["$ref"], expected)
	}
}

func assertEventResponse(t *testing.T, operation map[string]any, name string) {
	t.Helper()
	responses := objectValue(t, operation["responses"], name+".responses")
	response := objectValue(t, responses["200"], name+".200")
	content := objectValue(t, response["content"], name+".200.content")
	jsonContent := objectValue(t, content["application/json"], name+".200 JSON")
	jsonSchema := objectValue(t, jsonContent["schema"], name+".200 JSON schema")
	if jsonSchema["$ref"] != "#/components/schemas/PreviewTunnelEventPageResponse" {
		t.Fatalf("%s JSON response = %v", name, jsonSchema["$ref"])
	}
	stream := objectValue(t, content["text/event-stream"], name+".200 SSE")
	if objectValue(t, stream["schema"], name+".200 SSE schema")["type"] != "string" {
		t.Fatalf("%s SSE response must be a raw string stream", name)
	}
}

func stringSetFrom(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func TestMachineSetupOpenAPIOnlyExposesHostAndClientModes(t *testing.T) {
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
	post, ok := doc.Paths["/v1/machines/setup"]["post"].(map[string]any)
	if !ok {
		t.Fatal("machine setup operation is missing")
	}
	requestBody, ok := post["requestBody"].(map[string]any)
	if !ok {
		t.Fatal("machine setup request body is missing")
	}
	content, ok := requestBody["content"].(map[string]any)
	if !ok {
		t.Fatal("machine setup request content is missing")
	}
	jsonContent, ok := content["application/json"].(map[string]any)
	if !ok {
		t.Fatal("machine setup JSON content is missing")
	}
	schema, ok := jsonContent["schema"].(map[string]any)
	if !ok {
		t.Fatal("machine setup schema is missing")
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("machine setup properties are missing")
	}
	setupMode, ok := properties["setup_mode"].(map[string]any)
	if !ok {
		t.Fatal("machine setup mode schema is missing")
	}
	if got := stringSet(t, setupMode["enum"], "machine setup mode enum"); !reflect.DeepEqual(got, map[string]bool{"client": true, "host": true}) {
		t.Fatalf("machine setup mode enum = %#v, want client and host", got)
	}
	architecture, ok := properties["architecture"].(map[string]any)
	if !ok {
		t.Fatal("machine setup architecture schema is missing")
	}
	if got := stringSet(t, architecture["enum"], "machine setup architecture enum"); !reflect.DeepEqual(got, map[string]bool{"amd64": true, "arm64": true}) {
		t.Fatalf("machine setup architecture enum = %#v, want amd64 and arm64", got)
	}
	constraints, ok := schema["allOf"].([]any)
	if !ok || len(constraints) != 1 {
		t.Fatalf("machine setup platform matrix constraints = %#v", schema["allOf"])
	}
	encodedConstraint, err := json.Marshal(constraints[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"platform":{"const":"darwin"}`, `"architecture":{"const":"arm64"}`} {
		if !strings.Contains(string(encodedConstraint), required) {
			t.Fatalf("machine setup platform matrix constraint %s is missing %s", encodedConstraint, required)
		}
	}
}

func TestMachineInstallationOpenAPIIncludesIdentityBoundRecovery(t *testing.T) {
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
	operation := objectValue(t, doc.Paths["/v1/machines/pairings/installation"]["post"], "POST machine installation")
	description, ok := operation["description"].(string)
	if !ok || !strings.Contains(description, "24 hours") || !strings.Contains(description, "protected resume") {
		t.Fatalf("machine installation description does not document bounded recovery: %q", description)
	}
	requestBody := objectValue(t, operation["requestBody"], "machine installation request body")
	content := objectValue(t, requestBody["content"], "machine installation request content")
	jsonContent := objectValue(t, content["application/json"], "machine installation JSON content")
	schema := objectValue(t, jsonContent["schema"], "machine installation request schema")
	if required := stringSet(t, schema["required"], "machine installation required fields"); !required["verifier"] || !required["public_identity_key"] {
		t.Fatalf("machine installation required fields = %#v", required)
	}
	properties := objectValue(t, schema["properties"], "machine installation properties")
	identity := objectValue(t, properties["public_identity_key"], "machine installation public identity key")
	if identity["type"] != "string" || identity["minLength"] != float64(40) || identity["maxLength"] != float64(256) {
		t.Fatalf("public_identity_key schema = %#v", identity)
	}
	runtimeEnrolled := objectValue(t, properties["runtime_enrolled"], "machine installation runtime enrollment")
	if runtimeEnrolled["type"] != "boolean" || runtimeEnrolled["default"] != false {
		t.Fatalf("runtime_enrolled schema = %#v", runtimeEnrolled)
	}
	responses := objectValue(t, operation["responses"], "machine installation responses")
	okResponse := objectValue(t, responses["200"], "machine installation success response")
	responseDescription, ok := okResponse["description"].(string)
	if !ok || !strings.Contains(responseDescription, "identity-bound retry") || !strings.Contains(responseDescription, "recovery") {
		t.Fatalf("machine installation success response does not document replay/recovery: %q", responseDescription)
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
		"/v1/edge/routes/observations":                                       {"post"},
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
		"/v1/machines/update-summary":                                        {"get"},
		"/v1/machines/{machine_id}":                                          {"get", "patch", "delete"},
		"/v1/machines/{machine_id}/update-status":                            {"get"},
		"/v1/machines/{machine_id}/maintenance-approvals":                    {"get", "post"},
		"/v1/machines/{machine_id}/maintenance-approvals/{approval_id}/approve": {"post"},
		"/v1/machines/{machine_id}/maintenance-approvals/{approval_id}/reject":  {"post"},
		"/v1/machines/{machine_id}/connection-descriptor":                       {"post"},
		"/v1/machines/{machine_id}/connection-readiness":                        {"get"},
		"/v1/machines/{machine_id}/disconnect":                                  {"post"},
		"/v1/machines/{machine_id}/terminal-sessions":                           {"get", "post"},
		"/v1/machines/{machine_id}/terminal-sessions/{session_id}":              {"patch", "delete"},
		"/v1/machines/{machine_id}/terminal-sessions/{session_id}/close":        {"post"},
		"/v1/machines/pairings":                                                 {"post"},
		"/v1/runtime-observations":                                              {"post"},
		"/v1/admin/users/{user_id}/adjust-credits":                              {"post"},
		"/v1/admin/users/{user_id}/adjust-storage":                              {"post"},
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
	if scope["const"] != "account:read clients:revoke diagnostics:upload operations:read operations:write previews:read previews:write projects:connect projects:read session:refresh tunnels:read tunnels:write" {
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
	operation := doc.Paths["/v1/operations/{operation_id}"]
	assertRequiredBearerScope(t, objectValue(t, operation["get"], "GET operation"), "operations:read", "GET operation")
	assertRequiredBearerScope(t, objectValue(t, operation["delete"], "DELETE operation"), "operations:write", "DELETE operation")
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

func TestOpenAPIOriginTLSIsReferenceOnlyAndModeBound(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	tlsSchema := doc.Components.Schemas["TunnelRouteTLS"]
	properties := objectValue(t, tlsSchema["properties"], "TunnelRouteTLS.properties")
	verification := objectValue(t, properties["verification"], "TunnelRouteTLS.verification")
	wantModes := map[string]bool{"system": true, "custom_ca": true, "insecure_development": true}
	gotModes := stringSet(t, verification["enum"], "TunnelRouteTLS.verification.enum")
	if !reflect.DeepEqual(gotModes, wantModes) {
		t.Fatalf("origin TLS modes = %#v, want %#v", gotModes, wantModes)
	}
	if _, exists := gotModes["mutual_tls"]; exists {
		t.Fatal("mTLS must be an orthogonal credential reference, not a verification mode")
	}
	reference := doc.Components.Schemas["OriginCredentialReference"]
	pattern, _ := reference["pattern"].(string)
	if reference["maxLength"] != float64(512) || !strings.Contains(pattern, "://paperboat/") {
		t.Fatalf("origin reference is not bounded and Paperboat-scoped: %#v", reference)
	}
	encoded, err := json.Marshal(tlsSchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "bearer_token", "private_key_pem"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("origin TLS schema contains secret material field %q", forbidden)
		}
	}
	if len(arrayValue(t, tlsSchema["allOf"], "TunnelRouteTLS.allOf")) != 2 {
		t.Fatalf("origin TLS mode/reference conditions missing: %#v", tlsSchema)
	}
}

func TestOpenAPIEnvironmentScopeInventoryIsStrictMetadataOnly(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		}
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	item := doc.Components.Schemas["EnvironmentScopeInventoryItem"]
	if item["additionalProperties"] != false {
		t.Fatalf("inventory item must reject additional properties: %#v", item)
	}
	properties := objectValue(t, item["properties"], "EnvironmentScopeInventoryItem.properties")
	want := map[string]bool{"scope": true, "machine_id": true, "scope_state": true, "version": true, "key_epoch": true, "manifest_id": true, "names": true}
	got := make(map[string]bool, len(properties))
	for name := range properties {
		got[name] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inventory item fields = %#v, want %#v", got, want)
	}
	for _, forbidden := range []string{"envelope", "ciphertext", "content_hash", "wrapped_key", "value", "observation"} {
		if _, found := properties[forbidden]; found {
			t.Fatalf("inventory item exposes forbidden field %q", forbidden)
		}
	}
	operation := objectValue(t, doc.Paths["/v1/environment-scopes"]["get"], "GET /v1/environment-scopes")
	assertRequiredBearerScope(t, operation, "projects:read", "GET /v1/environment-scopes")
	responses := objectValue(t, operation["responses"], "GET /v1/environment-scopes responses")
	response := objectValue(t, responses["200"], "GET /v1/environment-scopes 200")
	headers := objectValue(t, response["headers"], "GET /v1/environment-scopes 200 headers")
	cacheControl := objectValue(t, headers["Cache-Control"], "Cache-Control")
	cacheSchema := objectValue(t, cacheControl["schema"], "Cache-Control.schema")
	if cacheSchema["const"] != "no-store" {
		t.Fatalf("Cache-Control schema = %#v", cacheSchema)
	}
}

func assertExactCLIScopes(t *testing.T, schema map[string]any, name string) {
	t.Helper()
	properties := objectValue(t, schema["properties"], name+".properties")
	scopes := objectValue(t, properties["scopes"], name+".scopes")
	if scopes["minItems"] != float64(12) || scopes["maxItems"] != float64(12) || scopes["uniqueItems"] != true {
		t.Fatalf("%s does not require exactly twelve unique scopes: %#v", name, scopes)
	}
	items := objectValue(t, scopes["items"], name+".scopes.items")
	actual := stringSet(t, items["enum"], name+".scopes.items.enum")
	expected := map[string]bool{
		"account:read": true, "clients:revoke": true, "projects:read": true,
		"projects:connect": true, "session:refresh": true, "diagnostics:upload": true,
		"previews:read": true, "previews:write": true, "tunnels:read": true,
		"tunnels:write": true, "operations:read": true, "operations:write": true,
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
