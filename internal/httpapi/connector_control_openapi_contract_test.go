package httpapi

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestOpenAPIFreezesConnectorControlAndCarrierBootstrap(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas    map[string]map[string]any `json:"schemas"`
			Parameters map[string]map[string]any `json:"parameters"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	control := objectValue(t, doc.Paths["/v1/tunnels/{tunnel_id}/connectors/{connector_id}/control"]["get"], "connector control GET")
	assertEmptySecurity(t, control, "connector control GET")
	assertParameterRefs(t, control, "#/components/parameters/ConnectorControlSubprotocol")
	assertExactResponseStatuses(t, control, "connector control GET", "101", "400")
	if got := doc.Components.Parameters["ConnectorControlSubprotocol"]["schema"].(map[string]any)["const"]; got != "paperboat.connector.v1" {
		t.Fatalf("connector control subprotocol = %v", got)
	}
	controlDescription, _ := control["description"].(string)
	for _, required := range []string{"signed Hello", "sole authentication", "Query parameters", "cookies", "bearer"} {
		if !strings.Contains(controlDescription, required) {
			t.Fatalf("connector control description does not freeze %q", required)
		}
	}

	bootstrap := objectValue(t, doc.Paths["/v1/tunnels/{tunnel_id}/connectors/{connector_id}/carrier-bootstrap"]["post"], "carrier bootstrap POST")
	assertEmptySecurity(t, bootstrap, "carrier bootstrap POST")
	assertParameterRefs(t, bootstrap,
		"#/components/parameters/IdempotencyKey",
		"#/components/parameters/MachineIdentity",
		"#/components/parameters/MachineProof",
	)
	assertRequestSchema(t, bootstrap, "#/components/schemas/ConnectorCarrierBootstrapRequest")
	assertResponseSchema(t, bootstrap, "200", "#/components/schemas/ConnectorCarrierBootstrapResponse")
	assertExactResponseStatuses(t, bootstrap, "carrier bootstrap POST", "200", "400", "401", "403", "409", "415", "503")
	for _, status := range []string{"400", "401", "403", "409", "415", "503"} {
		assertResponseSchema(t, bootstrap, status, "#/components/schemas/ConnectorCarrierBootstrapErrorResponse")
	}

	for name, requiredFields := range map[string][]string{
		"ConnectorCarrierBootstrapRequest":    {"schema", "kind", "session_id", "process_generation", "config_generation", "config_content_hash"},
		"ConnectorCarrierBootstrapDescriptor": {"schema", "kind", "account_id", "tunnel_id", "connector_id", "host_id", "stable_endpoint_id", "session_id", "process_generation", "credential_generation", "config_generation", "config_content_hash", "carriers", "issued_at", "expires_at"},
		"ConnectorCarrierBootstrapNode":       {"edge_node_id", "edge_process_epoch", "failure_domain", "endpoints", "server_spki_sha256", "server_certificate_chain_pem"},
		"ConnectorCarrierBootstrapError":      {"schema", "kind", "code", "component", "message", "outcome", "retryable", "repair_action", "request_id", "correlation_id"},
	} {
		schema := doc.Components.Schemas[name]
		if schema == nil || schema["additionalProperties"] != false {
			t.Fatalf("%s must exist and reject unknown fields", name)
		}
		required := stringSet(t, schema["required"], name+".required")
		for _, field := range requiredFields {
			if !required[field] {
				t.Fatalf("%s does not require %q", name, field)
			}
		}
	}

	descriptorProperties := objectValue(t, doc.Components.Schemas["ConnectorCarrierBootstrapDescriptor"]["properties"], "bootstrap descriptor properties")
	endpointID := objectValue(t, descriptorProperties["stable_endpoint_id"], "bootstrap stable_endpoint_id")
	if endpointID["pattern"] != "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" || !strings.Contains(endpointID["description"].(string), "immutable") {
		t.Fatalf("bootstrap stable endpoint identity is not canonical: %#v", endpointID)
	}
	carriers := objectValue(t, descriptorProperties["carriers"], "bootstrap carriers")
	if carriers["minItems"] != float64(1) || carriers["maxItems"] != float64(4) || carriers["uniqueItems"] != true || !strings.Contains(carriers["description"].(string), "distinct failure_domain") {
		t.Fatalf("carrier cardinality or failure-domain contract is incomplete: %#v", carriers)
	}
	if !strings.Contains(objectValue(t, descriptorProperties["expires_at"], "bootstrap expires_at")["description"].(string), "two minutes") {
		t.Fatal("bootstrap lifetime bound is not documented")
	}
	nodeProperties := objectValue(t, doc.Components.Schemas["ConnectorCarrierBootstrapNode"]["properties"], "bootstrap node properties")
	endpoints := objectValue(t, nodeProperties["endpoints"], "bootstrap endpoints")
	if endpoints["minItems"] != float64(2) || endpoints["maxItems"] != float64(2) || endpoints["uniqueItems"] != true || len(arrayValue(t, endpoints["allOf"], "bootstrap endpoint transport requirements")) != 2 {
		t.Fatalf("bootstrap endpoints do not require an exact transport pair: %#v", endpoints)
	}

	errorProperties := objectValue(t, doc.Components.Schemas["ConnectorCarrierBootstrapError"]["properties"], "bootstrap error properties")
	codes := stringSet(t, objectValue(t, errorProperties["code"], "bootstrap error code")["enum"], "bootstrap error code enum")
	wantCodes := map[string]bool{
		"invalid_content_type": true, "invalid_request": true,
		"machine_identity_required": true, "machine_identity_invalid": true,
		"connector_access_forbidden": true, "connector_session_stale": true,
		"carrier_unavailable": true, "connector_control_invalid": true,
		"connector_control_unavailable": true,
	}
	if !reflect.DeepEqual(codes, wantCodes) {
		t.Fatalf("bootstrap error codes = %#v, want %#v", codes, wantCodes)
	}

	for _, schemaName := range []string{"ConnectorCarrierBootstrapRequest", "ConnectorCarrierBootstrapDescriptor", "ConnectorCarrierBootstrapNode", "ConnectorCarrierBootstrapResponse", "ConnectorCarrierBootstrapError", "ConnectorCarrierBootstrapErrorResponse"} {
		assertNoSecretSchemaKeys(t, schemaName, doc.Components.Schemas[schemaName])
	}
}

func TestOpenAPIFreezesConnectorEnrollmentActivation(t *testing.T) {
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

	issue := objectValue(t, doc.Paths["/v1/tunnels/{tunnel_id}/connectors/enrollments"]["post"], "connector enrollment issue")
	assertMachineControlSecurity(t, issue, "connector enrollment issue")
	assertParameterRefs(t, issue,
		"#/components/parameters/IdempotencyKey",
		"#/components/parameters/MachineIdentity",
		"#/components/parameters/MachineProof",
	)
	assertRequestSchema(t, issue, "#/components/schemas/ConnectorEnrollmentRequest")
	assertResponseSchema(t, issue, "201", "#/components/schemas/ConnectorEnrollmentResponse")
	assertExactResponseStatuses(t, issue, "connector enrollment issue", "201", "400", "401", "403", "409")
	issueDescription, _ := issue["description"].(string)
	for _, required := range []string{"machine_control bearer", "X-Paperboat-Machine-Identity", "X-Paperboat-Machine-Proof", "Idempotency-Key", "exact POST path", "Browser sessions", "CSRF tokens", "client-session bearers"} {
		if !strings.Contains(issueDescription, required) {
			t.Fatalf("connector enrollment issue does not freeze %q", required)
		}
	}

	exchange := objectValue(t, doc.Paths["/v1/tunnels/{tunnel_id}/connectors/enrollments/exchange"]["post"], "connector enrollment exchange")
	assertMachineControlSecurity(t, exchange, "connector enrollment exchange")
	assertParameterRefs(t, exchange,
		"#/components/parameters/IdempotencyKey",
		"#/components/parameters/MachineIdentity",
		"#/components/parameters/MachineProof",
	)
	assertExactResponseStatuses(t, exchange, "connector enrollment exchange", "202", "400", "401", "403", "409")
	assertResponseSchema(t, exchange, "202", "#/components/schemas/ConnectorActivationResponse")
	description, _ := exchange["description"].(string)
	for _, required := range []string{"server-reserved", "immutable", "host must never guess", "exact idempotent replay", "obsolete operation-only"} {
		if !strings.Contains(description, required) {
			t.Fatalf("connector enrollment exchange does not freeze %q", required)
		}
	}

	activation := doc.Components.Schemas["ConnectorActivation"]
	if activation == nil || activation["additionalProperties"] != false {
		t.Fatal("ConnectorActivation must exist and reject unknown fields")
	}
	required := stringSet(t, activation["required"], "ConnectorActivation.required")
	for _, field := range []string{"schema", "kind", "account_id", "tunnel_id", "connector_id", "host_id", "stable_endpoint_id", "credential_generation", "process_generation", "operation"} {
		if !required[field] {
			t.Fatalf("ConnectorActivation does not require %q", field)
		}
	}
	properties := objectValue(t, activation["properties"], "ConnectorActivation.properties")
	if objectValue(t, properties["schema"], "ConnectorActivation.schema")["const"] != "paperboat.preview-tunnel/v1" || objectValue(t, properties["kind"], "ConnectorActivation.kind")["const"] != "connector_activation" {
		t.Fatal("ConnectorActivation discriminator is not canonical")
	}
	endpointID := objectValue(t, properties["stable_endpoint_id"], "ConnectorActivation.stable_endpoint_id")
	if endpointID["pattern"] != "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" || !strings.Contains(endpointID["description"].(string), "immutable") {
		t.Fatalf("ConnectorActivation stable endpoint identity is not canonical: %#v", endpointID)
	}
	for _, generation := range []string{"credential_generation", "process_generation"} {
		property := objectValue(t, properties[generation], "ConnectorActivation."+generation)
		if property["minimum"] != float64(1) || !strings.Contains(property["description"].(string), "Server-reserved immutable") {
			t.Fatalf("%s is not a positive immutable server fence: %#v", generation, property)
		}
	}
	operation := objectValue(t, properties["operation"], "ConnectorActivation.operation")
	constraints := arrayValue(t, operation["allOf"], "ConnectorActivation.operation.allOf")
	if len(constraints) != 2 {
		t.Fatalf("ConnectorActivation operation constraints = %#v", constraints)
	}
	operationConstraint := objectValue(t, constraints[1], "ConnectorActivation.operation constraint")
	operationProperties := objectValue(t, operationConstraint["properties"], "ConnectorActivation.operation constraint properties")
	for field, want := range map[string]string{"resource_kind": "connector", "phase": "connecting", "state": "running"} {
		if objectValue(t, operationProperties[field], "ConnectorActivation.operation."+field)["const"] != want {
			t.Fatalf("ConnectorActivation operation %s is not %q", field, want)
		}
	}
	assertNoSecretSchemaKeys(t, "ConnectorActivation", activation)
}

func assertEmptySecurity(t *testing.T, operation map[string]any, label string) {
	t.Helper()
	security := arrayValue(t, operation["security"], label+".security")
	if len(security) != 0 {
		t.Fatalf("%s security = %#v, want no HTTP authentication fallback", label, security)
	}
}

func assertMachineControlSecurity(t *testing.T, operation map[string]any, label string) {
	t.Helper()
	security := arrayValue(t, operation["security"], label+".security")
	if len(security) != 1 {
		t.Fatalf("%s security = %#v, want machine-control bearer only", label, security)
	}
	requirement := objectValue(t, security[0], label+".security[0]")
	if len(requirement) != 1 {
		t.Fatalf("%s security = %#v, want no browser or generic bearer fallback", label, security)
	}
	scopes, ok := requirement["bearerMachineControl"].([]any)
	if !ok || len(scopes) != 0 {
		t.Fatalf("%s security = %#v, want bearerMachineControl with no alternate scheme", label, security)
	}
}

func assertNoSecretSchemaKeys(t *testing.T, name string, schema map[string]any) {
	t.Helper()
	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				normalized := strings.ToLower(key)
				for _, forbidden := range []string{"private_key", "bearer", "token", "authorization", "cookie", "proof"} {
					if strings.Contains(normalized, forbidden) {
						t.Fatalf("%s contains forbidden secret field %q", name, key)
					}
				}
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(schema)
}
