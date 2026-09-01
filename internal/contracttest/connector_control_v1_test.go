package contracttest

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/xeipuuv/gojsonschema"
)

func TestConnectorControlBootstrapV1SchemaVectors(t *testing.T) {
	familyRoot := os.Getenv("PAPERBOAT_CONNECTOR_CONTRACT_ROOT")
	if familyRoot == "" {
		familyRoot = "../../testdata/contracts/connector-v1"
	}
	schemaBytes, err := os.ReadFile(filepath.Join(familyRoot, "schemas", "bootstrap.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(schemaBytes))
	if err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(filepath.Join(familyRoot, "fixtures", "bootstrap.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	seenValid, seenInvalid := 0, 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var vector struct {
			Case          string          `json:"case"`
			Valid         bool            `json:"valid"`
			ExpectedError string          `json:"expected_error"`
			Message       json.RawMessage `json:"message"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			t.Fatal(err)
		}
		result, err := schema.Validate(gojsonschema.NewBytesLoader(vector.Message))
		if err != nil {
			t.Fatalf("%s: validate schema: %v", vector.Case, err)
		}
		valid := result.Valid()
		if valid {
			valid = connectorBootstrapSemanticallyValid(vector.Message)
		}
		if valid != vector.Valid {
			t.Fatalf("%s: valid=%v want %v (schema errors=%v)", vector.Case, valid, vector.Valid, result.Errors())
		}
		if vector.Valid {
			seenValid++
		} else {
			seenInvalid++
			if vector.ExpectedError == "" {
				t.Fatalf("%s: invalid vector lacks expected_error", vector.Case)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if seenValid < 3 || seenInvalid < 4 {
		t.Fatalf("insufficient bootstrap coverage: valid=%d invalid=%d", seenValid, seenInvalid)
	}
}

func connectorBootstrapSemanticallyValid(message json.RawMessage) bool {
	var discriminator struct {
		Kind  string `json:"kind"`
		Error *struct {
			Kind string `json:"kind"`
		} `json:"error"`
	}
	if json.Unmarshal(message, &discriminator) != nil {
		return false
	}
	switch discriminator.Kind {
	case "carrier_bootstrap_request":
		var request connectorprotocol.CarrierBootstrapRequest
		return json.Unmarshal(message, &request) == nil && request.Validate() == nil
	case "carrier_bootstrap_descriptor":
		var descriptor connectorprotocol.CarrierBootstrapDescriptor
		return json.Unmarshal(message, &descriptor) == nil && descriptor.Validate(time.Time{}) == nil
	case "connector_activation":
		var activation struct {
			Schema               string `json:"schema"`
			Kind                 string `json:"kind"`
			TunnelID             string `json:"tunnel_id"`
			ConnectorID          string `json:"connector_id"`
			HostID               string `json:"host_id"`
			CredentialGeneration int64  `json:"credential_generation"`
			ProcessGeneration    int64  `json:"process_generation"`
			Operation            struct {
				Schema       string    `json:"schema"`
				Kind         string    `json:"kind"`
				ID           string    `json:"id"`
				ResourceKind string    `json:"resource_kind"`
				ResourceID   string    `json:"resource_id"`
				Phase        string    `json:"phase"`
				State        string    `json:"state"`
				CreatedAt    time.Time `json:"created_at"`
				UpdatedAt    time.Time `json:"updated_at"`
			} `json:"operation"`
		}
		return json.Unmarshal(message, &activation) == nil &&
			activation.Schema == "paperboat.preview-tunnel/v1" && activation.Kind == "connector_activation" &&
			connectorprotocol.ValidateIdentifier(activation.TunnelID) == nil &&
			connectorprotocol.ValidateIdentifier(activation.ConnectorID) == nil &&
			connectorprotocol.ValidateIdentifier(activation.HostID) == nil &&
			activation.CredentialGeneration > 0 && activation.ProcessGeneration > 0 &&
			activation.Operation.Schema == activation.Schema && activation.Operation.Kind == "operation" &&
			activation.Operation.ResourceKind == "connector" && activation.Operation.ResourceID == activation.ConnectorID &&
			activation.Operation.Phase == "connecting" && activation.Operation.State == "running" &&
			connectorprotocol.ValidateIdentifier(activation.Operation.ID) == nil &&
			!activation.Operation.CreatedAt.IsZero() && !activation.Operation.UpdatedAt.IsZero()
	case "":
		return discriminator.Error != nil && discriminator.Error.Kind == "error"
	default:
		return false
	}
}
