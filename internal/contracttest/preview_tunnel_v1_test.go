package contracttest

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/xeipuuv/gojsonschema"
)

func TestPreviewTunnelV1SchemaVectors(t *testing.T) {
	familyRoot := filepath.Join("..", "..", "testdata", "contracts", "preview-tunnel-v1")
	schemaBytes, err := os.ReadFile(filepath.Join(familyRoot, "schemas", "resources.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(schemaBytes))
	if err != nil {
		t.Fatal(err)
	}

	fixtures, err := os.Open(filepath.Join(familyRoot, "fixtures", "resources.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer fixtures.Close()

	seenValid, seenInvalid := 0, 0
	scanner := bufio.NewScanner(fixtures)
	for scanner.Scan() {
		var vector struct {
			Case          string          `json:"case"`
			Valid         bool            `json:"valid"`
			ExpectedError string          `json:"expected_error"`
			Resource      json.RawMessage `json:"resource"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			t.Fatal(err)
		}
		result, err := schema.Validate(gojsonschema.NewBytesLoader(vector.Resource))
		if err != nil {
			t.Fatalf("%s: validate: %v", vector.Case, err)
		}
		if vector.Valid {
			seenValid++
			if !result.Valid() {
				t.Errorf("%s: valid resource rejected: %v", vector.Case, result.Errors())
			}
			continue
		}
		seenInvalid++
		if vector.ExpectedError == "" {
			t.Errorf("%s: negative vector has no stable expected_error", vector.Case)
		}
		if result.Valid() {
			t.Errorf("%s: invalid resource accepted", vector.Case)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if seenValid != 19 || seenInvalid != 10 {
		t.Fatalf("unexpected fixture coverage: valid=%d invalid=%d", seenValid, seenInvalid)
	}
}
