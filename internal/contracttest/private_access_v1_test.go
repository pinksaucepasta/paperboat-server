package contracttest

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/xeipuuv/gojsonschema"
)

// TestPrivateAccessV1SchemaVectors exercises the local grant, authorize,
// decision, and safe-error fixture envelopes.
func TestPrivateAccessV1SchemaVectors(t *testing.T) {
	familyRoot := filepath.Join("..", "..", "testdata", "contracts", "preview-tunnel-v1")
	schemaBytes, err := os.ReadFile(filepath.Join(familyRoot, "schemas", "private_access.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(schemaBytes))
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := os.Open(filepath.Join(familyRoot, "fixtures", "private_access.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer fixtures.Close()

	seenValid, seenInvalid := 0, 0
	scanner := bufio.NewScanner(fixtures)
	scanner.Buffer(make([]byte, 4096), 1<<20)
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
			t.Fatalf("%s: validate: %v", vector.Case, err)
		}
		if vector.Valid {
			seenValid++
			if !result.Valid() {
				t.Errorf("%s: valid private access message rejected: %v", vector.Case, result.Errors())
			}
			continue
		}
		seenInvalid++
		if vector.ExpectedError == "" {
			t.Errorf("%s: negative vector has no stable expected_error", vector.Case)
		}
		if result.Valid() {
			t.Errorf("%s: invalid private access message accepted", vector.Case)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if seenValid < 1 || seenInvalid < 1 {
		t.Fatalf("private access fixture lacks positive and negative coverage: valid=%d invalid=%d", seenValid, seenInvalid)
	}
}
