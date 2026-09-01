package contracttest

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/telemetry"
	"github.com/xeipuuv/gojsonschema"
)

type telemetryHealthVector struct {
	Case          string         `json:"case"`
	Valid         bool           `json:"valid"`
	ExpectedError string         `json:"expected_error"`
	Base          string         `json:"base"`
	Snapshot      map[string]any `json:"snapshot"`
	Patch         map[string]any `json:"patch"`
	Remove        []string       `json:"remove"`
}

func TestTelemetryHealthV1SchemaVectors(t *testing.T) {
	familyRoot := os.Getenv("PAPERBOAT_TELEMETRY_CONTRACT_ROOT")
	if familyRoot == "" {
		familyRoot = filepath.Join("..", "..", "testdata", "contracts", "telemetry-v1")
	}
	schemaBytes, err := os.ReadFile(filepath.Join(familyRoot, "schemas", "health.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(schemaBytes))
	if err != nil {
		t.Fatal(err)
	}

	vectors, err := readTelemetryHealthVectors(filepath.Join(familyRoot, "fixtures", "health.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	bases := make(map[string]map[string]any)
	for _, vector := range vectors {
		if len(vector.Snapshot) != 0 {
			bases[vector.Case] = cloneTelemetryMap(vector.Snapshot)
		}
	}
	seenValid, seenInvalid := 0, 0
	seenErrors := map[string]bool{}
	for _, vector := range vectors {
		message, err := telemetryVectorSnapshot(vector, bases)
		if err != nil {
			t.Fatalf("%s: construct snapshot: %v", vector.Case, err)
		}
		result, err := schema.Validate(gojsonschema.NewBytesLoader(message))
		if err != nil {
			t.Fatalf("%s: validate schema: %v", vector.Case, err)
		}
		if vector.Valid {
			seenValid++
			if !result.Valid() {
				t.Errorf("%s: valid snapshot rejected: %v", vector.Case, result.Errors())
			}
			continue
		}
		seenInvalid++
		if vector.ExpectedError == "" {
			t.Errorf("%s: invalid vector lacks stable expected_error", vector.Case)
		}
		seenErrors[vector.ExpectedError] = true
		if result.Valid() {
			t.Errorf("%s: invalid snapshot accepted", vector.Case)
		}
	}
	if seenValid < 2 || seenInvalid != 8 {
		t.Fatalf("unexpected telemetry fixture coverage: valid=%d invalid=%d", seenValid, seenInvalid)
	}
	for _, expected := range []string{
		"secret_field_forbidden", "hostname_or_url_forbidden", "unknown_dimension", "unknown_status",
		"retry_mismatch", "broken_state_mismatch", "missing_required_field", "unknown_property",
	} {
		if !seenErrors[expected] {
			t.Errorf("missing telemetry negative vector %q", expected)
		}
	}

	tracker, err := telemetry.NewHealthTracker(func() time.Time {
		return time.Date(2026, 8, 31, 0, 0, 0, 0, time.FixedZone("test", 5*60*60+30*60))
	})
	if err != nil {
		t.Fatal(err)
	}
	if telemetry.HealthSchemaV1 != "paperboat.health/v1" {
		t.Fatalf("implementation schema = %q", telemetry.HealthSchemaV1)
	}
	actual, err := tracker.Snapshot().JSON()
	if err != nil {
		t.Fatal(err)
	}
	actualResult, err := schema.Validate(gojsonschema.NewBytesLoader(actual))
	if err != nil {
		t.Fatal(err)
	}
	if !actualResult.Valid() {
		t.Fatalf("implementation snapshot rejected: %v", actualResult.Errors())
	}
}

func readTelemetryHealthVectors(path string) ([]telemetryHealthVector, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var vectors []telemetryHealthVector
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var vector telemetryHealthVector
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			return nil, err
		}
		if vector.Case == "" {
			return nil, os.ErrInvalid
		}
		vectors = append(vectors, vector)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return vectors, nil
}

func telemetryVectorSnapshot(vector telemetryHealthVector, bases map[string]map[string]any) ([]byte, error) {
	var snapshot map[string]any
	if len(vector.Snapshot) != 0 {
		snapshot = cloneTelemetryMap(vector.Snapshot)
	} else {
		base, ok := bases[vector.Base]
		if !ok {
			return nil, os.ErrNotExist
		}
		snapshot = cloneTelemetryMap(base)
		mergeTelemetryMap(snapshot, vector.Patch)
		for _, path := range vector.Remove {
			removeTelemetryPath(snapshot, path)
		}
	}
	return json.Marshal(snapshot)
}

func cloneTelemetryMap(value map[string]any) map[string]any {
	encoded, _ := json.Marshal(value)
	var clone map[string]any
	_ = json.Unmarshal(encoded, &clone)
	return clone
}

func mergeTelemetryMap(destination, patch map[string]any) {
	for key, value := range patch {
		patchMap, ok := value.(map[string]any)
		if !ok {
			destination[key] = value
			continue
		}
		destinationMap, ok := destination[key].(map[string]any)
		if !ok {
			destinationMap = map[string]any{}
			destination[key] = destinationMap
		}
		mergeTelemetryMap(destinationMap, patchMap)
	}
}

func removeTelemetryPath(snapshot map[string]any, path string) {
	parts := strings.Split(path, ".")
	current := snapshot
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok {
			return
		}
		current = next
	}
	delete(current, parts[len(parts)-1])
}
