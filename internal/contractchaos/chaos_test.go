package contractchaos

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"
)

const previewTunnelSchemaV1 = "paperboat.preview-tunnel/v1"

type familyDefinition struct {
	schemaPath  string
	fixturePath string
}

type familyFixture struct {
	validator *gojsonschema.Schema
	fixtures  map[string]json.RawMessage
}

type fixtureEnvelope struct {
	Case     string          `json:"case"`
	Valid    bool            `json:"valid"`
	Message  json.RawMessage `json:"message"`
	Resource json.RawMessage `json:"resource"`
}

type chaosVector struct {
	ID          string `json:"id"`
	Family      string `json:"family"`
	FixtureCase string `json:"fixture_case"`
	Operation   string `json:"operation"`
	Expected    string `json:"expected"`
}

type chaosVectorCorpus struct {
	Version int           `json:"version"`
	Schema  string        `json:"schema"`
	Cases   []chaosVector `json:"cases"`
}

func TestPreviewTunnelV1ContractChaos(t *testing.T) {
	root := findContractRoot(t)
	families := loadFamilies(t, root)
	corpus := loadChaosVectors(t)
	assertVectorCoverage(t, corpus)
	assertCanonicalFixtures(t, families)

	for _, vector := range corpus.Cases {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			family, ok := families[vector.Family]
			if !ok {
				t.Fatalf("unknown contract family %q", vector.Family)
			}
			base, ok := family.fixtures[vector.FixtureCase]
			if !ok {
				t.Fatalf("fixture %q is not a valid %s fixture", vector.FixtureCase, vector.Family)
			}
			if expected := expectedOutcome(vector.Operation); expected != vector.Expected {
				t.Fatalf("vector expected %q for %s, want %q", vector.Expected, vector.Operation, expected)
			}

			switch vector.Operation {
			case "truncate":
				truncated := truncateJSON(base)
				assertStrictRejects(t, truncated)
				exerciseLastKnownGood(t, family.validator, base, truncated)
			case "corrupt":
				corrupt := corruptJSON(t, vector.Family, base)
				assertStrictAccepts(t, corrupt)
				assertSchemaRejects(t, family.validator, corrupt)
				exerciseLastKnownGood(t, family.validator, base, corrupt)
			case "duplicate_key":
				assertStrictRejects(t, duplicateRootKey(base, "schema", previewTunnelSchemaV1))
			case "mixed_version":
				mixed := mixedVersion(base)
				assertStrictAccepts(t, mixed)
				assertSchemaRejects(t, family.validator, mixed)
			case "over_limit_domains", "over_limit_metadata", "over_limit_target", "over_limit_aliases", "over_limit_admissions":
				overLimit := overLimitJSON(t, vector.Family, vector.Operation, base)
				assertStrictAccepts(t, overLimit)
				assertSchemaRejects(t, family.validator, overLimit)
			case "replay_stale_generation":
				exerciseGenerationLedger(t, family.validator, vector.Family, base)
			case "secret":
				secret := secretJSON(t, vector.Family, vector.FixtureCase, base)
				assertStrictAccepts(t, secret)
				assertSchemaRejects(t, family.validator, secret)
			default:
				t.Fatalf("unsupported chaos operation %q", vector.Operation)
			}
		})
	}
}

func findContractRoot(t *testing.T) string {
	t.Helper()
	return "../../testdata/contracts/preview-tunnel-v1"
}

func loadFamilies(t *testing.T, root string) map[string]familyFixture {
	t.Helper()
	definitions := map[string]familyDefinition{
		"resources": {
			schemaPath:  "schemas/resources.schema.json",
			fixturePath: "fixtures/resources.ndjson",
		},
		"dispatch": {
			schemaPath:  "schemas/dispatch.schema.json",
			fixturePath: "fixtures/dispatch.ndjson",
		},
		"attachment": {
			schemaPath:  "schemas/attachment.schema.json",
			fixturePath: "fixtures/attachment.ndjson",
		},
		"private_access": {
			schemaPath:  "schemas/private_access.schema.json",
			fixturePath: "fixtures/private_access.ndjson",
		},
	}

	families := make(map[string]familyFixture, len(definitions))
	for name, definition := range definitions {
		schemaBytes, err := os.ReadFile(filepath.Join(root, definition.schemaPath))
		if err != nil {
			t.Fatalf("read %s schema: %v", name, err)
		}
		validator, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(schemaBytes))
		if err != nil {
			t.Fatalf("compile %s schema: %v", name, err)
		}
		fixtures := readValidFixtures(t, filepath.Join(root, definition.fixturePath), name)
		families[name] = familyFixture{validator: validator, fixtures: fixtures}
	}
	return families
}

func readValidFixtures(t *testing.T, path, family string) map[string]json.RawMessage {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s fixtures: %v", family, err)
	}
	defer file.Close()

	fixtures := make(map[string]json.RawMessage)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 32<<20)
	for scanner.Scan() {
		var envelope fixtureEnvelope
		if err := json.Unmarshal(scanner.Bytes(), &envelope); err != nil {
			t.Fatalf("decode %s fixture envelope: %v", family, err)
		}
		if !envelope.Valid {
			continue
		}
		raw := envelope.Message
		if family == "resources" {
			raw = envelope.Resource
		}
		if envelope.Case == "" || len(raw) == 0 {
			t.Fatalf("%s fixture has no case or payload", family)
		}
		if _, exists := fixtures[envelope.Case]; exists {
			t.Fatalf("duplicate valid %s fixture case %q", family, envelope.Case)
		}
		fixtures[envelope.Case] = append(json.RawMessage(nil), raw...)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s fixtures: %v", family, err)
	}
	if len(fixtures) == 0 {
		t.Fatalf("%s fixtures have no valid vectors", family)
	}
	return fixtures
}

func loadChaosVectors(t *testing.T) chaosVectorCorpus {
	t.Helper()
	path := filepath.Join("testdata", "chaos_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chaos vectors: %v", err)
	}
	var corpus chaosVectorCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatalf("decode chaos vectors: %v", err)
	}
	if corpus.Version != 1 || corpus.Schema != previewTunnelSchemaV1 {
		t.Fatalf("chaos vector header = version %d schema %q, want version 1 schema %q", corpus.Version, corpus.Schema, previewTunnelSchemaV1)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("chaos vector corpus is empty")
	}
	return corpus
}

func assertVectorCoverage(t *testing.T, corpus chaosVectorCorpus) {
	t.Helper()
	families := []string{"resources", "dispatch", "attachment", "private_access"}
	operations := []string{"truncate", "corrupt", "duplicate_key", "mixed_version", "secret", "replay_stale_generation"}
	seen := make(map[string]map[string]bool)
	ids := make(map[string]bool)
	for _, vector := range corpus.Cases {
		if vector.ID == "" || vector.Family == "" || vector.FixtureCase == "" || vector.Operation == "" || vector.Expected == "" {
			t.Fatalf("incomplete chaos vector: %+v", vector)
		}
		if ids[vector.ID] {
			t.Fatalf("duplicate chaos vector id %q", vector.ID)
		}
		ids[vector.ID] = true
		if seen[vector.Operation] == nil {
			seen[vector.Operation] = make(map[string]bool)
		}
		seen[vector.Operation][vector.Family] = true
	}
	for _, operation := range operations {
		for _, family := range families {
			if !seen[operation][family] {
				t.Errorf("chaos vectors lack %s coverage for %s", operation, family)
			}
		}
	}
}

func assertCanonicalFixtures(t *testing.T, families map[string]familyFixture) {
	t.Helper()
	for familyName, family := range families {
		for caseName, raw := range family.fixtures {
			value, err := decodeStrictJSON(raw)
			if err != nil {
				t.Errorf("valid %s fixture %q is not strict JSON: %v", familyName, caseName, err)
				continue
			}
			if path, forbidden := findForbiddenKey(value, ""); forbidden {
				t.Errorf("valid %s fixture %q exposes forbidden field at %s", familyName, caseName, path)
			}
			assertSchemaAccepts(t, family.validator, raw)
		}
	}
}

func expectedOutcome(operation string) string {
	switch operation {
	case "truncate":
		return "decode_rejected"
	case "duplicate_key":
		return "duplicate_key_rejected"
	case "corrupt", "mixed_version", "over_limit_domains", "over_limit_metadata", "over_limit_target", "over_limit_aliases", "over_limit_admissions", "secret":
		return "schema_rejected"
	case "replay_stale_generation":
		return "ledger_rejected"
	default:
		return ""
	}
}

func assertSchemaAccepts(t *testing.T, validator *gojsonschema.Schema, raw []byte) {
	t.Helper()
	valid, err := schemaAccepts(validator, raw)
	if err != nil {
		t.Fatalf("schema validation failed: %v", err)
	}
	if !valid {
		t.Fatalf("schema rejected canonical or mutated-valid payload")
	}
}

func assertSchemaRejects(t *testing.T, validator *gojsonschema.Schema, raw []byte) {
	t.Helper()
	valid, err := schemaAccepts(validator, raw)
	if err != nil {
		t.Fatalf("schema validator errored for syntactically valid rejected payload: %v", err)
	}
	if valid {
		t.Fatalf("schema accepted corrupted, stale-version, secret, or over-limit payload")
	}
}

func schemaAccepts(validator *gojsonschema.Schema, raw []byte) (bool, error) {
	result, err := validator.Validate(gojsonschema.NewBytesLoader(raw))
	if err != nil {
		return false, err
	}
	return result.Valid(), nil
}

func assertStrictAccepts(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := decodeStrictJSON(raw); err != nil {
		t.Fatalf("strict JSON decoder rejected payload: %v", err)
	}
}

func assertStrictRejects(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := decodeStrictJSON(raw); err == nil {
		t.Fatal("strict JSON decoder accepted truncated or duplicate-key payload")
	}
}

type lastKnownGoodProjection struct {
	active   []byte
	rejected []byte
}

func exerciseLastKnownGood(t *testing.T, validator *gojsonschema.Schema, base, candidate []byte) {
	t.Helper()
	projection := lastKnownGoodProjection{}
	if !projection.apply(validator, base) {
		t.Fatal("canonical snapshot was not installed as last-known-good")
	}
	if projection.apply(validator, candidate) {
		t.Fatal("truncated or corrupt snapshot replaced last-known-good state")
	}
	if !bytes.Equal(projection.active, base) {
		t.Fatal("last-known-good state changed after rejected snapshot")
	}
	if !bytes.Equal(projection.rejected, candidate) {
		t.Fatal("rejected snapshot was not preserved byte-for-byte")
	}
}

func (projection *lastKnownGoodProjection) apply(validator *gojsonschema.Schema, raw []byte) bool {
	if _, err := decodeStrictJSON(raw); err != nil {
		projection.rejected = append([]byte(nil), raw...)
		return false
	}
	valid, err := schemaAccepts(validator, raw)
	if err != nil || !valid {
		projection.rejected = append([]byte(nil), raw...)
		return false
	}
	projection.active = append([]byte(nil), raw...)
	projection.rejected = nil
	return true
}

func truncateJSON(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	return append([]byte(nil), trimmed[:len(trimmed)-1]...)
}

func duplicateRootKey(raw []byte, key, value string) []byte {
	trimmed := bytes.TrimSpace(raw)
	keyJSON, _ := json.Marshal(key)
	valueJSON, _ := json.Marshal(value)
	result := append([]byte(nil), trimmed[:len(trimmed)-1]...)
	result = append(result, ',')
	result = append(result, keyJSON...)
	result = append(result, ':')
	result = append(result, valueJSON...)
	result = append(result, '}')
	return result
}

func mixedVersion(raw []byte) []byte {
	return bytes.Replace(raw, []byte(`"`+previewTunnelSchemaV1+`"`), []byte(`"paperboat.preview-tunnel/v2"`), 1)
}

func corruptJSON(t *testing.T, family string, raw []byte) []byte {
	t.Helper()
	root := decodeObject(t, raw)
	switch family {
	case "resources":
		root["routes"] = map[string]any{"corrupt": true}
	case "dispatch":
		root["target"] = []any{"corrupt"}
	case "attachment", "private_access":
		root["admissions"] = map[string]any{"corrupt": true}
	default:
		t.Fatalf("unsupported corrupt family %q", family)
	}
	return marshalObject(t, root)
}

func overLimitJSON(t *testing.T, family, operation string, raw []byte) []byte {
	t.Helper()
	root := decodeObject(t, raw)
	switch operation {
	case "over_limit_domains":
		domains := decodeArray(t, root["domains"])
		if len(domains) == 0 {
			t.Fatal("preview fixture has no domain template")
		}
		for len(domains) <= 8 {
			domains = append(domains, cloneJSONValue(t, domains[0]))
		}
		root["domains"] = domains
	case "over_limit_metadata":
		metadata := make(map[string]any, 65)
		for index := 0; index < 65; index++ {
			metadata[fmt.Sprintf("field_%02d", index)] = index
		}
		root["safe_metadata"] = metadata
	case "over_limit_target":
		target := objectValue(t, root["target"])
		target["address"] = strings.Repeat("a", 513)
		root["target"] = target
	case "over_limit_aliases":
		aliases := decodeArray(t, root["aliases"])
		if len(aliases) == 0 {
			t.Fatal("attachment fixture has no alias template")
		}
		template := objectValue(t, aliases[0])
		for len(aliases) <= 64 {
			alias := cloneJSONMap(t, template)
			index := len(aliases)
			alias["domain_id"] = fmt.Sprintf("domain_chaos_%02d", index)
			alias["hostname"] = fmt.Sprintf("chaos-%02d.example.com", index)
			aliases = append(aliases, alias)
		}
		root["aliases"] = aliases
	case "over_limit_admissions":
		admissions := decodeArray(t, root["admissions"])
		if len(admissions) == 0 {
			t.Fatal("private access fixture has no admission template")
		}
		template := cloneJSONValue(t, admissions[0])
		for len(admissions) <= 4096 {
			admissions = append(admissions, cloneJSONValue(t, template))
		}
		root["admissions"] = admissions
	default:
		t.Fatalf("unsupported over-limit operation %q for %s", operation, family)
	}
	return marshalObject(t, root)
}

func secretJSON(t *testing.T, family, fixtureCase string, raw []byte) []byte {
	t.Helper()
	root := decodeObject(t, raw)
	if family == "resources" && fixtureCase == "log-entry-resumable-redacted" {
		metadata := objectValue(t, root["metadata"])
		metadata["authorization"] = "Bearer chaos-secret"
		root["metadata"] = metadata
	} else {
		root["authorization"] = "Bearer chaos-secret"
	}
	return marshalObject(t, root)
}

type generationRecord struct {
	generation  int64
	fingerprint [32]byte
}

type generationLedger struct {
	entries  map[string]generationRecord
	accepted int
}

func exerciseGenerationLedger(t *testing.T, validator *gojsonschema.Schema, family string, base []byte) {
	t.Helper()
	key, generation, err := generationIdentity(family, base)
	if err != nil {
		t.Fatalf("generation identity: %v", err)
	}
	ledger := generationLedger{entries: make(map[string]generationRecord)}
	if got := ledger.apply(key, generation, base); got != "accepted" {
		t.Fatalf("initial generation result = %q, want accepted", got)
	}
	if got := ledger.apply(key, generation, base); got != "replay" {
		t.Fatalf("exact replay result = %q, want replay", got)
	}

	stale := mutateGeneration(t, family, base, -1)
	assertSchemaAccepts(t, validator, stale)
	staleKey, staleGeneration, err := generationIdentity(family, stale)
	if err != nil {
		t.Fatalf("stale generation identity: %v", err)
	}
	if staleKey != key || staleGeneration >= generation {
		t.Fatalf("stale mutation = key %q generation %d, want key %q below %d", staleKey, staleGeneration, key, generation)
	}
	if got := ledger.apply(staleKey, staleGeneration, stale); got != "stale" {
		t.Fatalf("stale generation result = %q, want stale", got)
	}

	newer := mutateGeneration(t, family, base, 1)
	assertSchemaAccepts(t, validator, newer)
	newerKey, newerGeneration, err := generationIdentity(family, newer)
	if err != nil {
		t.Fatalf("new generation identity: %v", err)
	}
	if newerKey != key || newerGeneration <= generation {
		t.Fatalf("new mutation = key %q generation %d, want key %q above %d", newerKey, newerGeneration, key, generation)
	}
	if got := ledger.apply(newerKey, newerGeneration, newer); got != "accepted" {
		t.Fatalf("new generation result = %q, want accepted", got)
	}
	if got := ledger.apply(newerKey, newerGeneration, newer); got != "replay" {
		t.Fatalf("new generation replay result = %q, want replay", got)
	}

	conflict := mutateSameGeneration(t, family, newer)
	assertSchemaAccepts(t, validator, conflict)
	conflictKey, conflictGeneration, err := generationIdentity(family, conflict)
	if err != nil {
		t.Fatalf("conflict generation identity: %v", err)
	}
	if conflictKey != key || conflictGeneration != newerGeneration {
		t.Fatalf("same-generation mutation = key %q generation %d, want key %q generation %d", conflictKey, conflictGeneration, key, newerGeneration)
	}
	if got := ledger.apply(conflictKey, conflictGeneration, conflict); got != "conflict" {
		t.Fatalf("same-generation mutation result = %q, want conflict", got)
	}
	if ledger.accepted != 2 {
		t.Fatalf("accepted generation count = %d, want 2; replay/stale/conflict mutated state", ledger.accepted)
	}
	entry := ledger.entries[key]
	if entry.generation != newerGeneration {
		t.Fatalf("ledger generation = %d, want newest %d", entry.generation, newerGeneration)
	}
}

func (ledger *generationLedger) apply(key string, generation int64, payload []byte) string {
	fingerprint := sha256.Sum256(payload)
	previous, exists := ledger.entries[key]
	if !exists {
		ledger.entries[key] = generationRecord{generation: generation, fingerprint: fingerprint}
		ledger.accepted++
		return "accepted"
	}
	if generation < previous.generation {
		return "stale"
	}
	if generation == previous.generation {
		if fingerprint == previous.fingerprint {
			return "replay"
		}
		return "conflict"
	}
	ledger.entries[key] = generationRecord{generation: generation, fingerprint: fingerprint}
	ledger.accepted++
	return "accepted"
}

func generationIdentity(family string, raw []byte) (string, int64, error) {
	root, err := decodeObjectValue(raw)
	if err != nil {
		return "", 0, err
	}
	var key string
	var value any
	switch family {
	case "resources":
		key, err = stringField(root, "id")
		value = root["generation"]
	case "dispatch":
		previewID, previewErr := stringField(root, "preview_id")
		operationID, operationErr := stringField(root, "operation_id")
		if previewErr != nil || operationErr != nil {
			return "", 0, errors.Join(previewErr, operationErr)
		}
		key = previewID + ":" + operationID
		value = root["generation"]
	case "attachment":
		binding, bindingErr := objectField(root, "binding")
		if bindingErr == nil {
			previewID, previewErr := stringField(binding, "preview_id")
			if previewErr != nil {
				return "", 0, previewErr
			}
			key = previewID
		} else {
			return "", 0, bindingErr
		}
		value = root["attachment_generation"]
	case "private_access":
		admissions, admissionsErr := arrayField(root, "admissions")
		if admissionsErr != nil || len(admissions) == 0 {
			if admissionsErr != nil {
				return "", 0, admissionsErr
			}
			return "", 0, errors.New("private access snapshot has no admissions")
		}
		admission, admissionErr := asObject(admissions[0])
		if admissionErr != nil {
			return "", 0, admissionErr
		}
		key, err = stringField(admission, "assignment_id")
		value = admission["assignment_generation"]
	default:
		return "", 0, fmt.Errorf("unsupported generation family %q", family)
	}
	if err != nil {
		return "", 0, err
	}
	generation, err := integerValue(value)
	if err != nil {
		return "", 0, fmt.Errorf("%s generation: %w", family, err)
	}
	return key, generation, nil
}

func mutateGeneration(t *testing.T, family string, raw []byte, delta int64) []byte {
	t.Helper()
	root := decodeObject(t, raw)
	switch family {
	case "resources", "dispatch":
		generation, err := integerValue(root["generation"])
		if err != nil {
			t.Fatal(err)
		}
		updatedGeneration := generation + delta
		root["generation"] = json.Number(strconv.FormatInt(updatedGeneration, 10))
		if family == "resources" {
			id, err := stringField(root, "id")
			if err != nil {
				t.Fatal(err)
			}
			root["etag"] = fmt.Sprintf("\"%s:%d\"", id, updatedGeneration)
		}
	case "attachment":
		generation, err := integerValue(root["attachment_generation"])
		if err != nil {
			t.Fatal(err)
		}
		root["attachment_generation"] = json.Number(strconv.FormatInt(generation+delta, 10))
	case "private_access":
		admissions := decodeArray(t, root["admissions"])
		admission := objectValue(t, admissions[0])
		generation, err := integerValue(admission["assignment_generation"])
		if err != nil {
			t.Fatal(err)
		}
		admission["assignment_generation"] = json.Number(strconv.FormatInt(generation+delta, 10))
		admissions[0] = admission
		root["admissions"] = admissions
	default:
		t.Fatalf("unsupported generation family %q", family)
	}
	return marshalObject(t, root)
}

func mutateSameGeneration(t *testing.T, family string, raw []byte) []byte {
	t.Helper()
	root := decodeObject(t, raw)
	switch family {
	case "resources":
		root["summary_code"] = "chaos_replay_conflict"
	case "dispatch":
		state, err := stringField(root, "state")
		if err != nil {
			t.Fatal(err)
		}
		if state == "ready" {
			root["state"] = "failed"
		} else {
			root["state"] = "ready"
		}
	case "attachment":
		root["observed_at"] = "2026-08-30T12:03:00Z"
	case "private_access":
		admissions := decodeArray(t, root["admissions"])
		admission := objectValue(t, admissions[0])
		admission["hostname"] = "replay-conflict.example.test"
		admissions[0] = admission
		root["admissions"] = admissions
	default:
		t.Fatalf("unsupported same-generation family %q", family)
	}
	return marshalObject(t, root)
}

func decodeStrictJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeStrictValue(decoder)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, errors.New("trailing JSON value")
		}
		return nil, err
	} else if token != nil {
		return nil, errors.New("trailing JSON token")
	}
	return value, nil
}

func decodeStrictValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("object member name is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return nil, fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			value, err := decodeStrictValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if end != json.Delim('}') {
			return nil, errors.New("object did not terminate")
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := decodeStrictValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if end != json.Delim(']') {
			return nil, errors.New("array did not terminate")
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func decodeObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	value, err := decodeObjectValue(raw)
	if err != nil {
		t.Fatalf("decode object: %v", err)
	}
	return value
}

func objectValue(t *testing.T, value any) map[string]any {
	t.Helper()
	object, err := asObject(value)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func decodeObjectValue(raw []byte) (map[string]any, error) {
	value, err := decodeStrictJSON(raw)
	if err != nil {
		return nil, err
	}
	return asObject(value)
}

func asObject(value any) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected object, got %T", value)
	}
	return object, nil
}

func decodeArray(t *testing.T, value any) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("expected array, got %T", value)
	}
	return array
}

func objectField(object map[string]any, field string) (map[string]any, error) {
	value, ok := object[field]
	if !ok {
		return nil, fmt.Errorf("missing object field %q", field)
	}
	return asObject(value)
}

func arrayField(object map[string]any, field string) ([]any, error) {
	value, ok := object[field]
	if !ok {
		return nil, fmt.Errorf("missing array field %q", field)
	}
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("field %q is %T, not array", field, value)
	}
	return array, nil
}

func stringField(object map[string]any, field string) (string, error) {
	value, ok := object[field]
	if !ok {
		return "", fmt.Errorf("missing string field %q", field)
	}
	stringValue, ok := value.(string)
	if !ok || stringValue == "" {
		return "", fmt.Errorf("field %q is %T, not non-empty string", field, value)
	}
	return stringValue, nil
}

func integerValue(value any) (int64, error) {
	switch number := value.(type) {
	case json.Number:
		return number.Int64()
	case float64:
		integer := int64(number)
		if float64(integer) != number {
			return 0, fmt.Errorf("%v is not an integer", number)
		}
		return integer, nil
	case int:
		return int64(number), nil
	default:
		return 0, fmt.Errorf("%T is not an integer", value)
	}
}

func cloneJSONValue(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("clone JSON value: %v", err)
	}
	cloned, err := decodeStrictJSON(data)
	if err != nil {
		t.Fatalf("decode cloned JSON value: %v", err)
	}
	return cloned
}

func cloneJSONMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	cloned, err := asObject(cloneJSONValue(t, value))
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}

func marshalObject(t *testing.T, object map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal JSON object: %v", err)
	}
	return data
}

var secretKeyPattern = regexp.MustCompile(`(?i)(^|[_-])(token|secret|private[_-]?key|authorization|password|cookie)($|[_-])`)

func findForbiddenKey(value any, path string) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := path + "." + key
			if secretKeyPattern.MatchString(key) {
				return childPath, true
			}
			if foundPath, found := findForbiddenKey(child, childPath); found {
				return foundPath, true
			}
		}
	case []any:
		for index, child := range typed {
			if foundPath, found := findForbiddenKey(child, fmt.Sprintf("%s[%d]", path, index)); found {
				return foundPath, true
			}
		}
	}
	return "", false
}
