package contracttest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
	"github.com/xeipuuv/gojsonschema"
)

func TestPreviewDispatchV1SchemaVectors(t *testing.T) {
	familyRoot := os.Getenv("PAPERBOAT_PREVIEW_TUNNEL_CONTRACT_ROOT")
	if familyRoot == "" {
		familyRoot = filepath.Join("..", "..", "testdata", "contracts", "preview-tunnel-v1")
	}
	schemaBytes, err := os.ReadFile(filepath.Join(familyRoot, "schemas", "dispatch.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(schemaBytes))
	if err != nil {
		t.Fatal(err)
	}

	fixtures, err := os.Open(filepath.Join(familyRoot, "fixtures", "dispatch.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer fixtures.Close()

	seenValid, seenInvalid := 0, 0
	scanner := bufio.NewScanner(fixtures)
	for scanner.Scan() {
		var vector struct {
			Case                string          `json:"case"`
			Valid               bool            `json:"valid"`
			ExpectedError       string          `json:"expected_error"`
			ExpectedRequestHash string          `json:"expected_request_hash"`
			Message             json.RawMessage `json:"message"`
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
				t.Errorf("%s: valid dispatch message rejected: %v", vector.Case, result.Errors())
				continue
			}
			var envelope struct {
				Kind string `json:"kind"`
			}
			if err := json.Unmarshal(vector.Message, &envelope); err != nil {
				t.Errorf("%s: strict decode: %v", vector.Case, err)
				continue
			}
			if envelope.Kind == previewv1.PreviewDispatchKind && vector.ExpectedRequestHash != "" {
				var request previewv1.DispatchRequest
				if err := decodeStrictDispatch(vector.Message, &request); err != nil {
					t.Errorf("%s: request decode: %v", vector.Case, err)
					continue
				}
				if request.RequestHash != vector.ExpectedRequestHash {
					t.Errorf("%s: request hash = %q, want fixture hash %q", vector.Case, request.RequestHash, vector.ExpectedRequestHash)
				}
				if err := request.Validate(time.Time{}); err != nil {
					t.Errorf("%s: canonical request validation: %v", vector.Case, err)
				}
			}
			continue
		}
		seenInvalid++
		if vector.ExpectedError == "" {
			t.Errorf("%s: negative vector has no stable expected_error", vector.Case)
		}
		if !result.Valid() {
			continue
		}
		if vector.ExpectedError != "request_hash_invalid" {
			t.Errorf("%s: invalid dispatch message accepted by schema", vector.Case)
			continue
		}
		var request previewv1.DispatchRequest
		if err := decodeStrictDispatch(vector.Message, &request); err != nil {
			t.Errorf("%s: request decode: %v", vector.Case, err)
			continue
		}
		if err := request.Validate(time.Time{}); err == nil {
			t.Errorf("%s: invalid request hash accepted by canonical validator", vector.Case)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if seenValid != 3 || seenInvalid != 3 {
		t.Fatalf("unexpected fixture coverage: valid=%d invalid=%d", seenValid, seenInvalid)
	}
}

func decodeStrictDispatch(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}
