package previewtunnelapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/xeipuuv/gojsonschema"
)

func TestAuthorizeUsesEverySecurityDimension(t *testing.T) {
	base := Actor{AccountID: "acct_1", ActorID: "actor_1", DeviceID: "dev_1", HostID: "host_1", Role: "user", Scopes: []string{"tunnels:write"}}
	request := AccessRequest{AccountID: "acct_1", Resource: "tunnels", Action: "write", RequireHost: true}
	if err := Authorize(base, request); err != nil {
		t.Fatalf("authorize valid host actor: %v", err)
	}
	tests := []struct {
		name  string
		actor Actor
		err   error
	}{
		{"account", Actor{AccountID: "acct_2", ActorID: "actor_1", DeviceID: "dev_1", HostID: "host_1", Role: "user", Scopes: []string{"tunnels:write"}}, ErrForbidden},
		{"actor", Actor{AccountID: "acct_1", DeviceID: "dev_1", HostID: "host_1", Role: "user", Scopes: []string{"tunnels:write"}}, ErrForbidden},
		{"device", Actor{AccountID: "acct_1", ActorID: "actor_1", HostID: "host_1", Role: "user", Scopes: []string{"tunnels:write"}}, ErrHostActorRequired},
		{"host", Actor{AccountID: "acct_1", ActorID: "actor_1", DeviceID: "dev_1", Role: "user", Scopes: []string{"tunnels:write"}}, ErrHostActorRequired},
		{"scope", Actor{AccountID: "acct_1", ActorID: "actor_1", DeviceID: "dev_1", HostID: "host_1", Role: "user", Scopes: []string{"tunnels:read"}}, ErrForbidden},
		{"role", Actor{AccountID: "acct_1", ActorID: "actor_1", DeviceID: "dev_1", HostID: "host_1", Role: "support", Scopes: []string{"tunnels:write"}}, ErrForbidden},
		{"unknown role", Actor{AccountID: "acct_1", ActorID: "actor_1", DeviceID: "dev_1", HostID: "host_1", Role: "", Scopes: []string{"tunnels:write"}}, ErrForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Authorize(test.actor, request); !errors.Is(err, test.err) {
				t.Fatalf("Authorize error = %v, want %v", err, test.err)
			}
		})
	}
}

func TestResourceScopeKeepsNestedTunnelResourcesUnderTunnelScopes(t *testing.T) {
	for _, kind := range []string{"tunnel", "route", "domain_binding", "connector", "config_generation"} {
		if got := resourceScope(kind); got != "tunnels" {
			t.Fatalf("resourceScope(%q) = %q", kind, got)
		}
	}
	if got := resourceScope("unknown"); got != "" {
		t.Fatalf("unknown resource scope = %q", got)
	}
}

func TestWireOperationAndErrorMatchSharedSchema(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	operation := Operation{
		Schema: schemaID, Kind: "operation", ID: "op_1", ResourceKind: "tunnel", ResourceID: "tun_1",
		Phase: "ready", State: "succeeded", Progress: 100, Retrying: false,
		CorrelationID: "corr_1", CreatedAt: now, UpdatedAt: now,
	}
	apiError := APIError{
		Schema: schemaID, Kind: "error", Code: "generation_conflict", Component: "control",
		Message: "The resource changed.", Outcome: "unchanged", Retryable: false,
		RepairAction: "refresh", RequestID: "req_1", CorrelationID: "corr_1",
	}
	schema := gojsonschema.NewReferenceLoader("file://" + mustAbs(t, "../../testdata/contracts/preview-tunnel-v1/schemas/resources.schema.json"))
	for _, value := range []any{operation, apiError} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		result, err := gojsonschema.Validate(schema, gojsonschema.NewBytesLoader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if !result.Valid() {
			t.Fatalf("wire value does not match shared schema: %s: %#v", raw, result.Errors())
		}
	}
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestOperationViewProjectsInternalStatesToContract(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	row := dbsqlc.Operation{
		ID: "op_1", ResourceKind: "tunnel", ResourceID: sql.NullString{String: "tun_1", Valid: true},
		Phase: "connecting", State: "uncertain", Progress: 70, Outcome: "uncertain",
		CorrelationID: "corr_1", CreatedAt: now, UpdatedAt: now,
	}
	view := operationView(row, "req_1")
	if view.State != "failed" || view.Error == nil || view.Error.Code != "operation_outcome_uncertain" || view.Error.Outcome != "uncertain" {
		t.Fatalf("uncertain view = %#v", view)
	}
	row.State = "cancelled"
	row.Outcome = "unchanged"
	row.ErrorCode = sql.NullString{String: "cancelled_by_actor", Valid: true}
	view = operationView(row, "req_1")
	if view.State != "canceled" {
		t.Fatalf("cancelled view state = %q", view.State)
	}
}

func TestIdempotencyHashAndETag(t *testing.T) {
	header := make(http.Header)
	header.Set(IdempotencyHeader, "create-123")
	if got, err := ParseIdempotencyKey(header); err != nil || got != "create-123" {
		t.Fatalf("ParseIdempotencyKey = %q, %v", got, err)
	}
	hashA, err := RequestHash([]byte(`{"name":"demo","enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := RequestHash([]byte(`{ "enabled": true, "name": "demo" }`))
	if err != nil || hashA != hashB {
		t.Fatalf("semantic hashes differ: %x %x, %v", hashA, hashB, err)
	}
	if _, err := RequestHash([]byte(`{"name":"a","name":"b"}`)); err == nil {
		t.Fatal("duplicate request field accepted")
	}

	header = make(http.Header)
	header.Set(IfMatchHeader, ETag("tunnel", "tun:1", 7))
	if generation, err := ParseIfMatch(header, "tunnel", "tun:1"); err != nil || generation != 7 {
		t.Fatalf("ParseIfMatch = %d, %v", generation, err)
	}
	if _, err := ParseIfMatch(header, "tunnel", "tun:2"); !errors.Is(err, ErrInvalidETag) {
		t.Fatalf("cross-resource ETag error = %v", err)
	}
}

func TestPaginationCursorIsScopedAndTamperEvident(t *testing.T) {
	codec, err := NewCursorCodec([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	position := EventPosition{AccountID: "acct_1", ResourceKind: "tunnel", ResourceID: "tun_1", Sequence: 42}
	cursor, err := codec.Encode(position)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := codec.Decode(cursor, EventPosition{AccountID: "acct_1", ResourceKind: "tunnel", ResourceID: "tun_1"}); err != nil || decoded != position {
		t.Fatalf("Decode = %#v, %v", decoded, err)
	}
	if _, err := codec.Decode(cursor, EventPosition{AccountID: "acct_2", ResourceKind: "tunnel", ResourceID: "tun_1"}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-account cursor error = %v", err)
	}
	replacement := byte('A')
	if cursor[0] == replacement {
		replacement = 'B'
	}
	tampered := string(replacement) + cursor[1:]
	if _, err := codec.Decode(tampered, position); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("tampered cursor error = %v", err)
	}
	if got, err := PageLimit(""); err != nil || got != DefaultPageLimit {
		t.Fatalf("default limit = %d, %v", got, err)
	}
	if _, err := PageLimit("201"); err == nil {
		t.Fatal("unbounded page limit accepted")
	}
}

func TestCursorCodecRejectsOversizedInput(t *testing.T) {
	codec, err := NewCursorCodec([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decode(strings.Repeat("a", maximumCursorSize+1), EventPosition{}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("oversized cursor error = %v", err)
	}
}

func TestSafeMetadataRejectsSecretsAndCopiesInput(t *testing.T) {
	input := map[string]any{
		"generation": int64(3), "attempt": uint32(2), "progress": float32(0.5),
		"credential_reference": "vault://connector/1", "nested": map[string]any{"status": "ready"},
	}
	safe, err := SafeMetadata(input)
	if err != nil {
		t.Fatal(err)
	}
	input["generation"] = int64(4)
	if safe["generation"] != int64(3) {
		t.Fatal("safe metadata aliases caller input")
	}
	for _, unsafe := range []map[string]any{
		{"authorization": "Bearer abc"},
		{"nested": map[string]any{"private_key": "value"}},
		{"note": "Bearer abc"},
		{"note": "origin failed: https://user:password@example.test/path"},
		{"note": "retry https://example.test/path?access_token=secret"},
		{"note": "request failed authorization=secret"},
		{"request-body": "payload"},
	} {
		if _, err := SafeMetadata(unsafe); !errors.Is(err, ErrUnsafeMetadata) {
			t.Fatalf("unsafe metadata error = %v", err)
		}
	}
	if _, err := SafeMetadata(map[string]any{"note": "origin failed: https://example.test/path?attempt=2"}); err != nil {
		t.Fatalf("safe embedded URL rejected: %v", err)
	}
}
