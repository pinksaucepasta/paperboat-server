package previewtunnelstore

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPreviewLeaseTargetAndEndpointValidation(t *testing.T) {
	for _, address := range []string{
		"localhost", "http://localhost:3000", "user@127.0.0.1:3000", "127.0.0.1:not-a-port",
		"127.0.0.1:0", "127.0.0.1:65536", "10.0.0.1:3000", "127.0.0.1:3000/path", "127.0.0.1:3000?x=1",
	} {
		if validPreviewTargetAddress(address) {
			t.Errorf("accepted non-canonical or non-loopback target %q", address)
		}
	}
	for _, address := range []string{"127.0.0.1:3000", "[::1]:8443", "localhost:3000"} {
		if !validPreviewTargetAddress(address) {
			t.Errorf("rejected valid local target %q", address)
		}
	}
	for _, target := range []struct {
		scheme, address, access string
	}{
		{"h2c", "127.0.0.1:5000", "public"},
		{"unix", "/run/paperboat.sock", "public"},
		{"tcp", "10.0.0.4:5432", "private"},
		{"tcp", "[fd00::4]:5432", "private"},
	} {
		if !ValidPreviewTargetV1(target.scheme, target.address, target.access) {
			t.Errorf("rejected valid %s target %q (%s)", target.scheme, target.address, target.access)
		}
	}
	for _, target := range []struct {
		scheme, address, access string
	}{
		{"unix", "relative.sock", "public"},
		{"unix", "/run/../paperboat.sock", "public"},
		{"tcp", "10.0.0.4:5432", "public"},
		{"tcp", "192.0.2.4:5432", "private"},
		{"tcp", "example.test:5432", "private"},
	} {
		if ValidPreviewTargetV1(target.scheme, target.address, target.access) {
			t.Errorf("accepted invalid %s target %q (%s)", target.scheme, target.address, target.access)
		}
	}
	for _, endpoint := range []string{
		"https://abc.preview.example.test",
		"https://7abc.preview.example.test",
	} {
		if !validPreviewEndpoint(endpoint) {
			t.Errorf("rejected valid endpoint %q", endpoint)
		}
	}
	for _, endpoint := range []string{
		"https://preview-abc.preview.example.test",
		"https://abc.preview.example.test:443",
		"https://abc.preview.example.test/path",
		"https://user:pass@abc.preview.example.test",
		"https://abc_preview.preview.example.test",
	} {
		if validPreviewEndpoint(endpoint) {
			t.Errorf("accepted invalid or vanity endpoint %q", endpoint)
		}
	}
}

func TestValidatePreviewLeaseRequiresAuditRequestIdentity(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	input := CreatePreviewLeaseV1Input{
		OperationID: "op_1", LeaseID: "prv_1", AuditEventID: "aud_1", AccountID: "acct_1", ActorID: "user_1", ActorType: "user",
		OwnerDeviceID: "device_1", OwnerSessionID: "session_1", TargetScheme: "http", TargetAddress: "127.0.0.1:3000",
		AccessMode: "public", EndpointID: "pep_1", Endpoint: "https://abc.preview.example.test", LeaseDeadline: now.Add(time.Hour),
		RequestHash: []byte(strings.Repeat("a", 32)), IdempotencyKey: "create_1", CorrelationID: "cor_1", Now: now,
	}
	if err := validateCreatePreviewLeaseV1(input); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing request ID error = %v, want ErrInvalidInput", err)
	}
	input.RequestID = "req_1"
	if err := validateCreatePreviewLeaseV1(input); err != nil {
		t.Fatalf("valid lease input rejected: %v", err)
	}
	if input.UserDeadline != (sql.NullTime{}) {
		t.Fatal("unexpected user deadline in validation fixture")
	}
}

func TestTranslatePreviewLeaseCreateErrorUsesEndpointConstraint(t *testing.T) {
	endpointError := &pgconn.PgError{Code: "23505", ConstraintName: "preview_leases_endpoint_key"}
	if err := translatePreviewLeaseCreateError(endpointError); !errors.Is(err, ErrEndpointConflict) {
		t.Fatalf("endpoint constraint error = %v, want ErrEndpointConflict", err)
	}

	for _, err := range []error{
		&pgconn.PgError{Code: "23505", ConstraintName: "preview_leases_endpoint_id_key"},
		&pgconn.PgError{Code: "23505", ConstraintName: "other_table_endpoint_key"},
		errors.New("duplicate key value violates unique constraint preview_leases_endpoint_key"),
	} {
		if translated := translatePreviewLeaseCreateError(err); errors.Is(translated, ErrEndpointConflict) {
			t.Fatalf("unrelated error classified as endpoint conflict: %v", translated)
		}
	}
}
