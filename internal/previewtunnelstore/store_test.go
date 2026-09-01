package previewtunnelstore

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestNewRequiresDatabase(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("New(nil) error = %v, want ErrInvalidInput", err)
	}
}

func TestValidateSafeJSONRejectsCredentialAndPayloadFieldsAtAnyDepth(t *testing.T) {
	for _, raw := range []string{
		`{"token":"value"}`,
		`{"nested":{"private_key":"value"}}`,
		`{"items":[{"authorization":"value"}]}`,
		`{"request_body":{"safe":false}}`,
		`{"access_token":"value"}`,
		`{"headers":{"cookie":"value"}}`,
		`{"endpoint":"https://user:password@example.test"}`,
		`{"endpoint":"https://example.test?client_secret=value"}`,
		`{"routes":[],"routes":["duplicate"]}`,
	} {
		if err := validateSafeJSON([]byte(raw)); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("validateSafeJSON(%s) error = %v, want ErrInvalidInput", raw, err)
		}
	}
	if err := validateSafeJSON([]byte(`{"credential_reference":"keychain://connector/1","routes":[]}`)); err != nil {
		t.Fatalf("safe reference rejected: %v", err)
	}
}

func TestCanonicalSafeJSONStabilizesContentHashInput(t *testing.T) {
	canonical, err := canonicalSafeJSON([]byte("{\n  \"routes\": [], \"generation\": 1\n}"))
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != `{"generation":1,"routes":[]}` {
		t.Fatalf("canonical JSON = %s", canonical)
	}
}

func TestActivateConfigGenerationRejectsHashMismatchBeforeDatabaseUse(t *testing.T) {
	store := &Store{}
	_, err := store.ActivateConfigGeneration(t.Context(), dbsqlc.CreatePreviewTunnelConfigGenerationParams{
		ContentHash: make([]byte, sha256.Size), Snapshot: []byte(`{"generation":1}`),
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
}
