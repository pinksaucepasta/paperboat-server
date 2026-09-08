package httpapi

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/environment"
)

func TestVaultProjectionObservationStrictShape(t *testing.T) {
	observation := environment.VaultProjectionObservation{Schema: environment.VaultProjectionObservationSchema, ObservationSeq: 1, HostRecipientKeyID: "envk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", State: "pending", ObservedAt: time.Now().UTC()}
	raw, _ := json.Marshal(observation)
	var parsed *environment.VaultProjectionObservation
	if !validVaultProjectionObservationShape(raw, false, &parsed) {
		t.Fatal("pending bootstrap rejected")
	}
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "projection")
	raw, _ = json.Marshal(fields)
	if validVaultProjectionObservationShape(raw, false, &parsed) {
		t.Fatal("omitted exact member accepted")
	}
	fields["projection"] = nil
	fields["plaintext"] = "not allowed"
	raw, _ = json.Marshal(fields)
	if validVaultProjectionObservationShape(raw, true, &parsed) {
		t.Fatal("unknown field accepted")
	}
}
