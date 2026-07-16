package connectedmachines

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPairingJSONUsesConnectorFieldNames(t *testing.T) {
	encoded, err := json.Marshal(Pairing{ID: "cmp_1", UserCode: "ABCD1234", ExpiresAt: time.Unix(0, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	value := string(encoded)
	for _, field := range []string{"\"user_code\"", "\"expires_at\""} {
		if !strings.Contains(value, field) {
			t.Fatalf("pairing response missing %s: %s", field, value)
		}
	}
}

func TestMachineJSONUsesDashboardFieldNames(t *testing.T) {
	encoded, err := json.Marshal(Machine{ID: "cm_1", EnvironmentID: "env_1", DisplayName: "Test Mac", SeatState: "occupied", RuntimeVersions: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	value := string(encoded)
	for _, field := range []string{"\"id\"", "\"environment_id\"", "\"display_name\"", "\"seat_state\"", "\"runtime_versions\""} {
		if !strings.Contains(value, field) {
			t.Fatalf("machine response missing %s: %s", field, value)
		}
	}
}
