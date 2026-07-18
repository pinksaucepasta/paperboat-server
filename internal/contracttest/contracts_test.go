package contracttest

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/contracts/" + path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, target); err != nil {
		t.Fatal(err)
	}
}

func TestHelperProfilesDoNotGrantHostedLifecycleToBYOD(t *testing.T) {
	var profiles struct {
		Profiles map[string]struct {
			Required    []string          `json:"required"`
			Allowed     []string          `json:"allowed"`
			Forbidden   []string          `json:"forbidden"`
			Conditional map[string]string `json:"conditional"`
		} `json:"profiles"`
	}
	readJSON(t, "helper/profiles.json", &profiles)
	byod := profiles.Profiles["byod"]
	if !contains(byod.Required, "terminal.v1") || !contains(byod.Forbidden, "hosted.lifecycle.v1") {
		t.Fatalf("unsafe BYOD profile: %#v", byod)
	}
	if byod.Conditional["config.apply.v1"] == "" {
		t.Fatal("BYOD config application requires an explicit condition")
	}
}

func TestSessionAndPreviewControlStates(t *testing.T) {
	var session struct {
		States map[string]struct {
			Allow []string `json:"allow"`
		} `json:"states"`
	}
	readJSON(t, "states/session.json", &session)
	if contains(session.States["running"].Allow, "deleted") || !contains(session.States["closed"].Allow, "deleted") {
		t.Fatal("running sessions must close before control-plane deletion")
	}
	var preview struct {
		Initial string         `json:"initial"`
		HTTP    map[string]int `json:"http"`
	}
	readJSON(t, "states/preview.json", &preview)
	if preview.Initial != "registering" || preview.HTTP["ready"] != 200 || preview.HTTP["expired"] != 410 || preview.HTTP["removed"] != 404 {
		t.Fatalf("unexpected preview contract: %#v", preview)
	}
}

func TestCredentialClassesAreNonInterchangeable(t *testing.T) {
	var matrix struct {
		Classes []struct {
			ID       string   `json:"id"`
			Audience string   `json:"audience"`
			Scopes   []string `json:"scopes"`
		} `json:"classes"`
	}
	readJSON(t, "credentials/classes.json", &matrix)
	seenID, seenAuthority := map[string]bool{}, map[string]string{}
	for _, class := range matrix.Classes {
		if seenID[class.ID] || class.Audience == "" || len(class.Scopes) == 0 {
			t.Fatalf("invalid credential class: %#v", class)
		}
		seenID[class.ID] = true
		for _, scope := range class.Scopes {
			key := class.Audience + "\x00" + scope
			if previous, duplicate := seenAuthority[key]; duplicate {
				t.Fatalf("credential authority %q shared by %s and %s", key, previous, class.ID)
			}
			seenAuthority[key] = class.ID
		}
	}
	for _, required := range []string{"cli_session", "helper_enrollment", "helper_identity", "connector_admission", "terminal_operation", "image_stage", "preview_registration", "activity_report", "config_sync", "signed_update", "edge_control", "usage_report"} {
		if !seenID[required] {
			t.Errorf("missing credential class %q", required)
		}
	}
}

func TestCredentialSigningVector(t *testing.T) {
	var vector struct {
		Key struct {
			Public string `json:"public_base64url"`
		} `json:"key"`
		Token string `json:"token"`
	}
	readJSON(t, "fixtures/credentials/terminal-operation.ed25519.json", &vector)
	parts := strings.Split(vector.Token, ".")
	if len(parts) != 3 {
		t.Fatal("credential vector is not compact JWS")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(vector.Key.Public)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("credential signing vector does not verify")
	}
}

func TestEdgeUsageVectorsAreMonotonicAndReplaySafe(t *testing.T) {
	f, err := os.Open("../../testdata/contracts/fixtures/edge/control.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seenUsage, seenRejected := 0, 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var vector struct {
			Valid         bool   `json:"valid"`
			Kind          string `json:"kind"`
			Error         string `json:"error"`
			Mutated       bool   `json:"mutated"`
			PreviousBytes uint64 `json:"previous_bytes"`
			Delta         uint64 `json:"delta"`
			Input         struct {
				Bytes uint64 `json:"bytes"`
			} `json:"input"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			t.Fatal(err)
		}
		if !vector.Valid {
			seenRejected++
			if vector.Error == "" || vector.Mutated {
				t.Fatal("edge rejection must be typed and pre-mutation")
			}
		}
		if vector.Kind == "usage" {
			seenUsage++
			want := uint64(0)
			if vector.Input.Bytes > vector.PreviousBytes {
				want = vector.Input.Bytes - vector.PreviousBytes
			}
			if vector.Delta != want {
				t.Fatalf("usage delta=%d, want %d", vector.Delta, want)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if seenUsage < 4 || seenRejected < 3 {
		t.Fatalf("insufficient edge coverage: usage=%d rejected=%d", seenUsage, seenRejected)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
