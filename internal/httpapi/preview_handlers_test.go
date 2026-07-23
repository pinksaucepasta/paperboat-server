package httpapi

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestHelperPreviewObservationDecodesCanonicalHelperPayload(t *testing.T) {
	body := []byte(`{"identity":"p-abcdefghijklmnopqrstuvwxyz","environment_id":"env_1","logical_name":"web","target":{"host":"127.0.0.1","port":3000},"state":"degraded","reason":"target_unhealthy","updated_at":"2026-07-22T11:30:00Z","revision":4}`)
	var input helperPreviewObservationInput
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		t.Fatalf("canonical helper observation rejected: input=%#v err=%v", input, err)
	}
	if input.LogicalName != "web" || input.Target.Host != "127.0.0.1" || input.Target.Port != 3000 || input.Reason != "target_unhealthy" {
		t.Fatalf("canonical helper observation changed: %#v", input)
	}
	unknown := append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"unexpected":true}`)...)
	decoder = json.NewDecoder(bytes.NewReader(unknown))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err == nil {
		t.Fatal("unknown observation field accepted")
	}
}

func TestPreviewObservationReadinessAcceptsTerminalStates(t *testing.T) {
	for _, state := range []string{"offline", "expired", "removed"} {
		helperReady, targetReady, valid := previewObservationReadiness(state)
		if helperReady || targetReady || !valid {
			t.Fatalf("state %q readiness = (%v, %v, %v)", state, helperReady, targetReady, valid)
		}
	}
}

func TestPreviewCredentialRejectsUnknownRequestFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/previews/credentials", bytes.NewBufferString(`{"unexpected":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	helperPreviewCredential(nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestOwnedPreviewResponseIncludesAccountContext(t *testing.T) {
	response := newOwnedPreviewResponse(controlplane.OwnedPreview{
		Preview:         dbsqlc.ControlPreview{ID: "prv_1", EnvironmentID: "env_1", PublicHost: "preview.example.test"},
		ProjectID:       "prj_1",
		MachineID:       sql.NullString{String: "cm_1", Valid: true},
		UserID:          sql.NullString{String: "usr_1", Valid: true},
		EnvironmentName: "workstation",
		EnvironmentKind: "byod",
		OwnerEmail:      "owner@example.test",
	})

	if response.ProjectID != "prj_1" || response.MachineID != "cm_1" || response.UserID != "usr_1" || response.EnvironmentName != "workstation" || response.EnvironmentKind != "byod" || response.OwnerEmail != "owner@example.test" {
		t.Fatalf("account context missing from preview response: %#v", response)
	}
}
