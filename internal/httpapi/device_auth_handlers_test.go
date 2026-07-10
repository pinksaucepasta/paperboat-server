package httpapi

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
)

func TestDecodeStrictJSONRejectsTrailingContent(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{name: "single object", body: `{"value":"ok"}`, want: true},
		{name: "trailing whitespace", body: "{\"value\":\"ok\"} \n\t", want: true},
		{name: "malformed trailing bytes", body: `{"value":"ok"} garbage`, want: false},
		{name: "second object", body: `{"value":"ok"} {"value":"extra"}`, want: false},
		{name: "second scalar", body: `{"value":"ok"} true`, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/auth/device/authorize", bytes.NewBufferString(tc.body))
			var out struct {
				Value string `json:"value"`
			}
			if got := decodeStrictJSON(rec, req, &out); got != tc.want {
				t.Fatalf("decodeStrictJSON = %v, want %v; response=%s", got, tc.want, rec.Body.String())
			}
			if !tc.want && rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestWriteClientDeleteErrorClassifiesOnlyMissingSessionAsNotFound(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{name: "missing", err: sql.ErrNoRows, want: http.StatusNotFound},
		{name: "wrapped missing", err: fmt.Errorf("outer: %w", sql.ErrNoRows), want: http.StatusNotFound},
		{name: "database failure", err: errors.New("database unavailable"), want: http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, "/api/auth/clients/cls_1", nil)
			writeClientDeleteError(rec, req, tc.err)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestWriteDeviceErrorMapsUnknownApprovalCodeToNotFound(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/device/requests/NOPE-CODE", nil)
	if !writeDeviceError(rec, req, &auth.DeviceError{Code: "device_request_not_found"}) {
		t.Fatal("error was not handled")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestWriteDeviceErrorMapsUnauthenticatedToUnauthorized(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/token/revoke", nil)
	if !writeDeviceError(rec, req, auth.ErrUnauthenticated) {
		t.Fatal("error was not handled")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want=401", rec.Code)
	}
}
