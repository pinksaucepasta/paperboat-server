package httpapi

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBodyLimitAllowsLargeEnvironmentRotationAndRetainsDefault(t *testing.T) {
	readBody := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if !errors.As(err, &maxErr) {
				t.Errorf("body read error=%v", err)
			}
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		if len(body) == 0 {
			t.Error("handler received an empty body")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := bodyLimit(1<<20, readBody)

	tests := []struct {
		name       string
		path       string
		bodySize   int
		wantStatus int
	}{
		{
			name:       "environment_rotation_payload_uses_two_megabytes",
			path:       "/v1/environment/rotate-personal",
			bodySize:   1800 << 10,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "environment_rotation_payload_over_two_megabytes_rejected",
			path:       "/v1/environment/rotate-personal",
			bodySize:   (2 << 20) + 1,
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:       "unrelated_route_keeps_one_megabyte_default",
			path:       "/v1/unrelated",
			bodySize:   1800 << 10,
			wantStatus: http.StatusRequestEntityTooLarge,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(bytes.Repeat([]byte{'x'}, test.bodySize)))
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, request)
			if result.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d", result.Code, test.wantStatus)
			}
		})
	}
}
