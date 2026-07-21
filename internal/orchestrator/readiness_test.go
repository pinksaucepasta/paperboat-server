package orchestrator

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPReadinessVerifierRequiresHostedCapabilities(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"ready", `{"live":true,"version":"test","capabilities":{"hosted_lifecycle":{"state":"ready"},"edge":{"state":"ready"},"control_plane":{"state":"ready"}},"checked_at":"2026-07-21T01:40:50Z"}`, true},
		{"not live", `{"live":false,"capabilities":{"hosted_lifecycle":{"state":"ready"},"edge":{"state":"ready"},"control_plane":{"state":"ready"}}}`, false},
		{"missing edge", `{"live":true,"capabilities":{"hosted_lifecycle":{"state":"ready"},"control_plane":{"state":"ready"}}}`, false},
		{"degraded", `{"live":true,"capabilities":{"hosted_lifecycle":{"state":"ready"},"edge":{"state":"degraded"},"control_plane":{"state":"ready"}}}`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			verify := NewHTTPReadinessVerifier(server.Client(), func(string) string { return server.URL })
			err := verify(context.Background(), "project_test")
			if (err == nil) != test.want {
				t.Fatalf("verify error=%v, want success=%v", err, test.want)
			}
		})
	}
}

func TestHTTPReadinessVerifierRejectsTrailingJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"live":true,"capabilities":{"hosted_lifecycle":{"state":"ready"},"edge":{"state":"ready"},"control_plane":{"state":"ready"}}} {}`))
	}))
	defer server.Close()
	verify := NewHTTPReadinessVerifier(server.Client(), func(string) string { return server.URL })
	if err := verify(context.Background(), "project_test"); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("error=%v, want trailing JSON rejection", err)
	}
}

func TestHTTPReadinessVerifierUsesPrivateTransportAndRouteHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "pb-project.hosted.example.invalid" || r.URL.Path != "/healthz" {
			t.Fatalf("request host=%q path=%q", r.Host, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"live":true,"capabilities":{"hosted_lifecycle":{"state":"ready"},"edge":{"state":"ready"},"control_plane":{"state":"ready"}}}`)
	}))
	defer server.Close()
	verify := NewHTTPReadinessVerifierWithHost(server.Client(), func(string) string { return server.URL + "/healthz" }, func(string) string { return "pb-project.hosted.example.invalid" })
	if err := verify(context.Background(), "project"); err != nil {
		t.Fatal(err)
	}
}
