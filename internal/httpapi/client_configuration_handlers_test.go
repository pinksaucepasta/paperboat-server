package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

func TestClientConfigurationPublishesDashboardURLs(t *testing.T) {
	cfg := config.Default()
	cfg.CLIAuth.VerificationURL = "https://dashboard.paperboat.test/cli/authorize"
	cfg.CLIAuth.MachinesURL = "https://console.paperboat.test/machines/add"
	request := httptest.NewRequest(http.MethodGet, "/v1/client-configuration", nil)
	recorder := httptest.NewRecorder()

	clientConfiguration(cfg).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data clientConfigurationResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Version != "1" {
		t.Fatalf("version=%q", response.Data.Version)
	}
	if response.Data.CLIVerificationURL != cfg.CLIAuth.VerificationURL {
		t.Fatalf("cli_verification_url=%q", response.Data.CLIVerificationURL)
	}
	if response.Data.MachinesURL != cfg.CLIAuth.MachinesURL {
		t.Fatalf("machines_url=%q", response.Data.MachinesURL)
	}
}
