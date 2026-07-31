package httpapi

import (
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

type clientConfigurationResponse struct {
	Version            string `json:"version"`
	CLIVerificationURL string `json:"cli_verification_url"`
	MachinesURL        string `json:"machines_url"`
}

func clientConfiguration(cfg config.Config) http.HandlerFunc {
	response := clientConfigurationResponse{
		Version:            "1",
		CLIVerificationURL: cfg.CLIAuth.VerificationURL,
		MachinesURL:        cfg.CLIAuth.MachinesURL,
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
	}
}
