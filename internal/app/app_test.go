package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	pbgithub "github.com/pinksaucepasta/paperboat-server/internal/github"
	"github.com/pinksaucepasta/paperboat-server/internal/workers"
)

func TestRunShutsDownHTTPServerBeforeReturningWorkerError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	workerErr := errors.New("worker failed")
	cfg := config.Default()
	cfg.HTTP.Address = address
	cfg.HTTP.ShutdownTimeout = time.Second
	app, err := New(Options{
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	app.worker = workers.NewSupervisor(func(context.Context) error {
		return workerErr
	})

	err = app.Run(context.Background())
	if !errors.Is(err, workerErr) {
		t.Fatalf("error = %v, want %v", err, workerErr)
	}

	client := http.Client{Timeout: 50 * time.Millisecond}
	resp, err := client.Get("http://" + address + "/healthz")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("server still accepted requests after Run returned")
	}
}

func TestNormalizeHelperIssuer(t *testing.T) {
	tests := map[string]string{
		"  https://paperboat.example///  ":              "https://paperboat.example",
		"HTTPS://PAPERBOAT.EXAMPLE:443/path/?ignored=1": "https://paperboat.example/path",
		"http://PAPERBOAT.EXAMPLE:80/":                  "http://paperboat.example",
	}
	for input, want := range tests {
		if got := normalizeHelperIssuer(input); got != want {
			t.Errorf("normalizeHelperIssuer(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestGitHubClientUsesExplicitRealCredentialsInFakeProviderDevelopment(t *testing.T) {
	cfg := config.Default()
	if _, ok := githubClient(cfg).(*pbgithub.FakeClient); !ok {
		t.Fatal("default development config did not use the fake GitHub client")
	}

	cfg.Secrets.GitHubClientID = "dev-github-app-client-id"
	cfg.Secrets.GitHubClientSecret = "dev-github-app-client-secret"
	if _, ok := githubClient(cfg).(pbgithub.HTTPClient); !ok {
		t.Fatal("explicit development GitHub credentials did not use the real GitHub client")
	}
}
