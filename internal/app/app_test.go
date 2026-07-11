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

func TestNormalizePapercodeIssuer(t *testing.T) {
	if got := normalizePapercodeIssuer("  https://paperboat.example///  "); got != "https://paperboat.example" {
		t.Fatalf("normalized issuer = %q", got)
	}
}
