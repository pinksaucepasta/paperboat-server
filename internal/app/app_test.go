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

	"github.com/jackc/puddle/v2"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	pbgithub "github.com/pinksaucepasta/paperboat-server/internal/github"
	"github.com/pinksaucepasta/paperboat-server/internal/telemetry"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
	"github.com/pinksaucepasta/paperboat-server/internal/workers"
)

func TestNewRejectsInjectedCertificateRuntimeWhenManagedCertificatesAreDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Certificates.Enabled = false

	application, err := New(Options{Config: cfg, CertificateRuntime: &tunnelv1.CertificateRuntime{}})
	if application != nil {
		t.Fatal("application created with a certificate runtime while managed certificates are disabled")
	}
	if !errors.Is(err, tunnelv1.ErrCertificateRuntimeUnavailable) {
		t.Fatalf("error = %v, want %v", err, tunnelv1.ErrCertificateRuntimeUnavailable)
	}
}

func TestNewAllowsInjectedCertificateRuntimeWhenManagedCertificatesAreEnabled(t *testing.T) {
	cfg := config.Default()
	cfg.Certificates.Enabled = true
	runtime := &tunnelv1.CertificateRuntime{}

	application, err := New(Options{Config: cfg, CertificateRuntime: runtime})
	if err != nil {
		t.Fatalf("New rejected an injected runtime with managed certificates enabled: %v", err)
	}
	if application == nil || application.certificateRuntime != runtime {
		t.Fatal("injected certificate runtime was not transferred to the application")
	}
	if err := application.db.Close(); err != nil {
		t.Fatalf("close application database: %v", err)
	}
}

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
	serviceHealth := app.telemetryHealth.Snapshot().Dimensions.Service
	if serviceHealth.Status != telemetry.StatusDown || serviceHealth.Code != "worker_failed" || serviceHealth.CorrelationID != "cor_server_lifecycle" {
		t.Fatalf("service health=%+v", serviceHealth)
	}
	if events := app.telemetryEvents.Snapshot(); len(events) < 2 || events[len(events)-1].Code != "worker_failed" {
		t.Fatalf("lifecycle events=%+v", events)
	}

	client := http.Client{Timeout: 50 * time.Millisecond}
	resp, err := client.Get("http://" + address + "/healthz")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("server still accepted requests after Run returned")
	}
}

func TestRunDoesNotCloseWorkerDependenciesBeforeJoin(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.HTTP.Address = address
	cfg.HTTP.ShutdownTimeout = 20 * time.Millisecond
	application, err := New(Options{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	application.worker = workers.NewSupervisor(func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		<-release
		return nil
	})

	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- application.Run(runCtx) }()
	<-started
	cancelRun()
	err = <-runDone
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run error = %v, want worker join deadline", err)
	}
	acquireCtx, cancelAcquire := context.WithTimeout(context.Background(), 10*time.Millisecond)
	connection, acquireErr := application.db.Pool().Acquire(acquireCtx)
	cancelAcquire()
	if connection != nil {
		connection.Release()
	}
	if errors.Is(acquireErr, puddle.ErrClosedPool) {
		t.Fatal("database closed before worker joined")
	}

	close(release)
	if err := application.worker.Wait(context.Background()); err != nil {
		t.Fatalf("join released worker: %v", err)
	}
	if application.certificateRuntime != nil {
		_ = application.certificateRuntime.Close()
	}
	if err := application.db.Close(); err != nil {
		t.Fatalf("close retained database: %v", err)
	}
}

func TestRunDoesNotCloseHandlerDependenciesBeforeHTTPDrain(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.HTTP.Address = address
	cfg.HTTP.ShutdownTimeout = 20 * time.Millisecond
	application, err := New(Options{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	application.worker = workers.NewSupervisor(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	application.server.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(handlerStarted)
		<-releaseHandler
	})

	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- application.Run(runCtx) }()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		deadline := time.Now().Add(time.Second)
		for {
			response, requestErr := http.Get("http://" + address)
			if response != nil {
				_ = response.Body.Close()
			}
			if requestErr == nil || time.Now().After(deadline) {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("HTTP handler did not start")
	}
	cancelRun()
	err = <-runDone
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run error = %v, want HTTP drain deadline", err)
	}
	acquireCtx, cancelAcquire := context.WithTimeout(context.Background(), 10*time.Millisecond)
	connection, acquireErr := application.db.Pool().Acquire(acquireCtx)
	cancelAcquire()
	if connection != nil {
		connection.Release()
	}
	if errors.Is(acquireErr, puddle.ErrClosedPool) {
		t.Fatal("database closed before HTTP handler drained")
	}

	close(releaseHandler)
	<-requestDone
	_ = application.server.Close()
	if application.certificateRuntime != nil {
		_ = application.certificateRuntime.Close()
	}
	if err := application.db.Close(); err != nil {
		t.Fatalf("close retained database: %v", err)
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
