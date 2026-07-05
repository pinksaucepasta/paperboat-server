package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/httpapi"
	"github.com/pinksaucepasta/paperboat-server/internal/workers"
)

type Options struct {
	Config config.Config
	Logger *slog.Logger
}

type App struct {
	cfg    config.Config
	logger *slog.Logger
	server *http.Server
	worker *workers.Supervisor
}

func New(opts Options) (*App, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	checker := readinessChecker{cfg: opts.Config}
	router := httpapi.NewRouter(httpapi.Options{
		Config:           opts.Config,
		Logger:           opts.Logger,
		ReadinessChecker: checker,
	})
	return &App{
		cfg:    opts.Config,
		logger: opts.Logger,
		server: &http.Server{
			Addr:              opts.Config.HTTP.Address,
			Handler:           router,
			ReadHeaderTimeout: opts.Config.HTTP.ReadHeaderTimeout,
		},
		worker: workers.NewSupervisor(),
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	errs := make(chan error, 2)
	go func() {
		a.logger.Info("http server starting", "address", a.cfg.HTTP.Address)
		if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
			return
		}
		errs <- nil
	}()
	go func() {
		errs <- a.worker.Run(ctx)
	}()

	var runErr error
	select {
	case <-ctx.Done():
		runErr = ctx.Err()
	case err := <-errs:
		if err != nil {
			runErr = err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.HTTP.ShutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}
	return runErr
}

type readinessChecker struct {
	cfg config.Config
}

func (r readinessChecker) Ready(context.Context) error {
	if r.cfg.Database.Driver == "" || r.cfg.Database.DSN == "" {
		return errors.New("database is not configured")
	}
	if r.cfg.Providers.FakeMode {
		return nil
	}
	providers := []config.ProviderConfig{
		r.cfg.Providers.WorkOS,
		r.cfg.Providers.Polar,
		r.cfg.Providers.GitHub,
		r.cfg.Providers.Fly,
		r.cfg.Providers.Agentunnel,
	}
	for _, provider := range providers {
		if !provider.Ready {
			return errors.New("provider is not ready")
		}
	}
	return nil
}
