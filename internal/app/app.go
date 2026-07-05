package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
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
	db     *db.DB
	server *http.Server
	worker *workers.Supervisor
}

func New(opts Options) (*App, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	store, err := db.Open(opts.Config.Database)
	if err != nil {
		return nil, err
	}
	auditWriter := audit.NewWriter(store)
	authService := auth.NewService(store, auditWriter, workOSVerifier(opts.Config), opts.Config.Secrets.SessionKeys, publicURLSecure(opts.Config.HTTP.PublicBaseURL))
	checker := readinessChecker{cfg: opts.Config, db: store}
	router := httpapi.NewRouter(httpapi.Options{
		Config:           opts.Config,
		Logger:           opts.Logger,
		ReadinessChecker: checker,
		Auth:             authService,
	})
	return &App{
		cfg:    opts.Config,
		logger: opts.Logger,
		db:     store,
		server: &http.Server{
			Addr:              opts.Config.HTTP.Address,
			Handler:           router,
			ReadHeaderTimeout: opts.Config.HTTP.ReadHeaderTimeout,
		},
		worker: workers.NewSupervisor(),
	}, nil
}

func workOSVerifier(cfg config.Config) auth.WorkOSVerifier {
	if cfg.Providers.FakeMode {
		return auth.FakeWorkOSVerifier{}
	}
	return auth.HTTPWorkOSVerifier{
		BaseURL:      cfg.Providers.WorkOS.BaseURL,
		ClientID:     cfg.Secrets.WorkOSClientID,
		ClientSecret: cfg.Secrets.WorkOSClientSecret,
	}
}

func publicURLSecure(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https"
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
	if err := a.db.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}
	return runErr
}

type readinessChecker struct {
	cfg config.Config
	db  *db.DB
}

func (r readinessChecker) Ready(ctx context.Context) error {
	if err := r.db.Ping(ctx); err != nil {
		return fmt.Errorf("database is not ready: %w", err)
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
