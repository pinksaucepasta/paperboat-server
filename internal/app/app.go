package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/catalog"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	pbgithub "github.com/pinksaucepasta/paperboat-server/internal/github"
	"github.com/pinksaucepasta/paperboat-server/internal/httpapi"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/orchestrator"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
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
	billingRepo := billing.NewRepository(store)
	catalogRepo := catalog.NewRepository(store.SQL())
	flyProvider := flyClient(opts.Config)
	authService := auth.NewService(store, auditWriter, workOSVerifier(opts.Config), opts.Config.Secrets.SessionKeys, publicURLSecure(opts.Config.HTTP.PublicBaseURL))
	deviceAuthService := auth.NewDeviceService(store, auditWriter, opts.Config.CLIAuth, opts.Config.Secrets.SessionKeys)
	billingService := billing.NewService(billingRepo, polarClient(opts.Config), auditWriter)
	githubService := pbgithub.NewService(store, auditWriter, githubClient(opts.Config), opts.Config)
	projectService := projects.NewService(store, auditWriter, opts.Config)
	agentunnelProvider := agentunnelClient(opts.Config)
	mintKeys, err := mintKeyProvider(opts.Config)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	credentialIssuer := agentunnel.CredentialIssuer(agentunnel.FakeCredentialIssuer{})
	if !opts.Config.Providers.FakeMode {
		credentialIssuer = &agentunnel.PapercodeCredentialIssuer{
			Issuer: normalizePapercodeIssuer(opts.Config.HTTP.PublicBaseURL), Signer: mintKeys,
			HTTPClient: &http.Client{Timeout: opts.Config.HTTP.RequestTimeout}, RequireHTTPS: true,
			ProofTTL: opts.Config.CLIAuth.MintProofLifetime,
		}
	}
	agentunnelService := agentunnel.NewServiceWithCredentials(store, projectService, agentunnelProvider, credentialIssuer, auditWriter, opts.Config)
	deviceAuthService.SetDownstreamRevoker(agentunnelService)
	orchestratorService := orchestrator.NewServiceWithAgentunnel(store, flyProvider, opts.Config, agentunnelProvider)
	meteringService := metering.NewRuntimeService(store, flyProvider, billingRepo)
	meteringService.SetDownstreamRevoker(agentunnelService)
	checker := readinessChecker{cfg: opts.Config, db: store}
	router := httpapi.NewRouter(httpapi.Options{
		Config:           opts.Config,
		Logger:           opts.Logger,
		ReadinessChecker: checker,
		Auth:             authService,
		DeviceAuth:       deviceAuthService,
		Billing:          billingService,
		Catalog:          catalogRepo,
		CatalogWriter:    catalogRepo,
		Fly:              flyProvider,
		GitHub:           githubService,
		Projects:         projectService,
		Agentunnel:       agentunnelService,
		MeteringRepo:     metering.NewRuntimeRepository(store, opts.Config.Secrets.EncryptionKey),
		MintKeys:         mintKeys,
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
		worker: workers.NewSupervisor(
			orchestratorService.Worker(2*opts.Config.HTTP.RequestTimeout/15),
			meteringService.Worker(opts.Config.HTTP.RequestTimeout),
		),
	}, nil
}

func normalizePapercodeIssuer(raw string) string {
	return config.NormalizeIssuer(raw)
}

func mintKeyProvider(cfg config.Config) (*mint.Provider, error) {
	if len(cfg.Secrets.MintSigningKeys) > 0 {
		return mint.ParseKeys(cfg.Secrets.MintSigningKeys, cfg.CLIAuth.MintActiveKeyID, cfg.CLIAuth.MintJWKSMaxAge)
	}
	if cfg.Environment != config.EnvironmentProduction {
		return mint.NewEphemeral(cfg.CLIAuth.MintJWKSMaxAge)
	}
	return nil, errors.New("mint signing keys are not configured")
}

func flyClient(cfg config.Config) fly.Client {
	if cfg.Providers.FakeMode {
		return fly.NewFakeClient()
	}
	return &fly.SDKClient{
		APIToken: cfg.Secrets.FlyAPIToken,
		AppName:  cfg.Fly.AppName,
		OrgSlug:  cfg.Fly.OrgSlug,
		BaseURL:  cfg.Providers.Fly.BaseURL,
	}
}

func githubClient(cfg config.Config) pbgithub.Client {
	if cfg.Providers.FakeMode {
		return &pbgithub.FakeClient{}
	}
	return pbgithub.HTTPClient{
		BaseURL:  cfg.Providers.GitHub.BaseURL,
		TokenURL: cfg.GitHub.OAuthTokenURL,
	}
}

func agentunnelClient(cfg config.Config) agentunnel.Client {
	if cfg.Providers.FakeMode {
		return agentunnel.FakeClient{BaseURL: cfg.Providers.Agentunnel.BaseURL}
	}
	return agentunnel.HTTPClient{
		BaseURL:              cfg.Providers.Agentunnel.BaseURL,
		APIKey:               cfg.Secrets.AgentunnelAPIKey,
		PapercodeLocalURL:    cfg.Providers.Agentunnel.PapercodeLocalURL,
		RouteExpiresIn:       cfg.Providers.Agentunnel.RouteExpiresIn,
		RouteSubdomainPrefix: cfg.Providers.Agentunnel.RouteSubdomainPrefix,
		AccessPolicyID:       cfg.Providers.Agentunnel.AccessPolicyID,
		UploadMaxBytes:       cfg.Providers.Agentunnel.UploadMaxBytes,
	}
}

func polarClient(cfg config.Config) billing.PolarClient {
	if cfg.Providers.FakeMode {
		return billing.FakePolarClient{}
	}
	return billing.HTTPPolarClient{
		BaseURL: cfg.Providers.Polar.BaseURL,
		APIKey:  cfg.Secrets.PolarAPIKey,
	}
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
