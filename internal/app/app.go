package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/access"
	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/catalog"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	pbgithub "github.com/pinksaucepasta/paperboat-server/internal/github"
	"github.com/pinksaucepasta/paperboat-server/internal/httpapi"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/orchestrator"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
	"github.com/pinksaucepasta/paperboat-server/internal/terminalsessions"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
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
	billingService.SetAutoTopupRetryCooldown(opts.Config.Billing.AutoTopupRetryCooldown)
	billingService.SetCheckoutReservationTTL(opts.Config.Billing.CheckoutReservationTTL)
	billingService.SetEncryptionKey(opts.Config.Secrets.EncryptionKey)
	githubService := pbgithub.NewService(store, auditWriter, githubClient(opts.Config), opts.Config)
	if opts.Config.Providers.FakeMode {
		githubService.SetRepositoryAccessBroker(pbgithub.FakeRepositoryAccessBroker{})
	} else if opts.Config.GitHub.AppID != "" && opts.Config.Secrets.GitHubAppPrivateKey != "" {
		githubAccessBroker, brokerErr := pbgithub.NewGitHubAppBroker(pbgithub.GitHubAppBrokerConfig{
			BaseURL: opts.Config.Providers.GitHub.BaseURL, AppID: opts.Config.GitHub.AppID,
			PrivateKeyPEM: opts.Config.Secrets.GitHubAppPrivateKey,
			Client:        providerHTTPClient("github-app", opts.Config.HTTP.RequestTimeout),
		})
		if brokerErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure GitHub App repository access: %w", brokerErr)
		}
		githubService.SetRepositoryAccessBroker(githubAccessBroker)
	}
	projectService := projects.NewService(store, auditWriter, opts.Config)
	terminalSessionService := terminalsessions.New(store, projectService, opts.Config.TerminalSessions.MaxActivePerProject, opts.Config.TerminalSessions.RetryBackoff, opts.Config.TerminalSessions.MaxAttemptsBeforeAlert)
	accessProvider := access.Client(access.DisabledClient{})
	mintKeys, err := mintKeyProvider(opts.Config)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	credentialIssuer := access.CredentialIssuer(access.DisabledCredentialIssuer{})
	if opts.Config.Providers.FakeMode {
		accessProvider = access.FakeClient{}
		credentialIssuer = access.FakeCredentialIssuer{}
	}
	accessService := access.NewServiceWithCredentials(store, projectService, accessProvider, credentialIssuer, auditWriter, opts.Config)
	accessService.ConfigureCanonicalAccess(mintKeys)
	terminalSessionService.ConfigureControl(func(ctx context.Context, environmentID string) (string, error) {
		route, routeErr := store.Queries().GetActiveHelperRouteForEnvironment(ctx, environmentID)
		if routeErr != nil {
			return "", routeErr
		}
		return "https://" + route.PublicHost, nil
	}, mintKeys, normalizeHelperIssuer(opts.Config.HTTP.PublicBaseURL), &http.Client{Timeout: opts.Config.TerminalSessions.OperationTimeout})
	accessService.SetBeforeConnect(func(ctx context.Context, _ string, projectID string) error {
		return terminalSessionService.ApplyPending(ctx, projectID)
	})
	deviceAuthService.SetDownstreamRevoker(accessService)
	orchestratorService := orchestrator.NewService(store, flyProvider, opts.Config)
	orchestratorService.SetBeforeStop(terminalSessionService.SnapshotProject)
	meteringService := metering.NewRuntimeService(store, flyProvider, billingRepo)
	meteringService.SetDownstreamRevoker(accessService)
	checker := readinessChecker{cfg: opts.Config, db: store}
	userMachineService := usermachines.New(store, auditWriter, usermachines.Policy{PairingLifetime: opts.Config.UserMachines.PairingLifetime, OfflineAfter: opts.Config.UserMachines.OfflineAfter, AllowedPlatforms: opts.Config.UserMachines.AllowedPlatforms}, billingService)
	userMachineService.ConfigureProvisioning(accessProvider, opts.Config.Secrets.EncryptionKey)
	userMachineService.ConfigureAccess(credentialIssuer, normalizeHelperIssuer(opts.Config.HTTP.PublicBaseURL), opts.Config.CLIAuth.AccessTokenLifetime)
	userMachineService.ConfigureFileTransfer(accessdescriptor.FileTransferPolicy{
		Revision: opts.Config.Access.FileTransfer.Revision, MaxFileBytes: opts.Config.Access.FileTransfer.MaxFileBytes,
		MaxBatchFiles: opts.Config.Access.FileTransfer.MaxBatchFiles, MaxBatchBytes: opts.Config.Access.FileTransfer.MaxBatchBytes,
		MaxConcurrentTransfers: opts.Config.Access.FileTransfer.MaxConcurrentTransfers, RetentionSeconds: int64(opts.Config.Access.FileTransfer.Retention / time.Second),
		DeliveryTimeoutSeconds: int64(opts.Config.Access.FileTransfer.DeliveryTimeout / time.Second), MaxPendingSpoolBytes: opts.Config.Access.FileTransfer.MaxPendingSpoolBytes,
	})
	userMachineService.ConfigureTerminalSessions(opts.Config.TerminalSessions.MaxActivePerProject, mintKeys, &http.Client{Timeout: opts.Config.TerminalSessions.OperationTimeout})
	userMachineService.ConfigureMachineControl(mintKeys, normalizeHelperIssuer(opts.Config.HTTP.PublicBaseURL))
	userMachineService.ConfigureBootstrapCommand(opts.Config.UserMachines.BootstrapCommand)
	if err := userMachineService.ConfigureRuntimeRoute(opts.Config.RuntimeBaseDomain, opts.Config.UserMachines.RuntimeListenPort); err != nil {
		return nil, err
	}
	if err := userMachineService.ConfigureMachineArtifacts(opts.Config.UserMachines.MachineArtifactsJSON, opts.Config.UserMachines.MachineArtifactPublicKey); err != nil {
		return nil, err
	}
	billingService.SetUserMachineSessionRevoker(userMachineService)
	enrollmentService := controlplane.NewEnrollmentService(store, mintKeys, auditWriter, config.NormalizeIssuer(opts.Config.HTTP.PublicBaseURL), opts.Config.Secrets.EncryptionKey)
	hostedBootstrapService := controlplane.NewHostedBootstrapService(store, enrollmentService, opts.Config.Secrets.EncryptionKey)
	hostedBootstrapService.SetSourceCredentialIssuer(controlplane.HostedSourceCredentialIssuerFunc(
		func(ctx context.Context, userID, sourceURL string) (controlplane.HostedSourceCredential, error) {
			repositories, listErr := githubService.ListRepos(ctx, userID)
			if listErr != nil {
				return controlplane.HostedSourceCredential{}, listErr
			}
			for _, repository := range repositories {
				if !strings.EqualFold(strings.TrimSuffix(repository.CloneURL, "/"), strings.TrimSuffix(sourceURL, "/")) {
					continue
				}
				if !repository.Private {
					return controlplane.HostedSourceCredential{}, nil
				}
				authorizationRef, resolveErr := githubService.ResolveRepositoryAuthorization(ctx, userID, repository.ID)
				if resolveErr != nil {
					return controlplane.HostedSourceCredential{}, resolveErr
				}
				issued, issueErr := githubService.IssueRepositoryAccess(ctx, authorizationRef, repository.ID, "read")
				return controlplane.HostedSourceCredential{
					Username: "x-access-token", Password: issued.Token, ExpiresAt: issued.ExpiresAt,
				}, issueErr
			}
			return controlplane.HostedSourceCredential{}, nil
		},
	))
	if !opts.Config.Providers.FakeMode {
		hostedEnrollmentAudience := config.NormalizeIssuer(opts.Config.HTTP.PublicBaseURL) + "/v1/hosted-helper-enrollments"
		workloadVerifier, verifierErr := fly.NewWorkloadIdentityVerifier(
			opts.Config.Fly.OrgSlug,
			hostedEnrollmentAudience,
			providerHTTPClient("fly-oidc", opts.Config.HTTP.RequestTimeout),
		)
		if verifierErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure Fly workload identity: %w", verifierErr)
		}
		enrollmentService.ConfigureHostedWorkloadIdentity(opts.Config.Fly.AppName,
			controlplane.HostedWorkloadIdentityVerifierFunc(func(ctx context.Context, token string) (controlplane.HostedWorkloadIdentity, error) {
				identity, verifyErr := workloadVerifier.Verify(ctx, token)
				return controlplane.HostedWorkloadIdentity{
					AppName: identity.AppName, MachineID: identity.MachineID, TokenID: identity.TokenID,
				}, verifyErr
			}))
	}
	userMachineService.ConfigureHelperEnrollment(func(ctx context.Context, actorID, operationKey, environmentID string, lifetime time.Duration) (usermachines.HelperEnrollmentGrant, error) {
		grant, err := enrollmentService.Issue(ctx, actorID, operationKey, environmentID, lifetime)
		return usermachines.HelperEnrollmentGrant{EnrollmentID: grant.EnrollmentID, HelperID: grant.HelperID, Credential: grant.Credential, ExpiresAt: grant.ExpiresAt}, err
	})
	configAssignmentService := controlplane.NewConfigAssignmentService(store, auditWriter, opts.Config.ConfigSync.WarningRevision)
	configAssignmentService.SetRepositoryResolver(controlplane.ConfigRepositoryResolverFunc(func(ctx context.Context, userID, provider, externalID string) (controlplane.ConfigRepositoryConnection, error) {
		if provider != "github" || githubService == nil {
			return controlplane.ConfigRepositoryConnection{}, controlplane.ErrAssignmentForbidden
		}
		repository, accountID, resolveErr := githubService.ResolvePrivateRepository(ctx, userID, externalID)
		if resolveErr != nil {
			return controlplane.ConfigRepositoryConnection{}, resolveErr
		}
		authorizationRef, accessErr := githubService.ResolveRepositoryAuthorization(ctx, userID, externalID)
		if accessErr != nil {
			return controlplane.ConfigRepositoryConnection{}, accessErr
		}
		return controlplane.ConfigRepositoryConnection{
			ProviderAccountID: accountID, ExternalRepositoryID: repository.ID,
			DisplayName: repository.Owner + "/" + repository.Name, CloneURL: repository.CloneURL, PublishURL: repository.CloneURL,
			DefaultBranch: repository.DefaultBranch, AuthorizationRef: authorizationRef,
			CredentialCapability: "github_app_installation_repository_contents_rw",
		}, nil
	}))
	configAssignmentService.SetRepositoryCatalog(controlplane.ConfigRepositoryCatalogFunc(func(ctx context.Context, userID string) ([]controlplane.ConfigRepositoryCandidate, error) {
		if githubService == nil {
			return nil, controlplane.ErrAssignmentForbidden
		}
		repositories, listErr := githubService.ListRepos(ctx, userID)
		if listErr != nil {
			return nil, listErr
		}
		items := make([]controlplane.ConfigRepositoryCandidate, 0, len(repositories))
		for _, repository := range repositories {
			if !repository.Private || repository.ID == "" || repository.Owner == "" || repository.Name == "" {
				continue
			}
			items = append(items, controlplane.ConfigRepositoryCandidate{
				Provider: "github", ExternalID: repository.ID,
				DisplayName: repository.Owner + "/" + repository.Name, DefaultBranch: repository.DefaultBranch,
			})
		}
		return items, nil
	}))
	configCredentialService := controlplane.NewConfigCredentialService(store, mintKeys, config.NormalizeIssuer(opts.Config.HTTP.PublicBaseURL), opts.Config.Secrets.EncryptionKey)
	configCredentialService.SetAuditWriter(auditWriter)
	configCredentialService.SetWarningRevision(opts.Config.ConfigSync.WarningRevision)
	configCredentialService.SetRollout(opts.Config.ConfigSync.Mode, opts.Config.ConfigSync.BYODEnabled, opts.Config.ConfigSync.EnvironmentAllowlist)
	configLeaseService := controlplane.NewConfigLeaseService(store, auditWriter)
	configLeaseService.ConfigureAuthentication(enrollmentService, mintKeys, config.NormalizeIssuer(opts.Config.HTTP.PublicBaseURL), opts.Config.ConfigSync.WarningRevision)
	configLeaseService.ConfigureRollout(opts.Config.ConfigSync.Mode, opts.Config.ConfigSync.BYODEnabled, opts.Config.ConfigSync.EnvironmentAllowlist)
	configStatusService := controlplane.NewConfigStatusService(store, enrollmentService, auditWriter, opts.Config.ConfigSync.SummaryLimit)
	configStatusService.SetAccountPolicy(opts.Config.ConfigSync)
	configRepositoryAccessService := controlplane.NewConfigRepositoryAccessService(store, configLeaseService,
		controlplane.ConfigRepositoryAccessIssuerFuncs{
			Issue: func(ctx context.Context, authorizationRef, repositoryID, contentsPermission string) (controlplane.ScopedRepositoryCredential, error) {
				issued, issueErr := githubService.IssueRepositoryAccess(ctx, authorizationRef, repositoryID, contentsPermission)
				return controlplane.ScopedRepositoryCredential{Token: issued.Token, ExpiresAt: issued.ExpiresAt}, issueErr
			},
			Revoke: githubService.RevokeRepositoryAccess,
		}, opts.Config.Secrets.EncryptionKey, auditWriter)
	configRuntimeService := controlplane.NewConfigRuntimeService(store, configLeaseService, opts.Config.ConfigSync)
	configConflictService := controlplane.NewConfigConflictService(store, configLeaseService, auditWriter)
	routeService := controlplane.NewRouteService(store, auditWriter)
	var previewService *controlplane.PreviewService
	if opts.Config.Preview.BaseDomain != "" || opts.Config.Secrets.PreviewIdentityKey != "" {
		if opts.Config.Preview.BaseDomain == "" || opts.Config.Secrets.PreviewIdentityKey == "" {
			_ = store.Close()
			return nil, errors.New("preview base domain and identity key must be configured together")
		}
		previewKey, decodeErr := base64.StdEncoding.DecodeString(opts.Config.Secrets.PreviewIdentityKey)
		if decodeErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("decode preview identity key: %w", decodeErr)
		}
		previewService, err = controlplane.NewPreviewService(store, auditWriter, previewKey, opts.Config.Preview.BaseDomain)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure previews: %w", err)
		}
	}
	orchestratorService.SetHostedRouteEnsurer(func(ctx context.Context, actorID, operationKey, environmentID, publicHost string) error {
		_, err := routeService.Create(ctx, actorID, operationKey, environmentID, "runtime_https_wss", publicHost, "127.0.0.1", 8080)
		return err
	})
	readinessClient := &http.Client{Timeout: opts.Config.Fly.OperationTimeout}
	orchestratorService.SetHostedReadinessVerifier(orchestrator.NewHTTPReadinessVerifierWithHost(readinessClient, func(projectID string) string {
		return orchestrator.HostedHelperHealthURL(opts.Config, projectID)
	}, func(projectID string) string { return orchestrator.HostedHelperHealthHost(opts.Config, projectID) }))
	controlDiagnostics := controlplane.NewDiagnosticsService(store)
	operationRecovery := controlplane.NewOperationRecoveryService(store, auditWriter)
	hostedProviderRecovery := controlplane.NewHostedProviderRecoveryService(store, auditWriter)
	billingRecovery := billing.NewRecoveryService(store, auditWriter)
	var edgeControlHandler http.Handler
	var edgeControlService *controlplane.EdgeService
	if opts.Config.Secrets.EdgeControlCredential != "" {
		edgeControlService = controlplane.NewEdgeService(store, opts.Config.Secrets.EdgeControlCredential)
		edgeControlService.SetBandwidthDebiter(userMachineService)
		edgeControlService.SetAuditWriter(auditWriter)
		edgeControlService.SetCredentialIssuer(mintKeys, config.NormalizeIssuer(opts.Config.HTTP.PublicBaseURL), opts.Config.Secrets.EncryptionKey)
		edgeControlService.SetFileTransferPolicy(mint.FileTransferPolicy{Revision: opts.Config.Access.FileTransfer.Revision, MaxFileBytes: opts.Config.Access.FileTransfer.MaxFileBytes, MaxBatchFiles: opts.Config.Access.FileTransfer.MaxBatchFiles, MaxBatchBytes: opts.Config.Access.FileTransfer.MaxBatchBytes, MaxConcurrentTransfers: opts.Config.Access.FileTransfer.MaxConcurrentTransfers, RetentionSeconds: int64(opts.Config.Access.FileTransfer.Retention / time.Second), DeliveryTimeoutSeconds: int64(opts.Config.Access.FileTransfer.DeliveryTimeout / time.Second), MaxPendingSpoolBytes: opts.Config.Access.FileTransfer.MaxPendingSpoolBytes})
		edgeControlHandler = edgeControlService.Handler()
	}
	router := httpapi.NewRouter(httpapi.Options{
		Config:                 opts.Config,
		Logger:                 opts.Logger,
		ReadinessChecker:       checker,
		Auth:                   authService,
		DeviceAuth:             deviceAuthService,
		Billing:                billingService,
		BillingRecovery:        billingRecovery,
		Catalog:                catalogRepo,
		CatalogWriter:          catalogRepo,
		Fly:                    flyProvider,
		GitHub:                 githubService,
		Projects:               projectService,
		TerminalSessions:       terminalSessionService,
		EnvironmentAccess:      accessService,
		MeteringRepo:           metering.NewRuntimeRepository(store, opts.Config.Secrets.EncryptionKey, opts.Config.ConfigSync.StaleHeartbeatAfter),
		RuntimeIdentity:        enrollmentService,
		Machines:               userMachineService,
		MintKeys:               mintKeys,
		EdgeControl:            edgeControlHandler,
		EdgeControlAdmin:       edgeControlService,
		Enrollment:             enrollmentService,
		HostedBootstrap:        hostedBootstrapService,
		ConfigAssignments:      configAssignmentService,
		ConfigCredentials:      configCredentialService,
		ConfigLeases:           configLeaseService,
		ConfigStatuses:         configStatusService,
		ConfigRepositoryAccess: configRepositoryAccessService,
		ConfigRuntime:          configRuntimeService,
		ConfigConflicts:        configConflictService,
		Routes:                 routeService,
		Previews:               previewService,
		ControlDiagnostics:     controlDiagnostics,
		OperationRecovery:      operationRecovery,
		HostedProviderRecovery: hostedProviderRecovery,
	})
	serverWorkers := []workers.Worker{
		orchestratorService.Worker(2 * opts.Config.HTTP.RequestTimeout / 15),
		meteringService.Worker(opts.Config.HTTP.RequestTimeout),
		billingService.AutoTopupWorker(opts.Config.HTTP.RequestTimeout),
		terminalSessionService.Worker(opts.Config.TerminalSessions.WorkerInterval),
		userMachineService.Worker(opts.Config.TerminalSessions.WorkerInterval),
		configAssignmentService.WarningReconciliationWorker(opts.Config.TerminalSessions.WorkerInterval),
		configRepositoryAccessService.RevocationWorker(opts.Config.TerminalSessions.WorkerInterval, 25),
	}
	if edgeControlService != nil {
		serverWorkers = append(serverWorkers, edgeControlService.StaleNodeWorker(opts.Config.TerminalSessions.WorkerInterval, controlplane.ControlTunnelNodeStaleAfter()))
	}
	return &App{
		cfg:    opts.Config,
		logger: opts.Logger,
		db:     store,
		server: &http.Server{
			Addr:              opts.Config.HTTP.Address,
			Handler:           router,
			ReadHeaderTimeout: opts.Config.HTTP.ReadHeaderTimeout,
		},
		worker: workers.NewSupervisor(serverWorkers...),
	}, nil
}

func normalizeHelperIssuer(raw string) string {
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
		Client:   providerHTTPClient("github", cfg.HTTP.RequestTimeout),
	}
}

func polarClient(cfg config.Config) billing.PolarClient {
	if cfg.Providers.FakeMode {
		return billing.FakePolarClient{}
	}
	return billing.HTTPPolarClient{
		BaseURL: cfg.Providers.Polar.BaseURL,
		APIKey:  cfg.Secrets.PolarAPIKey,
		Client:  providerHTTPClient("polar", cfg.HTTP.RequestTimeout),
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
		HTTPClient:   providerHTTPClient("workos", cfg.HTTP.RequestTimeout),
	}
}

func providerHTTPClient(provider string, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: observability.InstrumentProviderTransport(provider, http.DefaultTransport)}
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
	}
	for _, provider := range providers {
		if !provider.Ready {
			return errors.New("provider is not ready")
		}
	}
	return nil
}
