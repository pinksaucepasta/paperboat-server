package app

import (
	"context"
	"crypto/sha256"
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
	"github.com/pinksaucepasta/paperboat-server/internal/codexsessions"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/diagnosticuploads"
	"github.com/pinksaucepasta/paperboat-server/internal/environment"
	"github.com/pinksaucepasta/paperboat-server/internal/favorites"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	pbgithub "github.com/pinksaucepasta/paperboat-server/internal/github"
	"github.com/pinksaucepasta/paperboat-server/internal/httpapi"
	"github.com/pinksaucepasta/paperboat-server/internal/managedssh"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/orchestrator"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
	"github.com/pinksaucepasta/paperboat-server/internal/peersessions"
	"github.com/pinksaucepasta/paperboat-server/internal/previewattachment"
	"github.com/pinksaucepasta/paperboat-server/internal/previewdispatch"
	"github.com/pinksaucepasta/paperboat-server/internal/previewdomain"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
	"github.com/pinksaucepasta/paperboat-server/internal/privateaccess"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
	"github.com/pinksaucepasta/paperboat-server/internal/releaseauthority"
	"github.com/pinksaucepasta/paperboat-server/internal/releases"
	"github.com/pinksaucepasta/paperboat-server/internal/telemetry"
	"github.com/pinksaucepasta/paperboat-server/internal/terminalsessions"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelcert"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
	"github.com/pinksaucepasta/paperboat-server/internal/workers"
)

type Options struct {
	Config config.Config
	Logger *slog.Logger
	// CertificateRuntime is a fully composed managed-certificate lifecycle.
	// App owns it after New succeeds and closes it before the database on
	// shutdown. Supplying this is mutually exclusive with the legacy worker
	// and handler fields below.
	CertificateRuntime *tunnelv1.CertificateRuntime
	// CertificateWorker is supplied only by deployment composition that has
	// configured a real issuer, CAA policy, envelope-key resolver, and
	// authenticated edge distributor.  Nil keeps startup fail-closed without
	// inventing certificate material or provider credentials.
	CertificateWorker *tunnelv1.CertificateWorker
	// CertificateDistribution is the internal authenticated server-to-edge
	// transport used by the certificate worker's distributor. It is mounted
	// only on the edge-control handler and never exposed by the public API.
	CertificateDistribution http.Handler
}

type App struct {
	cfg                  config.Config
	logger               *slog.Logger
	db                   *db.DB
	server               *http.Server
	worker               *workers.Supervisor
	certificateRuntime   *tunnelv1.CertificateRuntime
	telemetryEvents      *telemetry.EventLog
	telemetryMetrics     *telemetry.Metrics
	telemetryHealth      *telemetry.HealthTracker
	telemetryHTTP        *telemetry.HTTPObserver
	telemetryDiagnostics *telemetry.Diagnostics
	telemetryProducer    *telemetry.Producer
	telemetryStartedAt   time.Time
}

func New(opts Options) (*App, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	certificateRuntime := opts.CertificateRuntime
	runtimeTransferred := false
	defer func() {
		if !runtimeTransferred && certificateRuntime != nil {
			_ = certificateRuntime.Close()
		}
	}()
	if certificateRuntime != nil && !opts.Config.Certificates.Enabled {
		return nil, fmt.Errorf("%w: injected runtime requires managed certificates to be enabled", tunnelv1.ErrCertificateRuntimeUnavailable)
	}
	if certificateRuntime != nil && (opts.CertificateWorker != nil || opts.CertificateDistribution != nil) {
		return nil, fmt.Errorf("certificate runtime cannot be combined with legacy certificate options")
	}
	store, err := db.Open(opts.Config.Database)
	if err != nil {
		return nil, err
	}
	if certificateRuntime == nil && opts.Config.Certificates.Enabled {
		certificateRuntime, err = newCertificateRuntime(context.Background(), store, opts.Config)
		if err != nil {
			_ = store.Close()
			return nil, err
		}
	}
	if certificateRuntime != nil {
		opts.CertificateRuntime = certificateRuntime
		opts.CertificateWorker = certificateRuntime.Worker
		opts.CertificateDistribution = certificateRuntime.Distribution.Handler()
	}
	auditWriter := audit.NewWriter(store)
	previewTunnelStore, err := previewtunnelstore.New(store)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview tunnel store: %w", err)
	}
	previewDomainRepository, err := previewdomain.NewSQLRepository(store, previewdomain.Config{})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview domain repository: %w", err)
	}
	if err := previewTunnelStore.ConfigurePreviewDomains(previewDomainBatchCreatorAdapter{repository: previewDomainRepository}); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure atomic preview domains: %w", err)
	}
	previewAttachmentProduction, err := previewattachment.NewProduction(store)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview carrier attachment: %w", err)
	}
	cursorKey := sha256.Sum256([]byte("paperboat.preview-tunnel.cursor\x00" + opts.Config.Secrets.EncryptionKey))
	previewDomainService, err := previewdomain.NewService(previewDomainRepository, previewdomain.Config{
		CursorKey:     cursorKey[:],
		ChallengeZone: opts.Config.Certificates.ChallengeZone,
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview domain service: %w", err)
	}
	previewTunnelAPI, err := previewtunnelapi.NewService(previewTunnelStore, cursorKey[:])
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview tunnel API: %w", err)
	}
	previewLeaseService, err := previewv1.NewService(previewTunnelStore, previewv1.Config{
		EndpointDomain:      opts.Config.Preview.BaseDomain,
		CursorKey:           cursorKey[:],
		AttachmentReadiness: previewAttachmentProduction.Service,
		PreviewDomains:      previewDomainRepository,
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview lease service: %w", err)
	}
	tunnelRepository, err := tunnelv1.NewRepository(store)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure tunnel repository: %w", err)
	}
	tunnelEndpointBuilder, err := tunnelv1.NewEndpointBuilder("https://" + opts.Config.Tunnel.BaseDomain)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure tunnel endpoint builder: %w", err)
	}
	tunnelService, err := tunnelv1.NewService(tunnelRepository, tunnelv1.Config{
		EndpointBuilder: tunnelEndpointBuilder,
		CursorKey:       cursorKey[:],
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure tunnel service: %w", err)
	}
	tunnelResourceService, err := tunnelv1.NewResourceService(tunnelRepository, tunnelv1.ResourceConfig{
		CursorKey: cursorKey[:], ChallengeZone: opts.Config.Certificates.ChallengeZone, AllowInsecureDevelopment: opts.Config.Environment == config.EnvironmentDevelopment,
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure tunnel resource service: %w", err)
	}
	domainReconciler, err := tunnelv1.NewDomainReconciler(store, tunnelv1.NetDomainDNSResolver{}, nil)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure tunnel domain reconciler: %w", err)
	}
	previewDomainReconciler, err := previewdomain.NewDNSReconciler(previewDomainRepository, tunnelv1.NetDomainDNSResolver{}, previewdomain.ReconcilerConfig{})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview domain reconciler: %w", err)
	}
	billingRepo := billing.NewRepository(store)
	catalogRepo := catalog.NewRepository(store)
	flyProvider := flyClient(opts.Config)
	authService := auth.NewService(store, auditWriter, workOSVerifier(opts.Config), opts.Config.Secrets.SessionKeys, publicURLSecure(opts.Config.HTTP.PublicBaseURL))
	deviceAuthService := auth.NewDeviceService(store, auditWriter, opts.Config.CLIAuth, opts.Config.Secrets.SessionKeys)
	billingService := billing.NewService(billingRepo, polarClient(opts.Config), auditWriter)
	billingService.SetAutoTopupRetryCooldown(opts.Config.Billing.AutoTopupRetryCooldown)
	billingService.SetCheckoutReservationTTL(opts.Config.Billing.CheckoutReservationTTL)
	billingService.SetEncryptionKey(opts.Config.Secrets.EncryptionKey)
	githubService := pbgithub.NewService(store, auditWriter, githubClient(opts.Config), opts.Config)
	// Development can keep fake WorkOS, Polar, and Fly providers while using a
	// real, installation-scoped GitHub App for config-sync qualification.
	// Prefer explicit App credentials over the workspace-wide fake-provider
	// default so repository access never falls back to an unrestricted fake.
	if opts.Config.GitHub.AppID != "" && opts.Config.Secrets.GitHubAppPrivateKey != "" {
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
	} else if opts.Config.Providers.FakeMode {
		githubService.SetRepositoryAccessBroker(pbgithub.FakeRepositoryAccessBroker{})
	}
	projectService := projects.NewService(store, auditWriter, opts.Config)
	terminalSessionService := terminalsessions.New(store, projectService, opts.Config.TerminalSessions.MaxActivePerProject, opts.Config.TerminalSessions.RetryBackoff, opts.Config.TerminalSessions.MaxAttemptsBeforeAlert)
	accessProvider := access.Client(access.DisabledClient{})
	mintKeys, err := mintKeyProvider(opts.Config)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	previewDispatcher, err := previewdispatch.New(previewdispatch.Config{
		Resolver: previewdispatch.DBMachineRouteResolver{DB: store},
		Signer:   mintKeys,
		Issuer:   normalizeHelperIssuer(opts.Config.HTTP.PublicBaseURL),
		Client:   providerHTTPClient("helper", opts.Config.HTTP.RequestTimeout),
		Timeout:  opts.Config.HTTP.RequestTimeout,
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview dispatcher: %w", err)
	}
	previewLeaseService.ConfigureDispatcher(previewDispatcher)
	credentialIssuer := access.CredentialIssuer(access.DisabledCredentialIssuer{})
	codexSessionService := codexsessions.New(store, mintKeys, normalizeHelperIssuer(opts.Config.HTTP.PublicBaseURL), 4)
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
	if len(opts.Config.Secrets.SessionKeys) > 0 {
		userMachineService.ConfigureOneShotCLIAuth(opts.Config.CLIAuth.ClientID, opts.Config.CLIAuth.AllowedScopes, opts.Config.CLIAuth.AccessTokenLifetime, opts.Config.CLIAuth.RefreshTokenLifetime, opts.Config.Secrets.SessionKeys[0])
	}
	userMachineService.ConfigureAccess(credentialIssuer, normalizeHelperIssuer(opts.Config.HTTP.PublicBaseURL), opts.Config.CLIAuth.AccessTokenLifetime)
	userMachineService.ConfigureFileTransfer(accessdescriptor.FileTransferPolicy{
		Revision: opts.Config.Access.FileTransfer.Revision, MaxFileBytes: opts.Config.Access.FileTransfer.MaxFileBytes,
		MaxBatchFiles: opts.Config.Access.FileTransfer.MaxBatchFiles, MaxBatchBytes: opts.Config.Access.FileTransfer.MaxBatchBytes,
		MaxConcurrentTransfers: opts.Config.Access.FileTransfer.MaxConcurrentTransfers, RetentionSeconds: int64(opts.Config.Access.FileTransfer.Retention / time.Second),
		DeliveryTimeoutSeconds: int64(opts.Config.Access.FileTransfer.DeliveryTimeout / time.Second), MaxPendingSpoolBytes: opts.Config.Access.FileTransfer.MaxPendingSpoolBytes,
	})
	userMachineService.ConfigureTerminalSessions(opts.Config.TerminalSessions.MaxActivePerProject, mintKeys, &http.Client{Timeout: opts.Config.TerminalSessions.OperationTimeout})
	userMachineService.ConfigureMachineControl(mintKeys, normalizeHelperIssuer(opts.Config.HTTP.PublicBaseURL))
	publicBaseURL := strings.TrimRight(config.NormalizeIssuer(opts.Config.HTTP.PublicBaseURL), "/")
	releaseBaseURL := strings.TrimRight(config.NormalizeIssuer(opts.Config.ReleaseBaseURL), "/")
	if releaseBaseURL == "" {
		releaseBaseURL = publicBaseURL
	}
	userMachineService.ConfigureBootstrapCommand("curl -fsSL " + releaseBaseURL + "/install | bash -s -- --pair")
	if err := userMachineService.ConfigureRuntimeRoute(opts.Config.RuntimeBaseDomain, opts.Config.UserMachines.RuntimeListenPort); err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.Config.ReleaseDirectory) != "" {
		if err := userMachineService.ConfigureMachineArtifacts(releaseBaseURL+"/tuf", "bootstrap"); err != nil {
			return nil, err
		}
		userMachineService.ConfigureMachineArtifactVersionResolver(func() string {
			current, currentErr := releases.ReadCurrent(opts.Config.ReleaseDirectory)
			if currentErr != nil {
				return ""
			}
			return current.Version
		})
	}
	var releaseAuthorityService *releaseauthority.Service
	if len(opts.Config.ReleaseAuthority.PublicKeys) > 0 {
		authorityKeys, authorityErr := releaseauthority.ParseKeys(opts.Config.ReleaseAuthority.PublicKeys)
		if authorityErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure release authority keys: %w", authorityErr)
		}
		releaseAuthorityService, authorityErr = releaseauthority.New(store, auditWriter, releaseauthority.Config{Keys: authorityKeys, Threshold: opts.Config.ReleaseAuthority.Threshold})
		if authorityErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure release authority: %w", authorityErr)
		}
	}
	var releaseFileHandler http.Handler
	if strings.TrimSpace(opts.Config.ReleaseDirectory) != "" {
		releaseFileHandler, err = httpapi.NewReleaseFiles(opts.Config.ReleaseDirectory)
		if err != nil {
			return nil, fmt.Errorf("configure release directory: %w", err)
		}
	}
	billingService.SetUserMachineSessionRevoker(userMachineService)
	enrollmentService := controlplane.NewEnrollmentService(store, mintKeys, auditWriter, config.NormalizeIssuer(opts.Config.HTTP.PublicBaseURL), opts.Config.Secrets.EncryptionKey)
	connectorControlStore, err := connectorprotocol.NewSQLControlStore(store, connectorprotocol.SQLControlStoreConfig{})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure connector control store: %w", err)
	}
	connectorPersistentServer, err := connectorprotocol.NewPersistentServer(connectorControlStore, connectorControlStore, connectorprotocol.ServerConfig{Capabilities: connectorprotocol.ProductionCapabilities()})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure connector control server: %w", err)
	}
	connectorRotationDispatcher, err := connectorprotocol.NewRotationDispatcher(connectorprotocol.RotationDispatcherConfig{
		Store: connectorControlStore, VerifyOldProof: connectorControlStore.VerifyRotationOldProof,
		ReportError: func(dispatchErr error) {
			opts.Logger.Error("connector credential rotation reconciliation failed", "error", dispatchErr)
		},
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure connector rotation dispatcher: %w", err)
	}
	connectorDrainDispatcher, err := connectorprotocol.NewDrainDispatcher(connectorprotocol.DrainDispatcherConfig{
		Store: connectorControlStore,
		ReportError: func(dispatchErr error) {
			opts.Logger.Error("connector drain reconciliation failed", "error", dispatchErr)
		},
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure connector drain dispatcher: %w", err)
	}
	connectorControlTransport, err := connectorprotocol.NewControlTransportWithDispatchers(connectorPersistentServer, nil, connectorRotationDispatcher, connectorDrainDispatcher)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure connector control transport: %w", err)
	}
	connectorControlHandler, err := connectorprotocol.NewWebSocketHandler(connectorControlTransport)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure connector control websocket: %w", err)
	}
	connectorCarrierBootstrapHandler, err := httpapi.NewConnectorCarrierBootstrapHandler(
		connectorControlTransport.Sessions(),
		connectorprotocol.SQLCarrierBootstrapSource{DB: store},
		enrollmentService,
	)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure connector carrier bootstrap: %w", err)
	}
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
	userMachineService.ConfigureHelperRecovery(func(ctx context.Context, actorID, operationKey, environmentID, helperID string, lifetime time.Duration) (usermachines.HelperEnrollmentGrant, error) {
		grant, err := enrollmentService.RecoverHelper(ctx, actorID, operationKey, environmentID, helperID, lifetime)
		return usermachines.HelperEnrollmentGrant{EnrollmentID: grant.EnrollmentID, HelperID: grant.HelperID, Credential: grant.Credential, ExpiresAt: grant.ExpiresAt}, err
	})
	userMachineService.ConfigureAuthenticatedHelperEnrollment(
		func(ctx context.Context, actorID, operationKey, environmentID string, lifetime time.Duration, guard usermachines.HelperEnrollmentAuthorityGuard) (usermachines.HelperEnrollmentGrant, error) {
			return usermachines.PersistAuthenticatedHelperEnrollment(ctx, store, environmentID, guard, func(ctx context.Context) (usermachines.HelperEnrollmentGrant, error) {
				grant, err := enrollmentService.Issue(ctx, actorID, operationKey, environmentID, lifetime)
				return usermachines.HelperEnrollmentGrant{EnrollmentID: grant.EnrollmentID, HelperID: grant.HelperID, Credential: grant.Credential, ExpiresAt: grant.ExpiresAt}, err
			})
		},
		func(ctx context.Context, actorID, operationKey, environmentID, helperID string, lifetime time.Duration, guard usermachines.HelperEnrollmentAuthorityGuard) (usermachines.HelperEnrollmentGrant, error) {
			return usermachines.PersistAuthenticatedHelperEnrollment(ctx, store, environmentID, guard, func(ctx context.Context) (usermachines.HelperEnrollmentGrant, error) {
				grant, err := enrollmentService.RecoverHelper(ctx, actorID, operationKey, environmentID, helperID, lifetime)
				return usermachines.HelperEnrollmentGrant{EnrollmentID: grant.EnrollmentID, HelperID: grant.HelperID, Credential: grant.Credential, ExpiresAt: grant.ExpiresAt}, err
			})
		},
	)
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
	peerIdentityRepository, err := peeridentity.NewSQLRepository(store, auditWriter)
	if err != nil {
		return nil, err
	}
	peerIdentityService, err := peeridentity.NewService(peerIdentityRepository)
	if err != nil {
		return nil, err
	}
	// ENV Injection reuses only the public account-root resolver. The general
	// server encryption key is deliberately never passed to ENV code.
	environmentVariableService := environment.NewService(store, auditWriter, peerIdentityService)
	peerSessionRepository, err := peersessions.NewSQLRepository(store, auditWriter, controlplane.ControlTunnelNodeStaleAfter(), opts.Config.Secrets.EncryptionKey)
	if err != nil {
		return nil, err
	}
	peerSessionService, err := peersessions.New(peerSessionRepository, mintKeys, config.NormalizeIssuer(opts.Config.HTTP.PublicBaseURL))
	if err != nil {
		return nil, err
	}
	managedSSHRepository, err := managedssh.NewSQLRepository(store, auditWriter)
	if err != nil {
		return nil, err
	}
	managedSSHService, err := managedssh.NewService(managedSSHRepository)
	if err != nil {
		return nil, err
	}
	var diagnosticUploadService *diagnosticuploads.Service
	if opts.Config.Diagnostics.ObjectEndpoint != "" {
		diagnosticRepository, repositoryErr := diagnosticuploads.NewSQLRepository(store, auditWriter)
		if repositoryErr != nil {
			_ = store.Close()
			return nil, repositoryErr
		}
		objectContext, cancelObjects := context.WithTimeout(context.Background(), opts.Config.HTTP.RequestTimeout)
		objectStore, objectErr := diagnosticuploads.NewS3ObjectStore(objectContext, opts.Config.Diagnostics, opts.Config.Secrets.DiagnosticsAccessKey, opts.Config.Secrets.DiagnosticsSecretKey, &http.Client{Timeout: opts.Config.HTTP.RequestTimeout})
		cancelObjects()
		if objectErr != nil {
			_ = store.Close()
			return nil, objectErr
		}
		diagnosticUploadService, err = diagnosticuploads.New(diagnosticRepository, objectStore)
		if err != nil {
			_ = store.Close()
			return nil, err
		}
		if err = diagnosticUploadService.SetRetention(opts.Config.Diagnostics.Retention); err != nil {
			_ = store.Close()
			return nil, err
		}
	}
	var edgeControlHandler http.Handler
	var edgeControlService *controlplane.EdgeService
	if opts.Config.Secrets.EdgeControlCredential != "" {
		edgeControlService = controlplane.NewEdgeService(store, opts.Config.Secrets.EdgeControlCredential)
		edgeControlService.SetCertificateDistribution(opts.CertificateDistribution)
		edgeControlService.SetBandwidthDebiter(userMachineService)
		edgeControlService.SetAuditWriter(auditWriter)
		edgeControlService.SetCredentialIssuer(mintKeys, config.NormalizeIssuer(opts.Config.HTTP.PublicBaseURL), opts.Config.Secrets.EncryptionKey)
		edgeControlService.SetFileTransferPolicy(mint.FileTransferPolicy{Revision: opts.Config.Access.FileTransfer.Revision, MaxFileBytes: opts.Config.Access.FileTransfer.MaxFileBytes, MaxBatchFiles: opts.Config.Access.FileTransfer.MaxBatchFiles, MaxBatchBytes: opts.Config.Access.FileTransfer.MaxBatchBytes, MaxConcurrentTransfers: opts.Config.Access.FileTransfer.MaxConcurrentTransfers, RetentionSeconds: int64(opts.Config.Access.FileTransfer.Retention / time.Second), DeliveryTimeoutSeconds: int64(opts.Config.Access.FileTransfer.DeliveryTimeout / time.Second), MaxPendingSpoolBytes: opts.Config.Access.FileTransfer.MaxPendingSpoolBytes})
		edgeControlHandler = edgeControlService.Handler()
	}
	previewAttachmentMachineVerifier, err := httpapi.NewPreviewAttachmentMachineProofVerifier(enrollmentService)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview carrier machine verifier: %w", err)
	}
	previewAttachmentLeasePrecondition, err := httpapi.NewPreviewAttachmentLeasePreconditionChecker(previewTunnelStore)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview carrier lease precondition: %w", err)
	}
	previewAttachmentHandler, err := previewattachment.NewHTTPHandler(previewAttachmentProduction.Service, previewAttachmentMachineVerifier, previewAttachmentLeasePrecondition)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview carrier host handler: %w", err)
	}
	var previewEdgeAttachmentHandler http.Handler
	var privateAccessAuthorizeHandler http.Handler
	var privateAccessGrantHandler http.Handler
	var privateAccessRoutesHandler http.Handler
	if opts.Config.Secrets.EdgeControlCredential != "" {
		previewEdgeVerifier, verifierErr := previewattachment.NewDBPreviewEdgeRequestVerifier(store, opts.Config.Secrets.EdgeControlCredential)
		if verifierErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure preview carrier edge verifier: %w", verifierErr)
		}
		previewEdgeHandler, edgeHandlerErr := previewattachment.NewEdgeHTTPHandler(previewAttachmentProduction.Service, previewAttachmentProduction.Repository, previewEdgeVerifier)
		err = edgeHandlerErr
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure preview carrier edge handler: %w", err)
		}
		previewCertificateReadiness, readinessErr := tunnelcert.NewSQLStore(store)
		if readinessErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure preview certificate readiness: %w", readinessErr)
		}
		previewAliasProjector, projectorErr := previewdomain.NewPreviewCarrierAliasProjector(previewDomainRepository, previewCertificateReadiness, nil)
		if projectorErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure preview carrier aliases: %w", projectorErr)
		}
		if err = previewEdgeHandler.SetAliasProjector(previewAliasProjector); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("attach preview carrier aliases: %w", err)
		}
		previewEdgeAttachmentHandler = previewEdgeHandler
		privateAccessProduction, productionErr := privateaccess.NewProduction(
			store, previewAttachmentProduction.Repository, mintKeys,
			config.NormalizeIssuer(opts.Config.HTTP.PublicBaseURL), enrollmentService,
			privateaccess.PreviewEdgeVerifierAdapter{Verifier: previewEdgeVerifier},
			privateaccess.AuditWriterSink{Writer: auditWriter},
		)
		if productionErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure private access: %w", productionErr)
		}
		privateAccessAuthorizeHandler = privateAccessProduction.AuthorizeHTTP
		privateAccessGrantHandler = privateAccessProduction.GrantIssueHTTP
		privateAccessRoutesHandler = privateAccessProduction.AccessorRoutes
	}
	telemetryMetrics := telemetry.NewMetrics()
	telemetryHealth, telemetryErr := telemetry.NewHealthTracker(time.Now)
	if telemetryErr != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure telemetry health: %w", telemetryErr)
	}
	telemetryHTTP := &telemetry.HTTPObserver{
		Metrics: telemetryMetrics,
		Identity: func(ctx context.Context) (string, string) {
			return observability.RequestID(ctx), observability.CorrelationID(ctx)
		},
	}
	telemetryProducer := &telemetry.Producer{Metrics: telemetryMetrics, Health: telemetryHealth, Now: time.Now}
	// Connector protocol persistence owns the live session lifecycle. Attach
	// telemetry after the producer is composed; the adapter is best-effort and
	// never changes protocol persistence outcomes.
	connectorPersistentServer.SetTelemetryProducer(telemetryProducer)
	telemetryDiagnostics, telemetryErr := telemetry.NewDiagnostics(telemetry.DiagnosticsConfig{
		Metrics: telemetryMetrics,
		Health:  telemetryHealth,
		Now:     time.Now,
	})
	if telemetryErr != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure telemetry diagnostics: %w", telemetryErr)
	}
	if err = previewDomainReconciler.SetEventSink(previewDNSReconcileTelemetry(telemetryProducer)); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure preview DNS telemetry: %w", err)
	}
	if err = domainReconciler.SetTelemetryObserver(tunnelDNSReconcileTelemetry(telemetryProducer)); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("configure tunnel DNS telemetry: %w", err)
	}
	if opts.CertificateWorker != nil {
		if err = opts.CertificateWorker.SetTelemetryObserver(certificateTelemetry(telemetryProducer)); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure certificate telemetry: %w", err)
		}
	}
	if certificateRuntime != nil && certificateRuntime.PlatformWorker != nil {
		if err = certificateRuntime.PlatformWorker.SetTelemetryObserver(certificateTelemetry(telemetryProducer)); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure platform certificate telemetry: %w", err)
		}
	}
	router := httpapi.NewRouter(httpapi.Options{
		Config:                    opts.Config,
		Logger:                    opts.Logger,
		ReadinessChecker:          checker,
		Auth:                      authService,
		DeviceAuth:                deviceAuthService,
		Billing:                   billingService,
		BillingRecovery:           billingRecovery,
		Catalog:                   catalogRepo,
		CatalogWriter:             catalogRepo,
		Fly:                       flyProvider,
		GitHub:                    githubService,
		Projects:                  projectService,
		EnvironmentVariables:      environmentVariableService,
		TerminalSessions:          terminalSessionService,
		CodexSessions:             codexSessionService,
		EnvironmentAccess:         accessService,
		MeteringRepo:              metering.NewRuntimeRepository(store, opts.Config.Secrets.EncryptionKey, opts.Config.ConfigSync.StaleHeartbeatAfter),
		RuntimeIdentity:           enrollmentService,
		Machines:                  userMachineService,
		MintKeys:                  mintKeys,
		EdgeControl:               edgeControlHandler,
		EdgeControlAdmin:          edgeControlService,
		ProbeRegions:              edgeControlService,
		Enrollment:                enrollmentService,
		HostedBootstrap:           hostedBootstrapService,
		ConfigAssignments:         configAssignmentService,
		ConfigCredentials:         configCredentialService,
		ConfigLeases:              configLeaseService,
		ConfigStatuses:            configStatusService,
		ConfigRepositoryAccess:    configRepositoryAccessService,
		ConfigRuntime:             configRuntimeService,
		ConfigConflicts:           configConflictService,
		Routes:                    routeService,
		Favorites:                 favorites.NewService(store),
		ControlDiagnostics:        controlDiagnostics,
		OperationRecovery:         operationRecovery,
		PeerIdentity:              peerIdentityService,
		PeerSessions:              peerSessionService,
		ManagedSSH:                managedSSHService,
		DiagnosticUploads:         diagnosticUploadService,
		HostedProviderRecovery:    hostedProviderRecovery,
		ReleaseFiles:              releaseFileHandler,
		ReleaseAuthority:          releaseAuthorityService,
		PreviewTunnelAPI:          previewTunnelAPI,
		PreviewLeases:             previewLeaseService,
		PreviewDomains:            previewDomainService,
		Tunnels:                   tunnelService,
		TunnelResources:           tunnelResourceService,
		PreviewLogs:               tunnelResourceService,
		PreviewCarrierAttachment:  previewAttachmentHandler,
		PreviewCarrierEdge:        previewEdgeAttachmentHandler,
		PrivateAccessAuthorize:    privateAccessAuthorizeHandler,
		PrivateAccessGrant:        privateAccessGrantHandler,
		PrivateAccessRoutes:       privateAccessRoutesHandler,
		ConnectorControl:          connectorControlHandler,
		ConnectorCarrierBootstrap: connectorCarrierBootstrapHandler,
		TelemetryHTTP:             telemetryHTTP,
		TelemetryMetrics:          telemetryMetrics,
		TelemetryDiagnostics:      telemetryDiagnostics,
	})
	serverWorkers := []workers.Worker{
		peerSessionService.ExpiryWorker(opts.Config.TerminalSessions.WorkerInterval),
		orchestratorService.Worker(2 * opts.Config.HTTP.RequestTimeout / 15),
		meteringService.Worker(opts.Config.HTTP.RequestTimeout),
		billingService.AutoTopupWorker(opts.Config.HTTP.RequestTimeout),
		terminalSessionService.Worker(opts.Config.TerminalSessions.WorkerInterval),
		userMachineService.Worker(opts.Config.TerminalSessions.WorkerInterval),
		configAssignmentService.WarningReconciliationWorker(opts.Config.TerminalSessions.WorkerInterval),
		configRepositoryAccessService.RevocationWorker(opts.Config.TerminalSessions.WorkerInterval, 25),
		codexSessionService.Worker(time.Minute),
		previewLeaseReconciliationWorker(previewLeaseService, opts.Config.TerminalSessions.WorkerInterval, telemetryProducer),
		tunnelExpiryReconciliationWorker(tunnelService, opts.Config.TerminalSessions.WorkerInterval),
		connectorRotationDispatcher.Run,
		connectorDrainDispatcher.Run,
		domainReconciler.Worker(opts.Config.TerminalSessions.WorkerInterval, 100),
		previewDomainReconciler.Worker(opts.Config.TerminalSessions.WorkerInterval, 100),
		previewAttachmentProduction.Repository.OutboxWorker(opts.Config.TerminalSessions.WorkerInterval),
	}
	if edgeControlService != nil {
		serverWorkers = append(serverWorkers, edgeControlService.TunnelEdgeAssignmentWorker(opts.Config.TerminalSessions.WorkerInterval, 100))
		serverWorkers = append(serverWorkers, edgeControlService.StaleNodeWorker(opts.Config.TerminalSessions.WorkerInterval, controlplane.ControlTunnelNodeStaleAfter()))
	}
	if diagnosticUploadService != nil {
		serverWorkers = append(serverWorkers, diagnosticUploadService.Worker(time.Minute, opts.Logger))
	}
	if opts.CertificateWorker != nil {
		serverWorkers = append(serverWorkers, opts.CertificateWorker.Worker(opts.Config.TerminalSessions.WorkerInterval, 100))
	}
	if certificateRuntime != nil && certificateRuntime.PlatformWorker != nil {
		serverWorkers = append(serverWorkers, certificateRuntime.PlatformWorker.Worker(opts.Config.TerminalSessions.WorkerInterval, 3))
	}
	application := &App{
		cfg:    opts.Config,
		logger: opts.Logger,
		db:     store,
		server: &http.Server{
			Addr:              opts.Config.HTTP.Address,
			Handler:           router,
			ReadHeaderTimeout: opts.Config.HTTP.ReadHeaderTimeout,
		},
		worker:               workers.NewSupervisor(serverWorkers...),
		certificateRuntime:   certificateRuntime,
		telemetryMetrics:     telemetryMetrics,
		telemetryHealth:      telemetryHealth,
		telemetryHTTP:        telemetryHTTP,
		telemetryDiagnostics: telemetryDiagnostics,
		telemetryProducer:    telemetryProducer,
	}
	runtimeTransferred = true
	return application, nil
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
	if cfg.Providers.FakeMode && !realGitHubOAuthConfigured(cfg) {
		return &pbgithub.FakeClient{}
	}
	return pbgithub.HTTPClient{
		BaseURL:  cfg.Providers.GitHub.BaseURL,
		TokenURL: cfg.GitHub.OAuthTokenURL,
		Client:   providerHTTPClient("github", cfg.HTTP.RequestTimeout),
	}
}

func realGitHubOAuthConfigured(cfg config.Config) bool {
	return strings.TrimSpace(cfg.Secrets.GitHubClientID) != "" &&
		strings.TrimSpace(cfg.Secrets.GitHubClientSecret) != ""
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
	//paperboat:allow-source-policy default-http owner=server-runtime reason=instrument-standard-transport-behind-configured-timeout
	return &http.Client{Timeout: timeout, Transport: observability.InstrumentProviderTransport(provider, http.DefaultTransport)}
}

func publicURLSecure(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https"
}

func (a *App) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runContext, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	telemetryEvents, telemetryErr := telemetry.NewEventLog(1024)
	if telemetryErr != nil {
		return fmt.Errorf("start telemetry event log: %w", telemetryErr)
	}
	a.telemetryEvents = telemetryEvents
	a.telemetryHTTP.Events = telemetryEvents
	if a.telemetryDiagnostics != nil {
		a.telemetryDiagnostics.SetEventLog(telemetryEvents)
	}
	a.telemetryProducer.Events = telemetryEvents
	defer telemetryEvents.Close()
	a.telemetryStartedAt = time.Now().UTC()
	if a.telemetryMetrics != nil {
		_ = a.telemetryMetrics.IncCounter(telemetry.MetricServiceRestarts, telemetry.MetricLabels{"outcome": "success"})
	}
	a.updateServiceTelemetry(telemetry.StatusReady, "running", "Control-plane service is running.", "", telemetry.RetryNone, time.Time{})
	serverErrors := make(chan error, 1)
	workerErrors := make(chan error, 1)
	go func() {
		a.logger.Info("http server starting", "address", a.cfg.HTTP.Address)
		if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
			return
		}
		serverErrors <- nil
	}()
	go func() {
		workerErrors <- a.worker.Run(runContext)
	}()

	var runErr error
	var workerErr error
	workerDone := false
	select {
	case <-ctx.Done():
		runErr = ctx.Err()
	case err := <-serverErrors:
		if err != nil {
			runErr = err
			a.updateServiceTelemetry(telemetry.StatusDown, "http_server_failed", "The control-plane HTTP server stopped unexpectedly.", "Restart paperboat-server and inspect correlated telemetry.", telemetry.RetryScheduled, time.Now().UTC().Add(time.Second))
		}
	case err := <-workerErrors:
		workerDone = true
		workerErr = err
		if err != nil && !errors.Is(err, context.Canceled) {
			runErr = err
			a.updateServiceTelemetry(telemetry.StatusDown, "worker_failed", "A required control-plane worker stopped unexpectedly.", "Restart paperboat-server and inspect correlated telemetry.", telemetry.RetryScheduled, time.Now().UTC().Add(time.Second))
		}
	}

	// Stop and join workers before closing the certificate hub or database. A
	// worker may still be holding an issuance/distribution reference after the
	// HTTP server has failed, so closing those components first creates a race
	// and can lose a terminal cleanup operation.
	cancelRun()
	workerShutdownCtx, cancelWorkerShutdown := context.WithTimeout(context.Background(), a.cfg.HTTP.ShutdownTimeout)
	if !workerDone {
		select {
		case workerErr = <-workerErrors:
			workerDone = true
		case <-workerShutdownCtx.Done():
			runErr = errors.Join(runErr, fmt.Errorf("stop workers: %w", workerShutdownCtx.Err()))
		}
	}
	workerJoinErr := a.worker.Wait(workerShutdownCtx)
	if workerJoinErr != nil {
		runErr = errors.Join(runErr, fmt.Errorf("join workers: %w", workerJoinErr))
	}
	cancelWorkerShutdown()
	if workerErr != nil && !errors.Is(workerErr, context.Canceled) && runErr == nil {
		runErr = workerErr
	}

	serverShutdownCtx, cancelServerShutdown := context.WithTimeout(context.Background(), a.cfg.HTTP.ShutdownTimeout)
	serverShutdownErr := a.server.Shutdown(serverShutdownCtx)
	cancelServerShutdown()
	if workerJoinErr != nil || serverShutdownErr != nil {
		// A child worker or HTTP handler may still hold the certificate hub or
		// database. Returning without closing those shared dependencies is safer
		// than racing live work; process teardown remains the final containment
		// boundary after a bounded graceful shutdown fails.
		return errors.Join(runErr, serverShutdownErr)
	}
	var runtimeCloseErr error
	if a.certificateRuntime != nil {
		runtimeCloseErr = a.certificateRuntime.Close()
	}
	if runErr == nil || errors.Is(runErr, context.Canceled) {
		a.updateServiceTelemetry(telemetry.StatusNotApplicable, "stopped", "Control-plane service stopped.", "", telemetry.RetryNone, time.Time{})
	}
	databaseCloseErr := a.db.Close()
	if runtimeCloseErr != nil {
		return fmt.Errorf("close certificate runtime: %w", runtimeCloseErr)
	}
	if databaseCloseErr != nil {
		return fmt.Errorf("close database: %w", databaseCloseErr)
	}
	return runErr
}

func (a *App) updateServiceTelemetry(status telemetry.HealthStatus, code, summary, repair string, retry telemetry.RetryDecision, nextRetryAt time.Time) {
	if a == nil {
		return
	}
	if a.telemetryHealth != nil {
		_ = a.telemetryHealth.Update(telemetry.HealthUpdate{Dimension: telemetry.DimensionService, Status: status, Code: code, Summary: summary, RepairAction: repair, CorrelationID: "cor_server_lifecycle", Retry: retry, NextRetryAt: nextRetryAt})
	}
	if a.telemetryMetrics != nil {
		selected := "stopped"
		if status == telemetry.StatusReady {
			selected = "running"
		} else if status == telemetry.StatusDegraded || status == telemetry.StatusDown {
			selected = "degraded"
		}
		uptime := uint64(0)
		if !a.telemetryStartedAt.IsZero() {
			elapsed := time.Since(a.telemetryStartedAt)
			if elapsed > 0 {
				uptime = uint64(elapsed.Seconds())
			}
		}
		for _, state := range []string{"running", "degraded", "stopped"} {
			value := uint64(0)
			if state == selected {
				value = uptime
			}
			_ = a.telemetryMetrics.SetGauge(telemetry.MetricServiceUptime, telemetry.MetricLabels{"state": state}, value)
		}
	}
	if a.telemetryEvents != nil {
		severity, outcome := telemetry.SeverityInfo, telemetry.OutcomeStateChange
		if status == telemetry.StatusDegraded || status == telemetry.StatusDown {
			severity, outcome = telemetry.SeverityError, telemetry.OutcomeFailed
		}
		_, _ = a.telemetryEvents.Record(telemetry.EventInput{At: time.Now().UTC(), Severity: severity, Component: telemetry.DimensionService, Name: "service_lifecycle", Code: code, Outcome: outcome, Message: summary, CorrelationID: "cor_server_lifecycle", Retry: retry, NextRetryAt: nextRetryAt})
	}
}

type readinessChecker struct {
	cfg config.Config
	db  *db.DB
}

func (r readinessChecker) Ready(ctx context.Context) error {
	if err := r.db.Ping(ctx); err != nil {
		return fmt.Errorf("database is not ready: %w", err)
	}
	if r.cfg.Environment == config.EnvironmentProduction {
		if err := releases.Ready(r.cfg.ReleaseDirectory); err != nil {
			return fmt.Errorf("release distribution is not ready: %w", err)
		}
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
