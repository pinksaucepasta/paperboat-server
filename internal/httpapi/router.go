package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/access"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/catalog"
	"github.com/pinksaucepasta/paperboat-server/internal/classifier"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/configsync"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	pbgithub "github.com/pinksaucepasta/paperboat-server/internal/github"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
	"github.com/pinksaucepasta/paperboat-server/internal/terminalsessions"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

type ReadinessChecker interface {
	Ready(context.Context) error
}

type Options struct {
	Config                 config.Config
	Logger                 *slog.Logger
	ReadinessChecker       ReadinessChecker
	Auth                   *auth.Service
	DeviceAuth             *auth.DeviceService
	Billing                *billing.Service
	BillingRecovery        *billing.RecoveryService
	Catalog                catalog.Reader
	CatalogWriter          catalog.RegionWriter
	Fly                    fly.Client
	GitHub                 *pbgithub.Service
	Projects               *projects.Service
	TerminalSessions       *terminalsessions.Service
	EnvironmentAccess      *access.Service
	MeteringRepo           *metering.RuntimeRepository
	ActivityIdentity       *controlplane.EnrollmentService
	ConfigSync             *configsync.Repository
	Classifier             *classifier.Controller
	UserMachines           *usermachines.Service
	MintKeys               *mint.Provider
	EdgeControl            http.Handler
	EdgeControlAdmin       *controlplane.EdgeService
	Enrollment             *controlplane.EnrollmentService
	HostedBootstrap        *controlplane.HostedBootstrapService
	ConfigAssignments      *controlplane.ConfigAssignmentService
	ConfigCredentials      *controlplane.ConfigCredentialService
	ConfigLeases           *controlplane.ConfigLeaseService
	ConfigStatuses         *controlplane.ConfigStatusService
	ConfigRepositoryAccess *controlplane.ConfigRepositoryAccessService
	ConfigRuntime          *controlplane.ConfigRuntimeService
	ConfigClassification   *controlplane.ConfigClassificationService
	ConfigConflicts        *controlplane.ConfigConflictService
	Routes                 *controlplane.RouteService
	Previews               *controlplane.PreviewService
	ControlDiagnostics     *controlplane.DiagnosticsService
	OperationRecovery      *controlplane.OperationRecoveryService
	HostedProviderRecovery *controlplane.HostedProviderRecoveryService
	OverrideHandler        http.Handler
}

func NewRouter(opts Options) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	var handler http.Handler
	if opts.OverrideHandler != nil {
		handler = opts.OverrideHandler
	} else {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", health)
		mux.HandleFunc("GET /readyz", ready(opts.ReadinessChecker))
		mux.HandleFunc("GET /v1/client-configuration", clientConfiguration(opts.Config))
		mux.Handle("GET /metrics", metrics(opts.ControlDiagnostics))
		if opts.MintKeys != nil {
			mux.Handle("GET /.well-known/jwks.json", opts.MintKeys)
		}
		if opts.EdgeControl != nil {
			mux.Handle("/v1/", opts.EdgeControl)
		}
		if opts.Previews != nil {
			mux.Handle("GET /v1/tls/authorizations/previews", previewTLSAsk(opts.Previews))
			mux.Handle("GET /v1/tls/authorizations/routes", previewTLSAsk(opts.Previews))
		}
		if opts.Enrollment != nil {
			mux.HandleFunc("POST /v1/helper-enrollments", helperEnrollmentExchange(opts.Enrollment, opts.Logger))
			mux.HandleFunc("POST /v1/hosted-helper-enrollments", hostedHelperEnrollmentExchange(opts.Enrollment, opts.Logger))
			mux.HandleFunc("POST /v1/helper-identity-renewals", helperIdentityRenew(opts.Enrollment))
			if opts.UserMachines != nil {
				mux.Handle("POST /v1/user-machine-installation-failures", helperInstallationFailure(opts.Enrollment, opts.UserMachines))
			}
			if opts.Previews != nil {
				mux.Handle("POST /v1/previews/credentials", helperPreviewCredential(opts.Enrollment))
				mux.Handle("POST /v1/previews/operations", helperPreviewOperation(opts.Previews, opts.Enrollment))
				mux.Handle("POST /v1/previews/observations", helperPreviewObservation(opts.Previews, opts.Enrollment))
			}
			if opts.Auth != nil {
				mux.Handle("POST /v1/environments/{environment_id}/helper-enrollments", requireAuth(opts.Auth, requireCSRF(opts.Auth, helperEnrollmentIssue(opts.Enrollment))))
				mux.Handle("POST /v1/environments/{environment_id}/helpers/{helper_id}/replace", requireAuth(opts.Auth, requireCSRF(opts.Auth, helperReplacement(opts.Enrollment))))
			}
		}
		if opts.HostedBootstrap != nil {
			mux.HandleFunc("POST /v1/hosted-helper-bootstrap", hostedBootstrapGet(opts.HostedBootstrap))
		}
		if opts.ConfigCredentials != nil {
			mux.HandleFunc("POST /v1/config/credentials", configCredentialIssue(opts.ConfigCredentials))
		}
		if opts.ConfigLeases != nil {
			mux.HandleFunc("POST /v1/config/leases/acquire", configLeaseAcquire(opts.ConfigLeases))
			mux.HandleFunc("POST /v1/config/leases/renew", configLeaseRenew(opts.ConfigLeases))
			mux.HandleFunc("POST /v1/config/leases/release", configLeaseRelease(opts.ConfigLeases))
		}
		if opts.ConfigStatuses != nil {
			mux.HandleFunc("POST /v1/config/status", configStatusRecord(opts.ConfigStatuses, opts.Logger))
		}
		if opts.ConfigRepositoryAccess != nil {
			mux.HandleFunc("POST /v1/config/repository-access", configRepositoryAccessIssue(opts.ConfigRepositoryAccess))
		}
		if opts.ConfigRuntime != nil {
			mux.HandleFunc("POST /v1/config/runtime", configRuntimeGet(opts.ConfigRuntime))
		}
		if opts.ConfigClassification != nil {
			mux.HandleFunc("POST /v1/config/classify", configClassification(opts.ConfigClassification))
		}
		if opts.ConfigConflicts != nil {
			mux.HandleFunc("POST /v1/config/conflict-resolutions/pending", configConflictPending(opts.ConfigConflicts))
			mux.HandleFunc("POST /v1/config/conflict-resolutions/acknowledge", configConflictAcknowledge(opts.ConfigConflicts))
		}
		if opts.Auth != nil {
			registerAuthRoutes(mux, opts)
			if opts.Previews != nil {
				previewAuth := func(scope string, next http.Handler) http.Handler {
					if opts.DeviceAuth != nil {
						return requireAnyAuth(opts.Auth, opts.DeviceAuth, requireScope(scope, next))
					}
					return requireAuth(opts.Auth, next)
				}
				mux.Handle("GET /v1/previews", previewAuth("projects:read", ownedPreviewList(opts.Previews)))
				mux.Handle("DELETE /v1/previews/{preview_id}", previewAuth("projects:connect", requireCSRF(opts.Auth, ownedPreviewRevoke(opts.Previews))))
			}
			if opts.Routes != nil {
				mux.Handle("POST /v1/environments/{environment_id}/routes", requireAuth(opts.Auth, requireCSRF(opts.Auth, routeIntentCreate(opts.Routes))))
				mux.Handle("PATCH /v1/routes/{route_id}", requireAuth(opts.Auth, requireCSRF(opts.Auth, routeIntentTransition(opts.Routes))))
			}
			if opts.ConfigAssignments != nil {
				configAuth := func(scope string, next http.Handler) http.Handler {
					if opts.DeviceAuth != nil {
						return requireAnyAuth(opts.Auth, opts.DeviceAuth, requireScope(scope, next))
					}
					return requireAuth(opts.Auth, next)
				}
				mux.Handle("GET /v1/config-repositories", configAuth("projects:read", configRepositories(opts.ConfigAssignments)))
				mux.Handle("GET /v1/config-repositories/candidates", configAuth("projects:read", configRepositoryCandidates(opts.ConfigAssignments)))
				mux.Handle("POST /v1/config-repositories", requireAuth(opts.Auth, requireCSRF(opts.Auth, configRepositoryConnect(opts.ConfigAssignments))))
				mux.Handle("DELETE /v1/config-repositories/{repository_id}", requireAuth(opts.Auth, requireCSRF(opts.Auth, configRepositoryDisconnect(opts.ConfigAssignments))))
				mux.Handle("GET /v1/environments/{environment_id}/config-assignment", configAuth("projects:read", configAssignmentGet(opts.ConfigAssignments)))
				mux.Handle("PUT /v1/environments/{environment_id}/config-assignment", configAuth("projects:connect", requireCSRF(opts.Auth, configAssignmentSet(opts.ConfigAssignments))))
				mux.Handle("GET /v1/environments/{environment_id}/config-assignment/warning", configAuth("projects:read", configWarning(opts.ConfigAssignments)))
				mux.Handle("POST /v1/environments/{environment_id}/config-assignment/consent", requireAuth(opts.Auth, requireCSRF(opts.Auth, configConsent(opts.ConfigAssignments))))
				mux.Handle("DELETE /v1/environments/{environment_id}/config-assignment/consent", requireAuth(opts.Auth, requireCSRF(opts.Auth, configConsentRemove(opts.ConfigAssignments))))
				mux.Handle("DELETE /v1/environments/{environment_id}/config-assignment", configAuth("projects:connect", requireCSRF(opts.Auth, configAssignmentClear(opts.ConfigAssignments))))
			}
		}
		if opts.UserMachines != nil {
			userMachineAuth := func(scope string, next http.Handler) http.Handler {
				if opts.DeviceAuth != nil {
					return requireAnyAuth(opts.Auth, opts.DeviceAuth, requireScope(scope, next))
				}
				return requireAuth(opts.Auth, next)
			}
			mux.HandleFunc("POST /v1/user-machines/pairings", userMachinePairings(opts.UserMachines))
			mux.Handle("POST /v1/user-machine-enrollments", requireAuth(opts.Auth, requireCSRF(opts.Auth, userMachineEnrollmentStart(opts.UserMachines))))
			mux.Handle("GET /v1/user-machine-enrollments/{enrollment_id}", requireAuth(opts.Auth, userMachineEnrollmentStatus(opts.UserMachines)))
			mux.Handle("POST /v1/user-machine-enrollments/{enrollment_id}/cancel", requireAuth(opts.Auth, requireCSRF(opts.Auth, userMachineEnrollmentCancel(opts.UserMachines))))
			mux.Handle("POST /v1/user-machine-enrollments/{enrollment_id}/retry", requireAuth(opts.Auth, requireCSRF(opts.Auth, userMachineEnrollmentRetry(opts.UserMachines))))
			mux.Handle("GET /v1/user-machines/overview", userMachineAuth("projects:read", userMachineOverview(opts.UserMachines)))
			mux.Handle("GET /v1/user-machines/{user_machine_id}", requireAuth(opts.Auth, userMachineGet(opts.UserMachines)))
			if opts.DeviceAuth != nil {
				mux.Handle("POST /v1/user-machines/{user_machine_id}/connection-descriptor", requireBearerAuth(opts.DeviceAuth, requireScope("projects:connect", userMachineConnectionDescriptor(opts.UserMachines))))
				mux.Handle("GET /v1/user-machines/{user_machine_id}/connection-readiness", requireBearerAuth(opts.DeviceAuth, requireScope("projects:connect", userMachineConnectionReadiness(opts.UserMachines))))
			}
			mux.Handle("GET /v1/user-machines/{user_machine_id}/terminal-sessions", userMachineAuth("projects:read", userMachineTerminalSessionsList(opts.UserMachines)))
			mux.Handle("POST /v1/user-machines/{user_machine_id}/terminal-sessions", userMachineAuth("projects:connect", userMachineTerminalSessionsCreate(opts.UserMachines)))
			mux.Handle("PATCH /v1/user-machines/{user_machine_id}/terminal-sessions/{session_id}", userMachineAuth("projects:connect", userMachineTerminalSessionsRename(opts.UserMachines)))
			mux.Handle("POST /v1/user-machines/{user_machine_id}/terminal-sessions/{session_id}/close", userMachineAuth("projects:connect", userMachineTerminalSessionsClose(opts.UserMachines)))
			mux.Handle("DELETE /v1/user-machines/{user_machine_id}/terminal-sessions/{session_id}", userMachineAuth("projects:connect", userMachineTerminalSessionsDelete(opts.UserMachines)))
			mux.HandleFunc("POST /v1/user-machines/pairings/installation", userMachineInstallationConsume(opts.UserMachines))
			mux.Handle("POST /v1/user-machines/pairings/{user_code}/approve", requireAuth(opts.Auth, requireCSRF(opts.Auth, userMachinePairingApprove(opts.UserMachines))))
			mux.Handle("POST /v1/user-machines/pairings/{user_code}/deny", requireAuth(opts.Auth, requireCSRF(opts.Auth, userMachinePairingDeny(opts.UserMachines))))
			mux.Handle("POST /v1/user-machines/{user_machine_id}/disconnect", userMachineAuth("projects:connect", requireCSRF(opts.Auth, userMachineDisconnect(opts.UserMachines))))
			mux.Handle("DELETE /v1/user-machines/{user_machine_id}", userMachineAuth("projects:connect", requireCSRF(opts.Auth, userMachineDelete(opts.UserMachines))))
			if opts.DeviceAuth != nil {
				mux.Handle("GET /v1/user-machines", requireAnyAuth(opts.Auth, opts.DeviceAuth, requireScope("projects:read", userMachinesList(opts.UserMachines))))
			} else {
				mux.Handle("GET /v1/user-machines", requireAuth(opts.Auth, userMachinesList(opts.UserMachines)))
			}
		}
		if opts.Billing != nil {
			mux.HandleFunc("POST /v1/webhooks/polar", polarWebhook(opts.Billing, opts.Config.Secrets.PolarWebhookSecret, opts.Config.Billing.PolarWebhookTolerance))
		}
		if opts.MeteringRepo != nil {
			mux.HandleFunc("POST /v1/environment-activity-observations", activityHeartbeat(opts.MeteringRepo, opts.ActivityIdentity, opts.Config.ConfigSync.SummaryLimit))
		}
		mux.HandleFunc("/", notFound)
		handler = mux
	}
	handler = secureHeaders(handler)
	handler = cors(opts.Config.HTTP.AllowedOrigins, handler)
	handler = bodyLimit(opts.Config.HTTP.MaxBodyBytes, handler)
	handler = timeout(opts.Config.HTTP.RequestTimeout, opts.Logger, handler)
	handler = recoverer(opts.Logger, handler)
	handler = accessLog(opts.Logger, handler)
	handler = requestID(handler)
	return handler
}

func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{
		"status": "healthy",
	}})
}

func metrics(diagnostics *controlplane.DiagnosticsService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			writeError(w, r, http.StatusForbidden, "forbidden", "Metrics are available only from localhost.")
			return
		}
		result := observability.MetricsSnapshot()
		if diagnostics != nil {
			durable, err := diagnostics.Metrics(r.Context())
			if err != nil {
				writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Control-plane diagnostics are unavailable.")
				return
			}
			for key, value := range durable {
				result[key] = value
			}
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
	}
}

func ready(checker ReadinessChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if checker == nil {
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Readiness checks are not configured.")
			return
		}
		if err := checker.Ready(r.Context()); err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Service dependencies are not ready.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{
			"status": "ready",
		}})
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, "not_found", "The requested endpoint was not found.")
}

func registerAuthRoutes(mux *http.ServeMux, opts Options) {
	userAuth := func(scope string, next http.Handler) http.Handler {
		if opts.DeviceAuth != nil {
			return requireAnyAuth(opts.Auth, opts.DeviceAuth, requireScope(scope, next))
		}
		return requireAuth(opts.Auth, next)
	}
	accountRead := func(next http.Handler) http.Handler {
		if opts.DeviceAuth != nil {
			return requireAnyAuth(opts.Auth, opts.DeviceAuth, requireScope("account:read", next))
		}
		return requireAuth(opts.Auth, next)
	}
	mux.HandleFunc("GET /v1/auth/workos/state", workOSState(opts.Auth))
	mux.HandleFunc("POST /v1/auth/workos/callback", workOSCallback(opts.Auth))
	mux.Handle("GET /v1/auth/workos/reauth/state", requireAuth(opts.Auth, workOSReauthState(opts.Auth)))
	mux.Handle("POST /v1/auth/workos/reauth/callback", requireAuth(opts.Auth, workOSReauthCallback(opts.Auth)))
	mux.Handle("POST /v1/auth/logout", requireAuth(opts.Auth, logout(opts.Auth, opts.EnvironmentAccess)))
	mux.Handle("GET /v1/auth/csrf", requireAuth(opts.Auth, csrf(opts.Auth)))
	meHandler := requireAuth(opts.Auth, me(opts.Auth))
	if opts.DeviceAuth != nil {
		meHandler = requireAnyAuth(opts.Auth, opts.DeviceAuth, me(opts.Auth))
	}
	mux.Handle("GET /v1/me", meHandler)
	if opts.ConfigStatuses != nil {
		mux.Handle("GET /v1/config-sync/status", accountRead(requireEntitlement(opts.Auth, configSyncStatus(opts.ConfigStatuses))))
	}
	if opts.ConfigConflicts != nil {
		mux.Handle("POST /v1/config-sync/environments/{environment_id}/conflict-resolutions", requireAuth(opts.Auth, requireCSRF(opts.Auth, configConflictRequest(opts.ConfigConflicts))))
	}
	if opts.ConfigSync != nil {
		mux.Handle("GET /v1/config-sync/overrides", requireAuth(opts.Auth, requireEntitlement(opts.Auth, configSyncOverrides(opts.ConfigSync))))
		mux.Handle("PUT /v1/config-sync/overrides", requireAuth(opts.Auth, requireEntitlement(opts.Auth, configSyncOverridePut(opts.ConfigSync))))
		mux.Handle("DELETE /v1/config-sync/overrides", requireAuth(opts.Auth, requireEntitlement(opts.Auth, configSyncOverrideDelete(opts.ConfigSync))))
		mux.Handle("POST /v1/config-sync/recovery-key/export", requireAuth(opts.Auth, requireEntitlement(opts.Auth, configSyncRecoveryExport(opts.Auth, opts.ConfigSync))))
		mux.Handle("POST /v1/config-sync/recovery-key/rotate", requireAuth(opts.Auth, requireEntitlement(opts.Auth, configSyncKeyRotate(opts.Auth, opts.ConfigSync))))
	}
	if opts.DeviceAuth != nil {
		requestNetwork := newRequestNetwork(opts.Config.HTTP.TrustedProxyCIDRs)
		mux.HandleFunc("POST /v1/auth/device/authorize", deviceAuthorize(opts.DeviceAuth, requestNetwork))
		mux.HandleFunc("POST /v1/auth/device/token", deviceToken(opts.DeviceAuth, requestNetwork))
		mux.Handle("GET /v1/auth/device/requests/{user_code}", requireAuth(opts.Auth, deviceRequest(opts.DeviceAuth, opts.Config.HTTP.PublicBaseURL)))
		mux.Handle("POST /v1/auth/device/requests/{user_code}/approve", requireAuth(opts.Auth, requireCSRF(opts.Auth, deviceDecision(opts.DeviceAuth, opts.Config.HTTP.PublicBaseURL, true))))
		mux.Handle("POST /v1/auth/device/requests/{user_code}/deny", requireAuth(opts.Auth, requireCSRF(opts.Auth, deviceDecision(opts.DeviceAuth, opts.Config.HTTP.PublicBaseURL, false))))
		mux.HandleFunc("POST /v1/auth/token/refresh", tokenRefresh(opts.DeviceAuth))
		mux.HandleFunc("POST /v1/auth/token/revoke", tokenRevoke(opts.DeviceAuth))
		mux.Handle("GET /v1/auth/cli-client-sessions", requireAnyAuth(opts.Auth, opts.DeviceAuth, requireScope("account:read", cliClientSessionsList(opts.DeviceAuth))))
		mux.Handle("DELETE /v1/auth/cli-client-sessions/{cli_client_session_id}", requireAnyAuth(opts.Auth, opts.DeviceAuth, requireCSRF(opts.Auth, requireScope("clients:revoke", cliClientSessionDelete(opts.DeviceAuth)))))
	}
	if opts.Billing != nil {
		mux.Handle("GET /v1/billing/entitlement", requireAuth(opts.Auth, billingEntitlement(opts.Billing)))
		mux.Handle("GET /v1/billing/usage", requireAuth(opts.Auth, billingUsage(opts.Billing)))
		mux.Handle("GET /v1/billing/plan-products", requireAuth(opts.Auth, billingPlanProducts(opts.Billing)))
		mux.Handle("GET /v1/billing/storage", requireAuth(opts.Auth, billingStorage(opts.Billing)))
		mux.Handle("GET /v1/billing/storage-change-preview", requireAuth(opts.Auth, billingStoragePreview(opts.Billing)))
		mux.Handle("PUT /v1/billing/storage", requireAuth(opts.Auth, requireCSRF(opts.Auth, billingStorageUpdate(opts.Billing))))
		mux.Handle("GET /v1/billing/auto-topup", requireAuth(opts.Auth, billingAutoTopup(opts.Billing)))
		mux.Handle("PUT /v1/billing/auto-topup", requireAuth(opts.Auth, requireCSRF(opts.Auth, billingAutoTopupUpdate(opts.Billing))))
		mux.Handle("POST /v1/billing/checkout", requireAuth(opts.Auth, requireCSRF(opts.Auth, billingCheckout(opts.Billing))))
		mux.Handle("POST /v1/billing/customer-portal", requireAuth(opts.Auth, requireCSRF(opts.Auth, billingCustomerPortal(opts.Billing))))
		if opts.Projects != nil {
			mux.Handle("GET /v1/usage-summary", accountRead(requireEntitlement(opts.Auth, dashboardUsageSummary(opts.Billing, opts.Projects))))
		}
	} else {
		mux.Handle("GET /v1/billing/entitlement", requireAuth(opts.Auth, http.HandlerFunc(paymentRequired)))
		mux.Handle("GET /v1/billing/usage", requireAuth(opts.Auth, http.HandlerFunc(paymentRequired)))
		mux.Handle("GET /v1/billing/plan-products", requireAuth(opts.Auth, http.HandlerFunc(paymentRequired)))
		mux.Handle("GET /v1/billing/storage", requireAuth(opts.Auth, http.HandlerFunc(paymentRequired)))
		mux.Handle("GET /v1/billing/storage-change-preview", requireAuth(opts.Auth, http.HandlerFunc(paymentRequired)))
		mux.Handle("PUT /v1/billing/storage", requireAuth(opts.Auth, requireCSRF(opts.Auth, http.HandlerFunc(dependencyUnavailable))))
		mux.Handle("GET /v1/billing/auto-topup", requireAuth(opts.Auth, http.HandlerFunc(paymentRequired)))
		mux.Handle("PUT /v1/billing/auto-topup", requireAuth(opts.Auth, requireCSRF(opts.Auth, http.HandlerFunc(dependencyUnavailable))))
		mux.Handle("POST /v1/billing/checkout", requireAuth(opts.Auth, requireCSRF(opts.Auth, http.HandlerFunc(dependencyUnavailable))))
		mux.Handle("POST /v1/billing/customer-portal", requireAuth(opts.Auth, requireCSRF(opts.Auth, http.HandlerFunc(dependencyUnavailable))))
	}
	if opts.EdgeControlAdmin != nil {
		mux.Handle("POST /v1/admin/edge/usage-keys", requireAuth(opts.Auth, requireCSRF(opts.Auth, requireAdmin(adminProvisionUsageKey(opts.EdgeControlAdmin)))))
		mux.Handle("POST /v1/admin/edge/usage-keys/{key_id}/revoke", requireAuth(opts.Auth, requireCSRF(opts.Auth, requireAdmin(adminRevokeUsageKey(opts.EdgeControlAdmin)))))
		mux.Handle("POST /v1/admin/mint/signing-keys/{key_id}/revoke", requireAuth(opts.Auth, requireCSRF(opts.Auth, requireAdmin(adminRevokeSigningKey(opts.EdgeControlAdmin)))))
	}
	if opts.OperationRecovery != nil {
		mux.Handle("POST /v1/admin/control-operations/{operation_id}/recover", requireAuth(opts.Auth, requireCSRF(opts.Auth, requireAdmin(adminRecoverControlOperation(opts.OperationRecovery)))))
	}
	if opts.HostedProviderRecovery != nil {
		mux.Handle("POST /v1/admin/hosted-provider-operations/{operation_id}/recover", requireAuth(opts.Auth, requireCSRF(opts.Auth, requireAdmin(adminRecoverHostedProviderOperation(opts.HostedProviderRecovery)))))
	}
	if opts.BillingRecovery != nil {
		mux.Handle("POST /v1/admin/billing/uncertain/{kind}/{operation_id}/recover", requireAuth(opts.Auth, requireCSRF(opts.Auth, requireAdmin(adminRecoverBillingOperation(opts.BillingRecovery)))))
	}
	if opts.Catalog != nil {
		mux.Handle("GET /v1/catalog/plans", userAuth("account:read", catalogPlans(opts.Catalog)))
		mux.Handle("GET /v1/catalog/machine-types", userAuth("projects:read", catalogMachineTypes(opts.Catalog)))
		mux.Handle("GET /v1/catalog/presets", userAuth("projects:read", catalogPresets(opts.Catalog)))
		mux.Handle("GET /v1/catalog/idle-timeouts", userAuth("projects:read", catalogIdleTimeouts(opts.Catalog)))
		mux.Handle("GET /v1/catalog/regions", userAuth("projects:read", catalogRegions(opts.Catalog, opts.Fly, opts.CatalogWriter)))
	} else {
		mux.Handle("GET /v1/catalog/plans", requireAuth(opts.Auth, http.HandlerFunc(dependencyUnavailable)))
		mux.Handle("GET /v1/catalog/machine-types", requireAuth(opts.Auth, http.HandlerFunc(dependencyUnavailable)))
		mux.Handle("GET /v1/catalog/presets", requireAuth(opts.Auth, http.HandlerFunc(dependencyUnavailable)))
		mux.Handle("GET /v1/catalog/idle-timeouts", requireAuth(opts.Auth, http.HandlerFunc(dependencyUnavailable)))
		mux.Handle("GET /v1/catalog/regions", requireAuth(opts.Auth, http.HandlerFunc(dependencyUnavailable)))
	}
	if opts.GitHub != nil {
		mux.Handle("GET /v1/github/status", requireAuth(opts.Auth, githubStatus(opts.GitHub)))
		mux.Handle("GET /v1/github/repositories", userAuth("projects:read", requireEntitlement(opts.Auth, githubRepositories(opts.GitHub))))
		mux.Handle("POST /v1/github/oauth/start", requireAuth(opts.Auth, requireCSRF(opts.Auth, githubOAuthStart(opts.Auth, opts.GitHub))))
		mux.Handle("GET /v1/github/oauth/callback", requireAuth(opts.Auth, githubOAuthBrowserCallback(opts.Auth, opts.GitHub)))
		mux.Handle("POST /v1/github/oauth/callback", requireAuth(opts.Auth, requireCSRF(opts.Auth, githubOAuthCallback(opts.Auth, opts.GitHub))))
		mux.Handle("POST /v1/github/config-repositories/provision", requireAuth(opts.Auth, requireCSRF(opts.Auth, githubProvisionConfigRepo(opts.GitHub))))
		if opts.Projects != nil {
			mux.Handle("GET /v1/projects", userAuth("projects:read", requireEntitlement(opts.Auth, projectsList(opts.Projects))))
			mux.Handle("POST /v1/projects", userAuth("projects:connect", requireEntitlement(opts.Auth, requireGitHubConnection(opts.GitHub, projectsCreate(opts.Projects)))))
			mux.Handle("GET /v1/projects/{project_id}", requireAuth(opts.Auth, requireEntitlement(opts.Auth, projectsGet(opts.Projects))))
			mux.Handle("PATCH /v1/projects/{project_id}", requireAuth(opts.Auth, requireEntitlement(opts.Auth, projectsUpdate(opts.Projects))))
			mux.Handle("DELETE /v1/projects/{project_id}", requireAuth(opts.Auth, requireEntitlement(opts.Auth, projectsDelete(opts.Projects, opts.EnvironmentAccess))))
			mux.Handle("POST /v1/projects/{project_id}/start", requireAuth(opts.Auth, requireEntitlement(opts.Auth, requireCSRF(opts.Auth, projectsStart(opts.Projects)))))
			mux.Handle("POST /v1/projects/{project_id}/stop", requireAuth(opts.Auth, requireEntitlement(opts.Auth, requireCSRF(opts.Auth, projectsStop(opts.Projects, opts.EnvironmentAccess)))))
			mux.Handle("POST /v1/projects/{project_id}/restart", requireAuth(opts.Auth, requireEntitlement(opts.Auth, requireCSRF(opts.Auth, projectsRestart(opts.Projects)))))
			mux.Handle("POST /v1/projects/{project_id}/keep-alive", requireAuth(opts.Auth, requireEntitlement(opts.Auth, requireCSRF(opts.Auth, projectsKeepAlive(opts.Projects)))))
			mux.Handle("POST /v1/projects/{project_id}/activity", userAuth("projects:connect", requireEntitlement(opts.Auth, projectsActivity(opts.Projects))))
			mux.Handle("GET /v1/projects/{project_id}/events", requireAuth(opts.Auth, requireEntitlement(opts.Auth, projectsEvents(opts.Projects))))
			if opts.EnvironmentAccess != nil {
				if opts.TerminalSessions != nil {
					mux.Handle("GET /v1/projects/{project_id}/terminal-sessions", userAuth("projects:read", requireEntitlement(opts.Auth, terminalSessionsList(opts.TerminalSessions))))
					mux.Handle("POST /v1/projects/{project_id}/terminal-sessions", userAuth("projects:connect", requireEntitlement(opts.Auth, terminalSessionsCreate(opts.TerminalSessions))))
					mux.Handle("PATCH /v1/projects/{project_id}/terminal-sessions/{session_id}", userAuth("projects:connect", requireEntitlement(opts.Auth, terminalSessionsRename(opts.TerminalSessions))))
					mux.Handle("POST /v1/projects/{project_id}/terminal-sessions/{session_id}/close", userAuth("projects:connect", requireEntitlement(opts.Auth, terminalSessionsClose(opts.TerminalSessions))))
					mux.Handle("DELETE /v1/projects/{project_id}/terminal-sessions/{session_id}", userAuth("projects:connect", requireEntitlement(opts.Auth, terminalSessionsDelete(opts.TerminalSessions))))
				}
				mux.Handle("POST /v1/projects/{project_id}/connection-descriptor", requireBearerAuth(opts.DeviceAuth, requireScope("projects:connect", requireEntitlement(opts.Auth, projectConnectionDescriptor(opts.EnvironmentAccess, access.DescriptorForCLI)))))
				mux.Handle("GET /v1/projects/{project_id}/connection-readiness", requireBearerAuth(opts.DeviceAuth, requireScope("projects:connect", requireEntitlement(opts.Auth, projectConnectionReadiness(opts.EnvironmentAccess)))))
			}
		} else {
			mux.Handle("POST /v1/projects", requireAuth(opts.Auth, requireEntitlement(opts.Auth, requireGitHubConnection(opts.GitHub, http.HandlerFunc(dependencyUnavailable)))))
		}
	}
	if opts.Projects == nil {
		mux.Handle("/v1/projects", requireAuth(opts.Auth, requireEntitlement(opts.Auth, http.HandlerFunc(dependencyUnavailable))))
		mux.Handle("/v1/projects/", requireAuth(opts.Auth, requireEntitlement(opts.Auth, http.HandlerFunc(dependencyUnavailable))))
	}
	if opts.Billing != nil {
		mux.Handle("POST /v1/admin/users/{user_id}/adjust-credits", requireAuth(opts.Auth, requireCSRF(opts.Auth, requireAdmin(adminAdjustCredits(opts.Billing)))))
		mux.Handle("POST /v1/admin/users/{user_id}/adjust-storage", requireAuth(opts.Auth, requireCSRF(opts.Auth, requireAdmin(adminAdjustStorage(opts.Billing)))))
	}
}

func dependencyUnavailable(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusServiceUnavailable, "service_unavailable", "The service required by this endpoint is unavailable.")
}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := observability.NormalizeRequestID(r.Header.Get("Request-Id"))
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("Request-Id", requestID)
		next.ServeHTTP(w, r.WithContext(observability.WithRequestID(r.Context(), requestID)))
	})
}

func accessLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		observability.LoggerWithRequest(r.Context(), logger).Info("http_request",
			"method", r.Method,
			"path", safeLogPath(r.URL.Path),
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func safeLogPath(path string) string {
	if strings.HasPrefix(path, "/v1/auth/device/requests/") {
		suffix := strings.TrimPrefix(path, "/v1/auth/device/requests/")
		switch {
		case strings.HasSuffix(suffix, "/approve"):
			return "/v1/auth/device/requests/{user_code}/approve"
		case strings.HasSuffix(suffix, "/deny"):
			return "/v1/auth/device/requests/{user_code}/deny"
		default:
			return "/v1/auth/device/requests/{user_code}"
		}
	}
	return path
}

func recoverer(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				writePanicError(w, r, logger, value)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func timeout(duration time.Duration, logger *slog.Logger, next http.Handler) http.Handler {
	if duration <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStreamingRequest(r) {
			next.ServeHTTP(w, r)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), duration)
		defer cancel()

		tw := newTimeoutResponseWriter(w)
		results := make(chan handlerResult, 1)
		go func() {
			defer func() {
				if value := recover(); value != nil {
					results <- handlerResult{panicValue: value}
					return
				}
				results <- handlerResult{}
			}()
			next.ServeHTTP(tw, r.WithContext(ctx))
		}()

		select {
		case result := <-results:
			if result.panicValue != nil {
				writePanicError(w, r, logger, result.panicValue)
				return
			}
		case <-ctx.Done():
			if !tw.markTimedOut() {
				return
			}
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Request timed out.")
		}
	})
}

func isStreamingRequest(r *http.Request) bool {
	for _, accept := range r.Header.Values("Accept") {
		for _, part := range strings.Split(accept, ",") {
			mediaType := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
			if mediaType == "text/event-stream" {
				return true
			}
		}
	}
	return false
}

func bodyLimit(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && limit > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

func cors(allowedOrigins []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && slices.Contains(allowedOrigins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func writePanicError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, value any) {
	observability.LoggerWithRequest(r.Context(), logger).Error("panic recovered", "panic", value, "stack", string(debug.Stack()))
	writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *statusRecorder) FlushError() error {
	if flusher, ok := r.ResponseWriter.(interface{ FlushError() error }); ok {
		return flusher.FlushError()
	}
	r.Flush()
	return nil
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

type handlerResult struct {
	panicValue any
}

type timeoutResponseWriter struct {
	dst      http.ResponseWriter
	header   http.Header
	mu       sync.Mutex
	started  bool
	timedOut bool
}

func newTimeoutResponseWriter(dst http.ResponseWriter) *timeoutResponseWriter {
	return &timeoutResponseWriter{
		dst:    dst,
		header: make(http.Header),
	}
}

func (w *timeoutResponseWriter) Header() http.Header {
	return w.header
}

func (w *timeoutResponseWriter) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timedOut || w.started {
		return
	}
	w.started = true
	copyHeader(w.dst.Header(), w.header)
	w.dst.WriteHeader(status)
}

func (w *timeoutResponseWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timedOut {
		return 0, context.DeadlineExceeded
	}
	if !w.started {
		w.started = true
		copyHeader(w.dst.Header(), w.header)
	}
	return w.dst.Write(b)
}

func (w *timeoutResponseWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timedOut {
		return
	}
	w.started = true
	copyHeader(w.dst.Header(), w.header)
	if flusher, ok := w.dst.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *timeoutResponseWriter) markTimedOut() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		w.timedOut = true
		return false
	}
	w.timedOut = true
	return true
}

func (w *timeoutResponseWriter) Unwrap() http.ResponseWriter {
	return w.dst
}

var errFlusherUnsupported = errors.New("response writer does not support flushing")

func (w *timeoutResponseWriter) FlushError() error {
	if _, ok := w.dst.(http.Flusher); !ok {
		return errFlusherUnsupported
	}
	w.Flush()
	return nil
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func requestIDFromContext(ctx context.Context) string {
	return observability.RequestID(ctx)
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req_unknown"
	}
	return "req_" + hex.EncodeToString(b[:])
}
