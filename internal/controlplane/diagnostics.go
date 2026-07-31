package controlplane

import (
	"context"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

type DiagnosticsService struct {
	store *db.DB
}

func NewDiagnosticsService(store *db.DB) *DiagnosticsService {
	return &DiagnosticsService{store: store}
}

func (s *DiagnosticsService) Metrics(ctx context.Context) (map[string]int64, error) {
	row, err := s.store.Queries().GetControlPlaneQueueMetrics(ctx)
	if err != nil {
		return nil, err
	}
	billing, err := s.store.Queries().GetBillingUncertainMetrics(ctx)
	if err != nil {
		return nil, err
	}
	configSync, err := s.store.Queries().GetConfigSyncMetrics(ctx)
	if err != nil {
		return nil, err
	}
	userMachines, err := s.store.Queries().GetUserMachineRuntimeMetrics(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]int64{
		"control_operation_queue_depth":                     row.OperationDepth,
		"control_operation_oldest_age_seconds":              row.OperationOldestAgeSeconds,
		"control_operation_dead_letter_depth":               row.OperationDeadLetterDepth,
		"control_reconciliation_queue_depth":                row.ReconciliationDepth,
		"control_reconciliation_oldest_age_seconds":         row.ReconciliationOldestAgeSeconds,
		"control_stale_node_depth":                          row.StaleNodeDepth,
		"hosted_orchestration_queue_depth":                  row.OrchestrationQueueDepth,
		"hosted_orchestration_expired_lease_depth":          row.OrchestrationExpiredLeaseDepth,
		"hosted_orchestration_oldest_age_seconds":           row.OrchestrationOldestAgeSeconds,
		"hosted_provider_uncertain_depth":                   row.HostedProviderUncertainDepth,
		"hosted_provider_retryable_depth":                   row.HostedProviderRetryableDepth,
		"hosted_provider_oldest_age_seconds":                row.HostedProviderOldestAgeSeconds,
		"hosted_readiness_failure_depth":                    row.HostedReadinessFailureDepth,
		"hosted_readiness_recent_failure_age_seconds":       row.HostedReadinessRecentFailureAgeSeconds,
		"hosted_orphan_review_depth":                        row.HostedOrphanReviewDepth,
		"billing_checkout_uncertain_depth":                  billing.CheckoutUncertain,
		"billing_portal_uncertain_depth":                    billing.PortalUncertain,
		"billing_subscription_update_uncertain_depth":       billing.SubscriptionUpdateUncertain,
		"billing_auto_topup_uncertain_depth":                billing.AutoTopupUncertain,
		"config_sync_eligible_environments":                 configSync.EligibleEnvironments,
		"config_sync_reporting_environments":                configSync.ReportingEnvironments,
		"config_sync_conflict_environments":                 configSync.ConflictEnvironments,
		"config_sync_pending_paths":                         configSync.PendingPaths,
		"config_sync_uncertain_publications":                configSync.UncertainPublications,
		"config_sync_active_writer_leases":                  configSync.ActiveWriterLeases,
		"config_sync_lease_contention_total":                configSync.LeaseContentionTotal,
		"config_sync_pending_resolutions":                   configSync.PendingResolutions,
		"config_sync_oldest_pending_resolution_age_seconds": configSync.OldestPendingResolutionAgeSeconds,
		"config_sync_pending_provider_revocations":          configSync.PendingProviderRevocations,
		"user_machine_bootstrap_failure_depth":              userMachines.BootstrapFailureDepth,
		"user_machine_heartbeat_oldest_age_seconds":         userMachines.HeartbeatOldestAgeSeconds,
		"user_machine_availability_drift_depth":             userMachines.AvailabilityDriftDepth,
		"user_machine_privileged_service_error_depth":       userMachines.PrivilegedServiceErrorDepth,
		"user_machine_unsupported_host_scope_depth":         userMachines.UnsupportedHostScopeDepth,
		"paperboat_runtime_update_rollbacks_total":          userMachines.UpdateRollbacksTotal,
	}, nil
}
