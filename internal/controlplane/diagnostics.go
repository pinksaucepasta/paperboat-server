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
	return map[string]int64{
		"control_operation_queue_depth":               row.OperationDepth,
		"control_operation_oldest_age_seconds":        row.OperationOldestAgeSeconds,
		"control_operation_dead_letter_depth":         row.OperationDeadLetterDepth,
		"control_reconciliation_queue_depth":          row.ReconciliationDepth,
		"control_reconciliation_oldest_age_seconds":   row.ReconciliationOldestAgeSeconds,
		"control_stale_node_depth":                    row.StaleNodeDepth,
		"hosted_orchestration_queue_depth":            row.OrchestrationQueueDepth,
		"hosted_orchestration_expired_lease_depth":    row.OrchestrationExpiredLeaseDepth,
		"hosted_orchestration_oldest_age_seconds":     row.OrchestrationOldestAgeSeconds,
		"hosted_provider_uncertain_depth":             row.HostedProviderUncertainDepth,
		"hosted_provider_retryable_depth":             row.HostedProviderRetryableDepth,
		"hosted_provider_oldest_age_seconds":          row.HostedProviderOldestAgeSeconds,
		"hosted_readiness_failure_depth":              row.HostedReadinessFailureDepth,
		"hosted_readiness_recent_failure_age_seconds": row.HostedReadinessRecentFailureAgeSeconds,
		"hosted_orphan_review_depth":                  row.HostedOrphanReviewDepth,
		"billing_checkout_uncertain_depth":            billing.CheckoutUncertain,
		"billing_portal_uncertain_depth":              billing.PortalUncertain,
		"billing_subscription_update_uncertain_depth": billing.SubscriptionUpdateUncertain,
		"billing_auto_topup_uncertain_depth":          billing.AutoTopupUncertain,
	}, nil
}
