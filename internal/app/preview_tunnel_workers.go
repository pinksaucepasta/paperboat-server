package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/previewdomain"
	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
	"github.com/pinksaucepasta/paperboat-server/internal/telemetry"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
	"github.com/pinksaucepasta/paperboat-server/internal/workers"
)

type previewLeaseReconciler interface {
	Reconcile(context.Context, string, string, string) (previewv1.ReconcileResult, error)
}

func previewDNSReconcileTelemetry(producer *telemetry.Producer) previewdomain.DNSReconcileEventSink {
	return previewdomain.DNSReconcileEventSinkFunc(func(_ context.Context, event previewdomain.DNSReconcileEvent) {
		if producer == nil {
			return
		}
		outcome := telemetry.DNSVerificationWaiting
		failure := telemetry.DNSFailureUnknown
		retry := telemetry.RetryWaitForChange
		nextRetryAt := event.NextCheckAt
		switch {
		case event.Verified:
			outcome, retry, nextRetryAt = telemetry.DNSVerificationSucceeded, telemetry.RetryNone, time.Time{}
		case event.ConflictState != "" && event.ConflictState != "none":
			outcome, failure, retry, nextRetryAt = telemetry.DNSVerificationFailed, telemetry.DNSFailureConflict, telemetry.RetryNotRetryable, time.Time{}
		case strings.Contains(event.Code, "timeout"):
			outcome, failure, retry = telemetry.DNSVerificationFailed, telemetry.DNSFailureTimeout, telemetry.RetryScheduled
		case strings.Contains(event.Code, "invalid"):
			outcome, failure, retry, nextRetryAt = telemetry.DNSVerificationFailed, telemetry.DNSFailureInvalid, telemetry.RetryNotRetryable, time.Time{}
		}
		_ = producer.RecordDNSVerification(telemetry.DNSVerificationInput{
			Outcome: outcome, FailureClass: failure, Retry: retry, NextRetryAt: nextRetryAt,
			Identity: telemetry.ProducerIdentity{IDs: telemetry.SafeIDs{DomainID: event.DomainID}},
		})
	})
}

func tunnelDNSReconcileTelemetry(producer *telemetry.Producer) func(context.Context, tunnelv1.DomainDNSReconcileEvent) {
	return func(_ context.Context, event tunnelv1.DomainDNSReconcileEvent) {
		if producer == nil {
			return
		}
		outcome, failure, retry, nextRetryAt := telemetry.DNSVerificationWaiting, telemetry.DNSFailureUnknown, telemetry.RetryWaitForChange, event.NextCheckAt
		if event.Verified {
			outcome, retry, nextRetryAt = telemetry.DNSVerificationSucceeded, telemetry.RetryNone, time.Time{}
		} else if event.ConflictState != "" && event.ConflictState != "clear" {
			outcome, failure, retry, nextRetryAt = telemetry.DNSVerificationFailed, telemetry.DNSFailureConflict, telemetry.RetryNotRetryable, time.Time{}
		} else if event.Code == "dns_verification_failed" {
			outcome, failure, retry = telemetry.DNSVerificationFailed, telemetry.DNSFailureUnknown, telemetry.RetryScheduled
		}
		_ = producer.RecordDNSVerification(telemetry.DNSVerificationInput{
			Outcome: outcome, FailureClass: failure, Retry: retry, NextRetryAt: nextRetryAt,
			Identity: telemetry.ProducerIdentity{IDs: telemetry.SafeIDs{DomainID: event.DomainID}},
		})
	}
}

func certificateTelemetry(producer *telemetry.Producer) func(context.Context, tunnelv1.CertificateTelemetryEvent) {
	return func(_ context.Context, event tunnelv1.CertificateTelemetryEvent) {
		if producer == nil {
			return
		}
		operation := telemetry.CertificateIssue
		switch event.Operation {
		case "renew":
			operation = telemetry.CertificateRenew
		case "replace":
			operation = telemetry.CertificateReplace
		case "revoke":
			operation = telemetry.CertificateRevoke
		}
		outcome, retry := telemetry.CertificateSucceeded, telemetry.RetryNone
		if event.Outcome != "success" {
			outcome, retry = telemetry.CertificateFailed, telemetry.RetryScheduled
		}
		_ = producer.RecordCertificateLifecycle(telemetry.CertificateLifecycleInput{
			Operation: operation, Outcome: outcome, Retry: retry, NextRetryAt: event.NextRetryAt,
			Identity: telemetry.ProducerIdentity{IDs: telemetry.SafeIDs{DomainID: event.DomainID, CertificateID: event.CertificateID}},
		})
	}
}

type tunnelExpiryReconciler interface {
	ReconcileExpired(context.Context, tunnelv1.ExpiryReconcileRequest) ([]tunnelv1.MutationResult, error)
}

func previewLeaseReconciliationWorker(service previewLeaseReconciler, interval time.Duration, producers ...*telemetry.Producer) workers.Worker {
	return periodicPreviewTunnelWorker(interval, func(ctx context.Context) error {
		requestID, correlationID, err := previewTunnelWorkerRequestIDs()
		if err != nil {
			return fmt.Errorf("allocate preview lease reconciliation identity: %w", err)
		}
		_, err = service.Reconcile(ctx, "paperboat-server.preview-lease-reconciler", correlationID, requestID)
		if err != nil {
			recordPreviewCleanup(producers, telemetry.PreviewCleanupFailed, requestID, correlationID, telemetry.RetryScheduled, time.Now().UTC().Add(interval))
			return fmt.Errorf("reconcile preview leases: %w", err)
		}
		recordPreviewCleanup(producers, telemetry.PreviewCleanupSucceeded, requestID, correlationID, telemetry.RetryNone, time.Time{})
		return nil
	})
}

func recordPreviewCleanup(producers []*telemetry.Producer, outcome telemetry.PreviewCleanupOutcome, requestID, correlationID string, retry telemetry.RetryDecision, nextRetryAt time.Time) {
	if len(producers) == 0 || producers[0] == nil {
		return
	}
	_ = producers[0].RecordPreviewCleanup(telemetry.PreviewCleanupInput{
		Outcome: outcome, Retry: retry, NextRetryAt: nextRetryAt,
		Identity: telemetry.ProducerIdentity{RequestID: requestID, CorrelationID: correlationID},
	})
}

func tunnelExpiryReconciliationWorker(service tunnelExpiryReconciler, interval time.Duration) workers.Worker {
	return periodicPreviewTunnelWorker(interval, func(ctx context.Context) error {
		requestID, correlationID, err := previewTunnelWorkerRequestIDs()
		if err != nil {
			return fmt.Errorf("allocate tunnel expiry reconciliation identity: %w", err)
		}
		_, err = service.ReconcileExpired(ctx, tunnelv1.ExpiryReconcileRequest{
			Limit: 100, ActorID: "paperboat-server.tunnel-expiry-reconciler", ActorType: "system",
			RequestID: requestID, CorrelationID: correlationID,
		})
		if err != nil {
			return fmt.Errorf("reconcile tunnel expiry: %w", err)
		}
		return nil
	})
}

func previewTunnelWorkerRequestIDs() (string, string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", err
	}
	return "req_" + hex.EncodeToString(raw[:16]), "cor_" + hex.EncodeToString(raw[16:]), nil
}

func periodicPreviewTunnelWorker(interval time.Duration, run func(context.Context) error) workers.Worker {
	if interval <= 0 {
		interval = time.Second
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := run(ctx); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}
