package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/previewdomain"
	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
	"github.com/pinksaucepasta/paperboat-server/internal/telemetry"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
)

type recordingPreviewLeaseReconciler struct {
	actorID, correlationID, requestID string
	err                               error
}

func TestPreviewDNSReconcileTelemetryProjectsTypedOutcome(t *testing.T) {
	events, err := telemetry.NewEventLog(8)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	health, err := telemetry.NewHealthTracker(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	producer := &telemetry.Producer{Metrics: telemetry.NewMetrics(), Events: events, Health: health, Now: time.Now}
	sink := previewDNSReconcileTelemetry(producer)
	sink.EmitDNSReconcileEvent(context.Background(), previewdomain.DNSReconcileEvent{DomainID: "domain_1", PreviewID: "preview_1", Code: "verified", OwnershipState: "verified", ConflictState: "none", Verified: true})
	if state := health.Snapshot().Dimensions.DNS; state.Status != telemetry.StatusReady || state.Code != "dns_verified" {
		t.Fatalf("verified DNS health = %+v", state)
	}
	sink.EmitDNSReconcileEvent(context.Background(), previewdomain.DNSReconcileEvent{DomainID: "domain_1", PreviewID: "preview_1", Code: "dns_conflict", OwnershipState: "pending", ConflictState: "conflict"})
	if state := health.Snapshot().Dimensions.DNS; state.Status != telemetry.StatusDegraded || state.Retry != telemetry.RetryNotRetryable {
		t.Fatalf("conflict DNS health = %+v", state)
	}
	recorded := events.Snapshot()
	if len(recorded) != 2 || recorded[0].Name != "dns_verification" || recorded[1].Outcome != telemetry.OutcomeFailed || recorded[1].IDs.DomainID != "domain_1" {
		t.Fatalf("DNS telemetry events = %+v", recorded)
	}
}

func TestTunnelDNSReconcileTelemetryProjectsTypedOutcome(t *testing.T) {
	events, err := telemetry.NewEventLog(4)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	health, err := telemetry.NewHealthTracker(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	producer := &telemetry.Producer{Metrics: telemetry.NewMetrics(), Events: events, Health: health, Now: time.Now}
	observe := tunnelDNSReconcileTelemetry(producer)
	observe(context.Background(), tunnelv1.DomainDNSReconcileEvent{DomainID: "domain_2", Code: "dns_verification_failed", NextCheckAt: time.Now().Add(time.Minute)})
	state := health.Snapshot().Dimensions.DNS
	if state.Status != telemetry.StatusDegraded || state.Retry != telemetry.RetryScheduled || state.NextRetryAt == nil {
		t.Fatalf("failed tunnel DNS health = %+v", state)
	}
	if recorded := events.Snapshot(); len(recorded) != 1 || recorded[0].IDs.DomainID != "domain_2" || recorded[0].Outcome != telemetry.OutcomeFailed {
		t.Fatalf("tunnel DNS events = %+v", recorded)
	}
}

func TestCertificateTelemetryProjectsLifecycleOutcome(t *testing.T) {
	events, err := telemetry.NewEventLog(4)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	health, err := telemetry.NewHealthTracker(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	producer := &telemetry.Producer{Metrics: telemetry.NewMetrics(), Events: events, Health: health, Now: time.Now}
	observe := certificateTelemetry(producer)
	observe(context.Background(), tunnelv1.CertificateTelemetryEvent{DomainID: "domain_3", CertificateID: "certificate_3", Operation: "renew", Outcome: "success"})
	state := health.Snapshot().Dimensions.Certificate
	if state.Status != telemetry.StatusReady || state.Code != "certificate_ready" {
		t.Fatalf("certificate health = %+v", state)
	}
	if recorded := events.Snapshot(); len(recorded) != 1 || recorded[0].IDs.CertificateID != "certificate_3" || recorded[0].Outcome != telemetry.OutcomeSuccess {
		t.Fatalf("certificate events = %+v", recorded)
	}
}

func (r *recordingPreviewLeaseReconciler) Reconcile(_ context.Context, actorID, correlationID, requestID string) (previewv1.ReconcileResult, error) {
	r.actorID, r.correlationID, r.requestID = actorID, correlationID, requestID
	return previewv1.ReconcileResult{}, r.err
}

type recordingTunnelExpiryReconciler struct {
	request tunnelv1.ExpiryReconcileRequest
	err     error
}

func (r *recordingTunnelExpiryReconciler) ReconcileExpired(_ context.Context, request tunnelv1.ExpiryReconcileRequest) ([]tunnelv1.MutationResult, error) {
	r.request = request
	return nil, r.err
}

func TestPeriodicPreviewTunnelWorkerRunsImmediatelyAndPropagatesFailure(t *testing.T) {
	want := errors.New("database unavailable")
	calls := 0
	worker := periodicPreviewTunnelWorker(time.Hour, func(context.Context) error {
		calls++
		return want
	})
	if err := worker(context.Background()); !errors.Is(err, want) || calls != 1 {
		t.Fatalf("error = %v, calls = %d", err, calls)
	}
}

func TestPeriodicPreviewTunnelWorkerStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	worker := periodicPreviewTunnelWorker(time.Hour, func(context.Context) error {
		calls++
		cancel()
		return nil
	})
	if err := worker(ctx); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("error = %v, calls = %d", err, calls)
	}
}

func TestPreviewTunnelWorkersSupplyDurableAuditIdentity(t *testing.T) {
	stop := errors.New("stop after first run")
	preview := &recordingPreviewLeaseReconciler{err: stop}
	if err := previewLeaseReconciliationWorker(preview, time.Hour)(context.Background()); !errors.Is(err, stop) {
		t.Fatalf("preview worker error = %v", err)
	}
	if preview.actorID != "paperboat-server.preview-lease-reconciler" || !strings.HasPrefix(preview.requestID, "req_") || !strings.HasPrefix(preview.correlationID, "cor_") {
		t.Fatalf("preview reconciliation identity = actor %q request %q correlation %q", preview.actorID, preview.requestID, preview.correlationID)
	}

	tunnel := &recordingTunnelExpiryReconciler{err: stop}
	if err := tunnelExpiryReconciliationWorker(tunnel, time.Hour)(context.Background()); !errors.Is(err, stop) {
		t.Fatalf("tunnel worker error = %v", err)
	}
	if tunnel.request.ActorID != "paperboat-server.tunnel-expiry-reconciler" || tunnel.request.ActorType != "system" || !strings.HasPrefix(tunnel.request.RequestID, "req_") || !strings.HasPrefix(tunnel.request.CorrelationID, "cor_") {
		t.Fatalf("tunnel reconciliation identity = %#v", tunnel.request)
	}
}

func TestPreviewLeaseWorkerEmitsCorrelatedCleanupTelemetry(t *testing.T) {
	events, err := telemetry.NewEventLog(8)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	health, err := telemetry.NewHealthTracker(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	producer := &telemetry.Producer{Metrics: telemetry.NewMetrics(), Events: events, Health: health, Now: time.Now}
	stop := errors.New("database unavailable")
	reconciler := &recordingPreviewLeaseReconciler{err: stop}
	if err := previewLeaseReconciliationWorker(reconciler, time.Second, producer)(context.Background()); !errors.Is(err, stop) {
		t.Fatalf("worker error=%v", err)
	}
	recorded := events.Snapshot()
	if len(recorded) != 1 || recorded[0].Name != "preview_cleanup" || recorded[0].Outcome != telemetry.OutcomeFailed || recorded[0].RequestID != reconciler.requestID || recorded[0].CorrelationID != reconciler.correlationID {
		t.Fatalf("events=%+v", recorded)
	}
	if state := health.Snapshot().Dimensions.Route; state.Status != telemetry.StatusDegraded || state.Retry != telemetry.RetryScheduled {
		t.Fatalf("route health=%+v", state)
	}
}
