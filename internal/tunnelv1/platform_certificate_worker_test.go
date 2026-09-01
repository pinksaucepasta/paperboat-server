package tunnelv1

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/tunnelcert"
)

func TestPlatformCertificateWorkerTelemetryUsesTargetIdentityAndRetry(t *testing.T) {
	worker := &PlatformCertificateWorker{}
	var events []CertificateTelemetryEvent
	if err := worker.SetTelemetryObserver(func(_ context.Context, event CertificateTelemetryEvent) {
		events = append(events, event)
	}); err != nil {
		t.Fatal(err)
	}
	next := time.Date(2026, time.September, 1, 12, 1, 0, 0, time.UTC)
	worker.emitTelemetry(context.Background(), tunnelcert.PlatformPreviewTargetID, "", "issue", "failed", next)
	worker.emitTelemetry(context.Background(), tunnelcert.PlatformPreviewTargetID, "cert_platform_1", "issue", "success", time.Time{})
	if len(events) != 2 {
		t.Fatalf("telemetry events = %d, want 2", len(events))
	}
	if events[0].DomainID != tunnelcert.PlatformPreviewTargetID || events[0].Operation != "issue" || events[0].Outcome != "failed" || !events[0].NextRetryAt.Equal(next) {
		t.Fatalf("failure event = %+v", events[0])
	}
	if events[1].DomainID != tunnelcert.PlatformPreviewTargetID || events[1].CertificateID != "cert_platform_1" || events[1].Outcome != "success" || !events[1].NextRetryAt.IsZero() {
		t.Fatalf("success event = %+v", events[1])
	}
}

func TestPlatformCertificateWorkerLastErrorClearsOnlyOnCompletePass(t *testing.T) {
	worker := &PlatformCertificateWorker{}
	transient := errors.New("temporary issuer failure")
	worker.setLastError(transient)
	if !errors.Is(worker.LastError(), transient) {
		t.Fatalf("last error = %v, want transient failure", worker.LastError())
	}
	// Reconcile invokes this only after every target has completed successfully;
	// a retryable target leaves the value untouched for health explainability.
	worker.setLastError(nil)
	if err := worker.LastError(); err != nil {
		t.Fatalf("cleared last error = %v", err)
	}
}

func TestPlatformCertificateWorkerTelemetryDistinguishesIssueAndRenew(t *testing.T) {
	if got := platformCertificateOperation(false); got != "issue" {
		t.Fatalf("initial platform operation = %q", got)
	}
	if got := platformCertificateOperation(true); got != "renew" {
		t.Fatalf("replacement platform operation = %q", got)
	}
}

func TestPlatformCertificateWorkerBackoffRestoresTypedFailure(t *testing.T) {
	for code, want := range map[string]error{
		"issuer_unavailable":        tunnelcert.ErrIssuerUnavailable,
		"dns_challenge_unavailable": tunnelcert.ErrDNSChallengeUnavailable,
		"edge_not_ready":            tunnelcert.ErrCertificateNotReady,
		"unknown_code":              ErrPlatformCertificateUnavailable,
	} {
		if got := platformRetryError(code); !errors.Is(got, want) {
			t.Fatalf("retry code %q = %v, want %v", code, got, want)
		}
	}
}

func TestPlatformRetryDelayIsBoundedAndExponential(t *testing.T) {
	if got := platformRetryDelay(1); got != time.Minute {
		t.Fatalf("first retry delay = %s", got)
	}
	if got := platformRetryDelay(3); got != 4*time.Minute {
		t.Fatalf("third retry delay = %s", got)
	}
	if got := platformRetryDelay(100); got != time.Hour {
		t.Fatalf("bounded retry delay = %s", got)
	}
}
