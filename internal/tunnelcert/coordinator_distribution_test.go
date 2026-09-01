package tunnelcert

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestCoordinatorRedistributesActiveCertificateAfterEdgeProcessReplacement
// covers the active-certificate fast path. A changed process epoch is a new
// distribution target, but it must reuse the active certificate material and
// retire the old process only after the replacement is active.
func TestCoordinatorRedistributesActiveCertificateAfterEdgeProcessReplacement(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	issuer := &testIssuer{bundle: testBundle(t, []string{"*.edge.example.test"}, now, 60*24*time.Hour)}
	coordinator, store, _, _ := coordinatorForTest(t, issuer)
	distributor := newDistributionLedger()
	coordinator.config.Distributor = distributor

	domain := Domain{
		ID: "platform_cert_preview_v1", AccountID: PlatformAccountID,
		TargetKind: TargetPlatformWildcard, Hostname: "*.edge.example.test",
		Generation: 1, Strategy: StrategyPlatformDNS01, OwnershipState: "verified",
		CAAState: "not_applicable",
		EdgeTargets: []EdgeTarget{
			{NodeID: "edge_a", ProcessEpoch: "epoch-old-a", Generation: 1},
			{NodeID: "edge_b", ProcessEpoch: "epoch-stable-b", Generation: 1},
		},
	}
	first, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Issued || first.Certificate.CertificateGeneration != 1 {
		t.Fatalf("initial result = %+v", first)
	}
	certificateID := first.Certificate.Reference[len("tcert_"):]

	domain.CertificateReference = first.Certificate.Reference
	domain.EdgeTargets[0].ProcessEpoch = "epoch-new-a"
	second, err := coordinator.Ensure(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if second.Issued || second.Certificate.CertificateGeneration != first.Certificate.CertificateGeneration {
		t.Fatalf("replacement result = %+v, want active generation %d without issuance", second, first.Certificate.CertificateGeneration)
	}
	if len(issuer.seen) != 1 {
		t.Fatalf("replacement called issuer %d times, want 1", len(issuer.seen))
	}

	if got, want := distributor.events(), []string{
		"stage:edge_a/epoch-old-a/1", "stage:edge_b/epoch-stable-b/1",
		"ready:edge_a/epoch-old-a/1", "ready:edge_b/epoch-stable-b/1",
		"activate:edge_a/epoch-old-a/1", "activate:edge_b/epoch-stable-b/1",
		"stage:edge_a/epoch-new-a/1", "ready:edge_a/epoch-new-a/1",
		"activate:edge_a/epoch-new-a/1", "retire:edge_a/epoch-old-a/1",
	}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("distribution events = %v, want %v", got, want)
	}

	if got := distributor.state(certificateID, DistributionTarget{NodeID: "edge_a", ProcessEpoch: "epoch-new-a", Generation: 1}); got != "active" {
		t.Fatalf("replacement edge state = %q, want active", got)
	}
	if got := distributor.state(certificateID, DistributionTarget{NodeID: "edge_a", ProcessEpoch: "epoch-old-a", Generation: 1}); got != "retired" {
		t.Fatalf("old edge state = %q, want retired", got)
	}
	if got := distributor.state(certificateID, DistributionTarget{NodeID: "edge_b", ProcessEpoch: "epoch-stable-b", Generation: 1}); got != "active" {
		t.Fatalf("stable edge state = %q, want active", got)
	}
	current, found, err := store.Current(context.Background(), domain.ID)
	if err != nil || !found || current.CertificateGeneration != first.Certificate.CertificateGeneration || current.State != StateActive {
		t.Fatalf("stored replacement = %+v found=%v err=%v", current, found, err)
	}
}

type distributionLedger struct {
	mu       sync.Mutex
	rows     map[string]string
	eventLog []string
}

func newDistributionLedger() *distributionLedger {
	return &distributionLedger{rows: make(map[string]string)}
}

func (d *distributionLedger) Stage(_ context.Context, request DistributionRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := distributionLedgerKey(request.Certificate.ID, request.Target)
	d.rows[key] = "staged"
	d.eventLog = append(d.eventLog, "stage:"+distributionTargetDescription(request.Target))
	return nil
}

func (d *distributionLedger) WaitReady(_ context.Context, request DistributionRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := distributionLedgerKey(request.Certificate.ID, request.Target)
	if d.rows[key] != "staged" {
		return ErrCertificateNotReady
	}
	d.rows[key] = "ready"
	d.eventLog = append(d.eventLog, "ready:"+distributionTargetDescription(request.Target))
	return nil
}

func (d *distributionLedger) Activate(_ context.Context, request DistributionRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := distributionLedgerKey(request.Certificate.ID, request.Target)
	if d.rows[key] != "ready" {
		return ErrCertificateNotReady
	}
	d.rows[key] = "active"
	d.eventLog = append(d.eventLog, "activate:"+distributionTargetDescription(request.Target))
	return nil
}

func (d *distributionLedger) Retire(_ context.Context, certificate StoredCertificate, target DistributionTarget) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := distributionLedgerKey(certificate.ID, target)
	if d.rows[key] == "" {
		return ErrGenerationConflict
	}
	d.rows[key] = "retired"
	d.eventLog = append(d.eventLog, "retire:"+distributionTargetDescription(target))
	return nil
}

func (d *distributionLedger) MissingCertificateTargets(_ context.Context, certificate StoredCertificate, targets []DistributionTarget) ([]DistributionTarget, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	missing := make([]DistributionTarget, 0, len(targets))
	for _, target := range targets {
		if err := target.Validate(); err != nil {
			return nil, err
		}
		if d.rows[distributionLedgerKey(certificate.ID, target)] != "active" {
			missing = append(missing, target)
		}
	}
	return missing, nil
}

func (d *distributionLedger) RetireObsoleteCertificateTargets(_ context.Context, certificate StoredCertificate, current []DistributionTarget) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	keep := make(map[string]struct{}, len(current))
	for _, target := range current {
		keep[distributionLedgerKey(certificate.ID, target)] = struct{}{}
	}
	for key, state := range d.rows {
		if state != "staged" && state != "ready" && state != "active" {
			continue
		}
		if _, ok := keep[key]; ok {
			continue
		}
		d.rows[key] = "retired"
		separator := len(certificate.ID) + 1
		if len(key) > separator {
			d.eventLog = append(d.eventLog, "retire:"+key[separator:])
		}
	}
	return nil
}

func (d *distributionLedger) state(certificateID string, target DistributionTarget) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rows[distributionLedgerKey(certificateID, target)]
}

func (d *distributionLedger) events() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.eventLog...)
}

func distributionLedgerKey(certificateID string, target DistributionTarget) string {
	return certificateID + "\x00" + distributionTargetDescription(target)
}

func distributionTargetDescription(target DistributionTarget) string {
	return fmt.Sprintf("%s/%s/%d", target.NodeID, target.ProcessEpoch, target.Generation)
}
