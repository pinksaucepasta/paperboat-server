package tunnelcert

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

// TestSQLCertificateDistributionCleanupFencesReplacedProcesses is opt-in and
// covers the cleanup state machine against PostgreSQL. A superseded/failed
// certificate on an old process is terminalized locally; the same states on
// the current process still use authenticated retire/revoke transport.
func TestSQLCertificateDistributionCleanupFencesReplacedProcesses(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run TLS PostgreSQL cleanup acceptance")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(dsn), "_test") {
		t.Fatal("PAPERBOAT_TEST_DATABASE_DSN must name an isolated *_test database")
	}

	ctx := context.Background()
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	fixture := sqlCertificateFixture{suffix: suffix}
	fixture.insert(t, database)
	t.Cleanup(func() {
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=$1`, fixture.accountID)
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_tunnel_nodes WHERE id=$1`, fixture.edgeID)
	})

	store, err := NewSQLStore(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	oldEpoch := fixture.epoch
	newEpoch := fixture.epoch + "_new"
	if _, err := database.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET process_epoch=$2 WHERE id=$1`, fixture.edgeID, newEpoch); err != nil {
		t.Fatal(err)
	}

	certificates := make([]StoredCertificate, 0, 4)
	for generation := uint64(1); generation <= 4; generation++ {
		certificate := fixture.certificate(generation, now)
		if err := store.PutStaged(ctx, certificate); err != nil {
			t.Fatalf("put staged certificate %d: %v", generation, err)
		}
		epoch := newEpoch
		if generation%2 == 1 {
			epoch = oldEpoch
		}
		if _, err := database.Queries().StageTunnelCertificateEdgeV1(ctx, dbsqlc.StageTunnelCertificateEdgeV1Params{
			CertificateID: certificate.ID, EdgeNodeID: fixture.edgeID, EdgeProcessEpoch: epoch,
			EdgeAssignmentGeneration: int64(generation), CertificateGeneration: int64(generation), Now: now,
		}); err != nil {
			t.Fatalf("stage certificate %d: %v", generation, err)
		}
		certificates = append(certificates, certificate)
	}
	// Generations 1 and 2 exercise superseded cleanup. Generations 3 and 4
	// exercise failed-certificate inclusion, including a failed edge row.
	for _, certificate := range certificates[:2] {
		if _, err := database.SQL().ExecContext(ctx, `UPDATE paperboat.tunnel_certificate_records SET state='superseded', updated_at=$2 WHERE id=$1`, certificate.ID, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, certificate := range certificates[2:] {
		if err := store.MarkFailed(ctx, certificate.ID, "issuer_timeout", now); err != nil {
			t.Fatalf("mark certificate %s failed: %v", certificate.ID, err)
		}
	}
	if _, err := database.SQL().ExecContext(ctx, `UPDATE paperboat.tunnel_certificate_edge_distributions SET state='failed', failure_code='edge_stage_failed' WHERE certificate_id=$1`, certificates[3].ID); err != nil {
		t.Fatal(err)
	}

	pending, err := database.Queries().ListPendingTunnelCertificateCleanupIDsV1(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != len(certificates) {
		t.Fatalf("pending cleanup certificates = %v, want %d", pending, len(certificates))
	}

	transport := newCleanupAcceptanceTransport()
	distributor, err := NewSQLDistributor(database, transport)
	if err != nil {
		t.Fatal(err)
	}
	cleaned, err := distributor.ReconcileCertificateDistributionCleanup(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if cleaned != len(certificates) {
		t.Fatalf("cleaned certificates = %d, want %d", cleaned, len(certificates))
	}

	rowsByCertificate := make(map[string]dbsqlc.TunnelCertificateEdgeDistribution, len(certificates))
	for _, certificate := range certificates {
		rows, err := database.Queries().ListTunnelCertificateEdgesV1(ctx, certificate.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("certificate %s edge rows = %d, want 1", certificate.ID, len(rows))
		}
		rowsByCertificate[certificate.ID] = rows[0]
	}
	if got := rowsByCertificate[certificates[0].ID].State; got != "retired" {
		t.Fatalf("stale superseded row state = %q, want retired", got)
	}
	if got := rowsByCertificate[certificates[1].ID].State; got != "retired" {
		t.Fatalf("current superseded row state = %q, want retired", got)
	}
	if got := rowsByCertificate[certificates[2].ID].State; got != "revoked" {
		t.Fatalf("stale failed row state = %q, want revoked", got)
	}
	if got := rowsByCertificate[certificates[3].ID].State; got != "revoked" {
		t.Fatalf("current failed row state = %q, want revoked", got)
	}

	retired := transport.retiredActions()
	if len(retired) != 1 || retired[0].certificateID != certificates[1].ID || retired[0].epoch != newEpoch {
		t.Fatalf("retire transport actions = %#v, want current superseded target only", retired)
	}
	revoked := transport.revokedActions()
	if len(revoked) != 1 || revoked[0].certificateID != certificates[3].ID || revoked[0].epoch != newEpoch || revoked[0].state != string(StateActive) {
		t.Fatalf("revoke transport actions = %#v, want current failed target with active transport metadata", revoked)
	}
}

type cleanupAcceptanceAction struct {
	certificateID string
	epoch         string
	state         string
}

type cleanupAcceptanceTransport struct {
	mu      sync.Mutex
	retired []cleanupAcceptanceAction
	revoked []cleanupAcceptanceAction
}

func newCleanupAcceptanceTransport() *cleanupAcceptanceTransport {
	return &cleanupAcceptanceTransport{}
}

func (t *cleanupAcceptanceTransport) Stage(context.Context, DistributionRequest) error {
	return nil
}

func (t *cleanupAcceptanceTransport) WaitReady(context.Context, DistributionRequest) error {
	return nil
}

func (t *cleanupAcceptanceTransport) Activate(context.Context, DistributionRequest) error {
	return nil
}

func (t *cleanupAcceptanceTransport) Retire(_ context.Context, certificate StoredCertificate, target DistributionTarget) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.retired = append(t.retired, cleanupAcceptanceAction{certificateID: certificate.ID, epoch: target.ProcessEpoch, state: string(certificate.State)})
	return nil
}

func (t *cleanupAcceptanceTransport) Revoke(_ context.Context, certificate StoredCertificate, target DistributionTarget) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.revoked = append(t.revoked, cleanupAcceptanceAction{certificateID: certificate.ID, epoch: target.ProcessEpoch, state: string(certificate.State)})
	return nil
}

func (t *cleanupAcceptanceTransport) retiredActions() []cleanupAcceptanceAction {
	t.mu.Lock()
	defer t.mu.Unlock()
	actions := append([]cleanupAcceptanceAction(nil), t.retired...)
	sort.Slice(actions, func(i, j int) bool { return actions[i].certificateID < actions[j].certificateID })
	return actions
}

func (t *cleanupAcceptanceTransport) revokedActions() []cleanupAcceptanceAction {
	t.mu.Lock()
	defer t.mu.Unlock()
	actions := append([]cleanupAcceptanceAction(nil), t.revoked...)
	sort.Slice(actions, func(i, j int) bool { return actions[i].certificateID < actions[j].certificateID })
	return actions
}

var _ EdgeCertificateTransport = (*cleanupAcceptanceTransport)(nil)
var _ EdgeCertificateRevocationTransport = (*cleanupAcceptanceTransport)(nil)
