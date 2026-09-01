package tunnelcert

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/testutil"
)

// TestSQLCertificateLifecycleOnPostgres is opt-in and intentionally runs only
// against a database whose name is explicitly marked as a test database.  It
// exercises the durable certificate records, lease lock, edge generation
// fence, replacement uniqueness, revocation, and domain.create completion.
func TestSQLCertificateLifecycleOnPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run TLS PostgreSQL acceptance")
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
	lock, err := NewSQLIssuanceLock(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := now.Add(time.Minute)
	if locked, err := lock.Acquire(ctx, fixture.domainID, "issuer_a_"+suffix, 1, now, until); err != nil || !locked {
		t.Fatalf("first issuance lock = %v, %v", locked, err)
	}
	if locked, err := lock.Acquire(ctx, fixture.domainID, "issuer_b_"+suffix, 1, now, until); err != nil || locked {
		t.Fatalf("second issuance lock = %v, %v", locked, err)
	}
	if err := lock.Release(ctx, fixture.domainID, "issuer_a_"+suffix); err != nil {
		t.Fatal(err)
	}

	first := fixture.certificate(1, now)
	if err := store.PutStaged(ctx, first); err != nil {
		t.Fatal(err)
	}
	edges, err := database.Queries().ListTunnelCertificateEdgesV1(ctx, first.ID)
	if err != nil || len(edges) != 0 {
		t.Fatalf("staged edges = %d, %v", len(edges), err)
	}
	if _, err := database.Queries().StageTunnelCertificateEdgeV1(ctx, stageParams(first, fixture, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Queries().MarkTunnelCertificateEdgeStateV1(ctx, readyParams(first, fixture, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Queries().MarkTunnelCertificateEdgeStateV1(ctx, activeParams(first, fixture, now)); err != nil {
		t.Fatal(err)
	}
	active, err := store.Activate(ctx, first.ID, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if active.State != StateActive || active.CertificateGeneration != 1 {
		t.Fatalf("active = %#v", active)
	}
	current, found, err := store.Current(ctx, fixture.domainID)
	if err != nil || !found || current.ID != first.ID || current.MasterKeyReference != "master/current" {
		t.Fatalf("current = %#v found=%v err=%v", current, found, err)
	}

	second := fixture.certificate(2, now)
	if err := store.PutStaged(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Queries().StageTunnelCertificateEdgeV1(ctx, stageParams(second, fixture, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Queries().MarkTunnelCertificateEdgeStateV1(ctx, readyParams(second, fixture, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Queries().MarkTunnelCertificateEdgeStateV1(ctx, activeParams(second, fixture, now)); err != nil {
		t.Fatal(err)
	}
	// SQLStore.Activate performs supersede + activation atomically. This is
	// required by the partial unique active index and keeps the old record
	// available until edge readiness has already been observed above.
	active, err = store.Activate(ctx, second.ID, 1, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if active.State != StateActive || active.CertificateGeneration != 2 {
		t.Fatalf("replacement active = %#v", active)
	}
	var oldState string
	if err := database.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.tunnel_certificate_records WHERE id=$1`, first.ID).Scan(&oldState); err != nil {
		t.Fatal(err)
	}
	if oldState != string(StateSuperseded) {
		t.Fatalf("old state = %q", oldState)
	}
	// A replacement edge process gets its own durable row.  The old process
	// remains active until the replacement is observed ready and activated.
	newEpoch := fixture.epoch + "_next"
	if _, err := database.Queries().StageTunnelCertificateEdgeV1(ctx, dbsqlc.StageTunnelCertificateEdgeV1Params{CertificateID: active.ID, EdgeNodeID: fixture.edgeID, EdgeProcessEpoch: newEpoch, EdgeAssignmentGeneration: 1, CertificateGeneration: int64(active.CertificateGeneration), Now: now}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("stale edge assignment stage error = %v", err)
	}
	if _, err := database.Queries().StageTunnelCertificateEdgeV1(ctx, dbsqlc.StageTunnelCertificateEdgeV1Params{CertificateID: active.ID, EdgeNodeID: fixture.edgeID, EdgeProcessEpoch: newEpoch, EdgeAssignmentGeneration: 2, CertificateGeneration: int64(active.CertificateGeneration), Now: now}); err != nil {
		t.Fatal(err)
	}
	wrongEpochParams := dbsqlc.MarkTunnelCertificateEdgeStateV1Params{State: "ready", ObservedAt: sql.NullTime{Time: now, Valid: true}, Now: now, CertificateID: active.ID, EdgeNodeID: fixture.edgeID, EdgeProcessEpoch: newEpoch, EdgeAssignmentGeneration: 1, CertificateGeneration: int64(active.CertificateGeneration)}
	if _, err := database.Queries().MarkTunnelCertificateEdgeStateV1(ctx, wrongEpochParams); err == nil {
		t.Fatal("stale edge assignment generation was accepted")
	}
	newReadyParams := wrongEpochParams
	newReadyParams.EdgeAssignmentGeneration = 2
	if _, err := database.Queries().MarkTunnelCertificateEdgeStateV1(ctx, newReadyParams); err != nil {
		t.Fatal(err)
	}
	newActiveParams := newReadyParams
	newActiveParams.State = "active"
	if _, err := database.Queries().MarkTunnelCertificateEdgeStateV1(ctx, newActiveParams); err != nil {
		t.Fatal(err)
	}
	var distributionRows int
	if err := database.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.tunnel_certificate_edge_distributions WHERE certificate_id=$1`, active.ID).Scan(&distributionRows); err != nil {
		t.Fatal(err)
	}
	if distributionRows != 2 {
		t.Fatalf("edge process replacement rows = %d, want 2", distributionRows)
	}

	if _, err := store.Revoke(ctx, second.ID, "operator_requested", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	current, found, err = store.Current(ctx, fixture.domainID)
	if err != nil || found {
		t.Fatalf("revoked current = %#v found=%v err=%v", current, found, err)
	}
	completer, err := NewSQLOperationCompleter(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := completer.CompleteDomainCreate(ctx, fixture.accountID, fixture.domainID, 2); err == nil {
		t.Fatal("revoked certificate completed domain.create")
	}
}

type sqlCertificateFixture struct {
	suffix    string
	accountID string
	tunnelID  string
	routeID   string
	domainID  string
	edgeID    string
	epoch     string
	opID      string
}

func (f *sqlCertificateFixture) insert(t *testing.T, database *db.DB) {
	t.Helper()
	ctx := context.Background()
	f.accountID = "usr_tls_" + f.suffix
	f.tunnelID = "tun_tls_" + f.suffix
	f.routeID = "rte_tls_" + f.suffix
	f.domainID = "dom_tls_" + f.suffix
	f.edgeID = "edge_tls_" + f.suffix
	f.epoch = "epoch_tls_" + f.suffix
	f.opID = "op_tls_create_" + f.suffix
	now := time.Now().UTC().Truncate(time.Microsecond)
	endpointID := testutil.EndpointUUID("tls-certificate:" + f.suffix)
	endpoint := "https://" + endpointID + ".tunnels.example.test"
	for _, query := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, []any{f.accountID, "sub_" + f.suffix, "tls-" + f.suffix + "@example.test"}},
		{`INSERT INTO paperboat.tunnels (id,account_id,name,stable_endpoint_id,stable_endpoint,created_by_host_id,created_by_actor_id,summary_transitioned_at,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$2,$7,$7,$7)`, []any{f.tunnelID, f.accountID, "tls-" + f.suffix, endpointID, endpoint, "host_" + f.suffix, now}},
		{`INSERT INTO paperboat.tunnel_routes (id,tunnel_id,name,protocol,match_type,match_hostname,origin_scheme,origin_address,created_by_actor_id,updated_by_actor_id,created_at,updated_at) VALUES ($1,$2,'default','http','exact',$3,'http','127.0.0.1:3000',$4,$4,$5,$5)`, []any{f.routeID, f.tunnelID, "tls-" + f.suffix + ".example.test", f.accountID, now}},
		{`INSERT INTO paperboat.tunnel_domains (id,account_id,tunnel_id,route_id,hostname,match_type,ownership_challenge_reference,ownership_state,dns_target,certificate_strategy,certificate_state,caa_state,conflict_state,generation,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,'exact','dns://tls','verified','target.example.test','managed','issuing','ready','clear',1,$6,$6)`, []any{f.domainID, f.accountID, f.tunnelID, f.routeID, "tls-" + f.suffix + ".example.test", now}},
		{`INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at) VALUES ($1,'default','v1',$2,'ready',true,$3)`, []any{f.edgeID, f.epoch, now}},
		{`INSERT INTO paperboat.operations (id,account_id,idempotency_key,request_hash,operation_type,resource_kind,resource_id,phase,state,progress,outcome,correlation_id,created_at,updated_at) VALUES ($1,$2,$3,decode(repeat('44',32),'hex'),'domain.create','domain_binding',$4,'issuing_certificate','running',70,'changed',$5,$6,$6)`, []any{f.opID, f.accountID, "idem_" + f.suffix, f.domainID, "corr_" + f.suffix, now}},
	} {
		if _, err := database.SQL().ExecContext(ctx, query.sql, query.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func (f sqlCertificateFixture) certificate(generation uint64, now time.Time) StoredCertificate {
	var fingerprint [32]byte
	for i := range fingerprint {
		fingerprint[i] = byte(generation)
	}
	ciphertext := bytes.Repeat([]byte{byte(generation)}, 64)
	return StoredCertificate{ID: "tcert_" + f.suffix + fmt.Sprintf("_%d", generation), DomainID: f.domainID, AccountID: f.accountID, TunnelID: f.tunnelID, Hostname: "tls-" + f.suffix + ".example.test", DomainGeneration: 1, CertificateGeneration: generation, Strategy: StrategyDelegatedDNS01, State: StateStaged, CertificateReference: "ref_" + f.suffix + fmt.Sprintf("_%d", generation), MasterKeyReference: "master/current", Envelope: ciphertext, CertificateCiphertext: ciphertext, PrivateKeyCiphertext: ciphertext, Fingerprint: fingerprint, Issuer: "test", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(24 * time.Hour), RenewalAt: now.Add(12 * time.Hour), UpdatedAt: now}
}

func stageParams(certificate StoredCertificate, fixture sqlCertificateFixture, now time.Time) dbsqlc.StageTunnelCertificateEdgeV1Params {
	return dbsqlc.StageTunnelCertificateEdgeV1Params{CertificateID: certificate.ID, EdgeNodeID: fixture.edgeID, EdgeProcessEpoch: fixture.epoch, EdgeAssignmentGeneration: 1, CertificateGeneration: int64(certificate.CertificateGeneration), Now: now}
}

func readyParams(certificate StoredCertificate, fixture sqlCertificateFixture, now time.Time) dbsqlc.MarkTunnelCertificateEdgeStateV1Params {
	return dbsqlc.MarkTunnelCertificateEdgeStateV1Params{State: "ready", ObservedAt: sql.NullTime{Time: now, Valid: true}, Now: now, CertificateID: certificate.ID, EdgeNodeID: fixture.edgeID, EdgeProcessEpoch: fixture.epoch, EdgeAssignmentGeneration: 1, CertificateGeneration: int64(certificate.CertificateGeneration)}
}

func activeParams(certificate StoredCertificate, fixture sqlCertificateFixture, now time.Time) dbsqlc.MarkTunnelCertificateEdgeStateV1Params {
	params := readyParams(certificate, fixture, now)
	params.State = "active"
	return params
}
