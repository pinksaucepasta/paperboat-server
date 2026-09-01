package tunnelcert_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/testutil"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelcert"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
	"github.com/pressly/goose/v3"
)

// TestPlatformCertificateLifecycleOnPostgres is the opt-in SQL acceptance
// boundary for the server-owned preview, tunnel, and runtime wildcard
// certificates. It is
// deliberately external to tunnelcert so the same test exercises the worker,
// SQL store, generated queries, and the migration catalog together.
func TestPlatformCertificateLifecycleOnPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run platform TLS PostgreSQL acceptance")
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
	// Register the close cleanup before the fixture cleanups below. Go runs
	// t.Cleanup callbacks in reverse registration order, so the database stays
	// open while the exact fixture cleanup executes on both success and failure.
	t.Cleanup(func() { database.Close() })
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	assertFullMigrationCatalog(t, ctx, database)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	// x509 encodes validity timestamps at whole-second precision; keeping the
	// fixture clock at that precision makes the issuer metadata exact too.
	clock := &platformAcceptanceClock{value: time.Now().UTC().Truncate(time.Second)}
	fixture := newPlatformAcceptanceFixture(suffix)
	fixture.insertEdges(t, database, clock.Now())
	fixture.insertUserDomain(t, database, clock.Now())
	fixture.insertPreviewDomain(t, database, clock.Now())

	keys := tunnelcert.ReferenceKeySource{Keys: map[string][]byte{"master/current": bytes.Repeat([]byte{0x2a}, 32)}}
	issuer := &platformAcceptanceIssuer{clock: clock}
	distributor := &platformAcceptanceDistributor{database: database, now: clock.Now}
	resolver, err := tunnelv1.NewSQLPlatformEdgeTargetResolver(database, 10*time.Minute, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	platformStore, err := tunnelcert.NewPlatformCertificateStore(database)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := tunnelcert.NewSQLIssuanceLock(database)
	if err != nil {
		t.Fatal(err)
	}

	definitions, err := tunnelcert.PlatformCertificateTargetDefinitions(tunnelcert.PlatformCertificateBases{
		PreviewBaseDomain: fixture.previewBase,
		TunnelBaseDomain:  fixture.tunnelBase,
		RuntimeBaseDomain: fixture.runtimeBase,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPlatformDefinitions(t, definitions, fixture)
	assertPlatformDNSIdentity(t, definitions[0])

	// The target table is the only valid platform owner namespace. A platform
	// certificate with a forged domain projection, and a lock with a missing
	// projection, must both be rejected by the database fences.
	badPlatform := fixture.platformCertificate(t, definitions[0], "missing_platform_target_"+suffix, 1, clock.Now())
	if err := platformStore.PutStaged(ctx, badPlatform); err == nil {
		t.Fatal("platform certificate with a missing target projection was accepted")
	}
	if locked, err := lock.Acquire(ctx, "missing_platform_target_"+suffix, "platform-lock-"+suffix, 1, clock.Now(), clock.Now().Add(time.Minute)); err == nil || locked {
		t.Fatalf("lock with a missing platform target was accepted: locked=%v err=%v", locked, err)
	}

	worker, err := tunnelv1.NewPlatformCertificateWorker(tunnelv1.PlatformCertificateWorkerConfig{
		Database:            database,
		Bases:               tunnelcert.PlatformCertificateBases{PreviewBaseDomain: fixture.previewBase, TunnelBaseDomain: fixture.tunnelBase, RuntimeBaseDomain: fixture.runtimeBase},
		EdgeTargets:         resolver.Resolve,
		Issuer:              issuer,
		CAA:                 platformAcceptanceCAA{},
		Keys:                keys,
		MasterKeyReference:  "master/current",
		IssuerName:          "acceptance-issuer",
		OwnerID:             "platform-worker-" + suffix,
		Distributor:         distributor,
		RenewBefore:         30 * 24 * time.Hour,
		DistributionTimeout: 30 * time.Second,
		Now:                 clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Force the first attempt down the durable failed-record path. The next
	// pass must wait for the recorded retry deadline and then allocate a new
	// certificate generation rather than reusing the failed row.
	distributor.failStage = true
	changed, err := worker.Reconcile(ctx, 10)
	if err != nil {
		t.Fatalf("initial failed platform reconciliation: %v", err)
	}
	if changed != 0 || issuer.calls != 2 {
		t.Fatalf("initial failed reconciliation changed=%d issuer_calls=%d", changed, issuer.calls)
	}
	failedCount := countRows(t, ctx, database.SQL(), `SELECT count(*) FROM paperboat.tunnel_certificate_records WHERE target_kind='platform_wildcard' AND state='failed' AND certificate_generation=1`)
	if failedCount != 3 {
		t.Fatalf("failed platform generation rows=%d, want 3", failedCount)
	}
	assertFailedPlatformPayloadFence(t, ctx, database)
	targets, err := platformStore.ListPlatformTargets(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 {
		t.Fatalf("platform target rows after failed pass=%d, want 3", len(targets))
	}
	for _, target := range targets {
		if target.CertificateState != "failed" || target.RetryCount != 1 || !target.NextRetryAt.After(clock.Now()) {
			t.Fatalf("failed target projection=%+v", target)
		}
	}

	clock.Advance(2 * time.Minute)
	distributor.failStage = false
	changed, err = worker.Reconcile(ctx, 10)
	if err != nil {
		t.Fatalf("platform retry reconciliation: %v", err)
	}
	if changed != 3 || issuer.calls != 6 {
		t.Fatalf("platform retry changed=%d issuer_calls=%d, want changed=3 calls=6", changed, issuer.calls)
	}
	assertPlatformTargetsReady(t, ctx, platformStore, fixture)
	assertActivePlatformCertificates(t, ctx, database, platformStore, fixture, keys, distributor)

	// A second pass is idempotent: no authority call and no extra certificate
	// rows are created while both active rows remain healthy and distributed.
	issuerCalls := issuer.calls
	activeRows := countRows(t, ctx, database.SQL(), `SELECT count(*) FROM paperboat.tunnel_certificate_records WHERE target_kind='platform_wildcard' AND state='active'`)
	changed, err = worker.Reconcile(ctx, 10)
	if err != nil || changed != 0 || issuer.calls != issuerCalls {
		t.Fatalf("idempotent platform reconciliation changed=%d calls=%d/%d err=%v", changed, issuer.calls, issuerCalls, err)
	}
	if got := countRows(t, ctx, database.SQL(), `SELECT count(*) FROM paperboat.tunnel_certificate_records WHERE target_kind='platform_wildcard' AND state='active'`); got != activeRows {
		t.Fatalf("idempotent active row count=%d, want %d", got, activeRows)
	}

	// Replaying the exact active payload is safe, while changing encrypted
	// material under the same ID is a generation conflict.
	var platformRows []tunnelcert.PlatformCertificateTarget
	platformRows, err = platformStore.ListPlatformTargets(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range platformRows {
		current, found, err := platformStore.Current(ctx, target.ID)
		if err != nil || !found {
			t.Fatalf("current platform certificate %s found=%v err=%v", target.ID, found, err)
		}
		if err := platformStore.PutStaged(ctx, current); err != nil {
			t.Fatalf("active platform replay %s: %v", target.ID, err)
		}
		mismatch := current
		mismatch.PrivateKeyCiphertext = append([]byte(nil), current.PrivateKeyCiphertext...)
		mismatch.PrivateKeyCiphertext[0] ^= 1
		if err := platformStore.PutStaged(ctx, mismatch); !errors.Is(err, tunnelcert.ErrGenerationConflict) {
			t.Fatalf("mismatched active replay %s error=%v, want generation conflict", target.ID, err)
		}
		next, err := platformStore.NextCertificateGeneration(ctx, target.ID)
		if err != nil || next != 3 {
			t.Fatalf("next platform generation %s=%d err=%v, want 3", target.ID, next, err)
		}
	}

	// Durable issuance locks are target-scoped, owner-fenced, and released by
	// exact generation. A competing owner cannot acquire the same target.
	lockOwnerA := "platform-lock-a-" + suffix
	lockOwnerB := "platform-lock-b-" + suffix
	if locked, err := lock.Acquire(ctx, definitions[0].ID, lockOwnerA, 1, clock.Now(), clock.Now().Add(time.Minute)); err != nil || !locked {
		t.Fatalf("platform issuance lock owner A=%v err=%v", locked, err)
	}
	if locked, err := lock.Acquire(ctx, definitions[0].ID, lockOwnerB, 1, clock.Now(), clock.Now().Add(time.Minute)); err != nil || locked {
		t.Fatalf("platform issuance lock owner B=%v err=%v, want fenced", locked, err)
	}
	if err := lock.ReleaseGeneration(ctx, definitions[0].ID, lockOwnerA, 1); err != nil {
		t.Fatal(err)
	}

	// Heartbeat version changes update liveness only. The platform assignment
	// generation remains one for both nodes.
	clock.Advance(time.Minute)
	for _, edge := range fixture.edgeTuples() {
		if _, err := database.Queries().HeartbeatControlTunnelNode(ctx, dbsqlc.HeartbeatControlTunnelNodeParams{
			Ready: true, Observation: []byte(`{"heartbeat":"changed"}`), Now: sql.NullTime{Time: clock.Now(), Valid: true}, ID: edge.nodeID, ProcessEpoch: edge.processEpoch,
		}); err != nil {
			t.Fatal(err)
		}
	}
	edges, err := resolver.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertStablePlatformEdgeGeneration(t, edges, fixture.edgeTuples())
	issuerCalls = issuer.calls
	if changed, err := worker.Reconcile(ctx, 10); err != nil || changed != 0 || issuer.calls != issuerCalls {
		t.Fatalf("heartbeat-only reconciliation changed=%d calls=%d/%d err=%v", changed, issuer.calls, issuerCalls, err)
	}

	// Replacing one process epoch creates exactly one new active distribution
	// tuple, without minting a certificate or changing its generation.
	replacementEpoch := "epoch-platform-" + suffix + "-replacement"
	clock.Advance(time.Minute)
	if _, err := database.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET process_epoch=$2,last_heartbeat_at=$3,updated_at=$3,version=version+1 WHERE id=$1`, fixture.edgeA, replacementEpoch, clock.Now()); err != nil {
		t.Fatal(err)
	}
	replacementEdges, err := resolver.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("replacement resolver edges=%+v", replacementEdges)
	var replacementResolved bool
	for _, edge := range replacementEdges {
		if edge.NodeID == fixture.edgeA && edge.ProcessEpoch == replacementEpoch && edge.Generation == 1 {
			replacementResolved = true
			break
		}
	}
	if !replacementResolved {
		t.Fatalf("replacement resolver did not return edge=%s epoch=%s: %+v", fixture.edgeA, replacementEpoch, replacementEdges)
	}
	var replacementPlatformRows []tunnelcert.PlatformCertificateTarget
	replacementPlatformRows, err = platformStore.ListPlatformTargets(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range replacementPlatformRows {
		current, found, err := platformStore.Current(ctx, target.ID)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("replacement preflight target=%s state=%s next_retry_at=%+v current_found=%v current_generation=%d current_renewal_at=%+v current_expires_at=%+v", target.ID, target.CertificateState, target.NextRetryAt, found, current.CertificateGeneration, current.RenewalAt, current.ExpiresAt)
	}
	coverageStart := len(distributor.coverageCalls)
	stageStart := len(distributor.stageCalls)
	issuerCalls = issuer.calls
	if changed, err := worker.Reconcile(ctx, 10); err != nil || changed != 0 || issuer.calls != issuerCalls {
		t.Fatalf("process replacement reconciliation changed=%d calls=%d/%d err=%v", changed, issuer.calls, issuerCalls, err)
	}
	for _, call := range distributor.coverageCalls[coverageStart:] {
		t.Logf("replacement coverage certificate=%s targets=%v missing=%v", call.certificateID, call.targets, call.missing)
	}
	t.Logf("replacement stage call count delta=%d", len(distributor.stageCalls)-stageStart)
	for _, call := range distributor.stageCalls[stageStart:] {
		t.Logf("replacement stage certificate=%s requested=%s returned=%s", call.certificateID, call.requested, call.returned)
	}
	for _, target := range definitions {
		current, found, err := platformStore.Current(ctx, target.ID)
		if err != nil || !found || current.CertificateGeneration != 2 {
			t.Fatalf("replacement current %s=%+v found=%v err=%v", target.ID, current, found, err)
		}
		edges, err := database.Queries().ListTunnelCertificateEdgesV1(ctx, current.ID)
		if err != nil {
			t.Fatal(err)
		}
		active := 0
		retiredOld := 0
		for _, edge := range edges {
			if edge.State == "active" {
				active++
				if edge.EdgeAssignmentGeneration != 1 || edge.ObservedCertificateGeneration != 2 {
					t.Fatalf("replacement active edge=%+v", edge)
				}
			}
			if edge.EdgeProcessEpoch == fixture.epochA && edge.State == "retired" {
				retiredOld++
			}
		}
		if active != 2 || retiredOld != 1 {
			t.Fatalf("replacement distributions=%+v active=%d retired_old=%d", edges, active, retiredOld)
		}
	}

	// Ordinary user certificates still have an owner FK and cascade when the
	// account is deleted. Platform records deliberately have no users owner.
	userStore, err := tunnelcert.NewSQLStore(database)
	if err != nil {
		t.Fatal(err)
	}
	userBundle, err := acceptanceBundle(fixture.userHostname, clock.Now(), 8, "user-acceptance-ca")
	if err != nil {
		t.Fatal(err)
	}
	userStored := fixture.userCertificate(t, userBundle, keys, clock.Now())
	if err := userStore.PutStaged(ctx, userStored); err != nil {
		t.Fatalf("put ordinary user certificate: %v", err)
	}
	if _, err := userStore.Activate(ctx, userStored.ID, 1, clock.Now()); err != nil {
		t.Fatalf("activate ordinary user certificate: %v", err)
	}
	assertUserOwnerCascade(t, ctx, database, fixture)

	previewStored := fixture.previewCertificate(t, keys, clock.Now())
	if err := userStore.PutStaged(ctx, previewStored); err != nil {
		t.Fatalf("put preview certificate: %v", err)
	}
	if _, err := userStore.Activate(ctx, previewStored.ID, 1, clock.Now()); err != nil {
		t.Fatalf("activate preview certificate: %v", err)
	}
	previewLockOwner := "preview-lock-" + suffix
	if locked, err := lock.Acquire(ctx, fixture.previewDomainID, previewLockOwner, 1, clock.Now(), clock.Now().Add(time.Minute)); err != nil || !locked {
		t.Fatalf("preview issuance lock=%v err=%v", locked, err)
	}

	// Migration 151 must refuse a rollback while the runtime target remains.
	// Once that target and all platform certificate state are removed, migration
	// 151 restores the original two-target constraints and migration 150 can
	// remove the platform table. Preview/user certificate rows and the preview
	// lock must survive both rollbacks.
	configurePlatformGoose(t)
	if err := goose.DownContext(ctx, database.SQL(), "migrations"); err == nil || !strings.Contains(strings.ToLower(err.Error()), "platform certificate") {
		t.Fatalf("platform migration Down refusal=%v", err)
	}
	if got := countRows(t, ctx, database.SQL(), `SELECT count(*) FROM paperboat.tunnel_platform_certificate_targets`); got != 3 {
		t.Fatalf("platform targets after guarded Down=%d, want 3", got)
	}
	if _, err := database.SQL().ExecContext(ctx, `DELETE FROM paperboat.tunnel_certificate_edge_distributions WHERE certificate_id IN (SELECT id FROM paperboat.tunnel_certificate_records WHERE target_kind='platform_wildcard')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SQL().ExecContext(ctx, `DELETE FROM paperboat.tunnel_certificate_records WHERE target_kind='platform_wildcard'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SQL().ExecContext(ctx, `DELETE FROM paperboat.tunnel_certificate_issuance_locks WHERE domain_id IN ($1,$2,$3)`, definitions[0].ID, definitions[1].ID, definitions[2].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SQL().ExecContext(ctx, `DELETE FROM paperboat.tunnel_platform_certificate_targets WHERE id=$1`, definitions[2].ID); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownContext(ctx, database.SQL(), "migrations"); err != nil {
		t.Fatalf("rollback migration 151: %v", err)
	}
	if exists := tableExists(t, ctx, database.SQL(), "tunnel_platform_certificate_targets"); !exists {
		t.Fatal("platform target table was removed by migration 151 Down")
	}
	if err := goose.DownContext(ctx, database.SQL(), "migrations"); err != nil {
		t.Fatalf("rollback migration 150: %v", err)
	}
	rolledBack := true
	t.Cleanup(func() {
		if rolledBack {
			configurePlatformGoose(t)
			if err := goose.UpContext(context.Background(), database.SQL(), "migrations"); err != nil {
				t.Errorf("restore migration 150 after failed rollback test: %v", err)
			}
		}
	})
	if exists := tableExists(t, ctx, database.SQL(), "tunnel_platform_certificate_targets"); exists {
		t.Fatal("platform target table survived migration 150 Down")
	}
	assertPreviewRowsSurviveRollback(t, ctx, database, fixture, previewStored, previewLockOwner)
	if err := goose.UpContext(ctx, database.SQL(), "migrations"); err != nil {
		t.Fatal(err)
	}
	rolledBack = false
	if !tableExists(t, ctx, database.SQL(), "tunnel_platform_certificate_targets") {
		t.Fatal("platform target table was not restored by migration 150 Up")
	}
	assertPreviewRowsSurviveRollback(t, ctx, database, fixture, previewStored, previewLockOwner)
	if err := platformStore.EnsurePlatformTargets(ctx, definitions, clock.Now()); err != nil {
		t.Fatal(err)
	}
	assertPlatformTargetsRecreated(t, ctx, platformStore, fixture)

	// The ordinary user row is still present after the guarded rollback and is
	// removed through the restored owner cascade. Platform targets survive it.
	if _, err := database.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, fixture.userAccountID); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, ctx, database.SQL(), `SELECT count(*) FROM paperboat.tunnel_certificate_records WHERE id=$1`, userStored.ID); got != 0 {
		t.Fatalf("ordinary user certificate rows after account delete=%d, want 0", got)
	}
	if got := countRows(t, ctx, database.SQL(), `SELECT count(*) FROM paperboat.tunnel_platform_certificate_targets WHERE id IN ($1,$2,$3)`, definitions[0].ID, definitions[1].ID, definitions[2].ID); got != 3 {
		t.Fatalf("platform targets after ordinary account delete=%d, want 3", got)
	}
	assertNoPlaintextCertificateColumnsOrLogs(t, ctx, database)

	t.Cleanup(func() {
		cleanupPlatformAcceptanceFixture(database, fixture, definitions, previewStored, previewLockOwner)
	})
}

type platformAcceptanceClock struct{ value time.Time }

func (c *platformAcceptanceClock) Now() time.Time { return c.value.UTC() }

func (c *platformAcceptanceClock) Advance(delta time.Duration) { c.value = c.value.Add(delta) }

type platformAcceptanceCAA struct{}

func (platformAcceptanceCAA) Check(context.Context, string, string) (tunnelcert.CAAResult, error) {
	return tunnelcert.CAAResult{State: "not_applicable"}, nil
}

type platformAcceptanceIssuer struct {
	clock          *platformAcceptanceClock
	calls          int
	requests       []tunnelcert.Domain
	challengeNames []string
}

func (i *platformAcceptanceIssuer) Issue(context.Context, tunnelcert.IssueRequest) (tunnelcert.CertificateBundle, error) {
	return tunnelcert.CertificateBundle{}, tunnelcert.ErrIssuerUnavailable
}

func (i *platformAcceptanceIssuer) IssueDNS01(_ context.Context, domain tunnelcert.Domain) (tunnelcert.CertificateBundle, error) {
	if domain.TargetKind != tunnelcert.TargetPlatformWildcard || domain.Strategy != tunnelcert.StrategyPlatformDNS01 {
		return tunnelcert.CertificateBundle{}, fmt.Errorf("unexpected platform issuer identity: target=%q strategy=%q", domain.TargetKind, domain.Strategy)
	}
	challengeName, err := tunnelcert.PlatformDNSChallengeTargetForDomain(domain)
	if err != nil {
		return tunnelcert.CertificateBundle{}, err
	}
	i.calls++
	i.requests = append(i.requests, domain)
	i.challengeNames = append(i.challengeNames, challengeName)
	return acceptanceBundle(domain.Hostname, i.clock.Now(), i.calls, "platform-acceptance-ca")
}

type platformAcceptanceDistributor struct {
	database      *db.DB
	now           func() time.Time
	failStage     bool
	stageCount    int
	sawStaged     bool
	coverageCalls []platformAcceptanceCoverageCall
	stageCalls    []platformAcceptanceStageCall
}

type platformAcceptanceCoverageCall struct {
	certificateID string
	targets       []string
	missing       []string
}

type platformAcceptanceStageCall struct {
	certificateID string
	requested     string
	returned      string
}

func (d *platformAcceptanceDistributor) Stage(ctx context.Context, request tunnelcert.DistributionRequest) error {
	d.stageCount++
	if request.Certificate.State != tunnelcert.StateStaged && request.Certificate.State != tunnelcert.StateActive || len(request.Certificate.PrivateKeyCiphertext) < 29 || bytes.Contains(request.Certificate.PrivateKeyCiphertext, []byte("PRIVATE KEY")) {
		return fmt.Errorf("stage did not receive an encrypted staged or active certificate")
	}
	d.sawStaged = true
	if d.failStage {
		return tunnelcert.ErrDistributionUnavailable
	}
	wantState := string(tunnelcert.StateStaged)
	if request.Certificate.State == tunnelcert.StateActive {
		wantState = string(tunnelcert.StateActive)
	}
	if got := d.certificateState(ctx, request.Certificate.ID); got != wantState {
		return fmt.Errorf("database certificate state at stage=%q want=%q", got, wantState)
	}
	staged, err := d.database.Queries().StageTunnelCertificateEdgeV1(ctx, dbsqlc.StageTunnelCertificateEdgeV1Params{
		CertificateID: request.Certificate.ID, EdgeNodeID: request.Target.NodeID, EdgeProcessEpoch: request.Target.ProcessEpoch,
		EdgeAssignmentGeneration: int64(request.Target.Generation), CertificateGeneration: int64(request.Certificate.CertificateGeneration), Now: d.now(),
	})
	requested := request.Target.NodeID + "/" + request.Target.ProcessEpoch + fmt.Sprintf("/%d", request.Target.Generation)
	returned := ""
	if err == nil {
		returned = staged.EdgeNodeID + "/" + staged.EdgeProcessEpoch + fmt.Sprintf("/%d", staged.EdgeAssignmentGeneration)
	}
	d.stageCalls = append(d.stageCalls, platformAcceptanceStageCall{certificateID: request.Certificate.ID, requested: requested, returned: returned})
	return err
}

func (d *platformAcceptanceDistributor) WaitReady(ctx context.Context, request tunnelcert.DistributionRequest) error {
	return d.markEdge(ctx, request, "ready")
}

func (d *platformAcceptanceDistributor) Activate(ctx context.Context, request tunnelcert.DistributionRequest) error {
	return d.markEdge(ctx, request, "active")
}

func (d *platformAcceptanceDistributor) Retire(ctx context.Context, certificate tunnelcert.StoredCertificate, target tunnelcert.DistributionTarget) error {
	return d.markEdge(ctx, tunnelcert.DistributionRequest{Certificate: certificate, Target: target}, "retired")
}

func (d *platformAcceptanceDistributor) MissingCertificateTargets(ctx context.Context, certificate tunnelcert.StoredCertificate, targets []tunnelcert.DistributionTarget) ([]tunnelcert.DistributionTarget, error) {
	rows, err := d.database.Queries().ListTunnelCertificateEdgesV1(ctx, certificate.ID)
	if err != nil {
		return nil, err
	}
	active := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.State == "active" && row.EdgeAssignmentGeneration > 0 && row.ObservedCertificateGeneration == int64(certificate.CertificateGeneration) {
			active[row.EdgeNodeID+"\x00"+row.EdgeProcessEpoch+fmt.Sprintf("\x00%d", row.EdgeAssignmentGeneration)] = true
		}
	}
	missing := make([]tunnelcert.DistributionTarget, 0, len(targets))
	for _, target := range targets {
		key := target.NodeID + "\x00" + target.ProcessEpoch + fmt.Sprintf("\x00%d", target.Generation)
		if !active[key] {
			missing = append(missing, target)
		}
	}
	coverageCall := platformAcceptanceCoverageCall{certificateID: certificate.ID, targets: make([]string, 0, len(targets)), missing: make([]string, 0, len(missing))}
	for _, target := range targets {
		coverageCall.targets = append(coverageCall.targets, target.NodeID+"/"+target.ProcessEpoch+fmt.Sprintf("/%d", target.Generation))
	}
	for _, target := range missing {
		coverageCall.missing = append(coverageCall.missing, target.NodeID+"/"+target.ProcessEpoch+fmt.Sprintf("/%d", target.Generation))
	}
	d.coverageCalls = append(d.coverageCalls, coverageCall)
	return missing, nil
}

func (d *platformAcceptanceDistributor) RetireCertificate(ctx context.Context, certificate tunnelcert.StoredCertificate) error {
	rows, err := d.database.Queries().ListTunnelCertificateEdgesV1(ctx, certificate.ID)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.State == "retired" || row.State == "revoked" {
			continue
		}
		if err := d.markEdge(ctx, tunnelcert.DistributionRequest{Certificate: certificate, Target: tunnelcert.DistributionTarget{NodeID: row.EdgeNodeID, ProcessEpoch: row.EdgeProcessEpoch, Generation: uint64(row.EdgeAssignmentGeneration)}}, "retired"); err != nil {
			return err
		}
	}
	return nil
}

func (d *platformAcceptanceDistributor) RetireObsoleteCertificateTargets(ctx context.Context, certificate tunnelcert.StoredCertificate, targets []tunnelcert.DistributionTarget) error {
	keep := make(map[string]bool, len(targets))
	for _, target := range targets {
		keep[target.NodeID+"\x00"+target.ProcessEpoch+fmt.Sprintf("\x00%d", target.Generation)] = true
	}
	rows, err := d.database.Queries().ListTunnelCertificateEdgesV1(ctx, certificate.ID)
	if err != nil {
		return err
	}
	for _, row := range rows {
		key := row.EdgeNodeID + "\x00" + row.EdgeProcessEpoch + fmt.Sprintf("\x00%d", row.EdgeAssignmentGeneration)
		if keep[key] || row.State == "retired" || row.State == "revoked" {
			continue
		}
		if err := d.markEdge(ctx, tunnelcert.DistributionRequest{Certificate: certificate, Target: tunnelcert.DistributionTarget{NodeID: row.EdgeNodeID, ProcessEpoch: row.EdgeProcessEpoch, Generation: uint64(row.EdgeAssignmentGeneration)}}, "retired"); err != nil {
			return err
		}
	}
	return nil
}

func (d *platformAcceptanceDistributor) markEdge(ctx context.Context, request tunnelcert.DistributionRequest, state string) error {
	if request.Certificate.ID == "" || request.Target.NodeID == "" {
		return tunnelcert.ErrInvalid
	}
	_, err := d.database.Queries().MarkTunnelCertificateEdgeStateV1(ctx, dbsqlc.MarkTunnelCertificateEdgeStateV1Params{
		State: state, ObservedAt: sql.NullTime{Time: d.now(), Valid: true}, Now: d.now(), CertificateID: request.Certificate.ID,
		EdgeNodeID: request.Target.NodeID, EdgeProcessEpoch: request.Target.ProcessEpoch, EdgeAssignmentGeneration: int64(request.Target.Generation), CertificateGeneration: int64(request.Certificate.CertificateGeneration),
	})
	return err
}

func (d *platformAcceptanceDistributor) certificateState(ctx context.Context, id string) string {
	var state string
	if err := d.database.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.tunnel_certificate_records WHERE id=$1`, id).Scan(&state); err != nil {
		return ""
	}
	return state
}

type platformAcceptanceEdge struct {
	nodeID       string
	processEpoch string
}

type platformAcceptanceFixture struct {
	suffix string

	previewBase string
	tunnelBase  string
	runtimeBase string
	edgeA       string
	edgeB       string
	epochA      string
	epochB      string

	userAccountID string
	userTunnelID  string
	userRouteID   string
	userDomainID  string
	userHostname  string

	previewAccountID string
	previewLeaseID   string
	previewDomainID  string
	previewHostname  string
}

func newPlatformAcceptanceFixture(suffix string) platformAcceptanceFixture {
	return platformAcceptanceFixture{
		suffix:      suffix,
		previewBase: "preview-" + suffix + ".platform.example.test",
		tunnelBase:  "tunnels-" + suffix + ".platform.example.test",
		runtimeBase: "runtime-" + suffix + ".platform.example.test",
		edgeA:       "edge-platform-a-" + suffix, edgeB: "edge-platform-b-" + suffix,
		epochA: "epoch-platform-a-" + suffix, epochB: "epoch-platform-b-" + suffix,
		userAccountID: "usr-platform-user-" + suffix, userTunnelID: "tun-platform-user-" + suffix,
		userRouteID: "rte-platform-user-" + suffix, userDomainID: "dom-platform-user-" + suffix,
		userHostname:     "user-" + suffix + ".customer.example.test",
		previewAccountID: "usr-platform-preview-" + suffix, previewLeaseID: "lease-platform-preview-" + suffix,
		previewDomainID: "dom-platform-preview-" + suffix, previewHostname: "preview-cert-" + suffix + ".customer.example.test",
	}
}

func (f platformAcceptanceFixture) edgeTuples() []platformAcceptanceEdge {
	return []platformAcceptanceEdge{{nodeID: f.edgeA, processEpoch: f.epochA}, {nodeID: f.edgeB, processEpoch: f.epochB}}
}

func (f platformAcceptanceFixture) insertEdges(t *testing.T, database *db.DB, now time.Time) {
	t.Helper()
	for _, edge := range f.edgeTuples() {
		if _, err := database.SQL().ExecContext(context.Background(), `INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at,version) VALUES ($1,'default','v1',$2,'ready',true,$3,1)`, edge.nodeID, edge.processEpoch, now); err != nil {
			t.Fatal(err)
		}
	}
}

func (f platformAcceptanceFixture) insertUserDomain(t *testing.T, database *db.DB, now time.Time) {
	t.Helper()
	endpointID := testutil.EndpointUUID("platform-user:" + f.suffix)
	endpoint := "https://" + endpointID + ".tunnels.example.test"
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, []any{f.userAccountID, "subject_" + f.suffix, "user-" + f.suffix + "@example.test"}},
		{`INSERT INTO paperboat.tunnels (id,account_id,name,stable_endpoint_id,stable_endpoint,created_by_host_id,created_by_actor_id,summary_transitioned_at,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$2,$7,$7,$7)`, []any{f.userTunnelID, f.userAccountID, "platform-user-" + f.suffix, endpointID, endpoint, "host-" + f.suffix, now}},
		{`INSERT INTO paperboat.tunnel_routes (id,tunnel_id,name,protocol,match_type,match_hostname,origin_scheme,origin_address,created_by_actor_id,updated_by_actor_id,created_at,updated_at) VALUES ($1,$2,'default','http','exact',$3,'http','127.0.0.1:3000',$4,$4,$5,$5)`, []any{f.userRouteID, f.userTunnelID, f.userHostname, f.userAccountID, now}},
		{`INSERT INTO paperboat.tunnel_domains (id,account_id,tunnel_id,route_id,hostname,match_type,ownership_challenge_reference,ownership_state,dns_target,certificate_strategy,certificate_state,caa_state,conflict_state,generation,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,'exact','dns-user-platform','verified','target.user.example.test','managed','issuing','ready','clear',1,$6,$6)`, []any{f.userDomainID, f.userAccountID, f.userTunnelID, f.userRouteID, f.userHostname, now}},
	}
	for _, item := range queries {
		if _, err := database.SQL().ExecContext(context.Background(), item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func (f platformAcceptanceFixture) insertPreviewDomain(t *testing.T, database *db.DB, now time.Time) {
	t.Helper()
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, []any{f.previewAccountID, "subject_preview_" + f.suffix, "preview-" + f.suffix + "@example.test"}},
		{`INSERT INTO paperboat.preview_leases (id,endpoint_id,endpoint,account_id,actor_id,owner_device_id,owner_session_id,target_scheme,target_address,access_mode,lease_deadline,user_deadline,allocation_state,edge_state,origin_state,terminal_state,created_at,ready_at,last_renewed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'http','127.0.0.1:3000','public',$8,$9,'ready','ready','ready','active',$10,$10,$10)`, []any{f.previewLeaseID, "endpoint-" + f.suffix, "https://preview-" + f.suffix + ".preview.example.test", f.previewAccountID, f.previewAccountID, "device-" + f.suffix, "session-" + f.suffix, now.Add(24 * time.Hour), now.Add(12 * time.Hour), now}},
		{`INSERT INTO paperboat.preview_domains (id,account_id,preview_id,preview_generation,hostname,match_type,ownership_challenge_reference,ownership_state,dns_target,observed_records,dns_provider,expected_records,dns_next_check_at,dns_ttl_seconds,verification_attempts,certificate_strategy,certificate_state,caa_state,conflict_state,generation,created_at,updated_at) VALUES ($1,$2,$3,1,$4,'exact','dns-preview-platform','verified','target.preview.example.test','[]'::jsonb,'generic','[]'::jsonb,$5,300,0,'managed','issuing','ready','clear',1,$5,$5)`, []any{f.previewDomainID, f.previewAccountID, f.previewLeaseID, f.previewHostname, now}},
	}
	for _, item := range queries {
		if _, err := database.SQL().ExecContext(context.Background(), item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func assertPlatformDefinitions(t *testing.T, definitions []tunnelcert.PlatformCertificateTargetDefinition, f platformAcceptanceFixture) {
	t.Helper()
	want := []tunnelcert.PlatformCertificateTargetDefinition{
		{ID: tunnelcert.PlatformPreviewTargetID, Kind: tunnelcert.PlatformPreviewWildcardTarget, Hostname: "*." + f.previewBase, AccountID: tunnelcert.PlatformAccountID, ChallengeReference: tunnelcert.PlatformPreviewChallengeReference, Generation: 1},
		{ID: tunnelcert.PlatformTunnelTargetID, Kind: tunnelcert.PlatformTunnelWildcardTarget, Hostname: "*." + f.tunnelBase, AccountID: tunnelcert.PlatformAccountID, ChallengeReference: tunnelcert.PlatformTunnelChallengeReference, Generation: 1},
		{ID: tunnelcert.PlatformRuntimeTargetID, Kind: tunnelcert.PlatformRuntimeWildcardTarget, Hostname: "*." + f.runtimeBase, AccountID: tunnelcert.PlatformAccountID, ChallengeReference: tunnelcert.PlatformRuntimeChallengeReference, Generation: 1},
	}
	if fmt.Sprintf("%+v", definitions) != fmt.Sprintf("%+v", want) {
		t.Fatalf("platform target definitions=%+v, want %+v", definitions, want)
	}
}

func assertPlatformDNSIdentity(t *testing.T, definition tunnelcert.PlatformCertificateTargetDefinition) {
	t.Helper()
	domain := tunnelcert.Domain{ID: definition.ID, AccountID: definition.AccountID, TargetKind: tunnelcert.TargetPlatformWildcard, Hostname: definition.Hostname, Generation: definition.Generation, Strategy: tunnelcert.StrategyPlatformDNS01, OwnershipState: "verified"}
	name, err := tunnelcert.PlatformDNSChallengeTargetForDomain(domain)
	if err != nil {
		t.Fatal(err)
	}
	want := "_acme-challenge." + strings.TrimPrefix(definition.Hostname, "*.")
	if name != want {
		t.Fatalf("platform DNS target=%q, want %q", name, want)
	}
	wrongStrategy := domain
	wrongStrategy.Strategy = tunnelcert.StrategyDelegatedDNS01
	if err := wrongStrategy.Validate(); !errors.Is(err, tunnelcert.ErrInvalid) {
		t.Fatalf("platform target accepted delegated strategy: %v", err)
	}
	wrongKind := domain
	wrongKind.TargetKind = tunnelcert.TargetDurableRoute
	wrongKind.TunnelID = "tun-platform-wrong"
	wrongKind.RouteID = "route-platform-wrong"
	wrongKind.Strategy = tunnelcert.StrategyDelegatedDNS01
	if err := wrongKind.Validate(); err != nil {
		t.Fatalf("ordinary target identity unexpectedly invalid: %v", err)
	}
	if _, err := tunnelcert.PlatformDNSChallengeTargetForDomain(wrongKind); !errors.Is(err, tunnelcert.ErrDNSChallengeUnavailable) {
		t.Fatalf("direct platform DNS helper accepted ordinary target: %v", err)
	}
}

func assertPlatformTargetsReady(t *testing.T, ctx context.Context, store *tunnelcert.PlatformCertificateStore, f platformAcceptanceFixture) {
	t.Helper()
	rows, err := store.ListPlatformTargets(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("platform targets=%d, want 3", len(rows))
	}
	want := map[string]tunnelcert.PlatformCertificateTargetDefinition{
		tunnelcert.PlatformPreviewTargetID: {ID: tunnelcert.PlatformPreviewTargetID, Kind: tunnelcert.PlatformPreviewWildcardTarget, Hostname: "*." + f.previewBase, AccountID: tunnelcert.PlatformAccountID, ChallengeReference: tunnelcert.PlatformPreviewChallengeReference, Generation: 1},
		tunnelcert.PlatformTunnelTargetID:  {ID: tunnelcert.PlatformTunnelTargetID, Kind: tunnelcert.PlatformTunnelWildcardTarget, Hostname: "*." + f.tunnelBase, AccountID: tunnelcert.PlatformAccountID, ChallengeReference: tunnelcert.PlatformTunnelChallengeReference, Generation: 1},
		tunnelcert.PlatformRuntimeTargetID: {ID: tunnelcert.PlatformRuntimeTargetID, Kind: tunnelcert.PlatformRuntimeWildcardTarget, Hostname: "*." + f.runtimeBase, AccountID: tunnelcert.PlatformAccountID, ChallengeReference: tunnelcert.PlatformRuntimeChallengeReference, Generation: 1},
	}
	for index, row := range rows {
		if row.AccountID != tunnelcert.PlatformAccountID || row.Generation != 1 || row.DesiredState != "active" || row.CertificateState != "ready" || row.CertificateReference == "" {
			t.Fatalf("platform target row=%+v", row)
		}
		definition, ok := want[row.ID]
		if !ok || row.Hostname != definition.Hostname || row.Kind != definition.Kind || row.ChallengeReference != definition.ChallengeReference {
			t.Fatalf("platform target row[%d]=%+v", index, row)
		}
		delete(want, row.ID)
	}
	if len(want) != 0 {
		t.Fatalf("platform targets missing=%v", want)
	}
}

func assertPlatformTargetsRecreated(t *testing.T, ctx context.Context, store *tunnelcert.PlatformCertificateStore, f platformAcceptanceFixture) {
	t.Helper()
	rows, err := store.ListPlatformTargets(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("recreated platform targets=%d, want 3", len(rows))
	}
	want := map[string]tunnelcert.PlatformCertificateTargetDefinition{
		tunnelcert.PlatformPreviewTargetID: {ID: tunnelcert.PlatformPreviewTargetID, Kind: tunnelcert.PlatformPreviewWildcardTarget, Hostname: "*." + f.previewBase, AccountID: tunnelcert.PlatformAccountID, ChallengeReference: tunnelcert.PlatformPreviewChallengeReference, Generation: 1},
		tunnelcert.PlatformTunnelTargetID:  {ID: tunnelcert.PlatformTunnelTargetID, Kind: tunnelcert.PlatformTunnelWildcardTarget, Hostname: "*." + f.tunnelBase, AccountID: tunnelcert.PlatformAccountID, ChallengeReference: tunnelcert.PlatformTunnelChallengeReference, Generation: 1},
		tunnelcert.PlatformRuntimeTargetID: {ID: tunnelcert.PlatformRuntimeTargetID, Kind: tunnelcert.PlatformRuntimeWildcardTarget, Hostname: "*." + f.runtimeBase, AccountID: tunnelcert.PlatformAccountID, ChallengeReference: tunnelcert.PlatformRuntimeChallengeReference, Generation: 1},
	}
	for index, row := range rows {
		if row.AccountID != tunnelcert.PlatformAccountID || row.Generation != 1 || row.DesiredState != "active" || row.CertificateState != "pending" || row.CertificateReference != "" {
			t.Fatalf("recreated platform target row=%+v", row)
		}
		definition, ok := want[row.ID]
		if !ok || row.Hostname != definition.Hostname || row.Kind != definition.Kind || row.ChallengeReference != definition.ChallengeReference {
			t.Fatalf("recreated platform target row[%d]=%+v", index, row)
		}
		delete(want, row.ID)
	}
	if len(want) != 0 {
		t.Fatalf("recreated platform targets missing=%v", want)
	}
}

func assertActivePlatformCertificates(t *testing.T, ctx context.Context, database *db.DB, store *tunnelcert.PlatformCertificateStore, f platformAcceptanceFixture, keys tunnelcert.MasterKeySource, distributor *platformAcceptanceDistributor) {
	t.Helper()
	rows, err := store.ListPlatformTargets(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !distributor.sawStaged {
		t.Fatal("distributor never observed an encrypted staged platform record")
	}
	// The first pass reaches one edge before each injected failure (3 calls),
	// and the retry stages both edges for all three targets (6 more calls).
	if distributor.stageCount != 9 {
		t.Fatalf("platform stage calls across failure and retry=%d, want 9", distributor.stageCount)
	}
	for _, target := range rows {
		current, found, err := store.Current(ctx, target.ID)
		if err != nil || !found || current.State != tunnelcert.StateActive || current.TargetKind != tunnelcert.TargetPlatformWildcard || current.Strategy != tunnelcert.StrategyPlatformDNS01 || current.CertificateGeneration != 2 {
			t.Fatalf("active platform certificate target=%s current=%+v found=%v err=%v", target.ID, current, found, err)
		}
		if len(current.CertificateCiphertext) < 29 || len(current.PrivateKeyCiphertext) < 29 || bytes.Contains(current.CertificateCiphertext, []byte("CERTIFICATE")) || bytes.Contains(current.PrivateKeyCiphertext, []byte("PRIVATE KEY")) {
			t.Fatalf("platform certificate %s contains plaintext markers", current.ID)
		}
		opened, err := tunnelcert.OpenParts(ctx, keys, current.MasterKeyReference, current.CertificateCiphertext, current.PrivateKeyCiphertext)
		if err != nil {
			t.Fatalf("open encrypted platform certificate %s: %v", current.ID, err)
		}
		opened.Issuer = current.Issuer
		opened.NotBefore = current.NotBefore
		opened.NotAfter = current.ExpiresAt
		if _, err := opened.Validate(current.Hostname, current.NotBefore.Add(time.Minute), 90*24*time.Hour); err != nil {
			t.Fatalf("validate decrypted platform certificate %s: %v", current.ID, err)
		}
		edges, err := database.Queries().ListTunnelCertificateEdgesV1(ctx, current.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(edges) != 2 {
			t.Fatalf("initial platform certificate %s edge rows=%d, want 2", current.ID, len(edges))
		}
		for _, edge := range edges {
			if edge.State != "active" || edge.EdgeAssignmentGeneration != 1 || edge.ObservedCertificateGeneration != 2 || (edge.EdgeProcessEpoch != f.epochA && edge.EdgeProcessEpoch != f.epochB) {
				t.Fatalf("initial platform edge=%+v", edge)
			}
		}
	}
}

func assertFailedPlatformPayloadFence(t *testing.T, ctx context.Context, database *db.DB) {
	t.Helper()
	var (
		id, domainID, accountID, hostname, strategy, certificateReference, masterKeyReference, issuer, state, failureCode string
		domainGeneration, certificateGeneration                                                                           int64
		certificateCiphertext, privateKeyCiphertext, fingerprint                                                          []byte
		notBefore, expiresAt, renewalAt, updatedAt                                                                        time.Time
	)
	err := database.SQL().QueryRowContext(ctx, `SELECT id,domain_id,account_id,hostname,domain_generation,certificate_generation,strategy,certificate_reference,master_key_reference,certificate_ciphertext,private_key_ciphertext,fingerprint,issuer,not_before,expires_at,renewal_at,state,failure_code,updated_at FROM paperboat.tunnel_certificate_records WHERE target_kind='platform_wildcard' AND state='failed' AND certificate_generation=1 ORDER BY id LIMIT 1`).Scan(
		&id, &domainID, &accountID, &hostname, &domainGeneration, &certificateGeneration, &strategy, &certificateReference, &masterKeyReference, &certificateCiphertext, &privateKeyCiphertext, &fingerprint, &issuer, &notBefore, &expiresAt, &renewalAt, &state, &failureCode, &updatedAt,
	)
	if err != nil {
		t.Fatalf("load failed platform certificate for payload fence: %v", err)
	}
	if state != string(tunnelcert.StateFailed) || failureCode == "" || len(fingerprint) != 32 || len(certificateCiphertext) == 0 || len(privateKeyCiphertext) == 0 {
		t.Fatalf("failed platform certificate before payload fence: state=%q failure_code=%q fingerprint=%d certificate=%d private_key=%d", state, failureCode, len(fingerprint), len(certificateCiphertext), len(privateKeyCiphertext))
	}
	beforeCertificate := append([]byte(nil), certificateCiphertext...)
	beforePrivateKey := append([]byte(nil), privateKeyCiphertext...)
	beforeFailureCode := failureCode
	beforeUpdatedAt := updatedAt
	var certificateFingerprint [32]byte
	copy(certificateFingerprint[:], fingerprint)
	candidate := tunnelcert.StoredCertificate{
		ID: id, DomainID: domainID, AccountID: accountID, Hostname: hostname,
		TargetKind: tunnelcert.TargetPlatformWildcard, DomainGeneration: uint64(domainGeneration), CertificateGeneration: uint64(certificateGeneration), Strategy: tunnelcert.Strategy(strategy), State: tunnelcert.StateStaged,
		CertificateReference: certificateReference, MasterKeyReference: masterKeyReference,
		Envelope: append([]byte(nil), certificateCiphertext...), CertificateCiphertext: append([]byte(nil), certificateCiphertext...), PrivateKeyCiphertext: append([]byte(nil), privateKeyCiphertext...), Fingerprint: certificateFingerprint,
		Issuer: issuer, NotBefore: notBefore, ExpiresAt: expiresAt, RenewalAt: renewalAt, UpdatedAt: updatedAt,
	}
	candidate.CertificateCiphertext[0] ^= 1
	platformStore, err := tunnelcert.NewPlatformCertificateStore(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := platformStore.PutStaged(ctx, candidate); !errors.Is(err, tunnelcert.ErrGenerationConflict) {
		t.Fatalf("failed same-ID payload replay error=%v, want generation conflict", err)
	}
	var afterState, afterFailureCode string
	var afterCertificateCiphertext, afterPrivateKeyCiphertext []byte
	var afterUpdatedAt time.Time
	if err := database.SQL().QueryRowContext(ctx, `SELECT state,failure_code,certificate_ciphertext,private_key_ciphertext,updated_at FROM paperboat.tunnel_certificate_records WHERE id=$1`, id).Scan(&afterState, &afterFailureCode, &afterCertificateCiphertext, &afterPrivateKeyCiphertext, &afterUpdatedAt); err != nil {
		t.Fatalf("reload failed platform certificate after payload fence: %v", err)
	}
	if afterState != string(tunnelcert.StateFailed) || afterFailureCode != beforeFailureCode || !bytes.Equal(afterCertificateCiphertext, beforeCertificate) || !bytes.Equal(afterPrivateKeyCiphertext, beforePrivateKey) || !afterUpdatedAt.Equal(beforeUpdatedAt) {
		t.Fatalf("failed platform certificate changed after payload fence: state=%q/%q failure_code=%q/%q certificate=%x/%x private_key=%x/%x updated_at=%s/%s", afterState, string(tunnelcert.StateFailed), afterFailureCode, beforeFailureCode, afterCertificateCiphertext, beforeCertificate, afterPrivateKeyCiphertext, beforePrivateKey, afterUpdatedAt, beforeUpdatedAt)
	}
	t.Logf("payload fence id=%s state=%s failure_code=%s certificate_sha256=%x private_key_sha256=%x updated_at=%s unchanged=1", id, afterState, afterFailureCode, sha256.Sum256(afterCertificateCiphertext), sha256.Sum256(afterPrivateKeyCiphertext), afterUpdatedAt.UTC().Format(time.RFC3339Nano))
}

func assertStablePlatformEdgeGeneration(t *testing.T, edges []tunnelcert.EdgeTarget, want []platformAcceptanceEdge) {
	t.Helper()
	if len(edges) != len(want) {
		t.Fatalf("resolved platform edges=%+v, want %d", edges, len(want))
	}
	for index, edge := range edges {
		if edge.NodeID != want[index].nodeID || edge.ProcessEpoch != want[index].processEpoch || edge.Generation != 1 {
			t.Fatalf("resolved platform edge[%d]=%+v", index, edge)
		}
	}
}

func assertUserOwnerCascade(t *testing.T, ctx context.Context, database *db.DB, f platformAcceptanceFixture) {
	t.Helper()
	var cascade bool
	if err := database.SQL().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_constraint c JOIN pg_class child ON child.oid=c.conrelid JOIN pg_class parent ON parent.oid=c.confrelid WHERE child.oid='paperboat.tunnel_certificate_records'::regclass AND parent.oid='paperboat.users'::regclass AND c.conname='tunnel_certificate_records_user_account_id_fkey' AND c.confdeltype='c')`).Scan(&cascade); err != nil {
		t.Fatal(err)
	}
	if !cascade {
		t.Fatal("ordinary certificate user-account cascade FK is not enforced")
	}
	var owner string
	if err := database.SQL().QueryRowContext(ctx, `SELECT user_account_id FROM paperboat.tunnel_certificate_records WHERE domain_id=$1`, f.userDomainID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != f.userAccountID {
		t.Fatalf("ordinary certificate owner=%q, want %q", owner, f.userAccountID)
	}
}

func assertPreviewRowsSurviveRollback(t *testing.T, ctx context.Context, database *db.DB, f platformAcceptanceFixture, certificate tunnelcert.StoredCertificate, lockOwner string) {
	t.Helper()
	var state, targetKind, previewID string
	if err := database.SQL().QueryRowContext(ctx, `SELECT state,target_kind,preview_id FROM paperboat.tunnel_certificate_records WHERE id=$1`, certificate.ID).Scan(&state, &targetKind, &previewID); err != nil {
		t.Fatal(err)
	}
	if state != "active" || targetKind != string(tunnelcert.TargetPreviewLease) || previewID != f.previewLeaseID {
		t.Fatalf("preview certificate after migration rollback state=%q kind=%q preview=%q", state, targetKind, previewID)
	}
	if got := countRows(t, ctx, database.SQL(), `SELECT count(*) FROM paperboat.tunnel_certificate_issuance_locks WHERE domain_id=$1 AND owner_id=$2`, f.previewDomainID, lockOwner); got != 1 {
		t.Fatalf("preview lock rows after migration rollback=%d, want 1", got)
	}
}

func assertNoPlaintextCertificateColumnsOrLogs(t *testing.T, ctx context.Context, database *db.DB) {
	t.Helper()
	forbidden := countRows(t, ctx, database.SQL(), `SELECT count(*) FROM information_schema.columns WHERE table_schema='paperboat' AND table_name IN ('tunnel_certificate_records','tunnel_log_entries') AND column_name IN ('certificate','certificate_pem','private_key','private_key_pem','private_key_plaintext','certificate_plaintext','key_material','secret_key')`)
	if forbidden != 0 {
		t.Fatalf("plaintext certificate/key columns=%d", forbidden)
	}
	markers := countRows(t, ctx, database.SQL(), `SELECT count(*) FROM paperboat.tunnel_log_entries WHERE message ILIKE '%PRIVATE KEY%' OR message ILIKE '%BEGIN CERTIFICATE%' OR metadata::text ILIKE '%PRIVATE KEY%' OR metadata::text ILIKE '%BEGIN CERTIFICATE%'`)
	if markers != 0 {
		t.Fatalf("certificate private material appeared in logs=%d", markers)
	}
	t.Logf("plaintext scan certificate_key_columns=%d log_markers=%d", forbidden, markers)
}

func (f platformAcceptanceFixture) platformCertificate(t *testing.T, definition tunnelcert.PlatformCertificateTargetDefinition, domainID string, generation uint64, now time.Time) tunnelcert.StoredCertificate {
	t.Helper()
	bundle, err := acceptanceBundle(definition.Hostname, now, int(generation)+30, "platform-acceptance-ca")
	if err != nil {
		t.Fatal(err)
	}
	keys := tunnelcert.ReferenceKeySource{Keys: map[string][]byte{"master/current": bytes.Repeat([]byte{0x2a}, 32)}}
	certificate, privateKey, err := tunnelcert.SealParts(context.Background(), keys, "master/current", bundle)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := bundle.Validate(definition.Hostname, now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tunnelcert.StoredCertificate{ID: "tcert-bad-platform-" + f.suffix, DomainID: domainID, AccountID: tunnelcert.PlatformAccountID, Hostname: definition.Hostname, TargetKind: tunnelcert.TargetPlatformWildcard, DomainGeneration: definition.Generation, CertificateGeneration: generation, Strategy: tunnelcert.StrategyPlatformDNS01, State: tunnelcert.StateStaged, CertificateReference: "ref-bad-platform-" + f.suffix, MasterKeyReference: "master/current", Envelope: append([]byte(nil), certificate...), CertificateCiphertext: certificate, PrivateKeyCiphertext: privateKey, Fingerprint: identity.Fingerprint, Issuer: identity.Issuer, NotBefore: identity.NotBefore, ExpiresAt: identity.NotAfter, RenewalAt: identity.NotAfter.Add(-24 * time.Hour), UpdatedAt: now}
}

func (f platformAcceptanceFixture) userCertificate(t *testing.T, bundle tunnelcert.CertificateBundle, keys tunnelcert.MasterKeySource, now time.Time) tunnelcert.StoredCertificate {
	t.Helper()
	certificate, privateKey, err := tunnelcert.SealParts(context.Background(), keys, "master/current", bundle)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := bundle.Validate(f.userHostname, now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tunnelcert.StoredCertificate{ID: "tcert-user-platform-" + f.suffix, DomainID: f.userDomainID, AccountID: f.userAccountID, TunnelID: f.userTunnelID, RouteID: f.userRouteID, TargetKind: tunnelcert.TargetDurableRoute, Hostname: f.userHostname, DomainGeneration: 1, CertificateGeneration: 1, Strategy: tunnelcert.StrategyDelegatedDNS01, State: tunnelcert.StateStaged, CertificateReference: "ref-user-platform-" + f.suffix, MasterKeyReference: "master/current", Envelope: append([]byte(nil), certificate...), CertificateCiphertext: certificate, PrivateKeyCiphertext: privateKey, Fingerprint: identity.Fingerprint, Issuer: identity.Issuer, NotBefore: identity.NotBefore, ExpiresAt: identity.NotAfter, RenewalAt: identity.NotAfter.Add(-24 * time.Hour), UpdatedAt: now}
}

func (f platformAcceptanceFixture) previewCertificate(t *testing.T, keys tunnelcert.MasterKeySource, now time.Time) tunnelcert.StoredCertificate {
	t.Helper()
	bundle, err := acceptanceBundle(f.previewHostname, now, 9, "preview-acceptance-ca")
	if err != nil {
		t.Fatal(err)
	}
	certificate, privateKey, err := tunnelcert.SealParts(context.Background(), keys, "master/current", bundle)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := bundle.Validate(f.previewHostname, now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tunnelcert.StoredCertificate{ID: "tcert-preview-platform-" + f.suffix, DomainID: f.previewDomainID, AccountID: f.previewAccountID, PreviewID: f.previewLeaseID, PreviewGeneration: 1, PreviewState: "active", PreviewExpiresAt: now.Add(24 * time.Hour), TargetKind: tunnelcert.TargetPreviewLease, Hostname: f.previewHostname, DomainGeneration: 1, CertificateGeneration: 1, Strategy: tunnelcert.StrategyDelegatedDNS01, State: tunnelcert.StateStaged, CertificateReference: "ref-preview-platform-" + f.suffix, MasterKeyReference: "master/current", Envelope: append([]byte(nil), certificate...), CertificateCiphertext: certificate, PrivateKeyCiphertext: privateKey, Fingerprint: identity.Fingerprint, Issuer: identity.Issuer, NotBefore: identity.NotBefore, ExpiresAt: identity.NotAfter, RenewalAt: identity.NotAfter.Add(-24 * time.Hour), UpdatedAt: now}
}

func acceptanceBundle(hostname string, now time.Time, serial int, issuer string) (tunnelcert.CertificateBundle, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tunnelcert.CertificateBundle{}, err
	}
	notBefore := now.Add(-time.Minute)
	notAfter := now.Add(60 * 24 * time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(int64(serial)), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tunnelcert.CertificateBundle{}, err
	}
	return tunnelcert.CertificateBundle{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		Issuer:         issuer, NotBefore: notBefore, NotAfter: notAfter,
	}, nil
}

func assertFullMigrationCatalog(t *testing.T, ctx context.Context, database *db.DB) {
	t.Helper()
	var maxVersion, applied int
	if err := database.SQL().QueryRowContext(ctx, `SELECT COALESCE(MAX(version_id),0)::int, count(*)::int FROM paperboat.goose_db_version WHERE is_applied`).Scan(&maxVersion, &applied); err != nil {
		t.Fatal(err)
	}
	if maxVersion != 150 {
		t.Fatalf("migration max version=%d, want 150", maxVersion)
	}
	// Goose keeps a version-zero baseline row, while four historical version
	// numbers are intentionally absent from this catalog.  Version 150 plus
	// the baseline therefore currently yields 147 applied rows.
	if applied < 147 {
		t.Fatalf("applied migration count=%d, want at least 147", applied)
	}
	t.Logf("migration catalog max_version=%d applied=%d", maxVersion, applied)
}

func configurePlatformGoose(t *testing.T) {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate acceptance test source")
	}
	databaseDir := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "db"))
	if _, err := os.Stat(filepath.Join(databaseDir, "migrations", "150_tunnel_platform_certificate_targets.sql")); err != nil {
		t.Fatalf("migration source directory unavailable: %v", err)
	}
	goose.SetBaseFS(os.DirFS(databaseDir))
	goose.SetTableName("paperboat.goose_db_version")
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
}

func countRows(t *testing.T, ctx context.Context, database *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func tableExists(t *testing.T, ctx context.Context, database *sql.DB, table string) bool {
	t.Helper()
	var exists bool
	if err := database.QueryRowContext(ctx, `SELECT to_regclass('paperboat.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func cleanupPlatformAcceptanceFixture(database *db.DB, fixture platformAcceptanceFixture, definitions []tunnelcert.PlatformCertificateTargetDefinition, previewCertificate tunnelcert.StoredCertificate, previewLockOwner string) {
	if database == nil || database.SQL() == nil {
		return
	}
	ctx := context.Background()
	_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.tunnel_certificate_edge_distributions WHERE certificate_id IN (SELECT id FROM paperboat.tunnel_certificate_records WHERE domain_id IN ($1,$2,$3,$4))`, definitions[0].ID, definitions[1].ID, definitions[2].ID, fixture.previewDomainID)
	_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.tunnel_certificate_records WHERE target_kind='platform_wildcard' OR id=$1`, previewCertificate.ID)
	_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.tunnel_certificate_issuance_locks WHERE domain_id IN ($1,$2,$3,$4) OR owner_id=$5`, definitions[0].ID, definitions[1].ID, definitions[2].ID, fixture.previewDomainID, previewLockOwner)
	if tableExistsQuiet(ctx, database.SQL(), "tunnel_platform_certificate_targets") {
		_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.tunnel_platform_certificate_targets WHERE id IN ($1,$2,$3)`, definitions[0].ID, definitions[1].ID, definitions[2].ID)
	}
	_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.preview_domains WHERE id=$1`, fixture.previewDomainID)
	_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.preview_leases WHERE id=$1`, fixture.previewLeaseID)
	_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.control_tunnel_nodes WHERE id IN ($1,$2)`, fixture.edgeA, fixture.edgeB)
	_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id IN ($1,$2)`, fixture.userAccountID, fixture.previewAccountID)
}

func tableExistsQuiet(ctx context.Context, database *sql.DB, table string) bool {
	var exists bool
	if err := database.QueryRowContext(ctx, `SELECT to_regclass('paperboat.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil {
		return false
	}
	return exists
}
