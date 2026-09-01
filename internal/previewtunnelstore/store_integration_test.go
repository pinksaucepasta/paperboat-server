package previewtunnelstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/testutil"
)

func TestPreviewTunnelV1PersistenceOnPostgres(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres repository integration tests")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
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
	store, err := New(database)
	if err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	accountID := "usr_trk03_" + suffix
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, accountID, "workos_"+suffix, "trk03-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}

	requestHash := sha256.Sum256([]byte("create-tunnel:" + suffix))
	endpointID := testutil.EndpointUUID("preview-store:" + suffix)
	create := CreateTunnelInput{
		OperationID: "op_" + suffix, TunnelID: "tun_" + suffix, AuditEventID: "aud_" + suffix,
		AccountID: accountID, IdempotencyKey: "create:" + suffix, RequestHash: requestHash,
		Name: "coolify-" + suffix, AccessMode: "public", StableEndpointID: endpointID,
		StableEndpoint: "https://" + endpointID + ".tunnels.example.test", HostID: "host_" + suffix,
		ActorID: accountID, ActorType: "user", CorrelationID: "cor_" + suffix, RequestID: "req_" + suffix,
		SourceDeviceID: "dev_" + suffix,
	}
	created, err := store.CreateTunnel(ctx, create)
	if err != nil {
		t.Fatal(err)
	}
	if created.Replayed || created.Tunnel.Generation != 1 || created.Operation.State != "succeeded" {
		t.Fatalf("unexpected create result: %#v", created)
	}

	replayInput := create
	replayInput.OperationID = "op_replay_" + suffix
	replayInput.TunnelID = "tun_replay_" + suffix
	replayInput.AuditEventID = "aud_replay_" + suffix
	replayed, err := store.CreateTunnel(ctx, replayInput)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.Tunnel.ID != created.Tunnel.ID || replayed.Operation.ID != created.Operation.ID {
		t.Fatalf("idempotent replay changed identity: %#v", replayed)
	}

	conflicting := replayInput
	conflicting.RequestHash = sha256.Sum256([]byte("different input"))
	if _, err := store.CreateTunnel(ctx, conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict error = %v", err)
	}

	concurrentBase := create
	concurrentBase.IdempotencyKey = "concurrent:" + suffix
	concurrentBase.RequestHash = sha256.Sum256([]byte("concurrent create"))
	concurrentBase.Name = "concurrent-" + suffix
	concurrentBase.StableEndpointID = testutil.EndpointUUID("preview-store-concurrent:" + suffix)
	concurrentBase.StableEndpoint = "https://" + concurrentBase.StableEndpointID + ".tunnels.example.test"
	type concurrentResult struct {
		result CreateTunnelResult
		err    error
	}
	concurrentResults := make(chan concurrentResult, 6)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for i := 0; i < 6; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			input := concurrentBase
			input.OperationID = fmt.Sprintf("op_concurrent_%d_%s", index, suffix)
			input.TunnelID = fmt.Sprintf("tun_concurrent_%d_%s", index, suffix)
			input.AuditEventID = fmt.Sprintf("aud_concurrent_%d_%s", index, suffix)
			<-start
			result, err := store.CreateTunnel(ctx, input)
			concurrentResults <- concurrentResult{result: result, err: err}
		}(i)
	}
	close(start)
	wait.Wait()
	close(concurrentResults)
	concurrentTunnelID := ""
	createdCount := 0
	for item := range concurrentResults {
		if item.err != nil {
			t.Fatalf("concurrent idempotent create failed: %v", item.err)
		}
		if concurrentTunnelID == "" {
			concurrentTunnelID = item.result.Tunnel.ID
		}
		if item.result.Tunnel.ID != concurrentTunnelID {
			t.Fatalf("concurrent replay returned tunnel %s, want %s", item.result.Tunnel.ID, concurrentTunnelID)
		}
		if !item.result.Replayed {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("concurrent creates committed %d winners, want 1", createdCount)
	}

	duplicate := create
	duplicate.OperationID = "op_duplicate_" + suffix
	duplicate.TunnelID = "tun_duplicate_" + suffix
	duplicate.AuditEventID = "aud_duplicate_" + suffix
	duplicate.IdempotencyKey = "duplicate:" + suffix
	duplicate.RequestHash = sha256.Sum256([]byte("duplicate name"))
	duplicate.StableEndpointID = testutil.EndpointUUID("preview-store-duplicate:" + suffix)
	duplicate.StableEndpoint = "https://" + duplicate.StableEndpointID + ".tunnels.example.test"
	if _, err := store.CreateTunnel(ctx, duplicate); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name error = %v, want ErrConflict", err)
	}
	var rolledBackOperations int
	if err := database.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.operations WHERE id=$1`, duplicate.OperationID).Scan(&rolledBackOperations); err != nil {
		t.Fatal(err)
	}
	if rolledBackOperations != 0 {
		t.Fatal("failed tunnel create committed its operation row")
	}

	paused, err := store.UpdateTunnelState(ctx, UpdateTunnelStateInput{
		TunnelID: created.Tunnel.ID, AccountID: accountID, DesiredState: "paused", ExpectedGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if paused.Generation != 2 || paused.DesiredState != "paused" {
		t.Fatalf("unexpected CAS result: %#v", paused)
	}
	if _, err := store.UpdateTunnelState(ctx, UpdateTunnelStateInput{
		TunnelID: created.Tunnel.ID, AccountID: accountID, DesiredState: "active", ExpectedGeneration: 1,
	}); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale update error = %v, want ErrGenerationConflict", err)
	}

	now := time.Now().UTC()
	route, err := store.CreateRoute(ctx, dbsqlc.CreatePreviewTunnelRouteParams{
		ID: "rte_" + suffix, TunnelID: created.Tunnel.ID, Name: "default", Protocol: "http",
		MatchType: "managed", MatchHostname: sql.NullString{String: create.StableEndpoint, Valid: true},
		Priority: 100, OriginScheme: "http", OriginAddress: "127.0.0.1:80", PreserveHost: true,
		TlsVerification: "not_applicable", ConnectTimeoutMs: 10000, IdleTimeoutMs: 90000,
		MaxConcurrentStreams: 128, DesiredState: "active", CreatedByActorID: accountID,
		UpdatedByActorID: accountID, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateRoute(ctx, dbsqlc.CreatePreviewTunnelRouteParams{
		ID: "rte_duplicate_" + suffix, TunnelID: created.Tunnel.ID, Name: route.Name, Protocol: "http",
		MatchType: "catch_all", Priority: 999, OriginScheme: "http", OriginAddress: "127.0.0.1:81",
		PreserveHost: true, TlsVerification: "not_applicable", ConnectTimeoutMs: 10000,
		IdleTimeoutMs: 90000, MaxConcurrentStreams: 128, DesiredState: "active",
		CreatedByActorID: accountID, UpdatedByActorID: accountID, Now: now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate route name error = %v, want ErrConflict", err)
	}

	domain, err := store.CreateDomain(ctx, dbsqlc.CreatePreviewTunnelDomainParams{
		ID: "dom_" + suffix, AccountID: accountID, TunnelID: created.Tunnel.ID, RouteID: route.ID,
		Hostname: "app-" + suffix + ".example.test", MatchType: "exact",
		OwnershipChallengeReference: "dns-challenge://" + suffix, OwnershipState: "pending",
		DnsTarget: "domains.example.test", ObservedRecords: json.RawMessage(`[]`),
		CertificateStrategy: "managed", CertificateState: "pending", CaaState: "unknown",
		ConflictState: "clear", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if domain.Generation != 1 {
		t.Fatalf("domain generation = %d", domain.Generation)
	}

	connector, err := store.CreateConnector(ctx, dbsqlc.CreatePreviewTunnelConnectorParams{
		ID: "con_" + suffix, TunnelID: created.Tunnel.ID, HostID: "host_" + suffix,
		CredentialReference: "credential://connector/" + suffix, CredentialThumbprint: "sha256:" + suffix,
		RotationGeneration: 1, DesiredState: "active", ProtocolVersion: "1.0",
		DrainState: "accepting", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if connector.ID == connector.TunnelID {
		t.Fatal("connector identity was conflated with tunnel identity")
	}
	if _, err := store.CreateConnectorSession(ctx, dbsqlc.CreatePreviewTunnelConnectorSessionParams{
		ID: "csn_" + suffix, ConnectorID: connector.ID, ProcessGeneration: 1,
		ProtocolVersion: "1.0", Capabilities: []string{"snapshot.v1"}, State: "authenticating",
		LeaseDeadline: now.Add(time.Minute), RetainedUntil: now.Add(time.Hour), Now: now,
	}); err != nil {
		t.Fatal(err)
	}

	preview, err := store.CreatePreviewLease(ctx, dbsqlc.CreatePreviewLeaseParams{
		ID: "prv_" + suffix, EndpointID: "pep_" + suffix,
		Endpoint: "https://" + suffix + ".preview.example.test", AccountID: accountID,
		ActorID: accountID, OwnerDeviceID: "dev_" + suffix, OwnerSessionID: "ses_" + suffix,
		TargetScheme: "http", TargetAddress: "127.0.0.1:3000", AccessMode: "public",
		LeaseDeadline: now.Add(time.Minute), AllocationState: "pending", EdgeState: "pending",
		OriginState: "unknown", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if preview.TerminalState != "active" || preview.OwnerSessionID == "" {
		t.Fatalf("invalid foreground preview lease: %#v", preview)
	}

	snapshot1 := []byte("{\n  \"routes\": [], \"generation\": 1\n}")
	canonical1 := []byte(`{"generation":1,"routes":[]}`)
	hash1 := sha256.Sum256(canonical1)
	generation1, err := store.ActivateConfigGeneration(ctx, dbsqlc.CreatePreviewTunnelConfigGenerationParams{
		TunnelID: created.Tunnel.ID, Generation: 1, ContentHash: hash1[:], Snapshot: snapshot1,
		CreatedByActorID: accountID, Now: now, RetainedUntil: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if generation1.ActivationState != "active" {
		t.Fatalf("generation one state = %s", generation1.ActivationState)
	}
	snapshot2 := []byte(`{"generation":2,"routes":["default"]}`)
	hash2 := sha256.Sum256(snapshot2)
	generation2, err := store.ActivateConfigGeneration(ctx, dbsqlc.CreatePreviewTunnelConfigGenerationParams{
		TunnelID: created.Tunnel.ID, Generation: 2, PreviousGeneration: sql.NullInt64{Int64: 1, Valid: true},
		ContentHash: hash2[:], Snapshot: snapshot2, CreatedByActorID: accountID,
		Now: now.Add(time.Second), RetainedUntil: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if generation2.ActivationState != "active" {
		t.Fatalf("generation two state = %s", generation2.ActivationState)
	}
	var activeCount, supersededCount int
	if err := database.SQL().QueryRowContext(ctx, `
SELECT count(*) FILTER (WHERE activation_state='active'), count(*) FILTER (WHERE activation_state='superseded')
FROM paperboat.tunnel_config_generations WHERE tunnel_id=$1`, created.Tunnel.ID).Scan(&activeCount, &supersededCount); err != nil {
		t.Fatal(err)
	}
	if activeCount != 1 || supersededCount != 1 {
		t.Fatalf("config activation active=%d superseded=%d", activeCount, supersededCount)
	}
	if _, err := database.SQL().ExecContext(ctx, `UPDATE paperboat.tunnel_config_generations SET snapshot='{}' WHERE tunnel_id=$1 AND generation=1`, created.Tunnel.ID); err == nil {
		t.Fatal("immutable configuration snapshot update succeeded")
	}
	if _, err := database.SQL().ExecContext(ctx, `UPDATE paperboat.audit_events SET outcome='unchanged' WHERE id=$1`, create.AuditEventID); err == nil {
		t.Fatal("append-only audit event update succeeded")
	}

	var forbiddenColumns int
	if err := database.SQL().QueryRowContext(ctx, `
SELECT count(*) FROM information_schema.columns
WHERE table_schema='paperboat'
  AND table_name IN ('tunnels','tunnel_routes','tunnel_domains','tunnel_connectors','tunnel_connector_sessions','preview_leases','tunnel_config_generations','operations')
  AND (column_name LIKE '%private_key%' OR column_name LIKE '%password%' OR column_name IN ('token','secret','credential_ciphertext'))`).Scan(&forbiddenColumns); err != nil {
		t.Fatal(err)
	}
	if forbiddenColumns != 0 {
		t.Fatalf("v1 persistence exposes %d reusable credential columns", forbiddenColumns)
	}
}
