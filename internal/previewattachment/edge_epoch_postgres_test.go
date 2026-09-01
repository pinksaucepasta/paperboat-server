package previewattachment

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// This test is deliberately opt-in. It exercises the real SQL repository on
// an isolated PostgreSQL database and never starts a local edge or host.
func TestPreviewCarrierEdgeProcessEpochReplacementOnPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run the preview carrier PostgreSQL test")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !safePreviewCarrierTestDSN(dsn) {
		t.Fatal("refusing to run preview carrier PostgreSQL test unless PAPERBOAT_TEST_DATABASE_DSN names a *_test database")
	}
	if productionDSN := strings.TrimSpace(os.Getenv("PAPERBOAT_DATABASE_DSN")); productionDSN != "" && samePreviewCarrierDatabase(dsn, productionDSN) {
		t.Fatal("refusing to run preview carrier PostgreSQL test against PAPERBOAT_DATABASE_DSN")
	}

	ctx := context.Background()
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, database); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	fixture := previewCarrierPostgresFixture{suffix: suffix}
	t.Cleanup(func() {
		// User deletion cascades the lease, operation, attachment, and outbox
		// rows. The edge node is independent and is deleted second because the
		// attachment FK deliberately uses ON DELETE RESTRICT.
		_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, fixture.accountID)
		_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.control_tunnel_nodes WHERE id=$1`, fixture.nodeID)
		_ = database.Close()
	})

	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := fixture.insert(ctx, database, now); err != nil {
		t.Fatal(err)
	}
	repository, err := NewSQLRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.SetClock(func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}

	first := fixture.attachment(1, fixture.epochOne)
	if _, err := repository.CreatePending(ctx, first); err != nil {
		t.Fatalf("create first attachment: %v", err)
	}
	released, err := repository.Release(ctx, first, now.Add(time.Second))
	if err != nil {
		t.Fatalf("release first attachment: %v", err)
	}
	if released.State != StateReleased || released.AttachmentGeneration != first.AttachmentGeneration+1 {
		t.Fatalf("released first attachment = %#v", released)
	}

	second := fixture.attachment(2, fixture.epochOne)
	if _, err := repository.CreatePending(ctx, second); err != nil {
		t.Fatalf("create second attachment: %v", err)
	}
	oldSnapshot, err := repository.PullPreviewCarrierSnapshot(ctx, fixture.nodeID, fixture.epochOne)
	if err != nil {
		t.Fatalf("initial epoch snapshot: %v", err)
	}
	if len(oldSnapshot) != 1 || oldSnapshot[0].OperationID != second.OperationID {
		t.Fatalf("initial snapshot = %#v, want only second operation", oldSnapshot)
	}

	// The node row is the source of truth for the process fence. Replacing the
	// process keeps the stable node ID but invalidates every old edge request.
	if _, err := database.SQL().ExecContext(ctx, `
UPDATE paperboat.control_tunnel_nodes
SET process_epoch=$2, state='ready', ready=true, last_heartbeat_at=$3, updated_at=$3
WHERE id=$1`, fixture.nodeID, fixture.epochTwo, now.Add(2*time.Second)); err != nil {
		t.Fatalf("replace edge process epoch: %v", err)
	}

	for name, call := range map[string]func() error{
		"old snapshot pull": func() error {
			_, err := repository.PullPreviewCarrierSnapshot(ctx, fixture.nodeID, fixture.epochOne)
			return err
		},
		"old detach pull and claim": func() error {
			_, err := repository.PullPreviewCarrierDetachOutbox(ctx, fixture.nodeID, fixture.epochOne)
			return err
		},
		"old detach ACK": func() error {
			return repository.AcknowledgePreviewCarrierOutbox(ctx, fixture.nodeID, fixture.epochOne, first.AccountID, first.OperationID, released.AttachmentGeneration, "detach")
		},
	} {
		if err := call(); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%s error = %v, want ErrUnauthorized", name, err)
		}
	}

	currentDetach, err := repository.PullPreviewCarrierDetachOutbox(ctx, fixture.nodeID, fixture.epochTwo)
	if err != nil {
		t.Fatalf("current detach pull: %v", err)
	}
	if len(currentDetach) != 0 {
		t.Fatalf("current epoch received old detach commands = %#v", currentDetach)
	}
	if err := repository.AcknowledgePreviewCarrierOutbox(ctx, fixture.nodeID, fixture.epochTwo, first.AccountID, first.OperationID, released.AttachmentGeneration, "detach"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("current epoch old detach ACK error = %v, want ErrNotFound", err)
	}

	// Renewing through the real SQL CAS rebinds the live route to the current
	// process epoch without changing its stable tunnel/connector/route IDs.
	next := second
	next.Binding.EdgeProcessEpoch = fixture.epochTwo
	next.ExpiresAt = now.Add(20 * time.Minute)
	renewed, err := repository.Renew(ctx, second, next, now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("renew to current edge epoch: %v", err)
	}
	if renewed.State != StatePending || renewed.AttachmentGeneration != second.AttachmentGeneration+1 || renewed.Binding.EdgeProcessEpoch != fixture.epochTwo {
		t.Fatalf("renewed attachment = %#v", renewed)
	}
	if renewed.TunnelID != second.TunnelID || renewed.ConnectorID != second.ConnectorID || renewed.RouteID != second.RouteID {
		t.Fatalf("renew changed stable carrier identity: before=%#v after=%#v", second.Binding, renewed.Binding)
	}

	currentSnapshot, err := repository.PullPreviewCarrierSnapshot(ctx, fixture.nodeID, fixture.epochTwo)
	if err != nil {
		t.Fatalf("current epoch snapshot: %v", err)
	}
	if len(currentSnapshot) != 1 || currentSnapshot[0].OperationID != second.OperationID || currentSnapshot[0].AttachmentGeneration != renewed.AttachmentGeneration {
		t.Fatalf("current snapshot = %#v, want renewed second operation", currentSnapshot)
	}
	if err := repository.AcknowledgePreviewCarrierOutbox(ctx, fixture.nodeID, fixture.epochTwo, renewed.AccountID, renewed.OperationID, renewed.AttachmentGeneration, "admit"); err != nil {
		t.Fatalf("current epoch admit ACK: %v", err)
	}
	if err := repository.AcknowledgePreviewCarrierOutbox(ctx, fixture.nodeID, fixture.epochTwo, renewed.AccountID, renewed.OperationID, renewed.AttachmentGeneration, "admit"); err != nil {
		t.Fatalf("current epoch lost-response admit ACK replay: %v", err)
	}
	admitted, err := repository.Get(ctx, renewed.AccountID, renewed.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if admitted.State != StateAdmitted || admitted.EdgeReady || admitted.Binding.EdgeProcessEpoch != fixture.epochTwo {
		t.Fatalf("admitted current attachment = %#v", admitted)
	}

	// The migration trigger is the final database-level guard. Even a direct
	// stale update cannot put an active attachment back under the old epoch.
	if _, err := database.SQL().ExecContext(ctx, `
UPDATE paperboat.preview_lease_carrier_attachments
SET edge_process_epoch=$1
WHERE account_id=$2 AND operation_id=$3`, fixture.epochOne, admitted.AccountID, admitted.OperationID); err == nil {
		t.Fatal("stale active attachment update unexpectedly succeeded")
	}
}

type previewCarrierPostgresFixture struct {
	suffix     string
	accountID  string
	machineID  string
	envID      string
	nodeID     string
	previewID  [2]string
	operation  [2]string
	sessionID  string
	publicKey  string
	thumbprint string
	epochOne   string
	epochTwo   string
}

func (f *previewCarrierPostgresFixture) initialize() {
	f.accountID = "usr_carrier_epoch_" + f.suffix
	f.machineID = "mch_carrier_epoch_" + f.suffix
	f.envID = "env_carrier_epoch_" + f.suffix
	f.nodeID = "edge-carrier-epoch-" + f.suffix
	f.previewID = [2]string{"prv_carrier_epoch_a_" + f.suffix, "prv_carrier_epoch_b_" + f.suffix}
	f.operation = [2]string{"op_carrier_epoch_a_" + f.suffix, "op_carrier_epoch_b_" + f.suffix}
	f.sessionID = "owner-session-carrier-epoch-" + f.suffix
	f.epochOne = "edge-process-one-" + f.suffix
	f.epochTwo = "edge-process-two-" + f.suffix
	key := sha256.Sum256([]byte("carrier-machine-key:" + f.suffix))
	f.publicKey = base64.RawURLEncoding.EncodeToString(key[:])
	thumbprint := sha256.Sum256(key[:])
	f.thumbprint = "sha256:" + base64.RawURLEncoding.EncodeToString(thumbprint[:])
}

func (f *previewCarrierPostgresFixture) insert(ctx context.Context, database *db.DB, now time.Time) error {
	f.initialize()
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, f.accountID, "workos_"+f.suffix, "carrier-epoch-"+f.suffix+"@example.test"); err != nil {
		return err
	}
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machines
  (id, user_id, environment_id, display_name, platform, architecture, workspace_root,
   state, seat_state, online, public_identity_key, installation_generation,
   worker_generation, worker_service_scope, connector_state)
VALUES ($1, $2, $3, $4, 'linux', 'amd64', '/workspace', 'online', 'occupied', true,
        $5, 1, 1, 'system', 'ready')`, f.machineID, f.accountID, f.envID, "Carrier epoch "+f.suffix, f.publicKey); err != nil {
		return err
	}
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.control_tunnel_nodes
  (id, edge_pool, protocol_version, process_epoch, endpoint_host, endpoint_tcp_port,
   endpoint_quic_port, relay_id, relay_region, relay_name, carrier_endpoint_host,
   carrier_endpoint_tcp_port, carrier_endpoint_quic_port, carrier_server_spki_sha256, carrier_server_certificate_chain_pem, signaling_host, stun_host,
   stun_port, state, ready, capacity, last_heartbeat_at)
VALUES ($1, 'test', '1.0', $2, 'edge.example.test', 24001, 24002,
        $3, 'test', 'Carrier epoch test', 'edge.example.test', 25001, 25002,
        'sha256:' || repeat('b',64), 'test-public-certificate-chain', 'edge.example.test', 'edge.example.test', 3478, 'ready', true, '{}', $4)`, f.nodeID, f.epochOne, "relay-"+f.suffix, now); err != nil {
		return err
	}
	for index := range f.previewID {
		previewEndpoint := fmt.Sprintf("https://carrier-epoch-%s-%c.preview.example.test", f.suffix, 'a'+rune(index))
		if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.preview_leases
  (id, endpoint_id, endpoint, account_id, actor_id, owner_device_id, owner_session_id,
   target_scheme, target_address, access_mode, lease_deadline, allocation_state,
   edge_state, origin_state, terminal_state, created_at, last_renewed_at)
VALUES ($1, $2, $3, $4, $4, $5, $6, 'http', '127.0.0.1:3000', 'public',
        $7, 'pending', 'pending', 'unknown', 'active', $8, $8)`, f.previewID[index], "pep_"+f.suffix+fmt.Sprint(index), previewEndpoint, f.accountID, f.machineID, f.sessionID, now.Add(30*time.Minute), now); err != nil {
			return err
		}
		requestHash := sha256.Sum256([]byte("carrier-epoch-operation:" + f.operation[index]))
		if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.operations
  (id, account_id, idempotency_key, request_hash, operation_type, resource_kind,
   resource_id, phase, state, progress, retrying, outcome, correlation_id,
   created_at, updated_at)
VALUES ($1, $2, $1, $3, 'preview.create', 'preview_lease', $4,
        'connecting', 'running', 60, false, 'changed', $5, $6, $6)`, f.operation[index], f.accountID, requestHash[:], f.previewID[index], "cor_"+f.operation[index], now); err != nil {
			return err
		}
		if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.preview_lease_create_operations (account_id, preview_id, operation_id)
VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, f.accountID, f.previewID[index], f.operation[index]); err != nil {
			return err
		}
	}
	return nil
}

func (f previewCarrierPostgresFixture) attachment(index int, processEpoch string) Attachment {
	operationID := f.operation[index-1]
	request := Request{
		PreviewID: f.previewID[index-1], OperationID: operationID,
		OwnerDeviceID: f.machineID, OwnerSessionID: f.sessionID,
		IdempotencyKey: operationID, RequestID: "req_" + operationID,
		CorrelationID: "cor_" + operationID,
	}
	hash, err := request.Hash(f.accountID)
	if err != nil {
		panic(err)
	}
	return Attachment{
		Schema: Schema, Kind: Kind,
		Binding: Binding{
			AccountID: f.accountID, PreviewID: request.PreviewID, OperationID: operationID,
			OwnerDeviceID: f.machineID, OwnerSessionID: f.sessionID, HostID: f.machineID,
			LeaseGeneration: 1, TunnelID: "pvc-tunnel-" + f.suffix,
			ConnectorID: "pvc-connector-" + f.suffix, SessionID: "pvc-session-" + f.suffix,
			ProcessGeneration: 1, ConfigGeneration: 1, RouteID: "pvc-route-" + f.suffix,
			RouteGeneration: 1, EdgeNodeID: f.nodeID, EdgeProcessEpoch: processEpoch,
			EdgeCarrierServerSPKISHA256: "sha256:" + strings.Repeat("b", 64), EdgeCarrierServerCertificateChainPEM: "test-public-certificate-chain",
			MachineIdentityPublicKey: f.publicKey, MachineIdentityThumbprint: f.thumbprint,
		},
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
		CorrelationID: request.CorrelationID, RequestHash: hash,
		Endpoint: fmt.Sprintf("https://carrier-epoch-%s-%c.preview.example.test", f.suffix, 'a'+rune(index-1)),
		Target:   Target{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "public",
		ConfigContentHash:    "sha256:" + strings.Repeat("a", 64),
		EdgeEndpoints:        []string{"tls://edge.example.test:25001", "quic://edge.example.test:25002"},
		AttachmentGeneration: 1, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(20 * time.Minute), State: StatePending,
	}
}

func safePreviewCarrierTestDSN(dsn string) bool {
	u, err := url.Parse(dsn)
	if err != nil {
		return false
	}
	database := strings.Trim(strings.TrimSpace(u.Path), "/")
	return strings.HasSuffix(strings.ToLower(database), "_test")
}

func samePreviewCarrierDatabase(left, right string) bool {
	l, lerr := url.Parse(left)
	r, rerr := url.Parse(right)
	return lerr == nil && rerr == nil && strings.EqualFold(l.Host, r.Host) && strings.EqualFold(strings.Trim(l.Path, "/"), strings.Trim(r.Path, "/"))
}
