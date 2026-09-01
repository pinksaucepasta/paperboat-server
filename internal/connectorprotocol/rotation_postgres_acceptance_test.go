package connectorprotocol

// These tests exercise the SQLControlStore against the real PostgreSQL
// schema. They are intentionally opt-in because they need an isolated
// database, but they never start Docker, Postgres, or a Paperboat service.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/testutil"
)

var trk08FixtureCounter atomic.Uint64

type trk08Clock struct {
	now time.Time
}

func (c *trk08Clock) Now() time.Time { return c.now }

type trk08Connector struct {
	id                   string
	hostID               string
	oldSessionID         string
	oldPrivate           ed25519.PrivateKey
	oldPublic            ed25519.PublicKey
	oldIdentityKeyID     string
	oldThumbprint        string
	oldCredentialRef     string
	newPrivate           ed25519.PrivateKey
	newPublic            ed25519.PublicKey
	newIdentityKeyID     string
	newThumbprint        string
	newCredentialRef     string
	newSessionID         string
	newProcessGeneration uint64
}

type trk08PostgresFixture struct {
	database    *db.DB
	store       *SQLControlStore
	clock       *trk08Clock
	suffix      string
	accountID   string
	tunnelID    string
	config      Snapshot
	connectors  []trk08Connector
	operationID string
}

func newTRK08PostgresFixture(t *testing.T) *trk08PostgresFixture {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run TRK-08 PostgreSQL acceptance tests")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}

	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := db.Migrate(ctx, database); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d_%d", time.Now().UnixNano(), trk08FixtureCounter.Add(1))
	clock := &trk08Clock{now: time.Now().UTC().Truncate(time.Microsecond)}
	f := &trk08PostgresFixture{
		database:  database,
		clock:     clock,
		suffix:    suffix,
		accountID: "usr_trk08_" + suffix,
		tunnelID:  "tun_trk08_" + suffix,
	}
	store, err := NewSQLControlStore(database, SQLControlStoreConfig{
		Clock:            clock,
		LeaseDuration:    30 * time.Minute,
		SessionRetention: 24 * time.Hour,
	})
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	f.store = store
	f.insertAccountAndTunnel(t)
	f.connectors = append(f.connectors, f.insertConnector(t, "a", true))
	f.connectors = append(f.connectors, f.insertConnector(t, "b", true))

	t.Cleanup(func() {
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id = $1`, f.accountID)
		_ = database.Close()
	})
	return f
}

func trk08Key(seed string) (ed25519.PrivateKey, ed25519.PublicKey, string, string) {
	digest := sha256.Sum256([]byte("paperboat-trk08-acceptance:" + seed))
	private := ed25519.NewKeyFromSeed(digest[:])
	public := private.Public().(ed25519.PublicKey)
	thumbprint, _ := IdentityThumbprint(public)
	return private, public, "ed25519:" + thumbprint, thumbprint
}

func (f *trk08PostgresFixture) insertAccountAndTunnel(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	database := f.database.SQL()
	if _, err := database.ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, f.accountID, "workos_"+f.accountID, f.accountID+"@example.test"); err != nil {
		t.Fatal(err)
	}

	hostID := "mch_trk08_" + f.suffix + "_a"
	_, hostPublic, _, _ := trk08Key("host:" + hostID)
	if _, err := database.ExecContext(ctx, `
INSERT INTO paperboat.user_machines
  (id, user_id, environment_id, display_name, platform, architecture, workspace_root,
   state, seat_state, public_identity_key, setup_roles, setup_mode)
VALUES ($1, $2, $3, $4, 'linux', 'amd64', '/workspace', 'online', 'occupied', $5,
        ARRAY['host']::text[], 'host')`, hostID, f.accountID, "env_"+hostID, "TRK08 host a", base64.RawURLEncoding.EncodeToString(hostPublic)); err != nil {
		t.Fatal(err)
	}

	endpointID := testutil.EndpointUUID("connector-rotation:" + f.suffix)
	endpoint := "https://" + endpointID + ".tunnels.example.test"
	if _, err := database.ExecContext(ctx, `
INSERT INTO paperboat.tunnels
  (id, account_id, name, desired_state, access_mode, generation,
   stable_endpoint_id, stable_endpoint, created_by_host_id, created_by_actor_id,
   summary_code, created_at, updated_at)
VALUES ($1, $2, $3, 'active', 'public', 1, $4, $5, $6, $2, 'pending', $7, $7)`,
		f.tunnelID, f.accountID, "trk08-"+f.suffix, endpointID, endpoint, hostID, f.clock.now); err != nil {
		t.Fatal(err)
	}

	payloadValue := map[string]any{
		"schema":          "paperboat.preview-tunnel/v1",
		"kind":            "tunnel_config_snapshot",
		"tunnel_id":       f.tunnelID,
		"generation":      uint64(1),
		"name":            "trk08-" + f.suffix,
		"desired_state":   "active",
		"access_mode":     "public",
		"stable_endpoint": endpoint,
		"expires_at":      nil,
		"routes":          []any{},
	}
	payload, err := json.Marshal(payloadValue)
	if err != nil {
		t.Fatal(err)
	}
	f.config, err = NewSnapshot(f.tunnelID, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	hashBytes := sha256.Sum256(f.config.Payload)
	if _, err := database.ExecContext(ctx, `
INSERT INTO paperboat.tunnel_config_generations
  (tunnel_id, generation, previous_generation, content_hash, snapshot,
   activation_state, created_by_actor_id, created_at, activated_at, retained_until)
VALUES ($1, 1, NULL, $2, $3, 'active', $4, $5, $5, $6)`,
		f.tunnelID, hashBytes[:], f.config.Payload, f.accountID, f.clock.now, f.clock.now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func (f *trk08PostgresFixture) insertConnector(t *testing.T, label string, withSession bool) trk08Connector {
	t.Helper()
	ctx := context.Background()
	connectorID := "con_trk08_" + f.suffix + "_" + label
	hostID := "mch_trk08_" + f.suffix + "_" + label
	oldPrivate, oldPublic, oldKeyID, oldThumbprint := trk08Key("old:" + connectorID)
	hostPublic := oldPublic
	credentialRef := "keychain://paperboat/trk08/" + f.suffix + "/" + label + "/1"
	if label == "a" {
		// The account/tunnel fixture already has host a. The key is still
		// deliberately connector-specific and is what SQLControlStore verifies.
		hostID = "mch_trk08_" + f.suffix + "_a"
	} else if label == "b" {
		hostID = "mch_trk08_" + f.suffix + "_b"
	}
	if label != "a" {
		_, hostPublic, _, _ = trk08Key("host:" + hostID)
		if _, err := f.database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machines
  (id, user_id, environment_id, display_name, platform, architecture, workspace_root,
   state, seat_state, public_identity_key, setup_roles, setup_mode)
VALUES ($1, $2, $3, $4, 'linux', 'amd64', '/workspace', 'online', 'occupied', $5,
        ARRAY['host']::text[], 'host')`, hostID, f.accountID, "env_"+hostID, "TRK08 host "+label, base64.RawURLEncoding.EncodeToString(hostPublic)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.tunnel_connectors
  (id, tunnel_id, host_id, credential_reference, credential_thumbprint,
   rotation_generation, desired_state, protocol_version, last_session_id,
   last_heartbeat_at, ready_at, last_applied_config_generation,
   drain_state, generation, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, 1, 'active', $6, NULL, $7, NULL, 0,
        'accepting', 1, $7, $7)`, connectorID, f.tunnelID, hostID, credentialRef, oldThumbprint, ProtocolVersion, f.clock.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.tunnel_connector_credential_generations
  (id, connector_id, tunnel_id, generation, credential_reference,
   credential_thumbprint, verifier_algorithm, verifier_public_key, state,
   valid_until, created_at)
VALUES ($1, $2, $3, 1, $4, $5, 'ed25519', $6, 'active', $7, $8)`,
		"cred_trk08_"+f.suffix+"_"+label+"_1", connectorID, f.tunnelID, credentialRef, oldThumbprint, []byte(oldPublic), f.clock.now.Add(4*time.Hour), f.clock.now); err != nil {
		t.Fatal(err)
	}

	connector := trk08Connector{
		id:               connectorID,
		hostID:           hostID,
		oldSessionID:     "ses_trk08_" + f.suffix + "_" + label + "_old",
		oldPrivate:       oldPrivate,
		oldPublic:        oldPublic,
		oldIdentityKeyID: oldKeyID,
		oldThumbprint:    oldThumbprint,
		oldCredentialRef: credentialRef,
	}
	if withSession {
		f.insertSession(t, connector, connector.oldSessionID, 1, 1, "ready")
	}
	return connector
}

func (f *trk08PostgresFixture) insertSession(t *testing.T, connector trk08Connector, sessionID string, processGeneration, credentialGeneration uint64, state string) {
	t.Helper()
	if _, err := f.database.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.tunnel_connector_sessions
  (id, connector_id, process_generation, protocol_version, capabilities,
   credential_generation, state, lease_deadline, last_heartbeat_at, ready_at,
   applied_config_generation, retained_until, created_at)
VALUES ($1, $2, $3, $4,
        ARRAY['config.snapshot.v1','config.delta.v1','config.ack.v1',
              'session.heartbeat.v1','auth.renew.v1','connector.drain.v1',
              'credential.rotate.v1']::text[], $5, $6, $7, $8, $9, 1, $10, $8)`,
		sessionID, connector.id, int64(processGeneration), ProtocolVersion, int64(credentialGeneration), state,
		f.clock.now.Add(20*time.Minute), f.clock.now, f.clock.now, f.clock.now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.SQL().ExecContext(context.Background(), `
UPDATE paperboat.tunnel_connectors
SET last_session_id = $1, last_heartbeat_at = $2, ready_at = CASE WHEN $3 = 'ready' THEN $2 ELSE ready_at END,
    last_applied_config_generation = CASE WHEN $3 = 'ready' THEN 1 ELSE last_applied_config_generation END,
    updated_at = $2
WHERE id = $4 AND tunnel_id = $5`, sessionID, f.clock.now, state, connector.id, f.tunnelID); err != nil {
		t.Fatal(err)
	}
}

func (f *trk08PostgresFixture) insertOperation(t *testing.T, operationID, operationType, resourceKind, resourceID, phase, state string) {
	t.Helper()
	hash := sha256.Sum256([]byte("request:" + operationID))
	if _, err := f.database.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.operations
  (id, account_id, idempotency_key, request_hash, operation_type,
   resource_kind, resource_id, phase, state, progress, outcome, correlation_id,
   created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, 'unchanged', $10, $11, $11)`,
		operationID, f.accountID, "idem_"+operationID, hash[:], operationType, resourceKind, resourceID, phase, state, "corr_"+operationID, f.clock.now); err != nil {
		t.Fatal(err)
	}
}

func assertTRK08Migration129(t *testing.T, f *trk08PostgresFixture) {
	t.Helper()
	ctx := context.Background()
	var applied bool
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id = 129 AND is_applied)`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("migration 129 is not applied")
	}
	var targetTable bool
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT to_regclass('paperboat.tunnel_connector_rotation_targets') IS NOT NULL`).Scan(&targetTable); err != nil {
		t.Fatal(err)
	}
	if !targetTable {
		t.Fatal("migration 129 rotation target table is missing")
	}
	for table, column := range map[string]string{
		"tunnel_connector_sessions":               "credential_generation",
		"tunnel_connector_credential_generations": "source_operation_id",
		"tunnel_connector_rotation_targets":       "revoke_session_id",
	} {
		var present bool
		if err := f.database.SQL().QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1 FROM information_schema.columns
  WHERE table_schema = 'paperboat' AND table_name = $1 AND column_name = $2
)`, table, column).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if !present {
			t.Fatalf("migration 129 column %s.%s is missing", table, column)
		}
	}
}

func trk08Challenge(f *trk08PostgresFixture, plan RotationPlan, connector trk08Connector, ordinal int) CredentialRotationChallenge {
	now := f.clock.now
	return CredentialRotationChallenge{
		AccountID:                plan.AccountID,
		TunnelID:                 plan.TunnelID,
		OperationID:              plan.OperationID,
		ConnectorID:              connector.id,
		HostID:                   connector.hostID,
		SessionID:                connector.oldSessionID,
		ProcessGeneration:        1,
		TargetSetHash:            plan.TargetSetHash,
		Target:                   plan.Targets[ordinal],
		OldCredentialGeneration:  1,
		NewCredentialGeneration:  2,
		OldIdentityKeyID:         connector.oldIdentityKeyID,
		OldIdentityKeyThumbprint: connector.oldThumbprint,
		ChallengeNonce:           fmt.Sprintf("rotation-challenge-%s-%s", f.suffix, connector.id),
		IssuedAt:                 now,
		ExpiresAt:                now.Add(time.Minute),
		OverlapUntil:             now.Add(10 * time.Minute),
		NewCredentialValidUntil:  now.Add(2 * time.Hour),
	}
}

func trk08Proof(t *testing.T, challenge CredentialRotationChallenge, connector *trk08Connector, suffix string) (CredentialRotationProof, CredentialRotationInstall) {
	t.Helper()
	newPrivate, newPublic, newKeyID, newThumbprint := trk08Key("new:" + challenge.ConnectorID)
	newReference := "keychain://paperboat/trk08/" + suffix + "/" + challenge.ConnectorID + "/2"
	proof := CredentialRotationProof{
		AccountID:                challenge.AccountID,
		TunnelID:                 challenge.TunnelID,
		OperationID:              challenge.OperationID,
		ConnectorID:              challenge.ConnectorID,
		HostID:                   challenge.HostID,
		SessionID:                challenge.SessionID,
		ProcessGeneration:        challenge.ProcessGeneration,
		TargetSetHash:            challenge.TargetSetHash,
		OldCredentialGeneration:  challenge.OldCredentialGeneration,
		NewCredentialGeneration:  challenge.NewCredentialGeneration,
		OldIdentityKeyID:         challenge.OldIdentityKeyID,
		OldIdentityKeyThumbprint: challenge.OldIdentityKeyThumbprint,
		NewIdentityKeyID:         newKeyID,
		NewIdentityKeyThumbprint: newThumbprint,
		NewPublicKey:             base64.RawURLEncoding.EncodeToString(newPublic),
		NewCredentialReference:   newReference,
		ChallengeNonce:           challenge.ChallengeNonce,
		IssuedAt:                 challenge.IssuedAt.Add(time.Second),
		NewCredentialValidUntil:  challenge.NewCredentialValidUntil,
	}
	proof, err := SignCredentialRotationProof(proof,
		func(payload []byte) []byte { return ed25519.Sign(connector.oldPrivate, payload) },
		func(payload []byte) []byte { return ed25519.Sign(newPrivate, payload) })
	if err != nil {
		t.Fatal(err)
	}
	install := CredentialRotationInstall{
		AccountID:                    challenge.AccountID,
		TunnelID:                     challenge.TunnelID,
		OperationID:                  challenge.OperationID,
		ConnectorID:                  challenge.ConnectorID,
		HostID:                       challenge.HostID,
		SessionID:                    challenge.SessionID,
		ProcessGeneration:            challenge.ProcessGeneration,
		TargetSetHash:                challenge.TargetSetHash,
		OldCredentialGeneration:      challenge.OldCredentialGeneration,
		NewCredentialGeneration:      challenge.NewCredentialGeneration,
		NewIdentityKeyID:             newKeyID,
		NewIdentityKeyThumbprint:     newThumbprint,
		NewPublicKey:                 base64.RawURLEncoding.EncodeToString(newPublic),
		NewCredentialReference:       newReference,
		ChallengeNonce:               challenge.ChallengeNonce,
		OverlapUntil:                 challenge.OverlapUntil,
		NewCredentialValidUntil:      challenge.NewCredentialValidUntil,
		ReplacementProcessGeneration: challenge.ProcessGeneration + 1,
	}
	connector.newPrivate = newPrivate
	connector.newPublic = newPublic
	connector.newIdentityKeyID = newKeyID
	connector.newThumbprint = newThumbprint
	connector.newCredentialRef = newReference
	connector.newSessionID = "ses_trk08_" + suffix + "_" + strings.TrimPrefix(strings.TrimPrefix(connector.id, "con_trk08_"+suffix+"_"), "") + "_new"
	connector.newProcessGeneration = install.ReplacementProcessGeneration
	return proof, install
}

func (f *trk08PostgresFixture) authRequest(connector trk08Connector, generation uint64, keyID, thumbprint string, private ed25519.PrivateKey, nonce string) AuthRequest {
	now := f.clock.now
	request := AuthRequest{
		AccountID:             f.accountID,
		TunnelID:              f.tunnelID,
		ConnectorID:           connector.id,
		HostID:                connector.hostID,
		IdentityKeyID:         keyID,
		IdentityKeyThumbprint: thumbprint,
		ProcessGeneration:     1,
		CredentialGeneration:  generation,
		Nonce:                 nonce,
		IssuedAt:              now,
		ExpiresAt:             now.Add(time.Minute),
	}
	request, _ = SignAuthProof(request, func(payload []byte) []byte { return ed25519.Sign(private, payload) })
	return request
}

func rotationSummary(plan RotationPlan, states map[string]RotationTargetState, codes map[string]Code, completedAt time.Time) RotationSummary {
	summary := RotationSummary{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, TargetSetHash: plan.TargetSetHash, Status: RotationAggregatePending}
	summary.Targets = make([]RotationTargetSummary, 0, len(plan.Targets))
	allRevoked := true
	failed := false
	for _, target := range plan.Targets {
		state := states[target.ConnectorID]
		if state != RotationTargetRevoked {
			allRevoked = false
		}
		if state == RotationTargetFailed {
			failed = true
		}
		summary.Targets = append(summary.Targets, RotationTargetSummary{Target: target, State: state, Code: codes[target.ConnectorID]})
	}
	if failed {
		summary.Status = RotationAggregateFailed
	} else if allRevoked {
		summary.Status = RotationAggregateSucceeded
		summary.CompletedAt = completedAt
	}
	return summary
}

func TestTRK08PostgresMigration129AndRotationAcceptance(t *testing.T) {
	f := newTRK08PostgresFixture(t)
	ctx := context.Background()
	assertTRK08Migration129(t, f)

	f.operationID = "op_trk08_rotate_" + f.suffix
	f.insertOperation(t, f.operationID, "connector.credentials.rotate", "tunnel", f.tunnelID, "validating", "pending")
	targets := []RotationTarget{
		{ConnectorID: f.connectors[0].id, HostID: f.connectors[0].hostID, OldCredentialGeneration: 1, NewCredentialGeneration: 2},
		{ConnectorID: f.connectors[1].id, HostID: f.connectors[1].hostID, OldCredentialGeneration: 1, NewCredentialGeneration: 2},
	}
	plan, err := NewRotationPlan(f.accountID, f.tunnelID, f.operationID, targets)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginCredentialRotation(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginCredentialRotation(ctx, plan); err != nil {
		t.Fatalf("idempotent begin: %v", err)
	}

	var targetCount, distinctHashes int
	var storedHash string
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT count(*), count(DISTINCT target_set_hash), min(target_set_hash)
FROM paperboat.tunnel_connector_rotation_targets
WHERE operation_id = $1 AND account_id = $2 AND tunnel_id = $3`, f.operationID, f.accountID, f.tunnelID).Scan(&targetCount, &distinctHashes, &storedHash); err != nil {
		t.Fatal(err)
	}
	if targetCount != 2 || distinctHashes != 1 || storedHash != plan.TargetSetHash {
		t.Fatalf("captured target set count=%d hashes=%d hash=%q plan=%q", targetCount, distinctHashes, storedHash, plan.TargetSetHash)
	}

	listed, err := f.store.ListCredentialRotationPlans(ctx, 10)
	if err != nil || len(listed) != 1 || listed[0].TargetSetHash != plan.TargetSetHash || len(listed[0].Targets) != 2 {
		t.Fatalf("listed rotation plans=%+v err=%v", listed, err)
	}
	directPlan, err := f.store.LoadCredentialRotationPlan(ctx, plan.OperationID)
	if err != nil || directPlan.OperationID != plan.OperationID || directPlan.TargetSetHash != plan.TargetSetHash || len(directPlan.Targets) != len(plan.Targets) {
		t.Fatalf("direct rotation plan=%+v err=%v", directPlan, err)
	}
	loaded, err := f.store.LoadCredentialRotation(ctx, plan)
	if err != nil || !loaded.Started || len(loaded.Targets) != 2 {
		t.Fatalf("loaded pending rotation=%+v err=%v", loaded, err)
	}

	third := f.insertConnector(t, "c", false)
	f.connectors = append(f.connectors, third)
	listed, err = f.store.ListCredentialRotationPlans(ctx, 10)
	if err != nil || len(listed) != 1 || len(listed[0].Targets) != 2 {
		t.Fatalf("new connector changed captured plan=%+v err=%v", listed, err)
	}
	wrongPlan, err := NewRotationPlan(f.accountID, f.tunnelID, f.operationID, append(append([]RotationTarget(nil), targets...), RotationTarget{ConnectorID: third.id, HostID: third.hostID, OldCredentialGeneration: 1, NewCredentialGeneration: 2}))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginCredentialRotation(ctx, wrongPlan); err == nil {
		t.Fatal("begin accepted a changed target set for an existing operation")
	}
	if err := f.database.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.tunnel_connector_rotation_targets WHERE operation_id = $1`, f.operationID).Scan(&targetCount); err != nil {
		t.Fatal(err)
	}
	if targetCount != 2 {
		t.Fatalf("changed target-set attempt left %d rows", targetCount)
	}

	challenges := make([]CredentialRotationChallenge, 0, 2)
	proofs := make([]CredentialRotationProof, 0, 2)
	installs := make([]CredentialRotationInstall, 0, 2)
	for index, connector := range f.connectors[:2] {
		challenge := trk08Challenge(f, plan, connector, index)
		wrongSession := challenge
		wrongSession.ProcessGeneration = 99
		if err := f.store.AuthorizeCredentialRotationSession(ctx, wrongSession); err == nil {
			t.Fatal("rotation authorization accepted a stale process generation")
		}
		if err := f.store.AuthorizeCredentialRotationSession(ctx, challenge); err != nil {
			t.Fatalf("authorize %s: %v", connector.id, err)
		}
		if err := f.store.RecordCredentialRotationChallenge(ctx, challenge); err != nil {
			t.Fatalf("challenge %s: %v", connector.id, err)
		}
		if err := f.store.RecordCredentialRotationChallenge(ctx, challenge); err != nil {
			t.Fatalf("replay challenge %s: %v", connector.id, err)
		}
		changedChallenge := challenge
		changedChallenge.ChallengeNonce += "-changed"
		if err := f.store.RecordCredentialRotationChallenge(ctx, changedChallenge); err == nil {
			t.Fatal("changed challenge replay was accepted")
		}
		proof, install := trk08Proof(t, challenge, &f.connectors[index], f.suffix)
		if err := f.store.RecordCredentialRotationProof(ctx, challenge, proof, install); err != nil {
			t.Fatalf("proof/install %s: %v", connector.id, err)
		}
		// A second install must not create a second credential generation or
		// another audit transition.
		if err := f.store.RecordCredentialRotationProof(ctx, challenge, proof, install); err == nil {
			t.Fatal("replayed proof/install was accepted as a new transition")
		}
		challenges = append(challenges, challenge)
		proofs = append(proofs, proof)
		installs = append(installs, install)
	}

	// A rotation nonce is scoped to the connector's durable proof ledger, not
	// merely to one operation. Reusing the first accepted nonce from a later
	// operation must fail even when the transcript (operation and target hash)
	// is different, and it must not stage a new credential generation.
	replayOperationID := "op_trk08_rotate_replay_" + f.suffix
	f.insertOperation(t, replayOperationID, "connector.credentials.rotate", "tunnel", f.tunnelID, "validating", "pending")
	replayTarget := RotationTarget{
		ConnectorID:             f.connectors[0].id,
		HostID:                  f.connectors[0].hostID,
		OldCredentialGeneration: 1,
		NewCredentialGeneration: 2,
	}
	replayPlan, err := NewRotationPlan(f.accountID, f.tunnelID, replayOperationID, []RotationTarget{replayTarget})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginCredentialRotation(ctx, replayPlan); err != nil {
		t.Fatal(err)
	}
	replayChallenge := trk08Challenge(f, replayPlan, f.connectors[0], 0)
	replayChallenge.ChallengeNonce = challenges[0].ChallengeNonce
	if err := f.store.AuthorizeCredentialRotationSession(ctx, replayChallenge); err != nil {
		t.Fatalf("authorize replay operation: %v", err)
	}
	if err := f.store.RecordCredentialRotationChallenge(ctx, replayChallenge); err != nil {
		t.Fatalf("challenge replay operation: %v", err)
	}
	replayConnector := f.connectors[0]
	replayProof, replayInstall := trk08Proof(t, replayChallenge, &replayConnector, f.suffix+"-replay")
	originalPayload, err := CredentialRotationProofPayload(proofs[0])
	if err != nil {
		t.Fatal(err)
	}
	replayPayload, err := CredentialRotationProofPayload(replayProof)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(originalPayload, replayPayload) {
		t.Fatal("cross-operation rotation proof unexpectedly reused the original transcript")
	}
	originalDigest := sha256.Sum256(originalPayload)
	replayDigest := sha256.Sum256(replayPayload)
	if originalDigest == replayDigest {
		t.Fatal("cross-operation rotation proof unexpectedly reused the original digest")
	}
	replayErr := f.store.RecordCredentialRotationProof(ctx, replayChallenge, replayProof, replayInstall)
	if !errors.Is(replayErr, ErrDurableReplay) {
		t.Fatalf("cross-operation nonce reuse error=%v, want durable replay", replayErr)
	}
	var replayLedgerKind string
	var replayLedgerGeneration int64
	var replayLedgerNonce string
	var replayLedgerDigest []byte
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT proof_kind, credential_generation, nonce, proof_digest
FROM paperboat.connector_proof_replays
WHERE account_id = $1 AND tunnel_id = $2 AND connector_id = $3
  AND nonce = $4`, f.accountID, f.tunnelID, f.connectors[0].id, challenges[0].ChallengeNonce).
		Scan(&replayLedgerKind, &replayLedgerGeneration, &replayLedgerNonce, &replayLedgerDigest); err != nil {
		t.Fatal(err)
	}
	if replayLedgerKind != "rotation" || replayLedgerGeneration != 1 || replayLedgerNonce != challenges[0].ChallengeNonce || !bytes.Equal(replayLedgerDigest, originalDigest[:]) {
		t.Fatalf("rotation replay ledger kind=%q generation=%d nonce=%q digest=%x", replayLedgerKind, replayLedgerGeneration, replayLedgerNonce, replayLedgerDigest)
	}
	var replayTargetState string
	var replayNewKey []byte
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT state, new_public_key
FROM paperboat.tunnel_connector_rotation_targets
WHERE operation_id = $1 AND connector_id = $2`, replayOperationID, f.connectors[0].id).Scan(&replayTargetState, &replayNewKey); err != nil {
		t.Fatal(err)
	}
	if replayTargetState != string(RotationTargetChallenged) || replayNewKey != nil {
		t.Fatalf("replayed operation advanced target state=%q new_key_present=%v", replayTargetState, replayNewKey != nil)
	}
	var generationCount int
	var generationSource string
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT count(*), min(COALESCE(source_operation_id, ''))
FROM paperboat.tunnel_connector_credential_generations
WHERE connector_id = $1 AND generation = 2`, f.connectors[0].id).Scan(&generationCount, &generationSource); err != nil {
		t.Fatal(err)
	}
	if generationCount != 1 || generationSource != f.operationID {
		t.Fatalf("replayed operation changed generation 2 count=%d source=%q want count=1 source=%q", generationCount, generationSource, f.operationID)
	}

	// Old credentials remain usable while the new verifier is staged. The
	// second generation is independently authenticated by its new public key.
	for index, connector := range f.connectors[:2] {
		oldRequest := f.authRequest(connector, 1, connector.oldIdentityKeyID, connector.oldThumbprint, connector.oldPrivate, fmt.Sprintf("auth-old-%s-%d", f.suffix, index))
		if _, err := f.store.AuthenticateConnector(ctx, oldRequest); err != nil {
			t.Fatalf("old overlap auth %s: %v", connector.id, err)
		}
		newRequest := f.authRequest(connector, 2, connector.newIdentityKeyID, connector.newThumbprint, connector.newPrivate, fmt.Sprintf("auth-new-%s-%d", f.suffix, index))
		if _, err := f.store.AuthenticateConnector(ctx, newRequest); err != nil {
			t.Fatalf("new overlap auth %s: %v", connector.id, err)
		}
	}

	states := map[string]RotationTargetState{f.connectors[0].id: RotationTargetInstalled, f.connectors[1].id: RotationTargetInstalled}
	for index := range f.connectors[:2] {
		connector := f.connectors[index]
		f.insertSession(t, connector, connector.newSessionID, connector.newProcessGeneration, 2, "authenticating")
		oldReady := CredentialRotationReady{
			AccountID:                f.accountID,
			TunnelID:                 f.tunnelID,
			OperationID:              f.operationID,
			ConnectorID:              connector.id,
			HostID:                   connector.hostID,
			SessionID:                connector.oldSessionID,
			PreviousSessionID:        connector.oldSessionID,
			ProcessGeneration:        1,
			TargetSetHash:            plan.TargetSetHash,
			OldCredentialGeneration:  1,
			NewCredentialGeneration:  2,
			NewIdentityKeyID:         connector.newIdentityKeyID,
			NewIdentityKeyThumbprint: connector.newThumbprint,
			NewPublicKey:             base64.RawURLEncoding.EncodeToString(connector.newPublic),
			NewCredentialReference:   connector.newCredentialRef,
			NewCredentialValidUntil:  challenges[index].NewCredentialValidUntil,
			ConfigGeneration:         1,
			ConfigContentHash:        f.config.ContentHash,
			EdgeReady:                true,
			RouteReady:               true,
			OriginReady:              true,
			ReadyAt:                  f.clock.now.Add(2 * time.Second),
		}
		if err := f.store.RecordCredentialRotationReady(ctx, oldReady); err == nil {
			t.Fatal("old-credential session was accepted as rotation-ready")
		}
		ready := oldReady
		ready.SessionID = connector.newSessionID
		ready.PreviousSessionID = connector.oldSessionID
		ready.ProcessGeneration = connector.newProcessGeneration
		if err := f.store.RecordCredentialRotationReady(ctx, ready); err != nil {
			t.Fatalf("new readiness %s: %v", connector.id, err)
		}
		states[connector.id] = RotationTargetReady
		var operationState string
		if err := f.database.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.operations WHERE id = $1`, f.operationID).Scan(&operationState); err != nil {
			t.Fatal(err)
		}
		if operationState != "running" {
			t.Fatalf("operation after target %s ready = %q, want running", connector.id, operationState)
		}
	}

	// Restart reconstruction reads only durable target rows. It must preserve
	// the ready state and must not re-capture the current connector listing.
	restarted, err := NewSQLControlStore(f.database, SQLControlStoreConfig{Clock: f.clock, LeaseDuration: 30 * time.Minute, SessionRetention: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := restarted.LoadCredentialRotation(ctx, plan)
	if err != nil || len(resumed.Targets) != 2 || resumed.Targets[0].State != RotationTargetReady || resumed.Targets[1].State != RotationTargetReady {
		t.Fatalf("restart load = %+v err=%v", resumed, err)
	}
	coordinator, err := NewRotationCoordinator(plan, RotationConfig{Store: restarted, Clock: f.clock, VerifyOldProof: func(context.Context, CredentialRotationProof, []byte, []byte) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Resume(ctx); err != nil {
		t.Fatalf("coordinator resume: %v", err)
	}
	if summary := coordinator.Summary(); summary.Status != RotationAggregatePending || len(summary.Targets) != 2 {
		t.Fatalf("resumed summary = %+v", summary)
	}
	// Readiness switches the replacement generation authoritative but keeps the
	// old generation in the configured overlap window. Verify both sides of
	// that handoff before the old row is expired and later revoked.
	overlapOld := f.authRequest(f.connectors[0], 1, f.connectors[0].oldIdentityKeyID, f.connectors[0].oldThumbprint, f.connectors[0].oldPrivate, "auth-old-overlap-"+f.suffix)
	if _, err := f.store.AuthenticateConnector(ctx, overlapOld); err != nil {
		t.Fatalf("old credential during overlap: %v", err)
	}
	var overlapState string
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT state FROM paperboat.tunnel_connector_credential_generations
WHERE connector_id = $1 AND generation = 1`, f.connectors[0].id).Scan(&overlapState); err != nil {
		t.Fatal(err)
	}
	if overlapState != "overlap" {
		t.Fatalf("old generation state after readiness=%q, want overlap", overlapState)
	}
	// Advance the injected clock beyond the configured overlap. Mutating the
	// credential row backwards would violate its valid_until > created_at
	// invariant and would not represent a real lifecycle transition.
	f.clock.now = challenges[0].OverlapUntil.Add(time.Second)
	expiredOld := f.authRequest(f.connectors[0], 1, f.connectors[0].oldIdentityKeyID, f.connectors[0].oldThumbprint, f.connectors[0].oldPrivate, "auth-old-expired-"+f.suffix)
	if _, err := f.store.AuthenticateConnector(ctx, expiredOld); err == nil {
		t.Fatal("expired old credential was accepted")
	}
	newAfterExpiry := f.authRequest(f.connectors[0], 2, f.connectors[0].newIdentityKeyID, f.connectors[0].newThumbprint, f.connectors[0].newPrivate, "auth-new-after-expiry-"+f.suffix)
	if _, err := f.store.AuthenticateConnector(ctx, newAfterExpiry); err != nil {
		t.Fatalf("new credential after old expiry: %v", err)
	}

	// The first target cannot be revoked until every target reports readiness.
	// At this point both are ready, so each revoke is accepted but aggregate
	// completion remains gated on the second result.
	revokes := make([]CredentialRotationRevoke, 0, 2)
	for index, connector := range f.connectors[:2] {
		revoke := CredentialRotationRevoke{
			AccountID:               f.accountID,
			TunnelID:                f.tunnelID,
			OperationID:             f.operationID,
			ConnectorID:             connector.id,
			HostID:                  connector.hostID,
			SessionID:               connector.newSessionID,
			ProcessGeneration:       connector.newProcessGeneration,
			TargetSetHash:           plan.TargetSetHash,
			OldCredentialGeneration: 1,
			NewCredentialGeneration: 2,
			RevokeNonce:             fmt.Sprintf("rotation-revoke-%s-%d", f.suffix, index),
			IssuedAt:                f.clock.now,
			Deadline:                f.clock.now.Add(4 * time.Second),
		}
		if err := f.store.RecordCredentialRotationRevoke(ctx, revoke); err != nil {
			t.Fatalf("revoke request %s: %v", connector.id, err)
		}
		if err := f.store.RecordCredentialRotationRevoke(ctx, revoke); err != nil {
			t.Fatalf("replay revoke request %s: %v", connector.id, err)
		}
		changed := revoke
		changed.RevokeNonce += "-changed"
		if err := f.store.RecordCredentialRotationRevoke(ctx, changed); err == nil {
			t.Fatal("changed revoke replay was accepted")
		}
		revokes = append(revokes, revoke)
		states[connector.id] = RotationTargetRevoking
	}

	badAck := CredentialRotationAck{
		AccountID:               f.accountID,
		TunnelID:                f.tunnelID,
		OperationID:             f.operationID,
		ConnectorID:             f.connectors[0].id,
		HostID:                  f.connectors[0].hostID,
		SessionID:               f.connectors[0].oldSessionID,
		ProcessGeneration:       1,
		TargetSetHash:           plan.TargetSetHash,
		OldCredentialGeneration: 1,
		NewCredentialGeneration: 2,
		Status:                  RotationAckRevoked,
	}
	pendingFirst := rotationSummary(plan, map[string]RotationTargetState{f.connectors[0].id: RotationTargetRevoked, f.connectors[1].id: RotationTargetRevoking}, nil, time.Time{})
	if err := f.store.RecordCredentialRotationResult(ctx, badAck, pendingFirst); err == nil {
		t.Fatal("stale replacement-session ACK was accepted")
	}

	acks := make([]CredentialRotationAck, 0, 2)
	for index, connector := range f.connectors[:2] {
		ack := CredentialRotationAck{
			AccountID:               f.accountID,
			TunnelID:                f.tunnelID,
			OperationID:             f.operationID,
			ConnectorID:             connector.id,
			HostID:                  connector.hostID,
			SessionID:               connector.newSessionID,
			ProcessGeneration:       connector.newProcessGeneration,
			TargetSetHash:           plan.TargetSetHash,
			OldCredentialGeneration: 1,
			NewCredentialGeneration: 2,
			Status:                  RotationAckRevoked,
		}
		states[connector.id] = RotationTargetRevoked
		if index == 0 {
			pending := rotationSummary(plan, states, nil, time.Time{})
			if err := f.store.RecordCredentialRotationResult(ctx, ack, pending); err != nil {
				t.Fatalf("first revoke result: %v", err)
			}
			if err := f.store.RecordCredentialRotationResult(ctx, ack, pending); err != nil {
				t.Fatalf("idempotent first revoke result: %v", err)
			}
			states[connector.id] = RotationTargetRevoked
			var operationState string
			if err := f.database.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.operations WHERE id = $1`, f.operationID).Scan(&operationState); err != nil {
				t.Fatal(err)
			}
			if operationState != "running" {
				t.Fatalf("operation after first revoke = %q, want running", operationState)
			}
		} else {
			succeeded := rotationSummary(plan, states, nil, f.clock.now.Add(time.Second))
			if err := f.store.RecordCredentialRotationResult(ctx, ack, succeeded); err != nil {
				t.Fatalf("second revoke result: %v", err)
			}
			if err := f.store.RecordCredentialRotationResult(ctx, ack, succeeded); err != nil {
				t.Fatalf("idempotent second revoke result: %v", err)
			}
		}
		acks = append(acks, ack)
	}

	var operationState string
	var progress int
	if err := f.database.SQL().QueryRowContext(ctx, `SELECT state, progress FROM paperboat.operations WHERE id = $1`, f.operationID).Scan(&operationState, &progress); err != nil {
		t.Fatal(err)
	}
	if operationState != "succeeded" || progress != 100 {
		t.Fatalf("final rotation operation state=%q progress=%d", operationState, progress)
	}
	revokedOld := f.authRequest(f.connectors[1], 1, f.connectors[1].oldIdentityKeyID, f.connectors[1].oldThumbprint, f.connectors[1].oldPrivate, "auth-old-revoked-"+f.suffix)
	if _, err := f.store.AuthenticateConnector(ctx, revokedOld); err == nil {
		t.Fatal("old credential was accepted after durable revoke")
	}
	plans, err := restarted.ListCredentialRotationPlans(ctx, 10)
	if err != nil || len(plans) != 1 || plans[0].OperationID != replayOperationID {
		t.Fatalf("completed rotation listing plans=%+v err=%v", plans, err)
	}
	terminalPlan, err := restarted.LoadCredentialRotationPlan(ctx, plan.OperationID)
	if err != nil || terminalPlan.OperationID != plan.OperationID || terminalPlan.TargetSetHash != plan.TargetSetHash {
		t.Fatalf("terminal direct plan=%+v err=%v", terminalPlan, err)
	}
	finalResume, err := restarted.LoadCredentialRotation(ctx, plan)
	if err != nil || finalResume.FinishedAt.IsZero() {
		t.Fatalf("final durable resume=%+v err=%v", finalResume, err)
	}

	// Rotation messages and durable rows contain public verification material
	// and write-only references only. Private keys and bearer-like values must
	// not appear in JSON or audit metadata.
	for index, connector := range f.connectors[:2] {
		for _, value := range []any{challenges[index], installs[index], revokes[index], acks[index]} {
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			text := string(encoded)
			for _, secret := range []string{base64.RawURLEncoding.EncodeToString(connector.oldPrivate), base64.RawURLEncoding.EncodeToString(connector.newPrivate), "BEGIN PRIVATE KEY", "Bearer "} {
				if strings.Contains(text, secret) {
					t.Fatalf("rotation message %T contains secret marker %q", value, secret)
				}
			}
		}
	}
	rows, err := f.database.SQL().QueryContext(ctx, `
SELECT event_type, metadata::text
FROM paperboat.audit_events
WHERE resource_type = 'tunnel' AND idempotency_key LIKE $1
ORDER BY cursor_sequence`, f.operationID+":%")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []string
	counts := map[string]int{}
	for rows.Next() {
		var event, metadata string
		if err := rows.Scan(&event, &metadata); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
		counts[event]++
		for _, secret := range []string{base64.RawURLEncoding.EncodeToString(f.connectors[0].oldPrivate), base64.RawURLEncoding.EncodeToString(f.connectors[0].newPrivate), "BEGIN PRIVATE KEY", "bearer"} {
			if strings.Contains(strings.ToLower(metadata), strings.ToLower(secret)) {
				t.Fatalf("audit event %s contains secret marker %q", event, secret)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	wantCounts := map[string]int{
		"connector.credential_rotation_started":          1,
		"connector.credential_rotation_challenged":       2,
		"connector.credential_rotation_installed":        2,
		"connector.credential_rotation_ready":            2,
		"connector.credential_rotation_revoke_requested": 2,
		"connector.credential_rotation_revoked":          2,
	}
	if len(events) != 11 {
		t.Fatalf("audit event count=%d events=%v", len(events), events)
	}
	for event, want := range wantCounts {
		if counts[event] != want {
			t.Fatalf("audit event %s count=%d want=%d all=%v", event, counts[event], want, events)
		}
	}
	if events[0] != "connector.credential_rotation_started" || events[len(events)-1] != "connector.credential_rotation_revoked" {
		t.Fatalf("audit ordering starts/ends with %v", events)
	}
	var secretColumns int
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT count(*) FROM information_schema.columns
WHERE table_schema = 'paperboat' AND table_name = 'tunnel_connector_rotation_targets'
  AND lower(column_name) IN ('private_key','bearer_token','secret','secret_value','token')`).Scan(&secretColumns); err != nil {
		t.Fatal(err)
	}
	if secretColumns != 0 {
		t.Fatalf("rotation target table has secret columns: %d", secretColumns)
	}

	// Keep this assertion explicit so a future SQL query cannot accidentally
	// make the captured set depend on the live connector list.
	gotTargets := make([]string, 0, 2)
	rows, err = f.database.SQL().QueryContext(ctx, `
SELECT connector_id FROM paperboat.tunnel_connector_rotation_targets
WHERE operation_id = $1 ORDER BY connector_id`, f.operationID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var connectorID string
		if err := rows.Scan(&connectorID); err != nil {
			t.Fatal(err)
		}
		gotTargets = append(gotTargets, connectorID)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	wantTargets := []string{f.connectors[0].id, f.connectors[1].id}
	sort.Strings(wantTargets)
	if fmt.Sprint(gotTargets) != fmt.Sprint(wantTargets) {
		t.Fatalf("durable target set=%v want=%v", gotTargets, wantTargets)
	}
}

func TestTRK08PostgresDisconnectMarksRotationUncertainAndRecovers(t *testing.T) {
	f := newTRK08PostgresFixture(t)
	ctx := context.Background()
	operationID := "op_trk08_recovery_" + f.suffix
	f.insertOperation(t, operationID, "connector.credentials.rotate", "tunnel", f.tunnelID, "connecting", "running")
	plan, err := NewRotationPlan(f.accountID, f.tunnelID, operationID, []RotationTarget{{ConnectorID: f.connectors[0].id, HostID: f.connectors[0].hostID, OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginCredentialRotation(ctx, plan); err != nil {
		t.Fatal(err)
	}
	disconnect := Disconnect{AccountID: f.accountID, TunnelID: f.tunnelID, ConnectorID: f.connectors[0].id, SessionID: f.connectors[0].oldSessionID, ProcessGeneration: 1, Reason: ReasonCredentialRotation, Retryable: true}
	if err := f.store.RecordDisconnected(ctx, SessionRef{TunnelID: f.tunnelID, ConnectorID: f.connectors[0].id, SessionID: f.connectors[0].oldSessionID, ProcessGeneration: 1}, disconnect); err != nil {
		t.Fatalf("disconnect recovery: %v", err)
	}
	var state string
	var retrying bool
	var errorCode string
	if err := f.database.SQL().QueryRowContext(ctx, `SELECT state, retrying, error_code FROM paperboat.operations WHERE id = $1`, operationID).Scan(&state, &retrying, &errorCode); err != nil {
		t.Fatal(err)
	}
	if state != "uncertain" || !retrying || errorCode != string(CodeStaleSession) {
		t.Fatalf("disconnect operation state=%q retrying=%v error=%q", state, retrying, errorCode)
	}
	if err := f.store.RecordDisconnected(ctx, SessionRef{TunnelID: f.tunnelID, ConnectorID: f.connectors[0].id, SessionID: f.connectors[0].oldSessionID, ProcessGeneration: 1}, disconnect); err != nil {
		t.Fatalf("idempotent disconnect recovery: %v", err)
	}

	// A replacement process may reconcile the same durable target. The old
	// process cannot authorize a challenge after its session is disconnected.
	replacementSession := "ses_trk08_" + f.suffix + "_a_replacement"
	f.insertSession(t, f.connectors[0], replacementSession, 2, 1, "authenticating")
	challenge := trk08Challenge(f, plan, f.connectors[0], 0)
	if err := f.store.AuthorizeCredentialRotationSession(ctx, challenge); err == nil {
		t.Fatal("disconnected old process authorized rotation")
	}
	challenge.SessionID = replacementSession
	challenge.ProcessGeneration = 2
	if err := f.store.AuthorizeCredentialRotationSession(ctx, challenge); err != nil {
		t.Fatalf("replacement process authorization: %v", err)
	}
	if err := f.store.RecordCredentialRotationChallenge(ctx, challenge); err != nil {
		t.Fatalf("replacement challenge after recovery: %v", err)
	}
	var recoveryAudits int
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT count(*) FROM paperboat.audit_events
WHERE event_type = 'connector.credential_rotation_recovery_required'
  AND resource_id = $1`, f.tunnelID).Scan(&recoveryAudits); err != nil {
		t.Fatal(err)
	}
	if recoveryAudits != 1 {
		t.Fatalf("recovery audit count=%d want=1", recoveryAudits)
	}

	// The control carrier registers the replacement after SQL session creation,
	// so connector.last_session_id may already point at the new process when it
	// reports the old process disconnected. The exact old rotation target still
	// has to become recoverable.
	replacementFirstOperation := "op_trk08_replacement_first_" + f.suffix
	f.insertOperation(t, replacementFirstOperation, "connector.credentials.rotate", "tunnel", f.tunnelID, "connecting", "running")
	replacementFirstPlan, err := NewRotationPlan(f.accountID, f.tunnelID, replacementFirstOperation, []RotationTarget{{ConnectorID: f.connectors[1].id, HostID: f.connectors[1].hostID, OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginCredentialRotation(ctx, replacementFirstPlan); err != nil {
		t.Fatal(err)
	}
	replacementFirstSession := "ses_trk08_" + f.suffix + "_b_replacement_first"
	f.insertSession(t, f.connectors[1], replacementFirstSession, 2, 1, "authenticating")
	oldRef := SessionRef{TunnelID: f.tunnelID, ConnectorID: f.connectors[1].id, SessionID: f.connectors[1].oldSessionID, ProcessGeneration: 1}
	oldDisconnect := Disconnect{AccountID: f.accountID, TunnelID: f.tunnelID, ConnectorID: oldRef.ConnectorID, SessionID: oldRef.SessionID, ProcessGeneration: oldRef.ProcessGeneration, Reason: ReasonSessionReplaced, Retryable: true}
	if err := f.store.RecordDisconnected(ctx, oldRef, oldDisconnect); err != nil {
		t.Fatalf("replacement-first disconnect recovery: %v", err)
	}
	if err := f.database.SQL().QueryRowContext(ctx, `SELECT state, retrying, error_code FROM paperboat.operations WHERE id = $1`, replacementFirstOperation).Scan(&state, &retrying, &errorCode); err != nil {
		t.Fatal(err)
	}
	if state != "uncertain" || !retrying || errorCode != string(CodeStaleSession) {
		t.Fatalf("replacement-first operation state=%q retrying=%v error=%q", state, retrying, errorCode)
	}
}

func TestTRK08PostgresReconnectRebindsInterruptedRotationPhases(t *testing.T) {
	f := newTRK08PostgresFixture(t)
	ctx := context.Background()

	installedOperation := "op_trk08_install_recovery_" + f.suffix
	f.insertOperation(t, installedOperation, "connector.credentials.rotate", "tunnel", f.tunnelID, "connecting", "running")
	installedPlan, err := NewRotationPlan(f.accountID, f.tunnelID, installedOperation, []RotationTarget{{ConnectorID: f.connectors[0].id, HostID: f.connectors[0].hostID, OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginCredentialRotation(ctx, installedPlan); err != nil {
		t.Fatal(err)
	}
	challenge := trk08Challenge(f, installedPlan, f.connectors[0], 0)
	if err := f.store.RecordCredentialRotationChallenge(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	proof, install := trk08Proof(t, challenge, &f.connectors[0], f.suffix+"-install-recovery")
	if err := f.store.RecordCredentialRotationProof(ctx, challenge, proof, install); err != nil {
		t.Fatal(err)
	}
	oldReconnect := "ses_trk08_" + f.suffix + "_old_reconnect"
	f.insertSession(t, f.connectors[0], oldReconnect, 3, 1, "ready")
	if err := f.store.ResetCredentialRotationInstall(ctx, installedPlan, installedPlan.Targets[0], SessionRef{TunnelID: f.tunnelID, ConnectorID: f.connectors[0].id, SessionID: oldReconnect, ProcessGeneration: 3}); err != nil {
		t.Fatalf("reset interrupted install: %v", err)
	}
	var installedState string
	var stagedCredentials int
	var stagedKey []byte
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT state, new_public_key FROM paperboat.tunnel_connector_rotation_targets
WHERE operation_id = $1 AND connector_id = $2`, installedOperation, f.connectors[0].id).Scan(&installedState, &stagedKey); err != nil {
		t.Fatal(err)
	}
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT count(*) FROM paperboat.tunnel_connector_credential_generations
WHERE connector_id = $1 AND generation = 2`, f.connectors[0].id).Scan(&stagedCredentials); err != nil {
		t.Fatal(err)
	}
	if installedState != string(RotationTargetChallenged) || stagedKey != nil || stagedCredentials != 0 {
		t.Fatalf("install recovery state=%q staged_key=%x credentials=%d", installedState, stagedKey, stagedCredentials)
	}

	revokeOperation := "op_trk08_revoke_rebind_" + f.suffix
	f.insertOperation(t, revokeOperation, "connector.credentials.rotate", "tunnel", f.tunnelID, "connecting", "running")
	revokePlan, err := NewRotationPlan(f.accountID, f.tunnelID, revokeOperation, []RotationTarget{{ConnectorID: f.connectors[1].id, HostID: f.connectors[1].hostID, OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginCredentialRotation(ctx, revokePlan); err != nil {
		t.Fatal(err)
	}
	revokeChallenge := trk08Challenge(f, revokePlan, f.connectors[1], 0)
	if err := f.store.RecordCredentialRotationChallenge(ctx, revokeChallenge); err != nil {
		t.Fatal(err)
	}
	revokeProof, revokeInstall := trk08Proof(t, revokeChallenge, &f.connectors[1], f.suffix+"-revoke-rebind")
	if err := f.store.RecordCredentialRotationProof(ctx, revokeChallenge, revokeProof, revokeInstall); err != nil {
		t.Fatal(err)
	}
	firstNewSession := "ses_trk08_" + f.suffix + "_new_ready"
	f.insertSession(t, f.connectors[1], firstNewSession, 2, 2, "authenticating")
	ready := CredentialRotationReady{AccountID: f.accountID, TunnelID: f.tunnelID, OperationID: revokeOperation, ConnectorID: f.connectors[1].id, HostID: f.connectors[1].hostID, SessionID: firstNewSession, PreviousSessionID: f.connectors[1].oldSessionID, ProcessGeneration: 2, TargetSetHash: revokePlan.TargetSetHash, OldCredentialGeneration: 1, NewCredentialGeneration: 2, NewIdentityKeyID: revokeInstall.NewIdentityKeyID, NewIdentityKeyThumbprint: revokeInstall.NewIdentityKeyThumbprint, NewPublicKey: revokeInstall.NewPublicKey, NewCredentialReference: revokeInstall.NewCredentialReference, NewCredentialValidUntil: revokeInstall.NewCredentialValidUntil, ConfigGeneration: f.config.Generation, ConfigContentHash: f.config.ContentHash, EdgeReady: true, RouteReady: true, OriginReady: true, ReadyAt: f.clock.now}
	if err := f.store.RecordCredentialRotationReady(ctx, ready); err != nil {
		t.Fatal(err)
	}
	initialRevoke := CredentialRotationRevoke{AccountID: f.accountID, TunnelID: f.tunnelID, OperationID: revokeOperation, ConnectorID: f.connectors[1].id, HostID: f.connectors[1].hostID, SessionID: firstNewSession, ProcessGeneration: 2, TargetSetHash: revokePlan.TargetSetHash, OldCredentialGeneration: 1, NewCredentialGeneration: 2, RevokeNonce: "rotation-revoke-initial-" + f.suffix, IssuedAt: f.clock.now, Deadline: f.clock.now.Add(DefaultAbortTimeout)}
	if err := f.store.RecordCredentialRotationRevoke(ctx, initialRevoke); err != nil {
		t.Fatal(err)
	}
	reboundSession := "ses_trk08_" + f.suffix + "_new_rebound"
	f.insertSession(t, f.connectors[1], reboundSession, 3, 2, "ready")
	rebound, err := f.store.RebindCredentialRotationRevoke(ctx, revokePlan, revokePlan.Targets[0], SessionRef{TunnelID: f.tunnelID, ConnectorID: f.connectors[1].id, SessionID: reboundSession, ProcessGeneration: 3}, "rotation-revoke-rebound-"+f.suffix, f.clock.now, f.clock.now.Add(DefaultAbortTimeout))
	if err != nil {
		t.Fatalf("rebind revoke: %v", err)
	}
	if rebound.SessionID != reboundSession || rebound.ProcessGeneration != 3 {
		t.Fatalf("rebound revoke=%+v", rebound)
	}
	loaded, err := f.store.LoadCredentialRotation(ctx, revokePlan)
	if err != nil || len(loaded.Targets) != 1 || loaded.Targets[0].Revoke.SessionID != reboundSession || loaded.Targets[0].Revoke.ProcessGeneration != 3 {
		t.Fatalf("loaded rebound=%+v err=%v", loaded, err)
	}

	expiredOperation := "op_trk08_expired_pending_" + f.suffix
	f.insertOperation(t, expiredOperation, "connector.credentials.rotate", "tunnel", f.tunnelID, "connecting", "running")
	expiredPlan, err := NewRotationPlan(f.accountID, f.tunnelID, expiredOperation, []RotationTarget{{ConnectorID: f.connectors[0].id, HostID: f.connectors[0].hostID, OldCredentialGeneration: 1, NewCredentialGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginCredentialRotation(ctx, expiredPlan); err != nil {
		t.Fatal(err)
	}
	if err := f.store.FailCredentialRotationTarget(ctx, expiredPlan, expiredPlan.Targets[0], CodeCredentialExpired); err != nil {
		t.Fatalf("fail expired pending target: %v", err)
	}
	var expiredTargetState, expiredOperationState, expiredCode string
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT rt.state, o.state, o.error_code
FROM paperboat.tunnel_connector_rotation_targets AS rt
JOIN paperboat.operations AS o ON o.id = rt.operation_id
WHERE rt.operation_id = $1 AND rt.connector_id = $2`, expiredOperation, f.connectors[0].id).Scan(&expiredTargetState, &expiredOperationState, &expiredCode); err != nil {
		t.Fatal(err)
	}
	if expiredTargetState != string(RotationTargetFailed) || expiredOperationState != "failed" || expiredCode != string(CodeCredentialExpired) {
		t.Fatalf("expired states target=%q operation=%q code=%q", expiredTargetState, expiredOperationState, expiredCode)
	}
}

func TestTRK08PostgresRevokeDrainPreservesForcedState(t *testing.T) {
	f := newTRK08PostgresFixture(t)
	ctx := context.Background()
	connector := f.connectors[0]
	if _, err := f.database.SQL().ExecContext(ctx, `
UPDATE paperboat.tunnel_connectors
SET desired_state = 'revoked', revoked_at = $1, drain_state = 'forced_closed', updated_at = $1
WHERE id = $2 AND tunnel_id = $3`, f.clock.now, connector.id, f.tunnelID); err != nil {
		t.Fatal(err)
	}
	revokedAuth := f.authRequest(connector, 1, connector.oldIdentityKeyID, connector.oldThumbprint, connector.oldPrivate, "auth-revoked-"+f.suffix)
	if _, err := f.store.AuthenticateConnector(ctx, revokedAuth); err == nil {
		t.Fatal("revoked connector accepted a new authentication")
	}

	for index, status := range []DrainStatus{DrainAccepted, DrainCompleted, DrainForced, DrainRejected} {
		operationID := fmt.Sprintf("op_trk08_revoke_drain_%s_%d", f.suffix, index)
		f.insertOperation(t, operationID, "connector.revoke", "connector", connector.id, "draining", "running")
		drain := Drain{
			AccountID:          f.accountID,
			TunnelID:           f.tunnelID,
			ConnectorID:        connector.id,
			SessionID:          connector.oldSessionID,
			ProcessGeneration:  1,
			DrainID:            operationID,
			Generation:         1,
			ContentHash:        f.config.ContentHash,
			Deadline:           f.clock.now.Add(2 * time.Second),
			StopNewStreams:     true,
			ForceAfterDeadline: true,
		}
		code := Code("")
		if status == DrainForced {
			code = CodeDrainTimeout
		} else if status == DrainRejected {
			code = CodeDrainRejected
		}
		if err := f.store.RecordDrain(ctx, SessionRef{TunnelID: f.tunnelID, ConnectorID: connector.id, SessionID: connector.oldSessionID, ProcessGeneration: 1}, drain, status, 0, code); err != nil {
			t.Fatalf("revoke drain status %s: %v", status, err)
		}
		// Terminal ACK replay is a no-op and must not turn a revoked connector
		// back into accepting/draining state or append a duplicate event.
		if status != DrainAccepted {
			if err := f.store.RecordDrain(ctx, SessionRef{TunnelID: f.tunnelID, ConnectorID: connector.id, SessionID: connector.oldSessionID, ProcessGeneration: 1}, drain, status, 0, code); err != nil {
				t.Fatalf("idempotent terminal drain %s: %v", status, err)
			}
		}
	}
	var desiredState, drainState string
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT desired_state, drain_state FROM paperboat.tunnel_connectors WHERE id = $1`, connector.id).Scan(&desiredState, &drainState); err != nil {
		t.Fatal(err)
	}
	if desiredState != "revoked" || drainState != "forced_closed" {
		t.Fatalf("late revoke drain ACK overwrote state desired=%q drain=%q", desiredState, drainState)
	}
	var rejectedState, rejectedOutcome, rejectedError string
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT state, outcome, COALESCE(error_code, '') FROM paperboat.operations
WHERE id = $1`, fmt.Sprintf("op_trk08_revoke_drain_%s_%d", f.suffix, 3)).Scan(&rejectedState, &rejectedOutcome, &rejectedError); err != nil {
		t.Fatal(err)
	}
	if rejectedState != "failed" || rejectedOutcome != "uncertain" || rejectedError != string(CodeDrainRejected) {
		t.Fatalf("rejected revoke drain operation state=%q outcome=%q error=%q", rejectedState, rejectedOutcome, rejectedError)
	}
	var staleErr error
	staleDrain := Drain{
		AccountID: f.accountID, TunnelID: f.tunnelID, ConnectorID: connector.id, SessionID: connector.oldSessionID,
		ProcessGeneration: 99, DrainID: "op_trk08_stale_drain_" + f.suffix, Generation: 1, ContentHash: f.config.ContentHash,
		Deadline: f.clock.now.Add(2 * time.Second), StopNewStreams: true, ForceAfterDeadline: true,
	}
	f.insertOperation(t, staleDrain.DrainID, "connector.revoke", "connector", connector.id, "draining", "running")
	staleErr = f.store.RecordDrain(ctx, SessionRef{TunnelID: f.tunnelID, ConnectorID: connector.id, SessionID: connector.oldSessionID, ProcessGeneration: 99}, staleDrain, DrainCompleted, 0, "")
	if staleErr == nil {
		t.Fatal("stale process drain ACK was accepted")
	}
	var acceptedAudits, completedAudits, forcedAudits, rejectedAudits int
	if err := f.database.SQL().QueryRowContext(ctx, `
SELECT count(*) FILTER (WHERE event_type = 'connector.revoke.accepted'),
       count(*) FILTER (WHERE event_type = 'connector.revoke.completed'),
       count(*) FILTER (WHERE event_type = 'connector.revoke.forced_close'),
       count(*) FILTER (WHERE event_type = 'connector.revoke.rejected')
	FROM paperboat.audit_events WHERE resource_id = $1`, connector.id).Scan(&acceptedAudits, &completedAudits, &forcedAudits, &rejectedAudits); err != nil {
		t.Fatal(err)
	}
	if acceptedAudits != 1 || completedAudits != 1 || forcedAudits != 1 || rejectedAudits != 1 {
		t.Fatalf("revoke drain audit counts accepted=%d completed=%d forced=%d rejected=%d", acceptedAudits, completedAudits, forcedAudits, rejectedAudits)
	}
}
