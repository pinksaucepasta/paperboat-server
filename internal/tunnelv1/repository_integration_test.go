package tunnelv1

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/testutil"
)

// TestSQLRepositoryExpiryResetOnPostgres is intentionally opt-in. It covers
// the PostgreSQL row-lock/query path that cannot be proven by the service
// fakes: expiry marks only the summary, and a later extension or explicit null
// clears that summary without changing the durable endpoint identity.
func TestSQLRepositoryExpiryResetOnPostgres(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run tunnel repository integration tests")
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
	repository, err := NewRepository(database)
	if err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	accountID := "usr_trk06_" + suffix
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, accountID, "workos_"+suffix, "trk06-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	hostID := "mch_trk06_" + suffix
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machines
  (id, user_id, environment_id, display_name, platform, architecture, workspace_root,
   state, seat_state, public_identity_key, setup_roles, setup_mode)
VALUES ($1, $2, $3, $4, 'linux', 'amd64', '/workspace', 'online', 'occupied', $5,
        ARRAY['host']::text[], 'host')`, hostID, accountID, "env_"+suffix, "Host "+suffix, strings.Repeat("A", 43)); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, accountID) }()

	now := time.Now().UTC().Truncate(time.Microsecond)
	expiresAt := now.Add(time.Minute)
	hash := sha256.Sum256([]byte("create:" + suffix))
	endpointID := testutil.EndpointUUID("repository:" + suffix)
	created, err := repository.Create(ctx, CreateRecord{
		OperationID: "op_create_" + suffix, TunnelID: "tun_" + suffix,
		StableEndpointID: endpointID, StableEndpoint: "https://" + endpointID + ".tunnels.example.test",
		AccountID: accountID, Name: "demo-" + suffix, AccessMode: AccessPublic,
		Origin:    OriginRequest{Scheme: "http", Address: "127.0.0.1:3000"},
		ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true}, IdempotencyKey: "create:" + suffix,
		RequestHash: hash, ActorID: accountID, AuditActorID: hostID, ActorType: "host", HostID: hostID,
		RequestID: "req_create_" + suffix, CorrelationID: "corr_create_" + suffix,
		SourceDeviceID: hostID, AuditEventID: "aud_create_" + suffix,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Operation.State != "running" || created.Tunnel.Generation != 1 {
		t.Fatalf("create result = %#v", created)
	}
	tcpHash := sha256.Sum256([]byte("create-tcp:" + suffix))
	tcpEndpointID := testutil.EndpointUUID("repository-tcp:" + suffix)
	tcpTunnel, err := repository.Create(ctx, CreateRecord{
		OperationID: "op_create_tcp_" + suffix, TunnelID: "tun_tcp_" + suffix,
		StableEndpointID: tcpEndpointID, StableEndpoint: "https://" + tcpEndpointID + ".tunnels.example.test",
		AccountID: accountID, Name: "tcp-" + suffix, AccessMode: AccessPrivate,
		Origin: OriginRequest{Scheme: "tcp", Address: "127.0.0.1:5432"}, IdempotencyKey: "create-tcp:" + suffix,
		RequestHash: tcpHash, ActorID: accountID, AuditActorID: hostID, ActorType: "host", HostID: hostID,
		RequestID: "req_create_tcp_" + suffix, CorrelationID: "corr_create_tcp_" + suffix,
		SourceDeviceID: hostID, AuditEventID: "aud_create_tcp_" + suffix,
	})
	if err != nil {
		t.Fatal(err)
	}
	public := AccessPublic
	publicHash := sha256.Sum256([]byte("public-tcp:" + suffix))
	if _, err := repository.Patch(ctx, PatchRecord{
		OperationID: "op_public_tcp_" + suffix, AuditEventID: "aud_public_tcp_" + suffix,
		TunnelID: tcpTunnel.Tunnel.ID, AccountID: accountID, AccessMode: &public,
		ExpectedGeneration: tcpTunnel.Tunnel.Generation, IdempotencyKey: "public-tcp:" + suffix,
		RequestHash: publicHash, ActorID: accountID, AuditActorID: hostID, ActorType: "host",
		RequestID: "req_public_tcp_" + suffix, CorrelationID: "corr_public_tcp_" + suffix,
		SourceDeviceID: hostID, Now: now,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("public TCP patch error = %v, want ErrInvalidInput", err)
	}
	var auditActorType, auditActorID string
	var auditActorUserID sql.NullString
	if err := database.SQL().QueryRowContext(ctx, `
SELECT actor_type, actor_id, actor_user_id
FROM paperboat.audit_events
WHERE id=$1`, "aud_create_"+suffix).Scan(&auditActorType, &auditActorID, &auditActorUserID); err != nil {
		t.Fatal(err)
	}
	if auditActorType != "host" || auditActorID != hostID || auditActorUserID.Valid {
		t.Fatalf("host audit identity = type=%q id=%q user_id=%#v", auditActorType, auditActorID, auditActorUserID)
	}
	var configGeneration int64
	var configState string
	var configSnapshot []byte
	if err := database.SQL().QueryRowContext(ctx, `
SELECT generation, activation_state, snapshot
FROM paperboat.tunnel_config_generations
WHERE tunnel_id=$1`, created.Tunnel.ID).Scan(&configGeneration, &configState, &configSnapshot); err != nil {
		t.Fatal(err)
	}
	if configGeneration != 1 || configState != "pending" || len(configSnapshot) == 0 {
		t.Fatalf("initial config generation = generation=%d state=%q snapshot=%s", configGeneration, configState, configSnapshot)
	}
	stableEndpoint := created.Tunnel.StableEndpoint

	var idCounter atomic.Uint64
	newID := func(prefix string) (string, error) {
		return fmt.Sprintf("%s_expiry_%s_%d", prefix, suffix, idCounter.Add(1)), nil
	}
	expired, err := repository.ReconcileExpired(ctx, ExpiryRecord{
		Now: expiresAt.Add(time.Second), Limit: 10, ActorID: "expiry-worker-" + suffix,
		ActorType: "system", RequestID: "req_expire_1_" + suffix,
		CorrelationID: "corr_expire_1_" + suffix, NewID: newID,
	})
	if err != nil || len(expired) == 0 {
		t.Fatalf("expiry result = %#v, err=%v", expired, err)
	}
	var expiredTunnel *MutationRecord
	for index := range expired {
		if expired[index].Tunnel.ID == created.Tunnel.ID {
			expiredTunnel = &expired[index]
			break
		}
	}
	if expiredTunnel == nil {
		t.Fatalf("expiry sweep did not include %s: %#v", created.Tunnel.ID, expired)
	}
	if expiredTunnel.Tunnel.SummaryCode != "expired" || expiredTunnel.Tunnel.DesiredState != DesiredActive || expiredTunnel.Tunnel.StableEndpoint != stableEndpoint {
		t.Fatalf("expiry changed durable state/identity: %#v", expiredTunnel.Tunnel)
	}

	extended := expiresAt.Add(3 * time.Hour)
	extendedHash := sha256.Sum256([]byte("extend:" + suffix))
	extendedResult, err := repository.Patch(ctx, PatchRecord{
		OperationID: "op_extend_" + suffix, AuditEventID: "aud_extend_" + suffix,
		TunnelID: created.Tunnel.ID, AccountID: accountID, ExpiresAt: &extended, ExpirySet: true,
		ExpectedGeneration: 1, IdempotencyKey: "extend:" + suffix, RequestHash: extendedHash,
		ActorID: accountID, AuditActorID: hostID, ActorType: "host", RequestID: "req_extend_" + suffix,
		CorrelationID: "corr_extend_" + suffix, SourceDeviceID: hostID,
		Now: expiresAt.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if extendedResult.Tunnel.SummaryCode != "pending" || extendedResult.Tunnel.Generation != 2 || extendedResult.Tunnel.StableEndpoint != stableEndpoint {
		t.Fatalf("expiry extension did not reset summary/preserve identity: %#v", extendedResult.Tunnel)
	}

	if _, err := repository.ReconcileExpired(ctx, ExpiryRecord{
		Now: extended.Add(time.Second), Limit: 10, ActorID: "expiry-worker-" + suffix,
		ActorType: "system", RequestID: "req_expire_2_" + suffix,
		CorrelationID: "corr_expire_2_" + suffix, NewID: newID,
	}); err != nil {
		t.Fatal(err)
	}
	removeHash := sha256.Sum256([]byte("remove-expiry:" + suffix))
	removed, err := repository.Patch(ctx, PatchRecord{
		OperationID: "op_remove_" + suffix, AuditEventID: "aud_remove_" + suffix,
		TunnelID: created.Tunnel.ID, AccountID: accountID, ExpirySet: true,
		ExpectedGeneration: 2, IdempotencyKey: "remove-expiry:" + suffix, RequestHash: removeHash,
		ActorID: accountID, AuditActorID: hostID, ActorType: "host", RequestID: "req_remove_" + suffix,
		CorrelationID: "corr_remove_" + suffix, SourceDeviceID: hostID,
		Now: extended.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if removed.Tunnel.SummaryCode != "pending" || removed.Tunnel.ExpiresAt.Valid || removed.Tunnel.Generation != 3 || removed.Tunnel.StableEndpoint != stableEndpoint {
		t.Fatalf("expiry removal did not reset summary/preserve identity: %#v", removed.Tunnel)
	}
}

type trk07PostgresFixture struct {
	database   *db.DB
	repository *SQLRepository
	suffix     string
	now        time.Time
	accounts   []string
}

var trk07FixtureCounter atomic.Uint64

// newTRK07PostgresFixture is deliberately opt-in. The resource repository
// uses PostgreSQL transaction, lock, FK, and generated-column behavior that is
// not reproducible with the service fake. The test never starts an application
// process or a local database.
func newTRK07PostgresFixture(t *testing.T) *trk07PostgresFixture {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run TRK-07 PostgreSQL integration tests")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background(), database); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d_%d", time.Now().UnixNano(), trk07FixtureCounter.Add(1))
	fixture := &trk07PostgresFixture{database: database, suffix: suffix, now: time.Now().UTC().Truncate(time.Microsecond)}
	fixture.addAccount(t, "primary")
	repository, err := NewRepository(database)
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	fixture.repository = repository
	t.Cleanup(func() {
		ctx := context.Background()
		for index := len(fixture.accounts) - 1; index >= 0; index-- {
			_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, fixture.accounts[index])
		}
		_ = database.Close()
	})
	return fixture
}

func (f *trk07PostgresFixture) addAccount(t *testing.T, label string) (string, string) {
	t.Helper()
	accountID := "usr_trk07_" + label + "_" + f.suffix
	hostID := "mch_trk07_" + label + "_" + f.suffix
	ctx := context.Background()
	if _, err := f.database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, accountID, "workos_"+accountID, accountID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	identityDigest := sha256.Sum256([]byte(hostID))
	publicIdentityKey := base64.RawURLEncoding.EncodeToString(identityDigest[:])
	if _, err := f.database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machines
  (id, user_id, environment_id, display_name, platform, architecture, workspace_root,
   state, seat_state, public_identity_key, setup_roles, setup_mode)
VALUES ($1, $2, $3, $4, 'linux', 'amd64', '/workspace', 'online', 'occupied', $5,
        ARRAY['host']::text[], 'host')`, hostID, accountID, "env_"+hostID, label+" host", publicIdentityKey); err != nil {
		t.Fatal(err)
	}
	f.accounts = append(f.accounts, accountID)
	return accountID, hostID
}

func (f *trk07PostgresFixture) createTunnel(t *testing.T, accountID, hostID, tunnelID, name string) MutationRecord {
	t.Helper()
	hash := sha256.Sum256([]byte("create:" + tunnelID))
	endpointID := testutil.EndpointUUID("repository-fixture:" + tunnelID)
	result, err := f.repository.Create(context.Background(), CreateRecord{
		OperationID: "op_" + tunnelID, TunnelID: tunnelID,
		StableEndpointID: endpointID, StableEndpoint: "https://" + endpointID + ".tunnels.example.test",
		AccountID: accountID, Name: name, AccessMode: AccessPublic,
		Origin:         OriginRequest{Scheme: "http", Address: "127.0.0.1:3000"},
		IdempotencyKey: "create:" + tunnelID, RequestHash: hash, ActorID: accountID, AuditActorID: hostID,
		ActorType: "host", HostID: hostID, RequestID: "req_" + tunnelID, CorrelationID: "corr_" + tunnelID,
		SourceDeviceID: hostID, AuditEventID: "aud_" + tunnelID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Tunnel.Generation != 1 || result.Operation.State != "running" {
		t.Fatalf("created tunnel = %#v", result)
	}
	return result
}

func trk07RouteInput(f *trk07PostgresFixture, accountID, hostID, tunnelID, routeID, name, hostname string) RouteRecord {
	now := f.now
	hash := sha256.Sum256([]byte("route:" + routeID))
	return RouteRecord{
		OperationID: "op_" + routeID, AuditEventID: "aud_" + routeID, AccountID: accountID, TunnelID: tunnelID,
		RouteID: routeID, Name: name, Protocol: "http", MatchType: "exact", Hostname: nullableString(hostname),
		PathPrefix: sql.NullString{}, Origin: RouteOriginRequest{Scheme: "http", Address: "127.0.0.1:8080", PreserveHost: true},
		Priority: 10, ConnectTimeoutMS: 10000, IdleTimeoutMS: 90000, MaxConcurrentStreams: 128, DesiredState: "active",
		IdempotencyKey: "route:" + routeID, RequestHash: hash, ActorID: accountID, AuditActorID: accountID, ActorType: "user",
		RequestID: "req_" + routeID, CorrelationID: "corr_" + routeID, SourceDeviceID: hostID, Now: now,
	}
}

func TestSQLRepositoryTRK07ConfigChainScopeAndConflictsOnPostgres(t *testing.T) {
	fixture := newTRK07PostgresFixture(t)
	ctx := context.Background()
	accountID := fixture.accounts[0]
	// The primary machine has a deterministic label-derived ID. Resolve it
	// through the fixture suffix to keep this test independent of insertion
	// ordering when a second account is added below.
	hostID := "mch_trk07_primary_" + fixture.suffix
	tunnelID := "tun_trk07_chain_" + fixture.suffix
	fixture.createTunnel(t, accountID, hostID, tunnelID, "chain-"+fixture.suffix)

	name := "chain-renamed"
	patchHash := sha256.Sum256([]byte("patch:" + tunnelID))
	patched, err := fixture.repository.Patch(ctx, PatchRecord{
		OperationID: "op_patch_" + tunnelID, AuditEventID: "aud_patch_" + tunnelID, TunnelID: tunnelID, AccountID: accountID,
		Name: &name, ExpectedGeneration: 1, IdempotencyKey: "patch:" + tunnelID, RequestHash: patchHash,
		ActorID: accountID, AuditActorID: hostID, ActorType: "host", RequestID: "req_patch_" + tunnelID,
		CorrelationID: "corr_patch_" + tunnelID, SourceDeviceID: hostID, Now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if patched.Tunnel.Generation != 2 {
		t.Fatalf("patch generation = %d, want 2", patched.Tunnel.Generation)
	}

	pausedHash := sha256.Sum256([]byte("pause:" + tunnelID))
	paused, err := fixture.repository.Transition(ctx, StateRecord{
		OperationID: "op_pause_" + tunnelID, AuditEventID: "aud_pause_" + tunnelID, TunnelID: tunnelID, AccountID: accountID,
		DesiredState: DesiredPaused, ExpectedGeneration: 2, IdempotencyKey: "pause:" + tunnelID, RequestHash: pausedHash,
		ActorID: accountID, AuditActorID: hostID, ActorType: "host", RequestID: "req_pause_" + tunnelID,
		CorrelationID: "corr_pause_" + tunnelID, SourceDeviceID: hostID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if paused.Tunnel.Generation != 3 || paused.Tunnel.DesiredState != DesiredPaused {
		t.Fatalf("pause result = %#v", paused.Tunnel)
	}

	resumedHash := sha256.Sum256([]byte("resume:" + tunnelID))
	resumed, err := fixture.repository.Transition(ctx, StateRecord{
		OperationID: "op_resume_" + tunnelID, AuditEventID: "aud_resume_" + tunnelID, TunnelID: tunnelID, AccountID: accountID,
		DesiredState: DesiredActive, ExpectedGeneration: 3, IdempotencyKey: "resume:" + tunnelID, RequestHash: resumedHash,
		ActorID: accountID, AuditActorID: hostID, ActorType: "host", RequestID: "req_resume_" + tunnelID,
		CorrelationID: "corr_resume_" + tunnelID, SourceDeviceID: hostID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Tunnel.Generation != 4 || resumed.Tunnel.DesiredState != DesiredActive {
		t.Fatalf("resume result = %#v", resumed.Tunnel)
	}

	routeID := "rte_trk07_chain_" + fixture.suffix
	route := trk07RouteInput(fixture, accountID, hostID, tunnelID, routeID, "api", "api-"+fixture.suffix+".example.test")
	pathPrefix := "/v1"
	serverName, caReference, mtlsReference := "backend.example.test", "ref://ca/"+fixture.suffix, "ref://mtls/"+fixture.suffix
	route.PathPrefix = nullableString(pathPrefix)
	route.Origin = RouteOriginRequest{Scheme: "https", Address: "backend.example.test:443", PreserveHost: false,
		HostOverride: resourceStringPtr("origin.example.test"), TLS: &RouteTLSRequest{Verification: "custom_ca", ServerName: &serverName, CAReference: &caReference, ClientCredentialReference: &mtlsReference}}
	routeResult, err := fixture.repository.CreateResourceRoute(ctx, route)
	if err != nil {
		t.Fatal(err)
	}
	if routeResult.Route.ID != routeID || routeResult.Operation.State != "running" {
		t.Fatalf("route result = %#v", routeResult)
	}

	var rows *sql.Rows
	rows, err = fixture.database.SQL().QueryContext(ctx, `
SELECT generation, previous_generation, content_hash, snapshot, activation_state
FROM paperboat.tunnel_config_generations
WHERE tunnel_id=$1
ORDER BY generation`, tunnelID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type snapshotRoute struct {
		ID                      string  `json:"id"`
		Protocol                string  `json:"protocol"`
		MatchType               string  `json:"match_type"`
		PathPrefix              *string `json:"path_prefix"`
		OriginScheme            string  `json:"origin_scheme"`
		TLSVerification         string  `json:"tls_verification"`
		TLSServerName           *string `json:"tls_server_name"`
		CAReference             *string `json:"ca_reference"`
		MTLSCredentialReference *string `json:"mtls_credential_reference"`
	}
	type snapshot struct {
		Kind       string          `json:"kind"`
		TunnelID   string          `json:"tunnel_id"`
		Generation int64           `json:"generation"`
		Name       string          `json:"name"`
		Routes     []snapshotRoute `json:"routes"`
	}
	count := 0
	var last snapshot
	for rows.Next() {
		var generation int64
		var previous sql.NullInt64
		var contentHash, snapshotJSON []byte
		var activationState string
		if err := rows.Scan(&generation, &previous, &contentHash, &snapshotJSON, &activationState); err != nil {
			t.Fatal(err)
		}
		wantGeneration := int64(count + 1)
		if generation != wantGeneration {
			t.Fatalf("config generations = gap at %d: got %d", wantGeneration, generation)
		}
		if count == 0 {
			if previous.Valid {
				t.Fatalf("generation 1 previous = %#v", previous)
			}
		} else if !previous.Valid || previous.Int64 != generation-1 {
			t.Fatalf("generation %d previous = %#v", generation, previous)
		}
		digest := sha256.Sum256(snapshotJSON)
		if !bytes.Equal(contentHash, digest[:]) {
			t.Fatalf("generation %d content hash does not match snapshot", generation)
		}
		if activationState != "pending" {
			t.Fatalf("generation %d activation state = %q", generation, activationState)
		}
		var decoded snapshot
		if err := json.Unmarshal(snapshotJSON, &decoded); err != nil {
			t.Fatalf("generation %d snapshot JSON: %v", generation, err)
		}
		wantName := "chain-renamed"
		if generation == 1 {
			wantName = "chain-" + fixture.suffix
		}
		if decoded.Kind != "tunnel_config_snapshot" || decoded.TunnelID != tunnelID || decoded.Generation != generation || decoded.Name != wantName {
			t.Fatalf("generation %d snapshot identity = %#v", generation, decoded)
		}
		last = decoded
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("config generation count = %d, want create+patch+pause+resume+route = 5", count)
	}
	var found bool
	for _, item := range last.Routes {
		if item.ID != routeID {
			continue
		}
		found = true
		if item.Protocol != "http" || item.MatchType != "exact" || item.PathPrefix == nil || *item.PathPrefix != pathPrefix || item.OriginScheme != "https" || item.TLSVerification != "custom_ca" || item.TLSServerName == nil || *item.TLSServerName != serverName || item.CAReference == nil || *item.CAReference != caReference || item.MTLSCredentialReference == nil || *item.MTLSCredentialReference != mtlsReference {
			t.Fatalf("full route snapshot = %#v", item)
		}
	}
	if !found {
		t.Fatalf("route %s missing from final config snapshot: %#v", routeID, last.Routes)
	}

	// Domain persistence is independently scoped from route persistence. The
	// create path must keep the state pending until external DNS proof exists;
	// verify only advances the state machine to another waiting generation.
	domainHost := "domain-" + fixture.suffix + ".example.test"
	domainInput := DomainRecord{OperationID: "op_trk07_domain_" + fixture.suffix, AuditEventID: "aud_trk07_domain_" + fixture.suffix,
		AccountID: accountID, TunnelID: tunnelID, DomainID: "dom_trk07_" + fixture.suffix, RouteID: routeID,
		Hostname: domainHost, MatchType: "exact", ChallengeReference: "dns-challenge://" + fixture.suffix, DNSTarget: "target.example.test",
		IdempotencyKey: "domain:" + fixture.suffix, RequestHash: sha256.Sum256([]byte("domain:" + fixture.suffix)), ActorID: accountID,
		AuditActorID: hostID, ActorType: "host", RequestID: "req_domain_" + fixture.suffix, CorrelationID: "corr_domain_" + fixture.suffix,
		SourceDeviceID: hostID, Now: fixture.now}
	domainResult, err := fixture.repository.CreateResourceDomain(ctx, domainInput)
	if err != nil {
		t.Fatal(err)
	}
	if domainResult.Domain.OwnershipState != "pending" || domainResult.Operation.Phase != "waiting_for_dns" || domainResult.Operation.State != "running" {
		t.Fatalf("domain create readiness = %#v", domainResult)
	}
	verifyInput := domainInput
	verifyInput.OperationID = "op_trk07_domain_verify_" + fixture.suffix
	verifyInput.AuditEventID = "aud_trk07_domain_verify_" + fixture.suffix
	verifyInput.IdempotencyKey = "domain:verify:" + fixture.suffix
	verifyInput.RequestHash = sha256.Sum256([]byte(verifyInput.IdempotencyKey))
	verifyInput.RequestID = "req_domain_verify_" + fixture.suffix
	verifyInput.CorrelationID = "corr_domain_verify_" + fixture.suffix
	verifyInput.ExpectedGeneration = domainResult.Domain.Generation
	verifiedRequest, err := fixture.repository.BeginResourceDomainVerification(ctx, verifyInput)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedRequest.Domain.OwnershipState != "pending" || verifiedRequest.Domain.Generation != 2 || verifiedRequest.Operation.Phase != "waiting_for_dns" || verifiedRequest.Operation.State != "running" {
		t.Fatalf("domain verify readiness = %#v", verifiedRequest)
	}

	// The targeted conflict query is serialized by the tunnel lock and treats
	// managed/exact as one hostname class. Exactly one of these concurrent
	// creates may commit; the loser must receive the typed conflict error.
	raceHostname := "race-" + fixture.suffix + ".example.test"
	inputs := []RouteRecord{
		trk07RouteInput(fixture, accountID, hostID, tunnelID, "rte_trk07_race_a_"+fixture.suffix, "race-a", raceHostname),
		trk07RouteInput(fixture, accountID, hostID, tunnelID, "rte_trk07_race_b_"+fixture.suffix, "race-b", raceHostname),
	}
	start := make(chan struct{})
	results := make(chan error, len(inputs))
	var waitGroup sync.WaitGroup
	for index := range inputs {
		waitGroup.Add(1)
		go func(input RouteRecord) {
			defer waitGroup.Done()
			<-start
			_, createErr := fixture.repository.CreateResourceRoute(ctx, input)
			results <- createErr
		}(inputs[index])
	}
	close(start)
	waitGroup.Wait()
	close(results)
	successes, conflicts := 0, 0
	for createErr := range results {
		switch {
		case createErr == nil:
			successes++
		case errors.Is(createErr, ErrRouteConflict):
			conflicts++
		default:
			t.Fatalf("concurrent route create error = %v", createErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent route outcome = successes=%d conflicts=%d", successes, conflicts)
	}

	otherAccount, otherHost := fixture.addAccount(t, "other")
	otherTunnelID := "tun_trk07_other_" + fixture.suffix
	other := fixture.createTunnel(t, otherAccount, otherHost, otherTunnelID, "other-"+fixture.suffix)
	otherRouteID := newRouteID(otherTunnelID)
	if rows, err := fixture.repository.ListResourceRoutes(ctx, accountID, otherTunnelID, nil, 10); err != nil || len(rows) != 0 {
		t.Fatalf("cross-account route list = rows=%d err=%v", len(rows), err)
	}
	if _, err := fixture.repository.GetResourceRoute(ctx, accountID, otherTunnelID, otherRouteID); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("cross-account route get = %v", err)
	}
	if _, err := fixture.repository.GetResourceRoute(ctx, otherAccount, otherTunnelID, otherRouteID); err != nil {
		t.Fatalf("same-account route get = %v", err)
	}
	otherDomain := domainInput
	otherDomain.OperationID = "op_trk07_domain_conflict_" + fixture.suffix
	otherDomain.AuditEventID = "aud_trk07_domain_conflict_" + fixture.suffix
	otherDomain.AccountID = otherAccount
	otherDomain.TunnelID = otherTunnelID
	otherDomain.DomainID = "dom_trk07_conflict_" + fixture.suffix
	otherDomain.RouteID = otherRouteID
	otherDomain.IdempotencyKey = "domain:conflict:" + fixture.suffix
	otherDomain.RequestHash = sha256.Sum256([]byte(otherDomain.IdempotencyKey))
	otherDomain.ActorID = otherAccount
	otherDomain.AuditActorID = otherAccount
	otherDomain.ActorType = "user"
	otherDomain.RequestID = "req_domain_conflict_" + fixture.suffix
	otherDomain.CorrelationID = "corr_domain_conflict_" + fixture.suffix
	otherDomain.SourceDeviceID = otherHost
	if _, err := fixture.repository.CreateResourceDomain(ctx, otherDomain); !errors.Is(err, ErrDomainConflict) {
		t.Fatalf("cross-account hostname conflict = %v", err)
	}

	// A child route reference is scoped in the same transaction. Supplying a
	// route owned by the first tunnel while creating a domain under the second
	// tunnel must not disclose or accept the cross-account child.
	crossDomain := DomainRecord{OperationID: "op_trk07_cross_domain_" + fixture.suffix, AuditEventID: "aud_trk07_cross_domain_" + fixture.suffix,
		AccountID: otherAccount, TunnelID: otherTunnelID, DomainID: "dom_trk07_cross_" + fixture.suffix, RouteID: routeID,
		Hostname: "cross-" + fixture.suffix + ".example.test", MatchType: "exact", ChallengeReference: "dns://cross/" + fixture.suffix,
		DNSTarget: "target.example.test", IdempotencyKey: "domain:cross:" + fixture.suffix, RequestHash: sha256.Sum256([]byte("domain:cross:" + fixture.suffix)),
		ActorID: otherAccount, AuditActorID: otherAccount, ActorType: "user", RequestID: "req_domain_cross_" + fixture.suffix,
		CorrelationID: "corr_domain_cross_" + fixture.suffix, SourceDeviceID: otherHost, Now: fixture.now}
	if _, err := fixture.repository.CreateResourceDomain(ctx, crossDomain); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("cross-account domain route binding = %v", err)
	}
	deleteDomain := verifyInput
	deleteDomain.OperationID = "op_trk07_domain_delete_" + fixture.suffix
	deleteDomain.AuditEventID = "aud_trk07_domain_delete_" + fixture.suffix
	deleteDomain.IdempotencyKey = "domain:delete:" + fixture.suffix
	deleteDomain.RequestHash = sha256.Sum256([]byte(deleteDomain.IdempotencyKey))
	deleteDomain.RequestID = "req_domain_delete_" + fixture.suffix
	deleteDomain.CorrelationID = "corr_domain_delete_" + fixture.suffix
	deleteDomain.ExpectedGeneration = verifiedRequest.Domain.Generation
	deletedDomain, err := fixture.repository.DeleteResourceDomain(ctx, deleteDomain)
	if err != nil {
		t.Fatal(err)
	}
	if deletedDomain.Domain.OwnershipState != "revoked" || deletedDomain.Domain.ConflictState != "quarantined" || !deletedDomain.Domain.DeletedAt.Valid || !deletedDomain.Changed {
		t.Fatalf("domain delete = %#v", deletedDomain)
	}
	deleteReplay := deleteDomain
	deleteReplay.OperationID = "op_trk07_domain_delete_replay_" + fixture.suffix
	deleteReplay.AuditEventID = "aud_trk07_domain_delete_replay_" + fixture.suffix
	deleteReplay.IdempotencyKey = "domain:delete:replay:" + fixture.suffix
	deleteReplay.RequestHash = sha256.Sum256([]byte(deleteReplay.IdempotencyKey))
	deleteReplay.RequestID = "req_domain_delete_replay_" + fixture.suffix
	deleteReplay.CorrelationID = "corr_domain_delete_replay_" + fixture.suffix
	deleteReplay.ExpectedGeneration = 1
	deletedReplay, err := fixture.repository.DeleteResourceDomain(ctx, deleteReplay)
	if err != nil {
		t.Fatal(err)
	}
	if deletedReplay.Changed || deletedReplay.Operation.State != "succeeded" || deletedReplay.Domain.ID != deletedDomain.Domain.ID {
		t.Fatalf("idempotent domain delete = %#v", deletedReplay)
	}
	_ = other
}

func TestSQLRepositoryTRK07EnrollmentReplayCredentialOverlapAndRotationOnPostgres(t *testing.T) {
	fixture := newTRK07PostgresFixture(t)
	ctx := context.Background()
	accountID := fixture.accounts[0]
	hostID := "mch_trk07_primary_" + fixture.suffix
	tunnelID := "tun_trk07_credentials_" + fixture.suffix
	createdTunnel := fixture.createTunnel(t, accountID, hostID, tunnelID, "credentials-"+fixture.suffix)
	now := fixture.now

	token1 := "pbce_" + fixture.suffix + "_one"
	tokenHash1 := sha256.Sum256([]byte(token1))
	issueInput := EnrollmentRecordInput{OperationID: "op_trk07_issue_" + fixture.suffix, EnrollmentID: "enr_trk07_1_" + fixture.suffix,
		AuditEventID: "aud_trk07_issue_" + fixture.suffix, AccountID: accountID, TunnelID: tunnelID, HostID: hostID,
		TokenHash: tokenHash1[:], Token: token1, Capabilities: []string{"http", "https"}, ExpiresAt: now.Add(5 * time.Minute),
		IdempotencyKey: "enrollment:issue:" + fixture.suffix, RequestHash: sha256.Sum256([]byte("enrollment:issue:" + fixture.suffix)),
		ActorID: accountID, AuditActorID: accountID, ActorType: "user", RequestID: "req_issue_" + fixture.suffix,
		CorrelationID: "corr_issue_" + fixture.suffix, SourceDeviceID: hostID, Now: now, CredentialLifetime: 24 * time.Hour}
	issued, err := fixture.repository.IssueConnectorEnrollment(ctx, issueInput)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Token != token1 || !issued.Operation.CompletedAt.Valid || issued.Operation.State != "succeeded" {
		t.Fatalf("issued enrollment = %#v", issued)
	}
	var storedTokenHash []byte
	if err := fixture.database.SQL().QueryRowContext(ctx, `SELECT token_hash FROM paperboat.tunnel_connector_enrollments WHERE id=$1`, issued.Enrollment.ID).Scan(&storedTokenHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedTokenHash, tokenHash1[:]) || bytes.Contains(storedTokenHash, []byte(token1)) {
		t.Fatalf("stored enrollment token hash = %x", storedTokenHash)
	}
	replayIssue := issueInput
	replayIssue.OperationID = "op_trk07_issue_replay_" + fixture.suffix
	replayIssue.AuditEventID = "aud_trk07_issue_replay_" + fixture.suffix
	if _, err := fixture.repository.IssueConnectorEnrollment(ctx, replayIssue); !errors.Is(err, ErrEnrollmentAlreadyIssued) {
		t.Fatalf("same-key enrollment replay = %v", err)
	}

	private1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))
	public1 := private1.Public().(ed25519.PublicKey)
	thumbprint1 := ConnectorCredentialThumbprint(public1)
	reference1 := "keychain://paperboat/" + fixture.suffix + "/one"
	exchangeKey1 := "enrollment:exchange:" + fixture.suffix + ":one"
	proof1 := ed25519.Sign(private1, ConnectorCredentialProofPayload(tunnelID, hostID, token1, reference1, thumbprint1, exchangeKey1))
	exchangeInput := EnrollmentExchangeRecord{OperationID: "op_trk07_exchange_1_" + fixture.suffix, AuditEventID: "aud_trk07_exchange_1_" + fixture.suffix,
		AccountID: accountID, TunnelID: tunnelID, HostID: hostID, TokenHash: tokenHash1[:], ProtocolVersion: "1.0",
		ConnectorID: "con_trk07_" + fixture.suffix, CredentialReference: reference1, CredentialThumbprint: thumbprint1,
		CredentialVerifierAlgorithm: "ed25519", CredentialVerifierPublicKey: public1, CredentialGenerationID: "crg_trk07_1_" + fixture.suffix,
		CredentialProof: proof1, IdempotencyKey: exchangeKey1, RequestHash: sha256.Sum256([]byte(exchangeKey1)), ActorID: hostID,
		AuditActorID: hostID, ActorType: "host", RequestID: "req_exchange_1_" + fixture.suffix, CorrelationID: "corr_exchange_1_" + fixture.suffix,
		SourceDeviceID: hostID, Now: now, CredentialLifetime: 24 * time.Hour, CredentialOverlap: 3 * time.Minute}
	enrolled, err := fixture.repository.ExchangeConnectorEnrollment(ctx, exchangeInput)
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.Connector.ID == "" || enrolled.StableEndpointID != createdTunnel.Tunnel.StableEndpointID || enrolled.Connector.RotationGeneration != 1 || enrolled.ProcessGeneration != 1 || enrolled.Operation.State != "running" || enrolled.Operation.CompletedAt.Valid {
		t.Fatalf("first enrollment exchange = %#v", enrolled)
	}
	var credentialCount int
	if err := fixture.database.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.tunnel_connector_credential_generations WHERE connector_id=$1`, enrolled.Connector.ID).Scan(&credentialCount); err != nil {
		t.Fatal(err)
	}
	if credentialCount != 1 {
		t.Fatalf("first credential generation count = %d", credentialCount)
	}

	replayExchange := exchangeInput
	replayExchange.OperationID = "op_trk07_exchange_replay_" + fixture.suffix
	replayed, err := fixture.repository.ExchangeConnectorEnrollment(ctx, replayExchange)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.StableEndpointID != enrolled.StableEndpointID || replayed.Connector.ID != enrolled.Connector.ID || replayed.Operation.ID != enrolled.Operation.ID || replayed.ProcessGeneration != enrolled.ProcessGeneration {
		t.Fatalf("same-key exchange replay = %#v", replayed)
	}
	differentKey := exchangeInput
	differentKey.OperationID = "op_trk07_exchange_other_" + fixture.suffix
	differentKey.AuditEventID = "aud_trk07_exchange_other_" + fixture.suffix
	differentKey.IdempotencyKey = "enrollment:exchange:" + fixture.suffix + ":other"
	differentKey.RequestHash = sha256.Sum256([]byte(differentKey.IdempotencyKey))
	differentKey.ConnectorID = "con_trk07_other_" + fixture.suffix
	if _, err := fixture.repository.ExchangeConnectorEnrollment(ctx, differentKey); !errors.Is(err, ErrEnrollmentReplay) {
		t.Fatalf("different-key consumed enrollment = %v", err)
	}

	rotationHash := sha256.Sum256([]byte("rotation:" + fixture.suffix))
	rotation, err := fixture.repository.RotateResourceCredentials(ctx, RotationRecord{OperationID: "op_trk07_rotate_" + fixture.suffix,
		AuditEventID: "aud_trk07_rotate_" + fixture.suffix, AccountID: accountID, TunnelID: tunnelID, ExpectedGeneration: 1,
		IdempotencyKey: "rotation:" + fixture.suffix, RequestHash: rotationHash, ActorID: accountID, AuditActorID: accountID,
		ActorType: "user", RequestID: "req_rotate_" + fixture.suffix, CorrelationID: "corr_rotate_" + fixture.suffix,
		SourceDeviceID: hostID, Now: now, OverlapUntil: now.Add(3 * time.Minute), CredentialLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if rotation.ResourceKind != "tunnel" || !rotation.ResourceID.Valid || rotation.ResourceID.String != tunnelID || rotation.State != "running" || rotation.CompletedAt.Valid {
		t.Fatalf("aggregate rotation operation = %#v", rotation)
	}
	var auditResourceType, auditResourceID string
	if err := fixture.database.SQL().QueryRowContext(ctx, `SELECT resource_type, resource_id FROM paperboat.audit_events WHERE id=$1`, "aud_trk07_rotate_"+fixture.suffix).Scan(&auditResourceType, &auditResourceID); err != nil {
		t.Fatal(err)
	}
	if auditResourceType != "tunnel" || auditResourceID != tunnelID {
		t.Fatalf("aggregate rotation audit = %s/%s", auditResourceType, auditResourceID)
	}

	revoked, err := fixture.repository.RevokeResourceConnector(ctx, ConnectorRecord{OperationID: "op_trk07_revoke_" + fixture.suffix, AuditEventID: "aud_trk07_revoke_" + fixture.suffix,
		AccountID: accountID, TunnelID: tunnelID, ConnectorID: enrolled.Connector.ID, ExpectedGeneration: enrolled.Connector.Generation,
		IdempotencyKey: "revoke:" + fixture.suffix, RequestHash: sha256.Sum256([]byte("revoke:" + fixture.suffix)), ActorID: accountID, AuditActorID: accountID,
		ActorType: "user", RequestID: "req_revoke_" + fixture.suffix, CorrelationID: "corr_revoke_" + fixture.suffix, SourceDeviceID: hostID, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Connector.DesiredState != "revoked" || revoked.Connector.DrainState != "forced_closed" {
		t.Fatalf("revoked connector = %#v", revoked.Connector)
	}

	token2 := "pbce_" + fixture.suffix + "_two"
	tokenHash2 := sha256.Sum256([]byte(token2))
	issue2 := issueInput
	issue2.OperationID = "op_trk07_issue_2_" + fixture.suffix
	issue2.EnrollmentID = "enr_trk07_2_" + fixture.suffix
	issue2.AuditEventID = "aud_trk07_issue_2_" + fixture.suffix
	issue2.TokenHash = tokenHash2[:]
	issue2.Token = token2
	issue2.IdempotencyKey = "enrollment:issue:" + fixture.suffix + ":two"
	issue2.RequestHash = sha256.Sum256([]byte(issue2.IdempotencyKey))
	issue2.RequestID = "req_issue_2_" + fixture.suffix
	issue2.CorrelationID = "corr_issue_2_" + fixture.suffix
	if _, err := fixture.repository.IssueConnectorEnrollment(ctx, issue2); err != nil {
		t.Fatal(err)
	}
	private2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, ed25519.SeedSize))
	public2 := private2.Public().(ed25519.PublicKey)
	thumbprint2 := ConnectorCredentialThumbprint(public2)
	reference2 := "keychain://paperboat/" + fixture.suffix + "/two"
	exchangeKey2 := "enrollment:exchange:" + fixture.suffix + ":two"
	proof2 := ed25519.Sign(private2, ConnectorCredentialProofPayload(tunnelID, hostID, token2, reference2, thumbprint2, exchangeKey2))
	exchange2 := exchangeInput
	exchange2.OperationID = "op_trk07_exchange_2_" + fixture.suffix
	exchange2.AuditEventID = "aud_trk07_exchange_2_" + fixture.suffix
	exchange2.TokenHash = tokenHash2[:]
	exchange2.CredentialReference = reference2
	exchange2.CredentialThumbprint = thumbprint2
	exchange2.CredentialVerifierPublicKey = public2
	exchange2.CredentialGenerationID = "crg_trk07_2_" + fixture.suffix
	exchange2.CredentialProof = proof2
	exchange2.IdempotencyKey = exchangeKey2
	exchange2.RequestHash = sha256.Sum256([]byte(exchangeKey2))
	exchange2.ConnectorID = "con_trk07_replacement_" + fixture.suffix
	exchange2.RequestID = "req_exchange_2_" + fixture.suffix
	exchange2.CorrelationID = "corr_exchange_2_" + fixture.suffix
	second, err := fixture.repository.ExchangeConnectorEnrollment(ctx, exchange2)
	if err != nil {
		t.Fatal(err)
	}
	if second.StableEndpointID != enrolled.StableEndpointID || second.Connector.ID != enrolled.Connector.ID || second.Connector.RotationGeneration != 2 || second.ProcessGeneration <= enrolled.ProcessGeneration {
		t.Fatalf("reactivated connector = %#v", second.Connector)
	}
	var activationCount int
	if err := fixture.database.SQL().QueryRowContext(ctx, `
SELECT count(*)
FROM paperboat.tunnel_connector_activations
WHERE connector_id=$1
  AND ((operation_id=$2 AND credential_generation=1 AND process_generation=$3)
    OR (operation_id=$4 AND credential_generation=2 AND process_generation=$5))`, enrolled.Connector.ID, enrolled.Operation.ID, enrolled.ProcessGeneration, second.Operation.ID, second.ProcessGeneration).Scan(&activationCount); err != nil {
		t.Fatal(err)
	}
	if activationCount != 2 {
		t.Fatalf("durable connector activation count = %d", activationCount)
	}
	var generations []struct {
		Generation int64
		State      string
		ValidUntil time.Time
		Algorithm  string
		PublicKey  []byte
	}
	credentialRows, err := fixture.database.SQL().QueryContext(ctx, `
SELECT generation, state, valid_until, verifier_algorithm, verifier_public_key
FROM paperboat.tunnel_connector_credential_generations
WHERE connector_id=$1
ORDER BY generation`, enrolled.Connector.ID)
	if err != nil {
		t.Fatal(err)
	}
	for credentialRows.Next() {
		var row struct {
			Generation int64
			State      string
			ValidUntil time.Time
			Algorithm  string
			PublicKey  []byte
		}
		if err := credentialRows.Scan(&row.Generation, &row.State, &row.ValidUntil, &row.Algorithm, &row.PublicKey); err != nil {
			_ = credentialRows.Close()
			t.Fatal(err)
		}
		generations = append(generations, row)
	}
	if err := credentialRows.Err(); err != nil {
		_ = credentialRows.Close()
		t.Fatal(err)
	}
	_ = credentialRows.Close()
	if len(generations) != 2 || generations[0].Generation != 1 || generations[0].State != "overlap" || generations[1].Generation != 2 || generations[1].State != "active" || !generations[0].ValidUntil.Equal(now.Add(3*time.Minute)) || generations[0].Algorithm != "ed25519" || !bytes.Equal(generations[1].PublicKey, public2) {
		t.Fatalf("credential overlap generations = %#v", generations)
	}
	if rows, err := fixture.repository.ListResourceConnectors(ctx, "account-not-owner", tunnelID, nil, 10); err != nil || len(rows) != 0 {
		t.Fatalf("cross-account connector list = rows=%d err=%v", len(rows), err)
	}
	if _, err := fixture.repository.GetResourceConnector(ctx, "account-not-owner", tunnelID, enrolled.Connector.ID); !errors.Is(err, ErrConnectorNotFound) {
		t.Fatalf("cross-account connector get = %v", err)
	}
}
