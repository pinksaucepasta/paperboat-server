package peersessions

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

func TestSQLRepositoryIssuesReplaysConflictsAndRevokesAtomicPair(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run peer-session repository integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	suffix := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_")) + strings.ReplaceAll(now.Format("150405.000000000"), ".", "")
	userID, clientID, environmentID, nodeID := "peer_user_"+suffix, "peer_cli_"+suffix, "peer_env_"+suffix, "peer_edge_"+suffix
	fastNodeID := "peer_edge_fast_" + suffix
	saturatedNodeID := "peer_edge_saturated_" + suffix
	controllingFingerprint, controlledFingerprint := sha256.Sum256([]byte("controlling:"+suffix)), sha256.Sum256([]byte("controlled:"+suffix))
	rootKey, rootFingerprint := sha256.Sum256([]byte("root-key:"+suffix)), sha256.Sum256([]byte("root-fingerprint:"+suffix))
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'peer test','desktop','test',ARRAY['account:read'],'active',$4,$4)`, clientID, userID, "client_"+suffix, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3)`, environmentID, "workspace_"+suffix, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,relay_region,protocol_version,process_epoch,state,ready,last_heartbeat_at,signaling_host,stun_host,stun_port,capacity,observation) VALUES ($1,'default','test','v1',$2,'ready',true,$3,'signal.example.test','stun.example.test',3478,'{"connectors":10}','{"active_streams":0}')`, nodeID, "epoch_"+suffix, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,relay_region,protocol_version,process_epoch,state,ready,last_heartbeat_at,signaling_host,stun_host,stun_port,capacity,observation) VALUES ($1,'default','fast','v1',$2,'ready',true,$3,'fast-signal.example.test','fast-stun.example.test',3478,'{"connectors":10}','{"active_streams":0}')`, fastNodeID, "fast_epoch_"+suffix, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,relay_region,protocol_version,process_epoch,state,ready,last_heartbeat_at,signaling_host,stun_host,stun_port,capacity,observation) VALUES ($1,'default','saturated','v1',$2,'ready',true,$3,'saturated-signal.example.test','saturated-stun.example.test',3478,'{"connectors":1}','{"active_streams":1}')`, saturatedNodeID, "saturated_epoch_"+suffix, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.account_e2ee_roots (user_id,public_key,fingerprint) VALUES ($1,$2,$3)`, userID, rootKey[:], rootFingerprint[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.account_e2ee_keys (key_id,user_id,public_key,fingerprint,generation) VALUES ($1,$2,$3,$4,1)`, "aek_"+fmt.Sprintf("%x", rootFingerprint[:]), userID, rootKey[:], rootFingerprint[:]); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []struct {
		fingerprint [32]byte
		id          string
		role        string
		seed        byte
	}{{controllingFingerprint, clientID, "cli", 3}, {controlledFingerprint, "endpoint_machine_" + suffix, "machine", 4}} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.peer_endpoint_certificates (fingerprint,user_id,key_id,endpoint_id,role,generation,serial,certificate,noise_public_key,quic_public_key,issued_at,expires_at) VALUES ($1,$2,$3,$4,$5,1,1,$6,$7,$8,$9,$10)`, endpoint.fingerprint[:], userID, "aek_"+fmt.Sprintf("%x", rootFingerprint[:]), endpoint.id, endpoint.role, []byte(strings.Repeat(string(endpoint.seed), 172)), []byte(strings.Repeat(string(endpoint.seed+10), 32)), []byte(strings.Repeat(string(endpoint.seed+20), 32)), now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	machineID := "endpoint_machine_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,installation_generation) VALUES ($1,$2,$3,'Peer machine','linux','amd64','/workspace','online','occupied',1)`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET relay_latency_worker_generation=1,relay_latency_generation=1,relay_latency_observed_at=$2,relay_latency_vector='[{"region":"fast","rtt_ms":10},{"region":"saturated","rtt_ms":1},{"region":"test","rtt_ms":100}]'::jsonb WHERE id=$1`, machineID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,generation,edge_pool,edge_node_id,state) VALUES ($1,$2,1,'test',$3,'admitted')`, environmentID, machineID, nodeID); err != nil {
		t.Fatal(err)
	}
	repository, err := NewSQLRepository(store, audit.NewWriter(store), 2*time.Minute, "peer-session-integration-encryption-key")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := mint.New([]mint.Key{{ID: "peer-integration", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("i", ed25519.SeedSize)))}}, "peer-integration", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, _ := New(repository, provider, "https://api.example.test")
	service.now = func() time.Time { return now }
	request := Request{OperationKey: "peer-operation-" + suffix, UserID: userID, CLIClientSessionID: clientID, EnvironmentID: environmentID, Purpose: "interactive", Consumer: "terminal", ControllingCertificateFingerprint: controllingFingerprint[:], ControlledCertificateFingerprint: controlledFingerprint[:], AttemptGeneration: 2, NetworkGeneration: 4, RelayLatency: &RelayLatencyVector{Generation: 1, ObservedAt: now, Samples: []RelayLatencySample{{Region: "fast", RTTMS: 10}, {Region: "saturated", RTTMS: 1}, {Region: "test", RTTMS: 100}}}}
	first, err := service.Issue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.EdgeNodeID != fastNodeID || first.EdgePool != "fast" {
		t.Fatalf("selected node=%s region=%s", first.EdgeNodeID, first.EdgePool)
	}
	controlled, err := service.NextControlled(ctx, userID, machineID, 1)
	if err != nil || controlled.IntentID != first.IntentID || controlled.EdgeNodeID != fastNodeID {
		t.Fatalf("controlled delivery=%+v err=%v", controlled, err)
	}
	if duplicate, err := service.NextControlled(ctx, userID, machineID, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("duplicate controlled delivery=%+v err=%v", duplicate, err)
	}
	replay, err := service.Issue(ctx, request)
	if err != nil || replay.IntentID != first.IntentID || replay.Controlling.Token != first.Controlling.Token || replay.Controlled.Token != first.Controlled.Token || replay.Relay.RouteAllocation != first.Relay.RouteAllocation || replay.Relay.Token != first.Relay.Token {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	var hysteresis []Pair
	for index, offset := range []time.Duration{time.Second, 4 * time.Second, 11 * time.Second} {
		at := now.Add(offset)
		if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET relay_latency_generation=$2,relay_latency_observed_at=$3,relay_latency_vector='[{"region":"fast","rtt_ms":100},{"region":"test","rtt_ms":10}]'::jsonb WHERE id=$1`, machineID, index+2, at); err != nil {
			t.Fatal(err)
		}
		restarted, err := NewSQLRepository(store, audit.NewWriter(store), 2*time.Minute, "peer-session-integration-encryption-key")
		if err != nil {
			t.Fatal(err)
		}
		restartedService, _ := New(restarted, provider, "https://api.example.test")
		restartedService.now = func() time.Time { return at }
		next := request
		next.OperationKey = request.OperationKey + "-hysteresis-" + string(rune('1'+index))
		next.AttemptGeneration = int64(3 + index)
		next.RelayLatency = &RelayLatencyVector{Generation: uint64(index + 2), ObservedAt: at, Samples: []RelayLatencySample{{Region: "fast", RTTMS: 100}, {Region: "test", RTTMS: 10}}}
		issued, issueErr := restartedService.Issue(ctx, next)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		hysteresis = append(hysteresis, issued)
		want := "fast"
		if index == 2 {
			want = "test"
		}
		if issued.EdgePool != want {
			t.Fatalf("hysteresis sample %d selected %s, want %s", index+1, issued.EdgePool, want)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_connector_generations SET edge_node_id=$2 WHERE environment_id=$1`, environmentID, fastNodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET state='offline',ready=false WHERE id=$1`, nodeID); err != nil {
		t.Fatal(err)
	}
	failoverAt := now.Add(12 * time.Second)
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET relay_latency_generation=5,relay_latency_observed_at=$2,relay_latency_vector='[{"region":"fast","rtt_ms":100},{"region":"saturated","rtt_ms":1},{"region":"test","rtt_ms":10}]'::jsonb WHERE id=$1`, machineID, failoverAt); err != nil {
		t.Fatal(err)
	}
	failoverRequest := request
	failoverRequest.OperationKey += "-failover"
	failoverRequest.AttemptGeneration = 6
	failoverRequest.RelayLatency = &RelayLatencyVector{Generation: 5, ObservedAt: failoverAt, Samples: []RelayLatencySample{{Region: "fast", RTTMS: 100}, {Region: "saturated", RTTMS: 1}, {Region: "test", RTTMS: 10}}}
	service.now = func() time.Time { return failoverAt }
	failover, err := service.Issue(ctx, failoverRequest)
	if err != nil || failover.EdgePool != "fast" {
		t.Fatalf("unhealthy-current failover=%+v err=%v", failover, err)
	}
	hysteresis = append(hysteresis, failover)
	service.now = func() time.Time { return now }
	conflict := request
	conflict.AttemptGeneration++
	if _, err := service.Issue(ctx, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	var intents, grants, relays int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_session_intents WHERE operation_key=$1`, request.OperationKey).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_signaling_grants WHERE intent_id=$1`, first.IntentID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_relay_allocations WHERE intent_id=$1`, first.IntentID).Scan(&relays); err != nil {
		t.Fatal(err)
	}
	if intents != 1 || grants != 2 || relays != 1 {
		t.Fatalf("original operation persisted intents=%d grants=%d relays=%d", intents, grants, relays)
	}
	revokeOperation := "peer-revoke-operation-" + suffix
	if err := repository.Revoke(ctx, userID, revokeOperation, first.IntentID, first.AttemptGeneration, "superseded", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for index, issued := range hysteresis {
		if err := repository.Revoke(ctx, userID, "peer-revoke-hysteresis-"+suffix+string(rune('1'+index)), issued.IntentID, issued.AttemptGeneration, "superseded", now.Add(12*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := repository.Revoke(ctx, userID, revokeOperation, first.IntentID, first.AttemptGeneration, "superseded", now.Add(2*time.Second)); err != nil {
		t.Fatalf("exact revocation replay = %v", err)
	}
	if err := repository.Revoke(ctx, userID, revokeOperation, first.IntentID, first.AttemptGeneration, "node_reassigned", now.Add(2*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("revocation conflict = %v", err)
	}
	revocations, err := controlplane.NewEdgeService(store, "test-edge-credential").Revocations(ctx)
	if err != nil || !contains(revocations.JTIs, credentialJTI(t, provider, first.Controlling.Token, "peer_signaling", now)) || !contains(revocations.JTIs, credentialJTI(t, provider, first.Controlled.Token, "peer_signaling", now)) || !contains(revocations.JTIs, credentialJTI(t, provider, first.Relay.Token, "peer_relay", now)) {
		t.Fatalf("peer signaling revocations = %+v, %v", revocations, err)
	}
	active, err := store.Queries().ListActivePeerSignalingJTIs(ctx, dbsqlc.ListActivePeerSignalingJTIsParams{EdgeNodeID: fastNodeID, Now: now.Add(2 * time.Second)})
	if err != nil || len(active) != 0 {
		t.Fatalf("active JTIs after revocation = %v, %v", active, err)
	}
	if _, err := service.Issue(ctx, request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revoked replay error = %v", err)
	}
}

func credentialJTI(t *testing.T, provider *mint.Provider, token, class string, now time.Time) string {
	t.Helper()
	claims, err := provider.VerifyCredential(token, "https://api.example.test", class, now)
	if err != nil {
		t.Fatal(err)
	}
	return claims.JTI
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
