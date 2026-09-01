package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

const controlStormCredential = "paperboat-control-storm-credential-0123456789"

type stormCarrierIdentity struct {
	Pin   string
	Chain string
}

var controlStormCarrierIdentity = mustControlStormCarrierIdentity()

func mustControlStormCarrierIdentity() stormCarrierIdentity {
	seed := sha256.Sum256([]byte("paperboat-control-storm-carrier-seed"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "paperboat-control-storm"},
		DNSNames:     []string{"edge.example.test"},
		NotBefore:    time.Unix(0, 0).UTC(),
		NotAfter:     time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		panic(fmt.Sprintf("create control-storm carrier certificate: %v", err))
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		panic(fmt.Sprintf("parse control-storm carrier certificate: %v", err))
	}
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return stormCarrierIdentity{
		Pin:   "sha256:" + hex.EncodeToString(digest[:]),
		Chain: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

type stormPhaseReport struct {
	Name          string        `json:"name"`
	Operations    int           `json:"operations"`
	P50           time.Duration `json:"p50"`
	P95           time.Duration `json:"p95"`
	Maximum       time.Duration `json:"maximum"`
	Elapsed       time.Duration `json:"elapsed"`
	RequestBytes  int64         `json:"request_bytes"`
	ResponseBytes int64         `json:"response_bytes"`
}

type controlStormReport struct {
	Machines         int                    `json:"machines"`
	Phases           []stormPhaseReport     `json:"phases"`
	HeapGrowthBytes  int64                  `json:"heap_growth_bytes"`
	GoroutineGrowth  int                    `json:"goroutine_growth"`
	CPUSeconds       float64                `json:"cpu_seconds"`
	DBMaxConnections int32                  `json:"db_max_connections"`
	DBEmptyAcquires  int64                  `json:"db_empty_acquires"`
	Transactions     db.TransactionSnapshot `json:"transactions"`
	Database         stormDatabaseProfile   `json:"database"`
}

type stormDatabaseProfile struct {
	Samples            int64 `json:"samples"`
	SampleFailures     int64 `json:"sample_failures"`
	MaxActiveSessions  int64 `json:"max_active_sessions"`
	MaxWaitingSessions int64 `json:"max_waiting_sessions"`
	MaxLocks           int64 `json:"max_locks"`
	MaxOperationDepth  int64 `json:"max_operation_depth"`
	MaxStaleNodeDepth  int64 `json:"max_stale_node_depth"`
	XactCommits        int64 `json:"xact_commits"`
	XactRollbacks      int64 `json:"xact_rollbacks"`
	Deadlocks          int64 `json:"deadlocks"`
	BlocksRead         int64 `json:"blocks_read"`
	BlocksHit          int64 `json:"blocks_hit"`
}

type stormHelperIdentity struct {
	Credential string
	PrivateKey ed25519.PrivateKey
	HelperID   string
	MachineID  string
}

func TestControlPlaneStorm(t *testing.T) {
	if os.Getenv("PAPERBOAT_CONTROL_STORM") != "1" {
		t.Skip("set PAPERBOAT_CONTROL_STORM=1 to run the PostgreSQL control storm")
	}
	scales := controlStormScales(t)
	reports := make([]controlStormReport, 0, len(scales))
	for _, machines := range scales {
		var report controlStormReport
		if t.Run(strconv.Itoa(machines), func(t *testing.T) { report = runControlStorm(t, machines) }) {
			reports = append(reports, report)
		}
	}
	encoded, err := json.Marshal(reports)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(encoded))
	if path := os.Getenv("PAPERBOAT_CONTROL_STORM_REPORT"); path != "" {
		if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func runControlStorm(t *testing.T, machines int) controlStormReport {
	store := openControlPlaneTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	prefix := fmt.Sprintf("storm-%d-%d-", machines, time.Now().UnixNano())
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = store.SQL().ExecContext(cleanupCtx, `DELETE FROM paperboat.control_signing_key_revocations WHERE key_id LIKE $1`, prefix+"%")
		_, _ = store.SQL().ExecContext(cleanupCtx, `DELETE FROM paperboat.users WHERE id LIKE $1`, prefix+"user_%")
		_, _ = store.SQL().ExecContext(cleanupCtx, `DELETE FROM paperboat.control_environments WHERE id LIKE $1`, prefix+"env_%")
		_, _ = store.SQL().ExecContext(cleanupCtx, `DELETE FROM paperboat.control_tunnel_nodes WHERE id LIKE $1`, prefix+"%")
	})

	service := NewEdgeService(store, controlStormCredential)
	mintKey := ed25519.NewKeyFromSeed(sha256Sum("paperboat-control-storm-mint"))
	signer, err := mint.New([]mint.Key{{ID: "control-storm", PrivateKey: mintKey}}, "control-storm", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service.SetCredentialIssuer(signer, "https://control-storm.paperboat.test", "paperboat-control-storm-encryption-key")
	server := httptest.NewTLSServer(service.Handler())
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.MaxIdleConns = machines
	transport.MaxIdleConnsPerHost = machines
	transport.MaxConnsPerHost = machines
	transport.IdleConnTimeout = 10 * time.Second
	client := &http.Client{Transport: transport, Timeout: 45 * time.Second}
	defer client.CloseIdleConnections()

	runtime.GC()
	baselineHeap, baselineGoroutines, baselineCPU := stormResources()
	baselineTransactions := store.TransactionStats()
	databaseProfile := startStormDatabaseSampler(ctx, store.SQL())
	t.Cleanup(func() { databaseProfile.Stop() })
	report := controlStormReport{Machines: machines}
	report.Phases = append(report.Phases,
		runStormPhase(t, ctx, "register", machines, func(index int) (int64, int64, error) {
			return stormRequest(ctx, client, http.MethodPost, server.URL+"/v1/nodes/register", controlStormCredential, stormRegistration(prefix, index, "epoch_1"))
		}),
		runStormPhase(t, ctx, "reconnect", machines, func(index int) (int64, int64, error) {
			return stormRequest(ctx, client, http.MethodPost, server.URL+"/v1/nodes/register", controlStormCredential, stormRegistration(prefix, index, "epoch_2"))
		}),
		runStormPhase(t, ctx, "heartbeat", machines, func(index int) (int64, int64, error) {
			return stormRequest(ctx, client, http.MethodPost, server.URL+"/v1/nodes/heartbeat", controlStormCredential, map[string]any{
				"edge_node_id": prefix + strconv.Itoa(index), "process_epoch": "epoch_2", "ready": true,
				"draining": false, "active_streams": index % 17, "at": time.Now().UTC(),
			})
		}),
	)
	standbyNodes := 0
	if machines == 1 {
		standbyNodes = 1
		if _, _, err := stormRequest(ctx, client, http.MethodPost, server.URL+"/v1/nodes/register", controlStormCredential, stormRegistration(prefix, 1, "epoch_2")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := stormRequest(ctx, client, http.MethodPost, server.URL+"/v1/nodes/heartbeat", controlStormCredential, map[string]any{
			"edge_node_id": prefix + "1", "process_epoch": "epoch_2", "ready": true,
			"draining": false, "active_streams": 0, "at": time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	helpers := seedStormAssignments(t, ctx, store.SQL(), signer, prefix, machines)
	report.Phases = append(report.Phases,
		runStormPhase(t, ctx, "route_snapshot", machines, func(index int) (int64, int64, error) {
			return stormRequest(ctx, client, http.MethodPost, server.URL+"/v1/edge/routes/desired-state", controlStormCredential, map[string]string{"edge_node_id": prefix + strconv.Itoa(index)})
		}),
	)
	stale := (machines + 1) / 2
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET last_heartbeat_at=$2
		WHERE id LIKE $1 AND mod(substring(id from length($3) + 1)::integer, 2)=0`, prefix+"%", time.Now().UTC().Add(-10*time.Minute), prefix); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().UTC().Add(-time.Minute)
	report.Phases = append(report.Phases,
		runStormPhase(t, ctx, "stale_node_fencing", stale, func(int) (int64, int64, error) {
			count, err := service.ReconcileStaleNodes(ctx, cutoff, 1)
			if err == nil && count != 1 {
				err = fmt.Errorf("reconciled %d stale nodes, want 1", count)
			}
			return 0, 0, err
		}),
		runStormPhase(t, ctx, "post_fence_snapshot", machines, func(index int) (int64, int64, error) {
			return stormRequest(ctx, client, http.MethodPost, server.URL+"/v1/edge/routes/desired-state", controlStormCredential, map[string]string{"edge_node_id": prefix + strconv.Itoa(index)})
		}),
		runStormPhase(t, ctx, "replacement_admission", stale, func(index int) (int64, int64, error) {
			return stormAdmissionRequest(ctx, client, server.URL, prefix, index*2, helpers[index*2])
		}),
	)
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_signing_key_revocations (key_id,reason,revoked_at)
		SELECT $1 || value::text, 'storm', now() FROM generate_series(0,$2::integer-1) value`, prefix, machines); err != nil {
		t.Fatal(err)
	}
	report.Phases = append(report.Phases, runStormPhase(t, ctx, "revocation_snapshot", machines, func(int) (int64, int64, error) {
		return stormRequest(ctx, client, http.MethodGet, server.URL+"/v1/trust/revocations", controlStormCredential, nil)
	}))

	var persisted, ready int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE ready AND process_epoch='epoch_2')
		FROM paperboat.control_tunnel_nodes WHERE id LIKE $1`, prefix+"%").Scan(&persisted, &ready); err != nil {
		t.Fatal(err)
	}
	if persisted != machines+standbyNodes || ready != machines-stale+standbyNodes {
		t.Fatalf("persisted nodes=%d ready epoch_2=%d want=%d/%d", persisted, ready, machines+standbyNodes, machines-stale+standbyNodes)
	}
	assertStormReplacement(t, ctx, store.SQL(), prefix, machines, stale)
	report.Phases = append(report.Phases, runTunnelClientStorm(t, ctx, server, prefix+"tunnel_client_", machines))
	var tunnelClientNodes int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.control_tunnel_nodes
		WHERE id LIKE $1 AND state='ready' AND ready AND process_epoch='tunnel_client_epoch'`, prefix+"tunnel_client_%").Scan(&tunnelClientNodes); err != nil {
		t.Fatal(err)
	}
	if tunnelClientNodes != machines {
		t.Fatalf("production tunnel client persisted %d ready nodes, want %d", tunnelClientNodes, machines)
	}

	client.CloseIdleConnections()
	report.Database = databaseProfile.Stop()
	runtime.GC()
	finalHeap, finalGoroutines, finalCPU := stormResources()
	report.HeapGrowthBytes = int64(finalHeap) - int64(baselineHeap)
	report.GoroutineGrowth = finalGoroutines - baselineGoroutines
	report.CPUSeconds = finalCPU - baselineCPU
	pool := store.Pool().Stat()
	report.DBMaxConnections = pool.MaxConns()
	report.DBEmptyAcquires = pool.EmptyAcquireCount()
	report.Transactions = transactionDelta(store.TransactionStats(), baselineTransactions)
	if report.HeapGrowthBytes > 128<<20 {
		t.Fatalf("heap growth=%d exceeds 128 MiB", report.HeapGrowthBytes)
	}
	if report.GoroutineGrowth > 64 {
		t.Fatalf("goroutine growth=%d exceeds 64", report.GoroutineGrowth)
	}
	if report.DBMaxConnections > 20 {
		t.Fatalf("database connections=%d exceeds configured bound 20", report.DBMaxConnections)
	}
	assertTransactionAmplification(t, report.Transactions)
	// pg_stat_activity includes the sampler's own query in addition to the
	// separately enforced 20-connection application pool.
	if report.Database.SampleFailures > report.Database.Samples/2 || report.Database.MaxActiveSessions > 21 || report.Database.MaxWaitingSessions > 20 {
		t.Fatalf("database profile exceeds bounds: %#v", report.Database)
	}
	cpuCeiling := float64(max(machines, 100)) * 0.15
	if report.CPUSeconds > cpuCeiling {
		t.Fatalf("process CPU %.2fs exceeds %.2fs ceiling", report.CPUSeconds, cpuCeiling)
	}
	return report
}

func runTunnelClientStorm(t *testing.T, ctx context.Context, server *httptest.Server, prefix string, nodes int) stormPhaseReport {
	t.Helper()
	binary := os.Getenv("PAPERBOAT_CONTROL_STORM_TUNNEL_BINARY")
	if binary == "" {
		t.Fatal("PAPERBOAT_CONTROL_STORM_TUNNEL_BINARY is required")
	}
	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("control-storm TLS certificate is unavailable")
	}
	reportFile, err := os.CreateTemp("", "paperboat-tunnel-control-storm-*.json")
	if err != nil {
		t.Fatal(err)
	}
	reportPath := reportFile.Name()
	if err := reportFile.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(reportPath) })
	config, err := json.Marshal(map[string]any{
		"base_url": server.URL, "credential": controlStormCredential,
		"ca_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})),
		"prefix": prefix, "nodes": nodes, "report_path": reportPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	command := exec.CommandContext(ctx, binary, "-test.run", "^TestControlStormParticipant$", "-test.count=1")
	command.Env = append(os.Environ(), "PAPERBOAT_TUNNEL_CONTROL_STORM="+string(config))
	output, err := command.CombinedOutput()
	elapsed := time.Since(started)
	if len(output) > maxEdgeDocument {
		t.Fatalf("production tunnel client output exceeds %d bytes", maxEdgeDocument)
	}
	if err != nil {
		t.Fatalf("production tunnel client failed after %s: %v: %s", elapsed, err, strings.TrimSpace(string(output)))
	}
	data, err := os.ReadFile(reportPath)
	if err != nil || len(data) > maxEdgeDocument {
		t.Fatalf("read production tunnel client report: %v", err)
	}
	var durations []time.Duration
	if err := json.Unmarshal(data, &durations); err != nil || len(durations) != nodes*4 {
		t.Fatalf("production tunnel client durations=%d want=%d: %v", len(durations), nodes*4, err)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	return stormPhaseReport{Name: "tunnel_control_client", Operations: len(durations), P50: percentileDuration(durations, 50), P95: percentileDuration(durations, 95), Maximum: durations[len(durations)-1], Elapsed: elapsed}
}

func transactionDelta(after, before db.TransactionSnapshot) db.TransactionSnapshot {
	return db.TransactionSnapshot{
		Serializable: db.TransactionStats{
			Calls: after.Serializable.Calls - before.Serializable.Calls, Attempts: after.Serializable.Attempts - before.Serializable.Attempts,
			Retries: after.Serializable.Retries - before.Serializable.Retries, Exhausted: after.Serializable.Exhausted - before.Serializable.Exhausted,
		},
		ReadCommitted: db.TransactionStats{
			Calls: after.ReadCommitted.Calls - before.ReadCommitted.Calls, Attempts: after.ReadCommitted.Attempts - before.ReadCommitted.Attempts,
			Retries: after.ReadCommitted.Retries - before.ReadCommitted.Retries, Exhausted: after.ReadCommitted.Exhausted - before.ReadCommitted.Exhausted,
		},
	}
}

func assertTransactionAmplification(t *testing.T, snapshot db.TransactionSnapshot) {
	t.Helper()
	for name, stats := range map[string]db.TransactionStats{"serializable": snapshot.Serializable, "read_committed": snapshot.ReadCommitted} {
		if stats.Attempts != stats.Calls+stats.Retries {
			t.Fatalf("%s transaction accounting calls=%d attempts=%d retries=%d", name, stats.Calls, stats.Attempts, stats.Retries)
		}
		if stats.Exhausted != 0 {
			t.Fatalf("%s exhausted transactions=%d", name, stats.Exhausted)
		}
		if stats.Calls > 0 && stats.Retries > stats.Calls*2 {
			t.Fatalf("%s retry amplification calls=%d retries=%d exceeds 2 retries per call", name, stats.Calls, stats.Retries)
		}
	}
}

type stormDatabaseSampler struct {
	database *sql.DB
	stop     context.CancelFunc
	done     chan struct{}
	mu       sync.Mutex
	profile  stormDatabaseProfile
	base     stormDatabaseCounters
	baseSet  bool
	stopped  bool
}

type stormDatabaseCounters struct {
	commits, rollbacks, deadlocks, blocksRead, blocksHit int64
}

func startStormDatabaseSampler(parent context.Context, database *sql.DB) *stormDatabaseSampler {
	ctx, cancel := context.WithCancel(parent)
	sampler := &stormDatabaseSampler{database: database, stop: cancel, done: make(chan struct{})}
	go func() {
		defer close(sampler.done)
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			sampler.sample(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return sampler
}

func (s *stormDatabaseSampler) sample(parent context.Context) {
	if s == nil || s.database == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 500*time.Millisecond)
	defer cancel()
	var active, waiting, locks, operationDepth, staleDepth int64
	var counters stormDatabaseCounters
	err := s.database.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()),
		(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event IS NOT NULL),
		(SELECT count(*) FROM pg_locks),
		(SELECT count(*) FROM control_operations WHERE state IN ('pending','failed','uncertain') OR (state='running' AND lease_expires_at <= now())),
		(SELECT count(*) FROM control_tunnel_nodes WHERE state IN ('registered','ready') AND (last_heartbeat_at IS NULL OR last_heartbeat_at <= now() - interval '2 minutes')),
		coalesce((SELECT xact_commit FROM pg_stat_database WHERE datname=current_database()),0),
		coalesce((SELECT xact_rollback FROM pg_stat_database WHERE datname=current_database()),0),
		coalesce((SELECT deadlocks FROM pg_stat_database WHERE datname=current_database()),0),
		coalesce((SELECT blks_read FROM pg_stat_database WHERE datname=current_database()),0),
		coalesce((SELECT blks_hit FROM pg_stat_database WHERE datname=current_database()),0)`).Scan(
		&active, &waiting, &locks, &operationDepth, &staleDepth, &counters.commits, &counters.rollbacks,
		&counters.deadlocks, &counters.blocksRead, &counters.blocksHit)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profile.Samples++
	if err != nil {
		s.profile.SampleFailures++
		return
	}
	if !s.baseSet {
		s.base = counters
		s.baseSet = true
	}
	s.profile.MaxActiveSessions = max64(s.profile.MaxActiveSessions, active)
	s.profile.MaxWaitingSessions = max64(s.profile.MaxWaitingSessions, waiting)
	s.profile.MaxLocks = max64(s.profile.MaxLocks, locks)
	s.profile.MaxOperationDepth = max64(s.profile.MaxOperationDepth, operationDepth)
	s.profile.MaxStaleNodeDepth = max64(s.profile.MaxStaleNodeDepth, staleDepth)
	s.profile.XactCommits = max64(0, counters.commits-s.base.commits)
	s.profile.XactRollbacks = max64(0, counters.rollbacks-s.base.rollbacks)
	s.profile.Deadlocks = max64(0, counters.deadlocks-s.base.deadlocks)
	s.profile.BlocksRead = max64(0, counters.blocksRead-s.base.blocksRead)
	s.profile.BlocksHit = max64(0, counters.blocksHit-s.base.blocksHit)
}

func (s *stormDatabaseSampler) Stop() stormDatabaseProfile {
	if s == nil {
		return stormDatabaseProfile{}
	}
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		s.stop()
	}
	s.mu.Unlock()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.profile
}

func max64(current, candidate int64) int64 {
	if candidate > current {
		return candidate
	}
	return current
}

type stormSQL interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func seedStormAssignments(t *testing.T, ctx context.Context, database stormSQL, signer *mint.Provider, prefix string, machines int) []stormHelperIdentity {
	t.Helper()
	statements := []string{
		`INSERT INTO paperboat.users (id,workos_subject,primary_email,status)
		 SELECT $1 || 'user_' || value, $1 || 'subject_' || value, $1 || 'user_' || value || '@example.test', 'active'
		 FROM generate_series(0,$2::integer-1) value`,
		`INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id)
		 SELECT $1 || 'env_' || value, $1 || 'workspace_' || value, $1 || 'user_' || value
		 FROM generate_series(0,$2::integer-1) value`,
		`INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,online)
		 SELECT $1 || 'machine_' || value, $1 || 'user_' || value, $1 || 'env_' || value,
		        'storm-' || value, 'linux', 'amd64', '/workspace', 'online', true
		 FROM generate_series(0,$2::integer-1) value`,
		`INSERT INTO paperboat.control_connector_generations
		 (environment_id,connector_id,machine_id,generation,edge_pool,edge_node_id,state,expires_at)
		 SELECT $1 || 'env_' || value, 'runtime', $1 || 'machine_' || value, 1, 'default', $1 || value, 'admitted', now() + interval '1 hour'
		 FROM generate_series(0,$2::integer-1) value`,
		`INSERT INTO paperboat.control_routes
		 (id,environment_id,connector_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation)
		 SELECT $1 || 'route_' || value, $1 || 'env_' || value, 'runtime', 'runtime_https_wss',
		        $1 || value || '.example.test', '127.0.0.1', 8443, 1, 1, $1 || value, 1
		 FROM generate_series(0,$2::integer-1) value`,
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement, prefix, machines); err != nil {
			t.Fatal(err)
		}
	}
	helpers := make([]stormHelperIdentity, machines)
	now := time.Now().UTC()
	for index := range helpers {
		seed := sha256Sum(prefix + "helper-key-" + strconv.Itoa(index))
		privateKey := ed25519.NewKeyFromSeed(seed)
		publicKey := privateKey.Public().(ed25519.PublicKey)
		thumbprintHash := sha256.Sum256(publicKey)
		thumbprint := "sha256:" + base64.RawURLEncoding.EncodeToString(thumbprintHash[:])
		helperID := prefix + "helper_" + strconv.Itoa(index)
		machineID := prefix + "machine_" + strconv.Itoa(index)
		if _, err := database.ExecContext(ctx, `UPDATE paperboat.user_machines SET public_identity_key=$2 WHERE id=$1`,
			machineID, base64.RawURLEncoding.EncodeToString(publicKey)); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx, `INSERT INTO paperboat.control_helpers
			(id,environment_id,key_thumbprint,public_key,state) VALUES ($1,$2,$3,$4,'active')`,
			helperID, prefix+"env_"+strconv.Itoa(index), thumbprint, publicKey); err != nil {
			t.Fatal(err)
		}
		credential, err := signer.SignCredential(mint.CredentialInput{
			Issuer: "https://control-storm.paperboat.test", Audience: "paperboat-control",
			Subject: helperID, JTI: prefix + "identity_" + strconv.Itoa(index), IssuedAt: now,
			ExpiresAt: now.Add(time.Hour), CredentialClass: "helper_identity",
			Scopes: []string{"helper:connect", "helper:renew"}, EnvironmentID: prefix + "env_" + strconv.Itoa(index),
			HelperID: helperID, MachineID: machineID, KeyThumbprint: thumbprint,
		})
		if err != nil {
			t.Fatal(err)
		}
		helpers[index] = stormHelperIdentity{Credential: credential, PrivateKey: privateKey, HelperID: helperID, MachineID: machineID}
	}
	return helpers
}

func assertStormReplacement(t *testing.T, ctx context.Context, database stormSQL, prefix string, machines, stale int) {
	t.Helper()
	var staleNodes, replacedConnectors, advancedRoutes, liveConnectors, liveRoutes int
	err := database.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM paperboat.control_tunnel_nodes node WHERE node.id LIKE $1 || '%' AND mod(substring(node.id from length($1) + 1)::integer,2)=0 AND node.state='offline' AND NOT node.ready),
		(SELECT count(*) FROM paperboat.control_connector_generations connector JOIN paperboat.control_tunnel_nodes node ON node.id=connector.edge_node_id
		 WHERE connector.machine_id LIKE $1 || 'machine_%' AND mod(substring(connector.machine_id from length($1 || 'machine_') + 1)::integer,2)=0
		   AND connector.state='admitted' AND connector.generation=2 AND node.state='ready' AND node.ready),
		(SELECT count(*) FROM paperboat.control_routes route WHERE route.id LIKE $1 || 'route_%'
		   AND mod(substring(route.id from length($1 || 'route_') + 1)::integer,2)=0 AND route.desired_revision=2 AND route.applied_revision=0 AND route.applied_node_id IS NULL AND route.applied_generation IS NULL),
		(SELECT count(*) FROM paperboat.control_connector_generations connector JOIN paperboat.control_tunnel_nodes node ON node.id=connector.edge_node_id
		 WHERE connector.machine_id LIKE $1 || 'machine_%' AND mod(substring(connector.machine_id from length($1 || 'machine_') + 1)::integer,2)=1
		   AND connector.state='admitted' AND connector.generation=1 AND node.state='ready' AND node.ready),
		(SELECT count(*) FROM paperboat.control_routes route WHERE route.id LIKE $1 || 'route_%'
		   AND mod(substring(route.id from length($1 || 'route_') + 1)::integer,2)=1 AND route.desired_revision=1 AND route.applied_revision=1 AND route.applied_generation=1)`, prefix).Scan(&staleNodes, &replacedConnectors, &advancedRoutes, &liveConnectors, &liveRoutes)
	if err != nil {
		t.Fatal(err)
	}
	live := machines - stale
	if staleNodes != stale || replacedConnectors != stale || advancedRoutes != stale || liveConnectors != live || liveRoutes != live {
		t.Fatalf("replacement stale_nodes=%d admitted=%d advanced=%d live_connectors=%d live_routes=%d want stale=%d live=%d", staleNodes, replacedConnectors, advancedRoutes, liveConnectors, liveRoutes, stale, live)
	}
}

func runStormPhase(t *testing.T, ctx context.Context, name string, operations int, operation func(int) (int64, int64, error)) stormPhaseReport {
	t.Helper()
	started := time.Now()
	latencies := make([]time.Duration, operations)
	var requestBytes, responseBytes atomic.Int64
	errorsByIndex := make([]error, operations)
	var wait sync.WaitGroup
	ready := make(chan struct{})
	for index := 0; index < operations; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			select {
			case <-ctx.Done():
				errorsByIndex[index] = ctx.Err()
				return
			case <-ready:
			}
			operationStarted := time.Now()
			sent, received, err := operation(index)
			latencies[index], errorsByIndex[index] = time.Since(operationStarted), err
			requestBytes.Add(sent)
			responseBytes.Add(received)
		}(index)
	}
	close(ready)
	wait.Wait()
	for index, err := range errorsByIndex {
		if err != nil {
			t.Fatalf("%s operation %d: %v", name, index, err)
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	report := stormPhaseReport{Name: name, Operations: operations, P50: percentileDuration(latencies, 50), P95: percentileDuration(latencies, 95), Maximum: latencies[len(latencies)-1], Elapsed: time.Since(started), RequestBytes: requestBytes.Load(), ResponseBytes: responseBytes.Load()}
	if ceiling := stormPhaseCeiling(name); report.Maximum > ceiling {
		t.Fatalf("%s maximum latency %s exceeds %s ceiling", name, report.Maximum, ceiling)
	}
	return report
}

func stormPhaseCeiling(name string) time.Duration {
	switch name {
	case "route_snapshot", "post_fence_snapshot":
		return 15 * time.Second
	case "revocation_snapshot":
		return 10 * time.Second
	case "stale_node_fencing":
		return 5 * time.Second
	default:
		return 2 * time.Second
	}
}

func stormAdmissionRequest(ctx context.Context, client *http.Client, baseURL, prefix string, index int, helper stormHelperIdentity) (int64, int64, error) {
	operationID := prefix + "replacement_" + strconv.Itoa(index)
	payload, err := json.Marshal(connectorAdmissionRequest{
		OperationID: operationID, EnvironmentID: prefix + "env_" + strconv.Itoa(index), MachineID: helper.MachineID,
		ConnectorID: "runtime", EdgePool: "default", ProtocolVersion: "1.0",
	})
	if err != nil {
		return 0, 0, err
	}
	bodyHash := sha256.Sum256(payload)
	now := time.Now().UTC()
	claims := HelperProofClaims{HelperID: helper.HelperID, EnvironmentID: prefix + "env_" + strconv.Itoa(index), OperationID: operationID,
		Method: http.MethodPost, Path: "/v1/connectors/admission", BodySHA256: base64.RawURLEncoding.EncodeToString(bodyHash[:]), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	proofPayload, err := json.Marshal(claims)
	if err != nil {
		return int64(len(payload)), 0, err
	}
	proof, err := json.Marshal(helperProofEnvelope{Algorithm: "EdDSA", Payload: base64.RawURLEncoding.EncodeToString(proofPayload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(helper.PrivateKey, proofPayload))})
	if err != nil {
		return int64(len(payload)), 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/connectors/admission", bytes.NewReader(payload))
	if err != nil {
		return int64(len(payload)), 0, err
	}
	request.Header.Set("Authorization", "Bearer "+helper.Credential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	response, err := client.Do(request)
	if err != nil {
		return int64(len(payload)), 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxEdgeDocument+1))
	if err != nil {
		return int64(len(payload)), int64(len(body)), err
	}
	if response.StatusCode != http.StatusOK {
		return int64(len(payload)), int64(len(body)), fmt.Errorf("status=%d body=%s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var admission ConnectorAdmission
	if err := json.Unmarshal(body, &admission); err != nil {
		return int64(len(payload)), int64(len(body)), err
	}
	if admission.ConnectorGeneration != 2 || admission.EdgeNodeID == "" || admission.EdgeNodeID == prefix+strconv.Itoa(index) || len(admission.Routes) != 1 || admission.Routes[0].RouteRevision != 2 {
		return int64(len(payload)), int64(len(body)), fmt.Errorf("invalid replacement admission generation=%d node=%q routes=%d", admission.ConnectorGeneration, admission.EdgeNodeID, len(admission.Routes))
	}
	return int64(len(payload)), int64(len(body)), nil
}

func sha256Sum(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func stormRequest(ctx context.Context, client *http.Client, method, endpoint, credential string, input any) (int64, int64, error) {
	var payload []byte
	var err error
	if input != nil {
		payload, err = json.Marshal(input)
		if err != nil {
			return 0, 0, err
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return int64(len(payload)), 0, err
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return int64(len(payload)), 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxEdgeDocument+1))
	if err != nil {
		return int64(len(payload)), int64(len(body)), err
	}
	if len(body) > maxEdgeDocument {
		return int64(len(payload)), int64(len(body)), fmt.Errorf("response exceeds %d bytes", maxEdgeDocument)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return int64(len(payload)), int64(len(body)), fmt.Errorf("status=%d body=%s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return int64(len(payload)), int64(len(body)), nil
}

func stormRegistration(prefix string, index int, epoch string) map[string]any {
	return map[string]any{
		"edge_node_id": prefix + strconv.Itoa(index), "edge_pool": "default", "relay_id": "storm-relay-" + strconv.Itoa(index),
		"relay_region": "storm", "relay_name": "Control Storm", "artifact": "storm",
		"protocol": "1.0", "process_epoch": epoch, "capacity": 128,
		"connector_endpoint":                   map[string]any{"host": "127.0.0.1", "tcp_port": 20000 + index, "quic_port": 30000 + index},
		"carrier_endpoint":                     map[string]any{"host": "edge.example.test", "tcp_port": 40000 + index, "quic_port": 50000 + index},
		"carrier_server_spki_sha256":           controlStormCarrierIdentity.Pin,
		"carrier_server_certificate_chain_pem": controlStormCarrierIdentity.Chain,
		"signaling_host":                       "signal.example.test", "stun_endpoint": map[string]any{"host": "127.0.0.1", "port": 3478},
	}
}

func controlStormScales(t *testing.T) []int {
	t.Helper()
	value := strings.TrimSpace(os.Getenv("PAPERBOAT_CONTROL_STORM_SCALES"))
	if value == "" {
		return []int{1, 10, 100, 300, 1000}
	}
	var scales []int
	for _, field := range strings.Split(value, ",") {
		scale, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || scale < 1 || scale > 1000 {
			t.Fatalf("invalid PAPERBOAT_CONTROL_STORM_SCALES value %q", field)
		}
		scales = append(scales, scale)
	}
	return scales
}

func percentileDuration(sorted []time.Duration, percentile int) time.Duration {
	index := (percentile*len(sorted)+99)/100 - 1
	return sorted[index]
}

func stormResources() (heap uint64, goroutines int, cpuSeconds float64) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	samples := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(samples)
	if samples[0].Value.Kind() == metrics.KindFloat64 {
		cpuSeconds = samples[0].Value.Float64()
	}
	return memory.HeapAlloc, runtime.NumGoroutine(), cpuSeconds
}
