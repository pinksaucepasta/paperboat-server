package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/httpapi"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

const (
	controlCredential = "edge-control-conformance-credential-0123456789"
	userID            = "usr_control_conformance"
	environmentID     = "env_control_conformance"
	nodeID            = "edge_control_conformance"
	nodeID2           = "edge_control_conformance_2"
	fullNodeID        = "edge_control_conformance_full"
	routeID           = "route_control_conformance"
	usageKeyID        = "usage_control_conformance"
	usageKeyID2       = "usage_control_conformance_2"
	fullUsageKeyID    = "usage_control_conformance_full"
	revokedKeyID      = "signing_key_control_conformance_revoked"
)

var errInvalidConformance = errors.New("invalid control conformance state")

type driverConfig struct {
	ControlURL          string `json:"control_url"`
	ControlCredential   string `json:"control_credential"`
	ControlCAFile       string `json:"control_ca_file"`
	NodeID              string `json:"edge_node_id"`
	EdgePool            string `json:"edge_pool"`
	ProcessEpoch        string `json:"process_epoch"`
	EnvironmentID       string `json:"environment_id"`
	HelperID            string `json:"helper_id"`
	ConnectorGeneration uint64 `json:"connector_generation"`
	RouteID             string `json:"route_id"`
	RouteRevision       uint64 `json:"route_revision"`
	UsageKeyID          string `json:"usage_key_id"`
	UsageSeed           string `json:"usage_seed_base64url"`
	CounterEpoch        string `json:"counter_epoch"`
	UsageOperationID    string `json:"usage_operation_id"`
	RevokedKeyID        string `json:"expected_revoked_key_id"`
	Now                 string `json:"now"`
}

func main() {
	if len(os.Args) != 5 && len(os.Args) != 8 {
		fmt.Fprintln(os.Stderr, "usage: paperboat-control-conformance <postgres-dsn> <absolute-tunnel-driver-path> <absolute-helper-path> <absolute-helper-driver-path> [<absolute-tunnel-service-path> <absolute-frps-path> <absolute-caddy-path>]")
		os.Exit(2)
	}
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "paperboat-control-conformance: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output *os.File) error {
	dsn, driverPath, helperPath, helperDriverPath := args[0], args[1], args[2], args[3]
	if !filepath.IsAbs(driverPath) || !filepath.IsAbs(helperPath) || !filepath.IsAbs(helperDriverPath) {
		return errors.New("conformance driver paths must be absolute")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		return err
	}
	defer store.Close()
	if err := waitForDatabase(ctx, store, 30*time.Second); err != nil {
		return err
	}
	if err := db.Migrate(ctx, store); err != nil {
		return err
	}
	if err := resetAndSeed(ctx, store); err != nil {
		return err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	public2, private2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	fullPublic, fullPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := conformanceExec(ctx, store, `INSERT INTO paperboat.control_signing_key_revocations (key_id,reason,revoked_at,actor_user_id) VALUES ($1,'conformance test',$2,$3)`, revokedKeyID, now, userID); err != nil {
		return err
	}
	edge := controlplane.NewEdgeService(store, controlCredential)
	edge.SetClock(func() time.Time { return now })
	publicKeys := map[string]ed25519.PublicKey{nodeID: public, nodeID2: public2, fullNodeID: fullPublic}
	usageKeyIDs := map[string]string{nodeID: usageKeyID, nodeID2: usageKeyID2, fullNodeID: fullUsageKeyID}
	var expectedNode atomic.Value
	expectedNode.Store(nodeID)
	var rootHandler http.Handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := httptest.NewRecorder()
		rootHandler.ServeHTTP(recorder, r)
		if r.URL.Path == "/v1/nodes/register" && recorder.Code == http.StatusNoContent {
			currentNode := expectedNode.Load().(string)
			var registered bool
			if err := conformanceScan(r.Context(), store, `SELECT EXISTS(SELECT 1 FROM paperboat.control_tunnel_nodes WHERE id=$1)`, []any{currentNode}, &registered); err != nil || !registered {
				http.Error(w, "registered node mismatch", http.StatusInternalServerError)
				return
			}
			var assignedNode string
			if err := conformanceScan(r.Context(), store, `UPDATE paperboat.control_connector_generations SET edge_node_id=$1 WHERE environment_id=$2 RETURNING edge_node_id`, []any{currentNode, environmentID}, &assignedNode); err != nil || assignedNode != currentNode {
				http.Error(w, "seed assignment", http.StatusInternalServerError)
				return
			}
			if err := conformanceExec(r.Context(), store, `INSERT INTO paperboat.control_usage_verification_keys (key_id,edge_node_id,public_key,not_before,expires_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (key_id) DO NOTHING`, usageKeyIDs[currentNode], currentNode, []byte(publicKeys[currentNode]), now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
				http.Error(w, "seed usage key", http.StatusInternalServerError)
				return
			}
		}
		if recorder.Code < 200 || recorder.Code >= 300 {
			fmt.Fprintf(os.Stderr, "conformance control response path=%s status=%d body=%s\n", r.URL.Path, recorder.Code, recorder.Body.String())
		}
		for key, values := range recorder.Header() {
			w.Header()[key] = append([]string(nil), values...)
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	})
	server := httptest.NewUnstartedServer(handler)
	server.StartTLS()
	defer server.Close()
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil || len(signingPublic) != ed25519.PublicKeySize {
		return errors.Join(errInvalidConformance, err)
	}
	signer, err := mint.New([]mint.Key{{ID: "control-conformance-signing-key", PrivateKey: signingPrivate}}, "control-conformance-signing-key", time.Minute)
	if err != nil {
		return err
	}
	enrollmentService := controlplane.NewEnrollmentService(store, signer, nil, server.URL, "control-conformance-encryption-key")
	edge.SetCredentialIssuer(signer, server.URL, "control-conformance-encryption-key")
	rootHandler = httpapi.NewRouter(httpapi.Options{EdgeControl: edge.Handler(), Enrollment: enrollmentService, MintKeys: signer})
	temporary := os.TempDir()
	root, err := os.MkdirTemp(temporary, "paperboat-control-conformance-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o700); err != nil {
		return err
	}
	certificate := server.Certificate()
	caPath := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		return err
	}
	if _, err := x509.ParseCertificate(certificate.Raw); err != nil {
		return err
	}
	grant, err := enrollmentService.Issue(ctx, userID, "helper-control-conformance-enrollment", environmentID, 5*time.Minute)
	if err != nil {
		return err
	}
	stateRoot := filepath.Join(root, "helper-state")
	enrollConfigPath := filepath.Join(root, "helper-enroll.json")
	enrollConfig, _ := json.Marshal(map[string]any{"control_url": server.URL, "control_ca_file": caPath, "state_root": stateRoot, "enrollment_credential": grant.Credential})
	if err := os.WriteFile(enrollConfigPath, enrollConfig, 0o600); err != nil {
		return err
	}
	helperCommand := exec.CommandContext(ctx, helperPath, "enroll", enrollConfigPath)
	helperCommand.Env = append(os.Environ(), "SSL_CERT_FILE="+caPath)
	if result, err := helperCommand.CombinedOutput(); err != nil {
		return fmt.Errorf("helper enrollment process: %w: %s", err, result)
	}
	var runtimeIdentity struct {
		HelperID      string `json:"helper_id"`
		EnvironmentID string `json:"environment_id"`
	}
	identityDocument, err := os.ReadFile(filepath.Join(stateRoot, "runtime-identity.json"))
	if err != nil || json.Unmarshal(identityDocument, &runtimeIdentity) != nil || runtimeIdentity.HelperID != grant.HelperID || runtimeIdentity.EnvironmentID != environmentID {
		return errors.Join(errInvalidConformance, err)
	}
	value := driverConfig{ControlURL: server.URL, ControlCredential: controlCredential, ControlCAFile: caPath, NodeID: nodeID, EdgePool: "default", ProcessEpoch: "process_control_conformance", EnvironmentID: environmentID, HelperID: runtimeIdentity.HelperID, ConnectorGeneration: 1, RouteID: routeID, RouteRevision: 1, UsageKeyID: usageKeyID, UsageSeed: base64.RawURLEncoding.EncodeToString(private.Seed()), CounterEpoch: "counter_control_conformance", UsageOperationID: "op_conformance_usage_0001", RevokedKeyID: revokedKeyID, Now: now.Format(time.RFC3339Nano)}
	configPath := filepath.Join(root, "driver.json")
	runDriver := func(label string) error {
		encoded, _ := json.Marshal(value)
		if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
			return err
		}
		command := exec.CommandContext(ctx, driverPath, configPath)
		result, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("tunnel driver %s: %w: %s", label, err, result)
		}
		if !json.Valid(result) {
			return fmt.Errorf("tunnel driver %s returned invalid evidence", label)
		}
		return nil
	}
	if err := runDriver("initial"); err != nil {
		return err
	}
	helperDriverConfigPath := filepath.Join(root, "helper-driver.json")
	helperDriverConfig, _ := json.Marshal(map[string]any{"control_url": server.URL, "control_ca_file": caPath, "state_root": stateRoot, "issuer": server.URL})
	if err := os.WriteFile(helperDriverConfigPath, helperDriverConfig, 0o600); err != nil {
		return err
	}
	helperAdmissionCommand := exec.CommandContext(ctx, helperDriverPath, helperDriverConfigPath)
	if result, err := helperAdmissionCommand.CombinedOutput(); err != nil || !json.Valid(result) {
		return fmt.Errorf("helper admission process: %w: %s", errors.Join(errInvalidConformance, err), result)
	}
	if err := runDriver("restart"); err != nil {
		return err
	}
	var appliedRevision, appliedGeneration int64
	var appliedNode string
	if err := conformanceScan(ctx, store, `SELECT applied_revision,applied_node_id,applied_generation FROM paperboat.control_routes WHERE id=$1`, []any{routeID}, &appliedRevision, &appliedNode, &appliedGeneration); err != nil || appliedRevision != 1 || appliedNode != nodeID || appliedGeneration != 1 {
		return fmt.Errorf("route observation was not persisted: revision=%d node=%q generation=%d: %w", appliedRevision, appliedNode, appliedGeneration, err)
	}
	var receiptCount int
	if err := conformanceScan(ctx, store, `SELECT count(*) FROM paperboat.control_usage_receipts WHERE operation_id='op_conformance_usage_0001'`, nil, &receiptCount); err != nil || receiptCount != 1 {
		return fmt.Errorf("usage replay was not exactly once: count=%d: %w", receiptCount, err)
	}
	if err := conformanceExec(ctx, store, `UPDATE paperboat.control_routes SET desired_state='replacing',desired_revision=2 WHERE id=$1`, routeID); err != nil {
		return err
	}
	expectedNode.Store(nodeID2)
	value.NodeID, value.ProcessEpoch = nodeID2, "process_control_conformance_2"
	value.RouteRevision, value.UsageKeyID = 2, usageKeyID2
	value.UsageSeed, value.CounterEpoch, value.UsageOperationID = base64.RawURLEncoding.EncodeToString(private2.Seed()), "counter_control_conformance_2", "op_conformance_usage_0002"
	if err := runDriver("reassignment"); err != nil {
		return err
	}
	if err := conformanceScan(ctx, store, `SELECT applied_revision,applied_node_id,applied_generation FROM paperboat.control_routes WHERE id=$1`, []any{routeID}, &appliedRevision, &appliedNode, &appliedGeneration); err != nil || appliedRevision != 2 || appliedNode != nodeID2 || appliedGeneration != 1 {
		return fmt.Errorf("route reassignment was not persisted: revision=%d node=%q generation=%d: %w", appliedRevision, appliedNode, appliedGeneration, err)
	}
	if err := conformanceScan(ctx, store, `SELECT count(*) FROM paperboat.control_usage_receipts WHERE environment_id=$1`, []any{environmentID}, &receiptCount); err != nil || receiptCount != 2 {
		return fmt.Errorf("reassigned usage was not persisted exactly once: count=%d: %w", receiptCount, err)
	}
	fullServiceRuns := 0
	if len(args) == 7 {
		for _, path := range args[4:] {
			if !filepath.IsAbs(path) {
				return errors.New("full tunnel paths must be absolute")
			}
		}
		expectedNode.Store(fullNodeID)
		if err := runFullTunnelConformance(ctx, store, rootHandler, root, caPath, server.URL, args[4], args[5], args[6], fullPrivate); err != nil {
			return err
		}
		fullServiceRuns = 2
	} else {
		if err := conformanceExec(ctx, store, `UPDATE paperboat.control_routes SET desired_state='detaching',desired_revision=3 WHERE id=$1`, routeID); err != nil {
			return err
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/routes/observed", bytes.NewBufferString(`{"edge_node_id":"`+nodeID2+`","routes":[]}`))
		request.Header.Set("Authorization", "Bearer "+controlCredential)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		edge.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			return fmt.Errorf("detach observation failed: status=%d body=%s", response.Code, response.Body.String())
		}
	}
	var state string
	var node any
	if err := conformanceScan(ctx, store, `SELECT desired_state,applied_node_id FROM paperboat.control_routes WHERE id=$1`, []any{routeID}, &state, &node); err != nil || state != "detached" || node != nil {
		return fmt.Errorf("route detach was not persisted: state=%q node=%v: %w", state, node, err)
	}
	return json.NewEncoder(output).Encode(map[string]any{"status": "passed", "helper_process_runs": 2, "helper_id": runtimeIdentity.HelperID, "tunnel_process_runs": 3, "full_tunnel_service_runs": fullServiceRuns, "usage_receipts": receiptCount, "route_state": state, "reassigned_node_id": nodeID2, "revoked_key_id": revokedKeyID})
}

func waitForDatabase(ctx context.Context, store *db.DB, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		if err := store.Ping(ctx); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("database readiness timeout: %w", last)
		case <-ticker.C:
		}
	}
}

type fullTunnelDeployment struct {
	ControlURL             string        `json:"control_url"`
	CredentialIssuer       string        `json:"credential_issuer"`
	ControlCredentialFile  string        `json:"control_credential_file"`
	ControlCAFile          string        `json:"control_ca_file"`
	JWKSFile               string        `json:"jwks_file"`
	RevocationsFile        string        `json:"revocations_file"`
	UsageSigningKeyFile    string        `json:"usage_signing_key_file"`
	FRPSBinary             string        `json:"frps_binary"`
	FRPSSHA256             string        `json:"frps_sha256"`
	CaddyBinary            string        `json:"caddy_binary"`
	CaddySHA256            string        `json:"caddy_sha256"`
	RuntimeDirectory       string        `json:"runtime_directory"`
	HookAddress            string        `json:"hook_address"`
	HookPath               string        `json:"hook_path"`
	ConnectorBindAddress   string        `json:"connector_bind_address"`
	ConnectorAdvertiseHost string        `json:"connector_advertise_host"`
	ConnectorTCPPort       int           `json:"connector_tcp_port"`
	ConnectorQUICPort      int           `json:"connector_quic_port"`
	PrivateVhostAddress    string        `json:"private_vhost_address"`
	CaddyListenAddress     string        `json:"caddy_listen_address"`
	CaddyAdminAddress      string        `json:"caddy_admin_address"`
	WildcardHost           string        `json:"wildcard_host"`
	TrustedProxyCIDRs      []string      `json:"trusted_proxy_cidrs"`
	CertificateIssuer      string        `json:"certificate_issuer"`
	NodeCapacity           uint32        `json:"node_capacity"`
	ControlInterval        time.Duration `json:"control_interval"`
	UsageInterval          time.Duration `json:"usage_interval"`
	ControlTimeout         time.Duration `json:"control_timeout"`
}

func runFullTunnelConformance(ctx context.Context, store *db.DB, handler http.Handler, root, caPath, controlURL, tunnelPath, frpsPath, caddyPath string, usagePrivate ed25519.PrivateKey) error {
	if err := conformanceExec(ctx, store, `UPDATE paperboat.control_routes SET desired_state='replacing',desired_revision=3 WHERE id=$1`, routeID); err != nil {
		return err
	}
	trustRoot := filepath.Join(root, "full-tunnel")
	runtimeRoot := filepath.Join(trustRoot, "runtime")
	if err := os.MkdirAll(runtimeRoot, 0o700); err != nil {
		return err
	}
	credentialPath := filepath.Join(trustRoot, "control.credential")
	jwksPath := filepath.Join(trustRoot, "jwks.json")
	revocationsPath := filepath.Join(trustRoot, "revocations.json")
	usagePath := filepath.Join(trustRoot, "usage.key")
	if err := os.WriteFile(credentialPath, []byte(controlCredential), 0o600); err != nil {
		return err
	}
	jwksRequest := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	jwksResponse := httptest.NewRecorder()
	handler.ServeHTTP(jwksResponse, jwksRequest)
	if jwksResponse.Code != http.StatusOK || !json.Valid(jwksResponse.Body.Bytes()) {
		return fmt.Errorf("full tunnel JWKS fixture status=%d", jwksResponse.Code)
	}
	if err := os.WriteFile(jwksPath, jwksResponse.Body.Bytes(), 0o600); err != nil {
		return err
	}
	revocationRequest := httptest.NewRequest(http.MethodGet, "/v1/trust/revocations", nil)
	revocationRequest.Header.Set("Authorization", "Bearer "+controlCredential)
	revocationResponse := httptest.NewRecorder()
	handler.ServeHTTP(revocationResponse, revocationRequest)
	if revocationResponse.Code != http.StatusOK || !json.Valid(revocationResponse.Body.Bytes()) {
		return fmt.Errorf("full tunnel revocation fixture status=%d", revocationResponse.Code)
	}
	if err := os.WriteFile(revocationsPath, revocationResponse.Body.Bytes(), 0o600); err != nil {
		return err
	}
	usageDocument, _ := json.Marshal(map[string]string{"key_id": fullUsageKeyID, "private_key": base64.RawURLEncoding.EncodeToString(usagePrivate)})
	if err := os.WriteFile(usagePath, usageDocument, 0o600); err != nil {
		return err
	}
	ports := make([]int, 7)
	seenPorts := make(map[int]struct{}, len(ports))
	for index := range ports {
		for {
			port, err := availablePort()
			if err != nil {
				return err
			}
			if _, exists := seenPorts[port]; exists {
				continue
			}
			ports[index] = port
			seenPorts[port] = struct{}{}
			break
		}
	}
	deployment := fullTunnelDeployment{
		ControlURL: controlURL, CredentialIssuer: controlURL, ControlCredentialFile: credentialPath, ControlCAFile: caPath, JWKSFile: jwksPath, RevocationsFile: revocationsPath, UsageSigningKeyFile: usagePath,
		FRPSBinary: frpsPath, FRPSSHA256: fileSHA256(frpsPath), CaddyBinary: caddyPath, CaddySHA256: fileSHA256(caddyPath), RuntimeDirectory: runtimeRoot,
		HookAddress: "127.0.0.1:" + fmt.Sprint(ports[0]), HookPath: "/private/control-conformance-hook", ConnectorBindAddress: "127.0.0.1", ConnectorAdvertiseHost: "edge.example.test", ConnectorTCPPort: ports[1], ConnectorQUICPort: ports[2],
		PrivateVhostAddress: "127.0.0.1:" + fmt.Sprint(ports[3]), CaddyListenAddress: "127.0.0.1:" + fmt.Sprint(ports[4]), CaddyAdminAddress: "127.0.0.1:" + fmt.Sprint(ports[5]), WildcardHost: "*.example.test", TrustedProxyCIDRs: []string{"127.0.0.0/8"}, CertificateIssuer: "internal",
		NodeCapacity: 8, ControlInterval: 250 * time.Millisecond, UsageInterval: 250 * time.Millisecond, ControlTimeout: 2 * time.Second,
	}
	if deployment.FRPSSHA256 == "" || deployment.CaddySHA256 == "" {
		return errInvalidConformance
	}
	deploymentPath := filepath.Join(trustRoot, "deployment.json")
	encoded, _ := json.Marshal(deployment)
	if err := os.WriteFile(deploymentPath, encoded, 0o600); err != nil {
		return err
	}
	statePath := filepath.Join(trustRoot, "edge-state.json")
	healthAddress := "127.0.0.1:" + fmt.Sprint(ports[6])
	var firstEpoch string
	for run := 1; run <= 2; run++ {
		command := exec.CommandContext(ctx, tunnelPath, "-node-id", fullNodeID, "-edge-pool", "default", "-health-address", healthAddress, "-state-path", statePath, "-deployment-config", deploymentPath, "-shutdown-timeout", "5s")
		var processOutput bytes.Buffer
		command.Stdout, command.Stderr = &processOutput, &processOutput
		if err := command.Start(); err != nil {
			return err
		}
		process := &processResult{done: make(chan struct{})}
		go func() {
			process.err = command.Wait()
			close(process.done)
		}()
		err := waitForFullTunnel(ctx, store, process, run, firstEpoch)
		if err == nil && run == 1 {
			err = conformanceScan(ctx, store, `SELECT process_epoch FROM paperboat.control_tunnel_nodes WHERE id=$1`, []any{fullNodeID}, &firstEpoch)
		}
		if err == nil && run == 2 {
			err = conformanceExec(ctx, store, `UPDATE paperboat.control_routes SET desired_state='detaching',desired_revision=4 WHERE id=$1`, routeID)
			if err == nil {
				err = waitForDetachedRoute(ctx, store, process)
			}
		}
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-process.done:
			if err == nil && process.err != nil {
				err = process.err
			}
		case <-time.After(8 * time.Second):
			_ = command.Process.Kill()
			<-process.done
			if err == nil {
				err = errors.New("full tunnel shutdown timed out")
			}
		}
		if err != nil {
			return fmt.Errorf("full tunnel run %d: %w: %s", run, err, processOutput.String())
		}
	}
	return nil
}

type processResult struct {
	done chan struct{}
	err  error
}

func waitForFullTunnel(ctx context.Context, store *db.DB, process *processResult, run int, priorEpoch string) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var revision int64
		var node, epoch string
		var ready bool
		err := conformanceScan(ctx, store, `SELECT r.applied_revision,coalesce(r.applied_node_id,''),n.process_epoch,n.ready FROM paperboat.control_routes r JOIN paperboat.control_tunnel_nodes n ON n.id=$1 WHERE r.id=$2`, []any{fullNodeID, routeID}, &revision, &node, &epoch, &ready)
		if err == nil && revision == 3 && node == fullNodeID && ready && (run == 1 || epoch != priorEpoch) {
			return nil
		}
		select {
		case <-process.done:
			return fmt.Errorf("process exited before readiness: %w", process.err)
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("full tunnel readiness timed out")
		case <-ticker.C:
		}
	}
}

func waitForDetachedRoute(ctx context.Context, store *db.DB, process *processResult) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var state string
		var node any
		if err := conformanceScan(ctx, store, `SELECT desired_state,applied_node_id FROM paperboat.control_routes WHERE id=$1`, []any{routeID}, &state, &node); err == nil && state == "detached" && node == nil {
			return nil
		}
		select {
		case <-process.done:
			return fmt.Errorf("process exited before detach: %w", process.err)
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("full tunnel detach timed out")
		case <-ticker.C:
		}
	}
}

func availablePort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func fileSHA256(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func resetAndSeed(ctx context.Context, store *db.DB) error {
	statements := []string{
		`DELETE FROM paperboat.control_usage_receipts WHERE environment_id='env_control_conformance'`,
		`DELETE FROM paperboat.control_usage_counters WHERE environment_id='env_control_conformance'`,
		`DELETE FROM paperboat.control_usage_verification_keys WHERE edge_node_id='edge_control_conformance'`,
		`DELETE FROM paperboat.control_usage_verification_keys WHERE edge_node_id='edge_control_conformance_2'`,
		`DELETE FROM paperboat.control_usage_verification_keys WHERE edge_node_id='edge_control_conformance_full'`,
		`DELETE FROM paperboat.control_routes WHERE environment_id='env_control_conformance'`,
		`DELETE FROM paperboat.control_connector_generations WHERE environment_id='env_control_conformance'`,
		`DELETE FROM paperboat.control_helpers WHERE environment_id='env_control_conformance'`,
		`DELETE FROM paperboat.control_tunnel_nodes WHERE id='edge_control_conformance'`,
		`DELETE FROM paperboat.control_tunnel_nodes WHERE id='edge_control_conformance_2'`,
		`DELETE FROM paperboat.control_tunnel_nodes WHERE id='edge_control_conformance_full'`,
		`DELETE FROM paperboat.control_signing_key_revocations WHERE key_id='signing_key_control_conformance_revoked'`,
		`DELETE FROM paperboat.control_environments WHERE id='env_control_conformance'`,
		`DELETE FROM paperboat.users WHERE id='usr_control_conformance'`,
		`INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ('usr_control_conformance','workos_control_conformance','control-conformance@example.test','active')`,
		`INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ('env_control_conformance','workspace_control_conformance','usr_control_conformance')`,
		`INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port) VALUES ('route_control_conformance','env_control_conformance','helper_https_wss','control-conformance.example.test','127.0.0.1',8080)`,
	}
	return store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement); err != nil {
				return err
			}
		}
		return nil
	})
}

func conformanceExec(ctx context.Context, store *db.DB, query string, args ...any) error {
	return store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, query, args...)
		return err
	})
}

func conformanceScan(ctx context.Context, store *db.DB, query string, args []any, destinations ...any) error {
	return store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.QueryRow(ctx, query, args...).Scan(destinations...)
	})
}
