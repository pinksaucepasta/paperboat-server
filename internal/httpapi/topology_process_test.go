package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/peersessions"
)

const topologyAuthorityIssuer = "https://authority.paperboat.test:9445"

type topologyEndpointMaterial struct {
	RootPublic         string          `json:"root_public"`
	LocalCertificate   string          `json:"local_certificate"`
	MachineCertificate string          `json:"machine_certificate"`
	LocalNoisePublic   string          `json:"local_noise_public"`
	LocalQUICPublic    string          `json:"local_quic_public"`
	MachineNoisePublic string          `json:"machine_noise_public"`
	MachineQUICPublic  string          `json:"machine_quic_public"`
	MachineDocument    json.RawMessage `json:"machine_document"`
}

func TestTopologyPeerAuthorityProcess(t *testing.T) {
	if os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_ROLE") != "peer-authority" {
		t.Skip("topology peer authority process mode is not configured")
	}
	processTimeout := 45 * time.Second
	if os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION") == "ssh" {
		processTimeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()
	material := readTopologyEndpointMaterial(t, ctx)
	localRaw := decodeTopologyMaterial(t, material.LocalCertificate)
	machineRaw := decodeTopologyMaterial(t, material.MachineCertificate)
	rootRaw := decodeTopologyMaterial(t, material.RootPublic)
	localNoise := decodeTopologyMaterial(t, material.LocalNoisePublic)
	localQUIC := decodeTopologyMaterial(t, material.LocalQUICPublic)
	machineNoise := decodeTopologyMaterial(t, material.MachineNoisePublic)
	machineQUIC := decodeTopologyMaterial(t, material.MachineQUICPublic)
	if len(rootRaw) != ed25519.PublicKeySize || len(localNoise) != 32 || len(localQUIC) != ed25519.PublicKeySize || len(machineNoise) != 32 || len(machineQUIC) != ed25519.PublicKeySize || len(material.MachineDocument) == 0 {
		t.Fatal("topology endpoint material is invalid")
	}

	store, err := db.Open(config.Database{Driver: "postgres", DSN: os.Getenv("PAPERBOAT_TOPOLOGY_DATABASE_DSN")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := waitTopologyDatabase(ctx, store); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	seedTopologyPeerAuthority(t, ctx, store, now, rootRaw, localRaw, machineRaw, localNoise, localQUIC, machineNoise, machineQUIC)
	repository, err := peersessions.NewSQLRepository(store, audit.NewWriter(store), 2*time.Minute, "peer-session-topology-encryption-key")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := mint.New([]mint.Key{{ID: "peer-integration", PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{'i'}, ed25519.SeedSize))}}, "peer-integration", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	credentialInput := mint.CredentialInput{
		Issuer: topologyAuthorityIssuer, Audience: "paperboat-machine", Subject: "account-topology", JTI: "jti-terminal-topology",
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "terminal_operation", Scopes: []string{"terminal:operate"},
		EnvironmentID: "environment-topology", MachineID: "endpoint-host", UserID: "account-topology", CLIClientSessionID: "endpoint-cli", SessionID: "session-topology",
	}
	credentialPath := "/authority/terminal-credential.json"
	if os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION") == "exec" {
		credentialInput.JTI = "jti-exec-topology"
		credentialInput.CredentialClass = "exec_operation"
		credentialInput.Scopes = []string{"exec:operate"}
		credentialInput.SessionID = ""
		credentialInput.OperationID = "operation-exec-topology"
		credentialPath = "/authority/exec-credential.json"
	} else if os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION") == "ssh" {
		credentialInput.CredentialClass = "ssh_operation"
		credentialInput.Scopes = []string{"ssh:operate"}
		credentialInput.SessionID = ""
		credentials := make(map[string]string, len(topologySSHOperationIDs))
		for index, operationID := range topologySSHOperationIDs {
			credentialInput.JTI = fmt.Sprintf("jti-ssh-topology-%d", index+1)
			credentialInput.OperationID = operationID
			credential, signErr := provider.SignCredential(credentialInput)
			if signErr != nil {
				t.Fatal(signErr)
			}
			credentials[operationID] = credential
		}
		writeTopologyAuthorityJSON(t, "/authority/ssh-credentials.json", credentials)
		credentialPath = ""
	} else if os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION") == "file" {
		credentialInput.JTI = "jti-file-topology"
		credentialInput.CredentialClass = "file_transfer"
		credentialInput.Scopes = []string{"file:transfer"}
		credentialInput.SessionID = ""
		credentialInput.SourceMachineID = "endpoint-cli"
		credentialPath = "/authority/file-credential.json"
	} else if os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION") == "codex" {
		credentialInput.JTI = "jti-codex-manage-topology"
		credentialInput.CredentialClass = "codex_manage"
		credentialInput.Scopes = []string{"codex:prepare", "codex:browse", "codex:renew", "codex:stop"}
		credentialInput.SessionID = "cdx_topology"
		credentialInput.InstallationGeneration = 1
		credentialInput.ConnectorID = "connector-topology"
		credentialInput.ConnectorGeneration = 1
		credentialInput.EdgePool = "relay-topology"
		credentialInput.EdgeNodeID = "edge-topology"
		manageCredential, signErr := provider.SignCredential(credentialInput)
		if signErr != nil {
			t.Fatal(signErr)
		}
		credentialInput.JTI = "jti-codex-connect-topology"
		credentialInput.CredentialClass = "codex_connect"
		credentialInput.Scopes = []string{"codex:connect"}
		connectCredential, signErr := provider.SignCredential(credentialInput)
		if signErr != nil {
			t.Fatal(signErr)
		}
		writeTopologyAuthorityJSON(t, "/authority/codex-credential.json", map[string]string{"manage_token": manageCredential, "connect_token": connectCredential})
		credentialPath = ""
	}
	if credentialPath != "" {
		terminalCredential, signErr := provider.SignCredential(credentialInput)
		if signErr != nil {
			t.Fatal(signErr)
		}
		writeTopologyAuthorityJSON(t, credentialPath, map[string]string{"token": terminalCredential})
	}
	service, err := peersessions.New(repository, provider, topologyAuthorityIssuer)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/endpoints/endpoint-host/certificates/1", func(w http.ResponseWriter, r *http.Request) {
		if !topologyBearerOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: material.MachineDocument})
	})
	mux.Handle("POST /v1/peer-attempts", topologyPeerAttemptHandler(t, service))
	mux.Handle("DELETE /v1/peer-attempts/{intent_id}/{attempt_generation}", topologyPeerAttemptDeleteHandler(service))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	listener, err := net.Listen("tcp4", "0.0.0.0:9445")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(tls.NewListener(listener, topologyAuthorityTLS(t))) }()
	writeTopologyAuthorityJSON(t, "/authority/authority-ready.json", true)
	fmt.Println("PAPERBOAT_TOPOLOGY_AUTHORITY_READY")
	completionPath := "/authority/ping-ok.json"
	switch os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION") {
	case "terminal":
		completionPath = "/authority/terminal-ok.json"
	case "exec":
		completionPath = "/authority/exec-ok.json"
	case "ssh":
		completionPath = "/authority/ssh-ok.json"
	case "file":
		completionPath = "/authority/file-ok.json"
	case "codex":
		completionPath = "/authority/codex-ok.json"
	case "preview":
		completionPath = "/authority/preview-ok.json"
	}
	waitTopologyFile(t, ctx, completionPath)
	verifyTopologyPeerPersistence(t, ctx, store)
	fmt.Println("PAPERBOAT_TOPOLOGY_AUTHORITY_OK")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}

var topologySSHOperationIDs = []string{
	"operation-ssh-command",
	"operation-ssh-scp-upload",
	"operation-ssh-scp-download",
	"operation-ssh-sftp",
	"operation-ssh-git",
	"operation-ssh-forward",
	"operation-ssh-rsync-upload",
	"operation-ssh-rsync-download",
	"operation-ssh-existing-key",
	"operation-ssh-password",
	"operation-ssh-reverse-forward",
	"operation-ssh-dynamic-forward",
	"operation-ssh-agent-forward",
}

func topologyPeerAttemptDeleteHandler(service *peersessions.Service) http.Handler {
	production := peerAttemptDelete(service)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !topologyBearerOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		client := auth.ClientPrincipal{SessionID: "endpoint-cli", Scopes: []string{"projects:connect"}}
		request := r.WithContext(context.WithValue(r.Context(), authContextKey{}, principal{User: auth.User{ID: "account-topology", Status: "active", Role: auth.RoleUser}, Client: &client}))
		production.ServeHTTP(w, request)
	})
}

func topologyPeerAttemptHandler(t *testing.T, service *peersessions.Service) http.Handler {
	t.Helper()
	production := peerAttemptCreate(service)
	var emittedMu sync.Mutex
	emitted := make(map[string]bool)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !topologyBearerOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		client := auth.ClientPrincipal{SessionID: "endpoint-cli", Scopes: []string{"projects:connect"}}
		request := r.WithContext(context.WithValue(r.Context(), authContextKey{}, principal{User: auth.User{ID: "account-topology", Status: "active", Role: auth.RoleUser}, Client: &client}))
		recorder := httptest.NewRecorder()
		production.ServeHTTP(recorder, request)
		for key, values := range recorder.Header() {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
		if recorder.Code != http.StatusCreated {
			return
		}
		var response struct {
			Data peerAttemptDescriptor `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Error(err)
			return
		}
		emittedMu.Lock()
		if emitted[response.Data.IntentID] {
			emittedMu.Unlock()
			return
		}
		emitted[response.Data.IntentID] = true
		emittedMu.Unlock()
		pair, err := service.NextControlled(r.Context(), "account-topology", "endpoint-host", 1)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			t.Error(err)
			return
		}
		controlled := peerAttemptResponse(pair, "controlled")
		writeTopologyAuthorityJSON(t, "/authority/descriptor.json", controlled)
		writeTopologyAuthorityJSON(t, "/authority/descriptor-"+pair.IntentID+".json", controlled)
		fmt.Printf("PAPERBOAT_TOPOLOGY_AUTHORITY_DESCRIPTOR intent=%s purpose=%s operation=%s attempt=%d\n", pair.IntentID, pair.Purpose, pair.OperationKey, pair.AttemptGeneration)
	})
}

func topologyBearerOK(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer access.payload.signature"
}

func seedTopologyPeerAuthority(t *testing.T, ctx context.Context, store *db.DB, now time.Time, rootRaw, localRaw, machineRaw, localNoise, localQUIC, machineNoise, machineQUIC []byte) {
	t.Helper()
	localFingerprint, machineFingerprint := sha256.Sum256(localRaw), sha256.Sum256(machineRaw)
	rootFingerprint := sha256.Sum256(rootRaw)
	relayPort := os.Getenv("PAPERBOAT_TOPOLOGY_RELAY_PORT")
	if relayPort == "" {
		relayPort = "9444"
	}
	if relayPort != "9443" && relayPort != "9444" {
		t.Fatal("topology relay port is invalid")
	}
	signalingHost := "relay.paperboat.test:" + relayPort
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, []any{"account-topology", "workos-account-topology", "topology@example.test"}},
		{`INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'topology','desktop','linux',ARRAY['projects:connect'],'active',$4,$4)`, []any{"endpoint-cli", "account-topology", "client-topology", now}},
		{`INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3)`, []any{"environment-topology", "workspace-topology", "account-topology"}},
		{`INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at,signaling_host,stun_host,stun_port) VALUES ($1,'relay-topology','v1','epoch-topology','ready',true,$2,$3,'relay.paperboat.test',3478)`, []any{"edge-topology", now, signalingHost}},
		{`INSERT INTO paperboat.account_e2ee_roots (user_id,public_key,fingerprint) VALUES ($1,$2,$3)`, []any{"account-topology", rootRaw, rootFingerprint[:]}},
		{`INSERT INTO paperboat.peer_endpoint_certificates (fingerprint,user_id,endpoint_id,role,generation,serial,certificate,noise_public_key,quic_public_key,issued_at,expires_at) VALUES ($1,$2,$3,'cli',1,1,$4,$5,$6,$7,$8)`, []any{localFingerprint[:], "account-topology", "endpoint-cli", localRaw, localNoise, localQUIC, now.Add(-time.Minute), now.Add(time.Hour)}},
		{`INSERT INTO paperboat.peer_endpoint_certificates (fingerprint,user_id,endpoint_id,role,generation,serial,certificate,noise_public_key,quic_public_key,issued_at,expires_at) VALUES ($1,$2,$3,'machine',1,2,$4,$5,$6,$7,$8)`, []any{machineFingerprint[:], "account-topology", "endpoint-host", machineRaw, machineNoise, machineQUIC, now.Add(-time.Minute), now.Add(time.Hour)}},
		{`INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,installation_generation) VALUES ($1,$2,$3,'Topology host','linux','amd64','/workspace','online','occupied',1)`, []any{"endpoint-host", "account-topology", "environment-topology"}},
		{`INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,generation,edge_pool,edge_node_id,state) VALUES ($1,$2,1,'relay-topology',$3,'admitted')`, []any{"environment-topology", "endpoint-host", "edge-topology"}},
	}
	for _, statement := range statements {
		if _, err := store.SQL().ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func verifyTopologyPeerPersistence(t *testing.T, ctx context.Context, store *db.DB) {
	t.Helper()
	direct := os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_CARRIER") == "direct-quic"
	var intents, grants, relays, interactive, directProbe, fileTransferKey, codex, privatePreview int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_session_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_signaling_grants`).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_relay_allocations`).Scan(&relays); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE purpose = 'interactive'), count(*) FILTER (WHERE purpose = 'direct_probe'), count(*) FILTER (WHERE purpose = 'file_transfer_key'), count(*) FILTER (WHERE purpose = 'codex'), count(*) FILTER (WHERE purpose = 'private_preview') FROM paperboat.peer_session_intents`).Scan(&interactive, &directProbe, &fileTransferKey, &codex, &privatePreview); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION") == "file" {
		if intents != 1 || grants != 2 || relays != 1 || interactive != 0 || directProbe != 0 || fileTransferKey != 1 {
			t.Fatalf("persisted intents=%d grants=%d relays=%d interactive=%d direct_probes=%d file_transfer_keys=%d", intents, grants, relays, interactive, directProbe, fileTransferKey)
		}
		return
	}
	if os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION") == "codex" {
		expectedProbes := 0
		if direct {
			expectedProbes = 1
		}
		if intents != 2+expectedProbes || grants != (2+expectedProbes)*2 || relays != 2+expectedProbes || interactive != 0 || directProbe != expectedProbes || fileTransferKey != 0 || codex != 2 {
			t.Fatalf("persisted intents=%d grants=%d relays=%d interactive=%d direct_probes=%d file_transfer_keys=%d codex=%d", intents, grants, relays, interactive, directProbe, fileTransferKey, codex)
		}
		return
	}
	if os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION") == "preview" {
		validProbeCount := !direct && directProbe == 0 || direct && directProbe >= 0 && directProbe <= 3
		if !validProbeCount || intents != 3+directProbe || grants != intents*2 || relays != intents || interactive != 0 || fileTransferKey != 0 || codex != 0 || privatePreview != 3 {
			t.Fatalf("persisted intents=%d grants=%d relays=%d interactive=%d direct_probes=%d file_transfer_keys=%d codex=%d private_previews=%d", intents, grants, relays, interactive, directProbe, fileTransferKey, codex, privatePreview)
		}
		return
	}
	if os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION") == "ssh" {
		expected := len(topologySSHOperationIDs)
		if os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_CARRIER") != "" {
			expected = 1
		}
		expectedProbes := 0
		if direct {
			expectedProbes = 1
		}
		total := expected + expectedProbes
		if intents != total || grants != total*2 || relays != total || interactive != expected || directProbe != expectedProbes || fileTransferKey != 0 {
			t.Fatalf("persisted SSH intents=%d grants=%d relays=%d interactive=%d direct_probes=%d", intents, grants, relays, interactive, directProbe)
		}
		return
	}
	if completion := os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION"); completion == "" || completion == "ping" {
		if intents != 1 || grants != 2 || relays != 1 || interactive != 0 || directProbe != 0 || fileTransferKey != 0 {
			t.Fatalf("persisted health-probe intents=%d grants=%d relays=%d interactive=%d direct_probes=%d file_transfer_keys=%d", intents, grants, relays, interactive, directProbe, fileTransferKey)
		}
		return
	}
	validProbeCount := direct && directProbe >= 0 && directProbe <= 1 || !direct && directProbe == 0
	if !validProbeCount || intents != 1+directProbe || grants != intents*2 || relays != intents || interactive != 1 || fileTransferKey != 0 {
		t.Fatalf("persisted intents=%d grants=%d relays=%d interactive=%d direct_probes=%d", intents, grants, relays, interactive, directProbe)
	}
}

func waitTopologyDatabase(ctx context.Context, store *db.DB) error {
	for {
		if err := store.Ping(ctx); err == nil {
			return nil
		}
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func readTopologyEndpointMaterial(t *testing.T, ctx context.Context) topologyEndpointMaterial {
	t.Helper()
	waitTopologyFile(t, ctx, "/authority/endpoint-material.json")
	data, err := os.ReadFile("/authority/endpoint-material.json")
	if err != nil {
		t.Fatal(err)
	}
	var material topologyEndpointMaterial
	if err := json.Unmarshal(data, &material); err != nil {
		t.Fatal(err)
	}
	return material
}

func decodeTopologyMaterial(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		t.Fatal("topology endpoint material is not canonical")
	}
	return decoded
}

func waitTopologyFile(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-time.After(25 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func writeTopologyAuthorityJSON(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

func topologyAuthorityTLS(t *testing.T) *tls.Config {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, ed25519.SeedSize))
	template := &x509.Certificate{SerialNumber: big.NewInt(73), Subject: pkix.Name{CommonName: "authority.paperboat.test"}, NotBefore: time.Unix(1_577_836_800, 0), NotAfter: time.Unix(4_102_444_800, 0), DNSNames: []string{"authority.paperboat.test"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private, Leaf: certificate}}}
}
