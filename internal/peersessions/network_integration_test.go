package peersessions

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
	"golang.org/x/crypto/curve25519"
)

func TestNetworkAuthorityProductionIdentityAndAccessLifecycle(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run peer network integration")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err = db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	suffix := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_")) + strings.ReplaceAll(now.Format("150405.000000000"), ".", "")
	userID, cliID, machineID, envID := "network_user_"+suffix, "network_cli_"+suffix, "network_machine_"+suffix, "network_env_"+suffix
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$2,$3,'active')`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions(id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES($1,$2,$3,'network test','desktop','test',ARRAY['projects:connect'],'active',$4,$4)`, cliID, userID, "client_"+suffix, now); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments(id,workspace_id,owner_user_id) VALUES($1,$2,$3)`, envID, "workspace_"+suffix, userID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation) VALUES($1,$2,$3,'Network machine','linux','amd64','/workspace','online','occupied',true,1)`, machineID, userID, envID); err != nil {
		t.Fatal(err)
	}

	identityRepo, err := peeridentity.NewSQLRepository(store, audit.NewWriter(store))
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := peeridentity.NewService(identityRepo)
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootFingerprint := sha256.Sum256(rootPublic)
	keyID, err := peeridentity.KeyID(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	cliRaw, cliFingerprint := networkCertificate(t, rootPrivate, userID, peeridentity.RoleCLI, cliID, 1, 1, now, now.Add(time.Hour))
	_, err = identityService.Bootstrap(ctx, peeridentity.BootstrapRequest{CLIClientSessionID: cliID, RootPublicKey: rootPublic, RegisterRequest: peeridentity.RegisterRequest{OperationID: "operation_bootstrap_" + suffix, UserID: userID, KeyID: keyID, Certificate: cliRaw, Expected: peeridentity.Expected{AccountID: userID, Role: peeridentity.RoleCLI, EndpointID: cliID, Generation: 1, Serial: 1}, ExpectedRootFingerprint: rootFingerprint, ExpectedCertificateFingerprint: cliFingerprint, ExpectedIssuedAt: now, ExpectedExpiresAt: now.Add(time.Hour), Now: now}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := identityService.RequestMachineEndpoint(ctx, peeridentity.MachineEndpointRequest{OperationID: "operation_machine_request_" + suffix, UserID: userID, EndpointID: machineID, Generation: 1, NoisePublicKey: [32]byte{3}, QUICPublicKey: [32]byte{4}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	machineRaw, machineFingerprint := networkCertificateWithKeys(t, rootPrivate, userID, peeridentity.RoleMachine, machineID, 1, 1, request.NoisePublicKey, request.QUICPublicKey, now, now.Add(time.Hour))
	_, err = identityService.Register(ctx, peeridentity.RegisterRequest{OperationID: "operation_machine_certificate_" + suffix, UserID: userID, KeyID: keyID, Certificate: machineRaw, Expected: peeridentity.Expected{AccountID: userID, Role: peeridentity.RoleMachine, EndpointID: machineID, Generation: 1, Serial: 1}, ExpectedRootFingerprint: rootFingerprint, ExpectedCertificateFingerprint: machineFingerprint, ExpectedIssuedAt: now, ExpectedExpiresAt: now.Add(time.Hour), Now: now})
	if err != nil {
		t.Fatal(err)
	}

	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := mint.New([]mint.Key{{ID: "network-test", PrivateKey: signingPrivate}}, "network-test", mint.MaxProofTTL)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewNetworkService(store, provider, "https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	cliPrivate, cliPublic := networkX25519Key(t)
	machinePrivate, machinePublic := networkX25519Key(t)
	_, cliDisco := networkX25519Key(t)
	_, machineDisco := networkX25519Key(t)
	cliRegistration, err := service.Register(ctx, NetworkRegistration{OperationID: "operation_network_cli_" + suffix, UserID: userID, EndpointID: cliID, Role: "cli", EndpointGeneration: 1, WireGuardPublicKey: cliPublic, DiscoPublicKey: cliDisco, QUICCertificateFingerprint: cliFingerprint[:]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET setup_mode='client',seat_state='released' WHERE id=$1`, machineID); err != nil {
		t.Fatal(err)
	}
	machineRegistration, err := service.Register(ctx, NetworkRegistration{OperationID: "operation_network_machine_" + suffix, UserID: userID, EndpointID: machineID, Role: "machine", MachineID: machineID, EndpointGeneration: 1, MachineGeneration: 1, WireGuardPublicKey: machinePublic, DiscoPublicKey: machineDisco, QUICCertificateFingerprint: machineFingerprint[:]})
	if err != nil {
		t.Fatal(err)
	}
	if cliRegistration.VirtualAddress == machineRegistration.VirtualAddress {
		t.Fatal("allocator reused virtual address")
	}
	regionalNodeID := "regional_node_" + suffix
	_, relayWG := networkX25519Key(t)
	_, relayDisco := networkX25519Key(t)
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_tunnel_nodes(id,edge_pool,protocol_version,process_epoch,endpoint_host,endpoint_tcp_port,endpoint_quic_port,state,ready,last_heartbeat_at,node_generation,region,failure_domain,roles,transports,capacity_limit,capacity_used,capacity_observed_at,registry_expires_at,allowed_account_ids,peer_relay_wireguard_public_key,peer_relay_disco_public_key,peer_relay_virtual_address) VALUES($1,'task8','v1',$2,'relay.example.test',443,444,'ready',true,$3,1,'hel','hel-a',ARRAY['relay','peer_relay'],ARRAY['derp_quic','peer_relay_udp'],100,20,$3,$4,ARRAY[$5],$6,$7,('fd7a:115c:a1e0::'::inet + nextval('paperboat.peer_network_virtual_address_seq')))`, regionalNodeID, "epoch_"+suffix, now, now.Add(time.Minute), userID, relayWG, relayDisco); err != nil {
		t.Fatal(err)
	}
	defer store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_tunnel_nodes WHERE id=$1`, regionalNodeID)
	// A client needs its authenticated native network without consuming a host
	// seat. Refresh must enforce the same policy as registration.
	if _, err = service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_client_config_" + suffix, UserID: userID, EndpointID: machineID}); err != nil {
		t.Fatalf("released-seat client configuration: %v", err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET setup_mode='host' WHERE id=$1`, machineID); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Register(ctx, NetworkRegistration{OperationID: "operation_network_machine_" + suffix, UserID: userID, EndpointID: machineID, Role: "machine", MachineID: machineID, EndpointGeneration: 1, MachineGeneration: 1, WireGuardPublicKey: machinePublic, DiscoPublicKey: machineDisco, QUICCertificateFingerprint: machineFingerprint[:]}); !errors.Is(err, ErrDenied) {
		t.Fatalf("released-seat host registration: %v", err)
	}
	if _, err = service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_host_released_" + suffix, UserID: userID, EndpointID: machineID}); err == nil {
		t.Fatal("released-seat host received network configuration")
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET seat_state='occupied' WHERE id=$1`, machineID); err != nil {
		t.Fatal(err)
	}
	initialCLIPrivate := append([]byte(nil), cliPrivate...)
	initialCLIConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_initial_config_" + suffix, UserID: userID, EndpointID: cliID})
	if err != nil {
		t.Fatal(err)
	}
	assertRegionalCandidates(t, initialCLIConfig.CandidateSet, userID, cliID, regionalNodeID, 1)
	assertRelayGrant(t, initialCLIConfig.RelayGrants, userID, cliID, regionalNodeID, "epoch_"+suffix, 1, cliPublic, cliDisco, cliFingerprint, nil, nil, 0, nil, nil)
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET state='draining',ready=false,drain_deadline=$2 WHERE id=$1`, regionalNodeID, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	drainingConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_draining_config_" + suffix, UserID: userID, EndpointID: cliID})
	if err != nil {
		t.Fatal(err)
	}
	assertRegionalCandidates(t, drainingConfig.CandidateSet, userID, cliID, "", 0)
	if len(drainingConfig.RelayGrants) != 0 {
		t.Fatalf("draining relay grants=%d", len(drainingConfig.RelayGrants))
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET state='ready',ready=true,drain_deadline=NULL WHERE id=$1`, regionalNodeID); err != nil {
		t.Fatal(err)
	}
	rotatedPrivate, rotatedPublic := networkX25519Key(t)
	_, rotatedDisco := networkX25519Key(t)
	if _, err = service.Register(ctx, NetworkRegistration{OperationID: "operation_network_cli_" + suffix, UserID: userID, EndpointID: cliID, Role: "cli", EndpointGeneration: 1, WireGuardPublicKey: cliPublic, DiscoPublicKey: rotatedDisco, QUICCertificateFingerprint: cliFingerprint[:]}); !errors.Is(err, ErrConflict) {
		t.Fatalf("registration replay changed disco=%v", err)
	}
	rotated, err := service.Register(ctx, NetworkRegistration{OperationID: "operation_network_rotate_" + suffix, UserID: userID, EndpointID: cliID, Role: "cli", EndpointGeneration: 1, ExpectedKeyGeneration: 1, WireGuardPublicKey: rotatedPublic, DiscoPublicKey: rotatedDisco, QUICCertificateFingerprint: cliFingerprint[:]})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.KeyGeneration != 2 || rotated.VirtualAddress != cliRegistration.VirtualAddress {
		t.Fatalf("rotation=%+v initial=%+v", rotated, cliRegistration)
	}
	cliPrivate, cliPublic = rotatedPrivate, rotatedPublic
	cliDisco = rotatedDisco
	if _, err = service.Register(ctx, NetworkRegistration{OperationID: "operation_network_wrong_role_" + suffix, UserID: userID, EndpointID: cliID, Role: "machine", MachineID: cliID, EndpointGeneration: 1, MachineGeneration: 1, WireGuardPublicKey: machinePublic, DiscoPublicKey: machineDisco, QUICCertificateFingerprint: cliFingerprint[:]}); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong role=%v", err)
	}
	if _, err = service.Register(ctx, NetworkRegistration{OperationID: "operation_network_wrong_key_" + suffix, UserID: userID, EndpointID: cliID, Role: "cli", EndpointGeneration: 1, ExpectedKeyGeneration: 2, WireGuardPublicKey: machinePublic, DiscoPublicKey: machineDisco, QUICCertificateFingerprint: machineFingerprint[:]}); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong certificate key=%v", err)
	}
	if _, err = service.Register(ctx, NetworkRegistration{OperationID: "operation_network_cross_account_" + suffix, UserID: "foreign_" + suffix, EndpointID: cliID, Role: "cli", EndpointGeneration: 1, WireGuardPublicKey: machinePublic, DiscoPublicKey: machineDisco, QUICCertificateFingerprint: cliFingerprint[:]}); !errors.Is(err, ErrDenied) {
		t.Fatalf("cross account=%v", err)
	}

	accessID := "umas_network_" + suffix
	grantExpiry := now.Add(4 * time.Minute)
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_access_sessions(id,user_machine_id,user_id,environment_id,cli_client_session_id,http_base_url,helper_terminal_session_id,helper_file_session_id,expires_at) VALUES($1,$2,$3,$4,$5,'https://machine.example.test',$6,$7,$8)`, accessID, machineID, userID, envID, cliID, "jti_terminal_"+suffix, "jti_file_"+suffix, grantExpiry); err != nil {
		t.Fatal(err)
	}
	cliConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_config_cli_" + suffix, UserID: userID, EndpointID: cliID})
	if err != nil {
		t.Fatal(err)
	}
	assertRelayGrant(t, cliConfig.RelayGrants, userID, cliID, regionalNodeID, "epoch_"+suffix, 1, cliPublic, cliDisco, cliFingerprint, machinePublic, machineDisco, 3, nil, nil)
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET configured_capabilities=array_append(configured_capabilities,'peer_relay'),observed_capabilities=array_append(observed_capabilities,'peer_relay') WHERE id=$1`, machineID); err != nil {
		t.Fatal(err)
	}
	deviceRelayConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_device_relay_cli_" + suffix, UserID: userID, EndpointID: cliID})
	if err != nil {
		t.Fatal(err)
	}
	assertRelayGrant(t, deviceRelayConfig.RelayGrants, userID, cliID, regionalNodeID, "epoch_"+suffix, 1, cliPublic, cliDisco, cliFingerprint, machinePublic, machineDisco, 3, machinePublic, machineDisco)
	deviceRelayClaims := networkClaims(t, deviceRelayConfig.RelayGrants[0])
	if peers, ok := deviceRelayClaims["relay_control_peers"].([]any); !ok || len(peers) != 1 || peers[0] != base64.RawURLEncoding.EncodeToString(machinePublic) {
		t.Fatalf("device relay control peers=%v", deviceRelayClaims["relay_control_peers"])
	}
	exerciseAdditiveAccessRelayAuthority(t, store, userID, cliID)
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.peer_network_identities SET disco_public_key=NULL WHERE user_id=$1 AND endpoint_id=$2`, userID, machineID); err != nil {
		t.Fatal(err)
	}
	derpOnly, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_config_derp_only_" + suffix, UserID: userID, EndpointID: cliID})
	if err != nil {
		t.Fatal(err)
	}
	derpClaims := networkClaims(t, derpOnly.RelayGrants[0])
	if _, ok := derpClaims["peer_relay"]; ok || derpClaims["peers"].([]any)[0].(map[string]any)["disco_public_key"] != nil {
		t.Fatalf("legacy identity received peer-relay authority=%v", derpClaims)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.peer_network_identities SET disco_public_key=$1 WHERE user_id=$2 AND endpoint_id=$3`, machineDisco, userID, machineID); err != nil {
		t.Fatal(err)
	}
	machineConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_config_machine_" + suffix, UserID: userID, EndpointID: machineID})
	if err != nil {
		t.Fatal(err)
	}
	machineRelayClaims := networkClaims(t, machineConfig.RelayGrants[0])
	if _, exists := machineRelayClaims["peer_relay"]; exists {
		t.Fatalf("relay device was instructed to allocate through itself: %v", machineRelayClaims)
	}
	assertNetworkConfig(t, cliConfig.Configuration, cliID, machineID, "dial", 3)
	assertNetworkConfig(t, machineConfig.Configuration, machineID, cliID, "accept", 3)
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_access_sessions SET expires_at=$2,updated_at=$3 WHERE id=$1`, accessID, now.Add(-time.Second), now); err != nil {
		t.Fatal(err)
	}
	expired, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_config_expired_" + suffix, UserID: userID, EndpointID: cliID})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkConfig(t, expired.Configuration, cliID, "", "", 0)
	assertRelayGrant(t, expired.RelayGrants, userID, cliID, regionalNodeID, "epoch_"+suffix, 1, cliPublic, cliDisco, cliFingerprint, nil, nil, 0, nil, nil)
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_access_sessions SET expires_at=$2,updated_at=$3 WHERE id=$1`, accessID, grantExpiry, now); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_access_sessions SET state='revoked',revoked_at=$2,revocation_reason='test',updated_at=$2 WHERE id=$1`, accessID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	revoked, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_config_revoked_" + suffix, UserID: userID, EndpointID: cliID})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkConfig(t, revoked.Configuration, cliID, "", "", 0)
	assertRelayGrant(t, revoked.RelayGrants, userID, cliID, regionalNodeID, "epoch_"+suffix, 1, cliPublic, cliDisco, cliFingerprint, nil, nil, 0, nil, nil)
	if networkGeneration(t, revoked.Configuration) <= networkGeneration(t, cliConfig.Configuration) {
		t.Fatal("revocation did not advance configuration generation")
	}
	if _, err = identityService.Revoke(ctx, "operation_machine_revoke_"+suffix, userID, machineID, 1, 1, "endpoint_removed", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_config_machine_denied_" + suffix, UserID: userID, EndpointID: machineID}); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked machine identity=%v", err)
	}

	if path := os.Getenv("PAPERBOAT_NETWORK_FIXTURE"); path != "" {
		fixture := map[string]any{"issuer": "https://api.example.test", "signing_key_id": "network-test", "signing_public_key": base64.RawURLEncoding.EncodeToString(signingPublic), "cli": networkFixtureBinding(t, cliConfig.Configuration), "machine": networkFixtureBinding(t, machineConfig.Configuration), "cli_private_key": base64.RawURLEncoding.EncodeToString(cliPrivate), "machine_private_key": base64.RawURLEncoding.EncodeToString(machinePrivate), "cli_configuration": cliConfig.Configuration, "machine_configuration": machineConfig.Configuration, "revoked_cli_configuration": revoked.Configuration}
		fixture["initial_cli_configuration"] = initialCLIConfig.Configuration
		fixture["initial_cli_private_key"] = base64.RawURLEncoding.EncodeToString(initialCLIPrivate)
		raw, marshalErr := json.Marshal(fixture)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_ = cliPublic
	exerciseNativeRelayLifecycle(t, store, service, userID, cliID, regionalNodeID)
}

func networkCertificate(t *testing.T, root ed25519.PrivateKey, account string, role peeridentity.Role, endpoint string, generation, serial uint64, issued, expires time.Time) ([]byte, [32]byte) {
	return networkCertificateWithKeys(t, root, account, role, endpoint, generation, serial, [32]byte{1}, [32]byte{2}, issued, expires)
}
func networkCertificateWithKeys(t *testing.T, root ed25519.PrivateKey, account string, role peeridentity.Role, endpoint string, generation, serial uint64, noise, quic [32]byte, issued, expires time.Time) ([]byte, [32]byte) {
	t.Helper()
	payload := []byte{'P', 'B', 'E', 'C', 1}
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(account)))
	payload = append(payload, account...)
	payload = append(payload, byte(role))
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(endpoint)))
	payload = append(payload, endpoint...)
	payload = append(payload, noise[:]...)
	payload = append(payload, quic[:]...)
	payload = binary.BigEndian.AppendUint64(payload, generation)
	payload = binary.BigEndian.AppendUint64(payload, serial)
	payload = binary.BigEndian.AppendUint64(payload, uint64(issued.Unix()))
	payload = binary.BigEndian.AppendUint64(payload, uint64(expires.Unix()))
	raw := append(payload, ed25519.Sign(root, payload)...)
	return raw, sha256.Sum256(raw)
}
func networkX25519Key(t *testing.T) ([]byte, []byte) {
	t.Helper()
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return private, public
}
func networkClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt parts=%d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err = json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
func networkFixtureBinding(t *testing.T, token string) any { return networkClaims(t, token)["self"] }
func networkGeneration(t *testing.T, token string) float64 {
	return networkClaims(t, token)["generation"].(float64)
}
func assertRegionalCandidates(t *testing.T, token, accountID, endpointID, nodeID string, count int) {
	t.Helper()
	claims := networkClaims(t, token)
	if claims["schema"] != "paperboat.regional-candidates.v1" || claims["aud"] != "paperboat-regional-candidates" || claims["account_id"] != accountID || claims["endpoint_id"] != endpointID {
		t.Fatalf("regional binding=%v", claims)
	}
	nodes := claims["nodes"].([]any)
	if len(nodes) != count || count > 0 && nodes[0].(map[string]any)["node_id"] != nodeID {
		t.Fatalf("regional nodes=%v", nodes)
	}
	if claims["exp"].(float64)-claims["iat"].(float64) > 60 {
		t.Fatalf("regional validity=%v", claims)
	}
}
func assertRelayGrant(t *testing.T, tokens []string, accountID, endpointID, nodeID, processEpoch string, nodeGeneration int64, selfKey, selfDisco []byte, fingerprint [32]byte, peerKey, peerDisco []byte, scopeCount int, relayWG, relayDisco []byte) {
	t.Helper()
	if len(tokens) != 1 {
		t.Fatalf("relay grants=%d", len(tokens))
	}
	claims := networkClaims(t, tokens[0])
	if claims["version"] != float64(1) || claims["aud"] != "paperboat-relay" || claims["account_id"] != accountID || claims["endpoint_id"] != endpointID || claims["node_id"] != nodeID || claims["process_epoch"] != processEpoch || claims["node_generation"] != float64(nodeGeneration) {
		t.Fatalf("relay binding=%v", claims)
	}
	if claims["wireguard_public_key"] != base64.RawURLEncoding.EncodeToString(selfKey) || claims["disco_public_key"] != base64.RawURLEncoding.EncodeToString(selfDisco) || claims["quic_certificate_fingerprint"] != hex.EncodeToString(fingerprint[:]) || claims["exp"].(float64)-claims["iat"].(float64) > 60 {
		t.Fatalf("relay identity/lifetime=%v", claims)
	}
	descriptor, hasDescriptor := claims["peer_relay"].(map[string]any)
	if relayWG == nil || relayDisco == nil {
		if hasDescriptor {
			t.Fatalf("unconfigured account received peer relay descriptor=%v", descriptor)
		}
	} else if !hasDescriptor || descriptor["wireguard_public_key"] != base64.RawURLEncoding.EncodeToString(relayWG) || descriptor["disco_public_key"] != base64.RawURLEncoding.EncodeToString(relayDisco) || descriptor["virtual_address"] == "" {
		t.Fatalf("peer relay descriptor=%v", descriptor)
	}
	peers := claims["peers"].([]any)
	if peerKey == nil {
		if len(peers) != 0 {
			t.Fatalf("relay peers=%v", peers)
		}
		return
	}
	if len(peers) != 1 {
		t.Fatalf("relay peers=%v", peers)
	}
	peer := peers[0].(map[string]any)
	if peer["wireguard_public_key"] != base64.RawURLEncoding.EncodeToString(peerKey) || peer["disco_public_key"] != base64.RawURLEncoding.EncodeToString(peerDisco) || len(peer["scopes"].([]any)) != scopeCount {
		t.Fatalf("relay peer=%v", peer)
	}
}
func assertNetworkConfig(t *testing.T, token, self, peer, direction string, scopeCount int) {
	t.Helper()
	claims := networkClaims(t, token)
	binding := claims["self"].(map[string]any)
	if binding["endpoint_id"] != self {
		t.Fatalf("self=%v", binding)
	}
	peers := claims["peers"].([]any)
	if peer == "" {
		if len(peers) != 0 {
			t.Fatalf("peers=%v", peers)
		}
		return
	}
	if len(peers) != 1 {
		t.Fatalf("peers=%v", peers)
	}
	entry := peers[0].(map[string]any)
	if entry["identity"].(map[string]any)["endpoint_id"] != peer {
		t.Fatalf("peer=%v", entry)
	}
	scopes := entry["scopes"].([]any)
	if len(scopes) != scopeCount {
		t.Fatalf("scopes=%v", scopes)
	}
	for _, raw := range scopes {
		if raw.(map[string]any)["direction"] != direction {
			t.Fatalf("scope=%v", raw)
		}
	}
}

func assertNetworkScope(t *testing.T, token, kind, resourceID, capability string) {
	t.Helper()
	claims := networkClaims(t, token)
	for _, rawPeer := range claims["peers"].([]any) {
		for _, rawScope := range rawPeer.(map[string]any)["scopes"].([]any) {
			scope := rawScope.(map[string]any)
			if scope["resource_kind"] == kind && scope["resource_id"] == resourceID && scope["capability"] == capability {
				return
			}
		}
	}
	t.Fatalf("scope %s/%s capability %s not found", kind, resourceID, capability)
}
