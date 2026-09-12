package peersessions

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/helperruntime"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
	"github.com/pinksaucepasta/paperboat-server/internal/teaminbox"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

func TestNetworkAuthorityProductionIdentityAndAccessLifecycle(t *testing.T) {
	holdBinary := os.Getenv("PAPERBOAT_TASK40_RUNTIME_HOLD_BIN")
	if holdBinary == "" {
		t.Skip("PAPERBOAT_TASK40_RUNTIME_HOLD_BIN is required for actual terminal-sharing runtime snapshots")
	}
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
	cliTLSDER, cliTLSPrivate, cliQUICPublic := networkEndpointTLS(t, "cli", now)
	cliRaw, cliFingerprint := networkCertificateWithKeys(t, rootPrivate, userID, peeridentity.RoleCLI, cliID, 1, 1, [32]byte{1}, cliQUICPublic, now, now.Add(time.Hour))
	_, err = identityService.Bootstrap(ctx, peeridentity.BootstrapRequest{CLIClientSessionID: cliID, RootPublicKey: rootPublic, RegisterRequest: peeridentity.RegisterRequest{OperationID: "operation_bootstrap_" + suffix, UserID: userID, KeyID: keyID, Certificate: cliRaw, Expected: peeridentity.Expected{AccountID: userID, Role: peeridentity.RoleCLI, EndpointID: cliID, Generation: 1, Serial: 1}, ExpectedRootFingerprint: rootFingerprint, ExpectedCertificateFingerprint: cliFingerprint, ExpectedIssuedAt: now, ExpectedExpiresAt: now.Add(time.Hour), Now: now}})
	if err != nil {
		t.Fatal(err)
	}
	machineTLSDER, machineTLSPrivate, machineQUICPublic := networkEndpointTLS(t, "machine", now)
	request, err := identityService.RequestMachineEndpoint(ctx, peeridentity.MachineEndpointRequest{OperationID: "operation_machine_request_" + suffix, UserID: userID, EndpointID: machineID, Generation: 1, NoisePublicKey: [32]byte{3}, QUICPublicKey: machineQUICPublic, Now: now})
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
	cliDisco := networkDiscoPublic(t, cliPrivate)
	machineDisco := networkDiscoPublic(t, machinePrivate)
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
	rotatedDisco := networkDiscoPublic(t, rotatedPrivate)
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
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_access_sessions(id,user_machine_id,user_id,environment_id,cli_client_session_id,http_base_url,helper_terminal_session_id,helper_file_session_id,capabilities,operation_id,expires_at) VALUES($1,$2,$3,$4,$5,'https://machine.example.test',$6,$7,ARRAY['terminal','files','private_access'],$8,$9)`, accessID, machineID, userID, envID, cliID, "jti_terminal_"+suffix, "jti_file_"+suffix, "operation_access_"+suffix, grantExpiry); err != nil {
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

	// A teammate keeps an independently rooted CLI identity. The signed network
	// projection joins that identity to the enrolled owner's exact machine key;
	// it never copies either account's private identity material.
	sharedUser, sharedCLI, teamID := "network_shared_user_"+suffix, "network_shared_cli_"+suffix, "network_team_"+suffix
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$2,$3,'active')`, sharedUser, "workos_"+sharedUser, sharedUser+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions(id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES($1,$2,$3,'shared network test','desktop','test',ARRAY['projects:connect'],'active',$4,$4)`, sharedCLI, sharedUser, "client_shared_"+suffix, now); err != nil {
		t.Fatal(err)
	}
	sharedRootPublic, sharedRootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sharedRootFingerprint := sha256.Sum256(sharedRootPublic)
	sharedKeyID, _ := peeridentity.KeyID(sharedRootPublic)
	sharedTLSDER, sharedTLSPrivate, sharedQUICPublic := networkEndpointTLS(t, "shared", now)
	sharedRaw, sharedFingerprint := networkCertificateWithKeys(t, sharedRootPrivate, sharedUser, peeridentity.RoleCLI, sharedCLI, 1, 1, [32]byte{1}, sharedQUICPublic, now, now.Add(time.Hour))
	if _, err = identityService.Bootstrap(ctx, peeridentity.BootstrapRequest{CLIClientSessionID: sharedCLI, RootPublicKey: sharedRootPublic, RegisterRequest: peeridentity.RegisterRequest{OperationID: "operation_shared_bootstrap_" + suffix, UserID: sharedUser, KeyID: sharedKeyID, Certificate: sharedRaw, Expected: peeridentity.Expected{AccountID: sharedUser, Role: peeridentity.RoleCLI, EndpointID: sharedCLI, Generation: 1, Serial: 1}, ExpectedRootFingerprint: sharedRootFingerprint, ExpectedCertificateFingerprint: sharedFingerprint, ExpectedIssuedAt: now, ExpectedExpiresAt: now.Add(time.Hour), Now: now}}); err != nil {
		t.Fatal(err)
	}
	sharedPrivate, sharedPublic := networkX25519Key(t)
	sharedDisco := networkDiscoPublic(t, sharedPrivate)
	if _, err = service.Register(ctx, NetworkRegistration{OperationID: "operation_shared_network_" + suffix, UserID: sharedUser, EndpointID: sharedCLI, Role: "cli", EndpointGeneration: 1, WireGuardPublicKey: sharedPublic, DiscoPublicKey: sharedDisco, QUICCertificateFingerprint: sharedFingerprint[:]}); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.teams(team_id,owner_account,generation) VALUES($1,$2,1)`, []any{teamID, userID}},
		{`INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'admin',true)`, []any{teamID, userID}},
		{`INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true)`, []any{teamID, sharedUser}},
		{`INSERT INTO paperboat.team_resource_bindings(team_id,resource_kind,resource_id,owner_account) VALUES($1,'machine',$2,$3)`, []any{teamID, machineID, userID}},
		{`INSERT INTO paperboat.team_machine_grants(team_id,machine_id,audience,account_id,capabilities) VALUES($1,$2,'selected_member',$3,ARRAY['terminal','exec','managed_ssh','files'])`, []any{teamID, machineID, sharedUser}},
		{`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation) VALUES($1,$2,$3,'Shared source','linux','amd64','/source','online','occupied',true,1)`, []any{"network_shared_source_" + suffix, sharedUser, "network_shared_source_env_" + suffix}},
		{`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation) VALUES($1,$2,$3,'Owner source','linux','amd64','/owner-source','online','occupied',true,1)`, []any{"network_owner_source_" + suffix, userID, "network_owner_source_env_" + suffix}},
		{`UPDATE paperboat.user_machines SET observed_capabilities=configured_capabilities WHERE id=$1`, []any{machineID}},
		{`INSERT INTO paperboat.control_helpers(id,environment_id,state) VALUES($1,$2,'active')`, []any{"network_helper_" + suffix, envID}},
		{`INSERT INTO paperboat.control_connector_generations(environment_id,machine_id,generation,edge_pool,edge_node_id,state) VALUES($1,$2,1,'task8',$3,'admitted')`, []any{envID, machineID, regionalNodeID}},
		{`INSERT INTO paperboat.control_routes(id,environment_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation) VALUES($1,$2,'runtime_https_wss',$3,'127.0.0.1',8080,1,1,$4,1)`, []any{"network_route_" + suffix, envID, "network-" + suffix + ".example.test", regionalNodeID}},
	} {
		if _, err = store.SQL().ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	machineService := usermachines.New(store, audit.NewWriter(store), usermachines.Policy{}, nil)
	machineService.ConfigureAccess(nil, "https://api.example.test", 5*time.Minute)
	machineService.ConfigureTerminalSessions(4, provider, nil)
	machineService.ConfigureFileTransfer(accessdescriptor.FileTransferPolicy{Revision: "shared-native-v1", MaxFileBytes: 1 << 20, MaxBatchFiles: 2, MaxBatchBytes: 2 << 20, MaxConcurrentTransfers: 2, RetentionSeconds: 60, DeliveryTimeoutSeconds: 60, MaxPendingSpoolBytes: 2 << 20})
	execOperationID := "operation_shared_exec_" + suffix
	execDescriptor, err := machineService.ExecDescriptor(ctx, sharedUser, "network_shared_source_"+suffix, machineID, sharedCLI, execOperationID)
	if err != nil {
		t.Fatal(err)
	}
	sharedAccess, _ := execDescriptor.Auth["access_session_id"].(string)
	if sharedAccess == "" || execDescriptor.Auth["token"] == "" {
		t.Fatalf("shared exec descriptor=%#v", execDescriptor)
	}
	ownerExecDescriptor, err := machineService.ExecDescriptor(ctx, userID, "network_owner_source_"+suffix, machineID, cliID, "operation_owner_exec_"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	activeExecDescriptor, err := machineService.ExecDescriptor(ctx, sharedUser, "network_shared_source_"+suffix, machineID, sharedCLI, "operation_shared_active_exec_"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	afterDisableExecDescriptor, err := machineService.ExecDescriptor(ctx, sharedUser, "network_shared_source_"+suffix, machineID, sharedCLI, "operation_shared_after_disable_exec_"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	sharedTerminalID := "umts_network_shared_" + suffix
	if _, err = store.Queries().CreateUserMachineTerminalSession(ctx, dbsqlc.CreateUserMachineTerminalSessionParams{ID: sharedTerminalID, UserMachineID: machineID, OwnerAccount: sharedUser, TerminalID: "term_network_shared_" + suffix, Name: "shared-shell", LaunchCwd: "/workspace"}); err != nil {
		t.Fatal(err)
	}
	terminalDescriptor, err := machineService.ConnectTerminalSession(ctx, sharedUser, "network_shared_source_"+suffix, machineID, sharedCLI, sharedTerminalID)
	if err != nil || !terminalDescriptor.Connectable {
		t.Fatalf("shared terminal connectable=%v status=%q reason=%q err=%v", terminalDescriptor.Connectable, terminalDescriptor.Status, terminalDescriptor.Reason, err)
	}
	ownerSharedTerminalID := "umts_network_owner_shared_" + suffix
	if _, err = store.Queries().CreateUserMachineTerminalSession(ctx, dbsqlc.CreateUserMachineTerminalSessionParams{ID: ownerSharedTerminalID, UserMachineID: machineID, OwnerAccount: userID, TerminalID: "term_network_owner_shared_" + suffix, Name: "owner-shared-shell", LaunchCwd: "/workspace"}); err != nil {
		t.Fatal(err)
	}
	ownerSharedTerminalDescriptor, err := machineService.ConnectTerminalSession(ctx, userID, "network_owner_source_"+suffix, machineID, cliID, ownerSharedTerminalID)
	if err != nil || !ownerSharedTerminalDescriptor.Connectable {
		t.Fatalf("owner shared terminal connectable=%v status=%q reason=%q err=%v", ownerSharedTerminalDescriptor.Connectable, ownerSharedTerminalDescriptor.Status, ownerSharedTerminalDescriptor.Reason, err)
	}
	var heldRuntime helperruntime.Client
	var heldRoute, heldOwnerToken string
	if holdBinary != "" {
		listenAddress := os.Getenv("PAPERBOAT_NETWORK_RUNTIME_LISTEN")
		if listenAddress == "" {
			listenAddress = "100.95.70.63:15443"
		}
		holdDir := t.TempDir()
		holdInput := filepath.Join(holdDir, "runtime.json")
		ownerAuth := ownerSharedTerminalDescriptor.Terminal["auth"].(map[string]any)
		holdDocument, _ := json.Marshal(map[string]any{"issuer": "https://api.example.test", "key_id": "network-test", "public_key": base64.RawURLEncoding.EncodeToString(signingPublic), "owner_token": ownerAuth["token"], "environment_id": envID, "machine_id": machineID, "session_id": ownerSharedTerminalID, "account_id": userID, "listen_address": listenAddress})
		if err = os.WriteFile(holdInput, holdDocument, 0o600); err != nil {
			t.Fatal(err)
		}
		hold := exec.Command(holdBinary, "-test.run", "^TestTask40HoldBrowserRuntime$", "-test.timeout", "5m")
		hold.Env = append(os.Environ(), "PAPERBOAT_TASK40_BROWSER_RUNTIME="+holdInput)
		if err = hold.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = os.WriteFile(filepath.Join(holdDir, "runtime-stop"), []byte("stop"), 0o600)
			_ = hold.Wait()
		}()
		readyPath := filepath.Join(holdDir, "runtime-ready.json")
		var ready struct {
			PublicHost string `json:"public_host"`
			CertPEM    string `json:"cert_pem"`
		}
		deadline := time.Now().Add(15 * time.Second)
		for {
			readyBytes, readErr := os.ReadFile(readyPath)
			if readErr == nil && json.Unmarshal(readyBytes, &ready) == nil && ready.PublicHost != "" && ready.CertPEM != "" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("real terminal runtime fixture did not become ready")
			}
			time.Sleep(20 * time.Millisecond)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(ready.CertPEM)) {
			t.Fatal("runtime fixture certificate is invalid")
		}
		if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.control_routes SET public_host=$2 WHERE id=$1`, "network_route_"+suffix, ready.PublicHost); err != nil {
			t.Fatal(err)
		}
		heldRuntime = helperruntime.Client{HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, Timeout: 10 * time.Second}}
		heldRoute, heldOwnerToken = "https://"+ready.PublicHost, ownerAuth["token"].(string)
		machineService.ConfigureTerminalSessions(4, provider, heldRuntime.HTTPClient)
	}
	terminalOwnerConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_terminal_owner_config_" + suffix, UserID: userID, EndpointID: cliID})
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PAPERBOAT_TERMINAL_SHARING_FIXTURE") != "" {
		if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.team_machine_grants SET active=false WHERE team_id=$1 AND machine_id=$2 AND account_id=$3`, teamID, machineID, sharedUser); err != nil {
			t.Fatal(err)
		}
	}
	viewerTeam, err := machineService.GrantTerminalSessionSharing(ctx, userID, teamID, ownerSharedTerminalID, teams.TerminalSessionGrantRequest{OperationID: "operation_terminal_view_" + suffix, ExpectedGeneration: 1, Audience: "selected_member", AccountID: sharedUser, Role: "viewer", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	viewerTerminalDescriptor, err := machineService.ConnectSharedTerminalSession(ctx, sharedUser, "network_shared_source_"+suffix, sharedCLI, ownerSharedTerminalID)
	if err != nil || !viewerTerminalDescriptor.Connectable {
		t.Fatalf("viewer terminal connectable=%v status=%q reason=%q err=%v", viewerTerminalDescriptor.Connectable, viewerTerminalDescriptor.Status, viewerTerminalDescriptor.Reason, err)
	}
	viewerAccessID := viewerTerminalDescriptor.Terminal["auth"].(map[string]any)["access_session_id"].(string)
	var viewerJTI string
	if err = store.SQL().QueryRowContext(ctx, `SELECT helper_terminal_session_id FROM paperboat.user_machine_access_sessions WHERE id=$1`, viewerAccessID).Scan(&viewerJTI); err != nil {
		t.Fatal(err)
	}
	terminalViewerConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_terminal_viewer_config_" + suffix, UserID: sharedUser, EndpointID: sharedCLI})
	if err != nil {
		t.Fatal(err)
	}
	terminalViewerMachineConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_terminal_viewer_machine_config_" + suffix, UserID: userID, EndpointID: machineID})
	if err != nil {
		t.Fatal(err)
	}
	interactiveTeam, err := machineService.GrantTerminalSessionSharing(ctx, userID, teamID, ownerSharedTerminalID, teams.TerminalSessionGrantRequest{OperationID: "operation_terminal_control_" + suffix, ExpectedGeneration: viewerTeam.Sharing.Generation, Audience: "selected_member", AccountID: sharedUser, Role: "interactive", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	interactiveTerminalDescriptor, err := machineService.ConnectSharedTerminalSession(ctx, sharedUser, "network_shared_source_"+suffix, sharedCLI, ownerSharedTerminalID)
	if err != nil || !interactiveTerminalDescriptor.Connectable {
		t.Fatalf("interactive terminal connectable=%v status=%q reason=%q err=%v", interactiveTerminalDescriptor.Connectable, interactiveTerminalDescriptor.Status, interactiveTerminalDescriptor.Reason, err)
	}
	terminalInteractiveConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_terminal_interactive_config_" + suffix, UserID: sharedUser, EndpointID: sharedCLI})
	if err != nil {
		t.Fatal(err)
	}
	terminalInteractiveMachineConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_terminal_interactive_machine_config_" + suffix, UserID: userID, EndpointID: machineID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = machineService.RemoveTerminalParticipant(ctx, userID, ownerSharedTerminalID, sharedUser, "operation_terminal_remove_"+suffix, interactiveTeam.Sharing.Generation); err != nil {
		t.Fatal(err)
	}
	terminalRevokedConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_terminal_revoked_config_" + suffix, UserID: sharedUser, EndpointID: sharedCLI})
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("PAPERBOAT_TERMINAL_SHARING_FIXTURE"); path != "" {
		fixture := map[string]any{
			"issuer": "https://api.example.test", "signing_key_id": "network-test", "signing_public_key": base64.RawURLEncoding.EncodeToString(signingPublic),
			"cli": networkFixtureBinding(t, cliConfig.Configuration), "shared_cli": networkFixtureBinding(t, terminalViewerConfig.Configuration), "machine": networkFixtureBinding(t, terminalViewerMachineConfig.Configuration),
			"cli_private_key": base64.RawURLEncoding.EncodeToString(cliPrivate), "shared_cli_private_key": base64.RawURLEncoding.EncodeToString(sharedPrivate), "machine_private_key": base64.RawURLEncoding.EncodeToString(machinePrivate),
			"owner_shared_configuration": terminalOwnerConfig.Configuration, "terminal_viewer_configuration": terminalViewerConfig.Configuration, "terminal_viewer_machine_configuration": terminalViewerMachineConfig.Configuration,
			"terminal_interactive_configuration": terminalInteractiveConfig.Configuration, "terminal_interactive_machine_configuration": terminalInteractiveMachineConfig.Configuration, "terminal_revoked_configuration": terminalRevokedConfig.Configuration,
			"terminal_owner_descriptor": ownerSharedTerminalDescriptor, "terminal_viewer_descriptor": viewerTerminalDescriptor, "terminal_interactive_descriptor": interactiveTerminalDescriptor, "terminal_viewer_jti": viewerJTI,
			"exec_descriptor": execDescriptor, "owner_exec_descriptor": ownerExecDescriptor, "environment_id": envID, "helper_id": "network_helper_" + suffix,
			"owner_cli_tls_der": base64.RawURLEncoding.EncodeToString(cliTLSDER), "owner_cli_tls_private": base64.RawURLEncoding.EncodeToString(cliTLSPrivate),
			"shared_cli_tls_der": base64.RawURLEncoding.EncodeToString(sharedTLSDER), "shared_cli_tls_private": base64.RawURLEncoding.EncodeToString(sharedTLSPrivate),
			"machine_tls_der": base64.RawURLEncoding.EncodeToString(machineTLSDER), "machine_tls_private": base64.RawURLEncoding.EncodeToString(machineTLSPrivate),
		}
		encoded, encodeErr := json.Marshal(fixture)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		if writeErr := os.WriteFile(path, encoded, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		active, grantErr := machineService.TerminalSessionSharing(ctx, userID, ownerSharedTerminalID)
		if grantErr != nil {
			t.Fatal(grantErr)
		}
		active, grantErr = machineService.GrantTerminalSessionSharing(ctx, userID, teamID, ownerSharedTerminalID, teams.TerminalSessionGrantRequest{OperationID: "operation_terminal_restart_old_grant_" + suffix, ExpectedGeneration: active.Sharing.Generation, Audience: "selected_member", AccountID: sharedUser, Role: "viewer", Active: true})
		if grantErr != nil {
			t.Fatal(grantErr)
		}
		if _, closeErr := heldRuntime.Terminal(ctx, heldRoute, heldOwnerToken, "close", ownerSharedTerminalID, "operation_t40_close"); closeErr != nil {
			t.Fatal(closeErr)
		}
		restarted, restartErr := heldRuntime.Terminal(ctx, heldRoute, heldOwnerToken, "restart", ownerSharedTerminalID, "operation_t40_restart")
		if restartErr != nil || restarted.Generation != 2 {
			t.Fatalf("runtime restart generation=%d err=%v", restarted.Generation, restartErr)
		}
		if stale, staleErr := machineService.ConnectSharedTerminalSession(ctx, sharedUser, "network_shared_source_"+suffix, sharedCLI, ownerSharedTerminalID); !errors.Is(staleErr, usermachines.ErrTerminalSessionNotFound) || stale.Connectable {
			t.Fatalf("stale generation connectable=%v status=%q reason=%q expected terminal-session-not-found=%v", stale.Connectable, stale.Status, stale.Reason, errors.Is(staleErr, usermachines.ErrTerminalSessionNotFound))
		}
		current, currentErr := machineService.TerminalSessionSharing(ctx, userID, ownerSharedTerminalID)
		if currentErr != nil {
			t.Fatal(currentErr)
		}
		if current.Sharing.Audience != "none" {
			t.Fatalf("sharing audience after restart=%q", current.Sharing.Audience)
		}
		freshTeam, teamErr := teams.NewService(store).Get(ctx, userID, teamID)
		if teamErr != nil {
			t.Fatal(teamErr)
		}
		if _, grantErr = machineService.GrantTerminalSessionSharing(ctx, userID, teamID, ownerSharedTerminalID, teams.TerminalSessionGrantRequest{OperationID: "operation_terminal_restart_fresh_grant_" + suffix, ExpectedGeneration: freshTeam.Generation, Audience: "selected_member", AccountID: sharedUser, Role: "viewer", Active: true}); grantErr != nil {
			t.Fatal(grantErr)
		}
		fresh, freshErr := machineService.ConnectSharedTerminalSession(ctx, sharedUser, "network_shared_source_"+suffix, sharedCLI, ownerSharedTerminalID)
		if freshErr != nil || !fresh.Connectable {
			t.Fatalf("fresh generation connectable=%v status=%q reason=%q err=%v", fresh.Connectable, fresh.Status, fresh.Reason, freshErr)
		}
		freshAuth := fresh.Terminal["auth"].(map[string]any)
		parts := strings.Split(freshAuth["token"].(string), ".")
		if len(parts) != 3 {
			t.Fatal("fresh generation credential is malformed")
		}
		payload, decodeErr := base64.RawURLEncoding.DecodeString(parts[1])
		var freshClaims struct {
			ExpectedGeneration uint64 `json:"expected_generation"`
		}
		if decodeErr != nil || json.Unmarshal(payload, &freshClaims) != nil || freshClaims.ExpectedGeneration != 2 {
			t.Fatalf("fresh credential expected_generation=%d", freshClaims.ExpectedGeneration)
		}
		return
	}
	inbox, err := teaminbox.New(store)
	if err != nil {
		t.Fatal(err)
	}
	machineService.ConfigureTeamInbox(inbox)
	if _, err = machineService.FileTransferDescriptor(ctx, sharedUser, "network_shared_source_"+suffix, machineID, sharedCLI, ""); !errors.Is(err, teaminbox.ErrPending) {
		t.Fatalf("cross-account descriptor without acceptance error=%v", err)
	}
	filePayload := []byte("server-issued-native-file")
	fileDigest := sha256.Sum256(filePayload)
	fileBatchID := "shared-native-batch-" + suffix
	fileRequest, err := inbox.Create(ctx, teaminbox.RequestInput{
		RequestID: "network_inbox_" + suffix, OperationID: "network_inbox_create_" + suffix,
		SenderAccount: sharedUser, SourceMachineID: "network_shared_source_" + suffix,
		DestinationMachineID: machineID, BatchID: fileBatchID,
		Files:     []teaminbox.File{{Basename: "shared.txt", Size: int64(len(filePayload)), SHA256: hex.EncodeToString(fileDigest[:])}},
		ExpiresAt: now.Add(5 * time.Minute),
	})
	if err != nil || fileRequest.Status != "pending" {
		t.Fatalf("manual Inbox request status=%q error=%v", fileRequest.Status, err)
	}
	if _, err = machineService.FileTransferDescriptorForRequest(ctx, sharedUser, "network_shared_source_"+suffix, machineID, sharedCLI, "", fileRequest.RequestID, fileRequest.ManifestDigest); !errors.Is(err, teaminbox.ErrPending) {
		t.Fatalf("pending Inbox descriptor error=%v", err)
	}
	if _, err = inbox.Decide(ctx, userID, fileRequest.RequestID, "approved", fileRequest.DecisionGeneration); err != nil {
		t.Fatal(err)
	}
	ownRequest, err := inbox.Create(ctx, teaminbox.RequestInput{
		RequestID: "network_own_inbox_" + suffix, OperationID: "network_own_inbox_create_" + suffix,
		SenderAccount: userID, SourceMachineID: "network_owner_source_" + suffix,
		DestinationMachineID: machineID, BatchID: "own-" + fileBatchID, Files: fileRequest.Files,
		ExpiresAt: now.Add(5 * time.Minute),
	})
	if err != nil || ownRequest.Status != "not_required" {
		t.Fatalf("own-device Inbox status=%q error=%v", ownRequest.Status, err)
	}
	if _, err = machineService.FileTransferDescriptor(ctx, userID, "network_owner_source_"+suffix, machineID, cliID, ""); err != nil {
		t.Fatalf("own-device descriptor without acceptance: %v", err)
	}
	fileDescriptor, err := machineService.FileTransferDescriptorForRequest(ctx, sharedUser, "network_shared_source_"+suffix, machineID, sharedCLI, "", fileRequest.RequestID, fileRequest.ManifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	sshHostPublicRaw, sshHostPrivateRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshClientPublicRaw, sshClientPrivateRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshHostPublicKey, _ := ssh.NewPublicKey(sshHostPublicRaw)
	sshClientPublicKey, _ := ssh.NewPublicKey(sshClientPublicRaw)
	sshHostPrivateBlock, _ := ssh.MarshalPrivateKey(sshHostPrivateRaw, "")
	sshClientPrivateBlock, _ := ssh.MarshalPrivateKey(sshClientPrivateRaw, "")
	sshHostPublic := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshHostPublicKey)))
	sshClientPublic := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshClientPublicKey)))
	sshHostPrivate := pem.EncodeToMemory(sshHostPrivateBlock)
	sshClientPrivate := pem.EncodeToMemory(sshClientPrivateBlock)
	sshFingerprint := sha256.Sum256(sshHostPublicKey.Marshal())
	sshClientFingerprint := sha256.Sum256(sshClientPublicKey.Marshal())
	sshSetFingerprint := sha256.Sum256([]byte("network-shared-ssh-set-" + suffix))
	sshSetID := "sshks_network_shared_" + suffix
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.machine_ssh_targets(user_machine_id,machine_generation,os_user,target_port,reconciliation_version,created_at,updated_at) VALUES($1,1,'paperboat',22,1,$2,$2)`, []any{machineID, now}},
		{`INSERT INTO paperboat.machine_ssh_host_key_owners(fingerprint,user_machine_id,algorithm,public_key,first_observed_at) VALUES($1,$2,'ssh-ed25519',$3,$4)`, []any{sshFingerprint[:], machineID, sshHostPublic, now}},
		{`INSERT INTO paperboat.managed_ssh_client_keys(fingerprint,user_id,cli_client_session_id,algorithm,public_key) VALUES($1,$2,$3,'ssh-ed25519',$4)`, []any{sshClientFingerprint[:], sharedUser, sharedCLI, sshClientPublic}},
		{`INSERT INTO paperboat.machine_ssh_host_key_sets(id,user_machine_id,machine_generation,observation_generation,set_fingerprint,state,reconciliation_version,observed_at,promoted_at) VALUES($1,$2,1,1,$3,'active',1,$4,$4)`, []any{sshSetID, machineID, sshSetFingerprint[:], now}},
		{`INSERT INTO paperboat.machine_ssh_host_keys(set_id,user_machine_id,fingerprint,ordinal) VALUES($1,$2,$3,0)`, []any{sshSetID, machineID, sshFingerprint[:]}},
	} {
		if _, err = store.SQL().ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	sshDescriptor, err := machineService.SSHDescriptor(ctx, sharedUser, "network_shared_source_"+suffix, machineID, sharedCLI, "operation_shared_ssh_"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	sharedConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_shared_config_" + suffix, UserID: sharedUser, EndpointID: sharedCLI})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkScope(t, sharedConfig.Configuration, "machine_access", sharedAccess, "exec")
	terminalAccess := terminalDescriptor.Terminal["auth"].(map[string]any)["access_session_id"].(string)
	assertNetworkScope(t, sharedConfig.Configuration, "machine_access", terminalAccess, "terminal")
	assertNetworkScope(t, sharedConfig.Configuration, "machine_access", sshDescriptor.Auth["access_session_id"].(string), "managed_ssh")
	assertNetworkScope(t, sharedConfig.Configuration, "machine_access", fileDescriptor.Auth["access_session_id"].(string), "file_transfer")
	assertNetworkPeerAccount(t, sharedConfig.Configuration, machineID, userID)
	assertNoNetworkCapability(t, sharedConfig.Configuration, "private_access")
	ownerSharedConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_owner_shared_" + suffix, UserID: userID, EndpointID: cliID})
	if err != nil {
		t.Fatal(err)
	}
	machineSharedConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_machine_shared_" + suffix, UserID: userID, EndpointID: machineID})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkPeerAccount(t, machineSharedConfig.Configuration, sharedCLI, sharedUser)
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET configured_capabilities=array_remove(configured_capabilities,'file_receive') WHERE id=$1`, machineID); err != nil {
		t.Fatal(err)
	}
	sharedDeviceDisabled, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_shared_file_disabled_" + suffix, UserID: sharedUser, EndpointID: sharedCLI})
	if err != nil {
		t.Fatal(err)
	}
	machineDeviceDisabled, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_machine_file_disabled_" + suffix, UserID: userID, EndpointID: machineID})
	if err != nil {
		t.Fatal(err)
	}
	assertNoNetworkCapability(t, sharedDeviceDisabled.Configuration, "file_transfer")
	if _, err = machineService.FileTransferDescriptor(ctx, sharedUser, "network_shared_source_"+suffix, machineID, sharedCLI, ""); !errors.Is(err, usermachines.ErrMachineCapabilityUnavailable) {
		t.Fatalf("disabled file receive descriptor error=%v", err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.team_machine_grants SET active=false WHERE team_id=$1 AND machine_id=$2 AND account_id=$3`, teamID, machineID, sharedUser); err != nil {
		t.Fatal(err)
	}
	withdrawnShared, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_shared_withdrawn_" + suffix, UserID: sharedUser, EndpointID: sharedCLI})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkConfig(t, withdrawnShared.Configuration, sharedCLI, "", "", 0)
	machineWithdrawnConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_machine_shared_withdrawn_" + suffix, UserID: userID, EndpointID: machineID})
	if err != nil {
		t.Fatal(err)
	}
	assertNoNetworkPeer(t, machineWithdrawnConfig.Configuration, sharedCLI)
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.team_machine_grants SET active=true WHERE team_id=$1 AND machine_id=$2 AND account_id=$3`, teamID, machineID, sharedUser); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET owner_team_id=$2 WHERE id=$1`, machineID, teamID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.teams SET owner_account=$2,generation=generation+1 WHERE team_id=$1`, teamID, sharedUser); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.team_members SET active=false WHERE team_id=$1 AND account_id=$2`, teamID, userID); err != nil {
		t.Fatal(err)
	}
	finalSharedExec, err := machineService.ExecDescriptor(ctx, sharedUser, "network_shared_source_"+suffix, machineID, sharedCLI, "operation_shared_after_owner_left_"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	finalSharedConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_shared_after_owner_left_config_" + suffix, UserID: sharedUser, EndpointID: sharedCLI})
	if err != nil {
		t.Fatal(err)
	}
	finalMachineConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_machine_after_owner_left_config_" + suffix, UserID: userID, EndpointID: machineID})
	if err != nil {
		t.Fatal(err)
	}
	removedOwnerConfig, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_removed_owner_config_" + suffix, UserID: userID, EndpointID: cliID})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkScope(t, finalSharedConfig.Configuration, "machine_access", finalSharedExec.Auth["access_session_id"].(string), "exec")
	assertNoNetworkPeer(t, removedOwnerConfig.Configuration, machineID)
	ownerAccessID, _ := ownerExecDescriptor.Auth["access_session_id"].(string)
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_access_sessions SET state='revoked',revoked_at=$2,revocation_reason='fixture_complete',updated_at=$2 WHERE id=$1`, ownerAccessID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_access_sessions SET expires_at=$2,updated_at=$3 WHERE id=$1`, accessID, now.Add(-time.Second), now); err != nil {
		t.Fatal(err)
	}
	expired, err := service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_config_expired_" + suffix, UserID: userID, EndpointID: cliID})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkConfig(t, expired.Configuration, cliID, "", "", 0)
	assertRelayGrant(t, expired.RelayGrants, userID, cliID, regionalNodeID, "epoch_"+suffix, 1, cliPublic, cliDisco, cliFingerprint, nil, nil, 0, machinePublic, machineDisco)
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
	assertRelayGrant(t, revoked.RelayGrants, userID, cliID, regionalNodeID, "epoch_"+suffix, 1, cliPublic, cliDisco, cliFingerprint, nil, nil, 0, machinePublic, machineDisco)
	if networkGeneration(t, revoked.Configuration) <= networkGeneration(t, cliConfig.Configuration) {
		t.Fatal("revocation did not advance configuration generation")
	}
	if _, err = identityService.Revoke(ctx, "operation_machine_revoke_"+suffix, userID, machineID, 1, 1, "endpoint_removed", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_config_machine_denied_" + suffix, UserID: userID, EndpointID: machineID}); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked machine identity=%v", err)
	}

	fixturePath := os.Getenv("PAPERBOAT_SHARED_NETWORK_FIXTURE")
	if fixturePath == "" {
		fixturePath = os.Getenv("PAPERBOAT_NETWORK_FIXTURE")
	}
	if path := fixturePath; path != "" {
		fixture := map[string]any{"issuer": "https://api.example.test", "signing_key_id": "network-test", "signing_public_key": base64.RawURLEncoding.EncodeToString(signingPublic), "cli": networkFixtureBinding(t, cliConfig.Configuration), "machine": networkFixtureBinding(t, machineConfig.Configuration), "cli_private_key": base64.RawURLEncoding.EncodeToString(cliPrivate), "machine_private_key": base64.RawURLEncoding.EncodeToString(machinePrivate), "cli_configuration": cliConfig.Configuration, "machine_configuration": machineConfig.Configuration, "revoked_cli_configuration": revoked.Configuration}
		fixture["initial_cli_configuration"] = initialCLIConfig.Configuration
		fixture["initial_cli_private_key"] = base64.RawURLEncoding.EncodeToString(initialCLIPrivate)
		fixture["shared_cli"] = networkFixtureBinding(t, sharedConfig.Configuration)
		fixture["shared_cli_private_key"] = base64.RawURLEncoding.EncodeToString(sharedPrivate)
		fixture["shared_cli_configuration"] = sharedConfig.Configuration
		fixture["shared_cli_revoked_configuration"] = withdrawnShared.Configuration
		fixture["machine_shared_configuration"] = machineSharedConfig.Configuration
		fixture["shared_device_disabled_configuration"] = sharedDeviceDisabled.Configuration
		fixture["machine_device_disabled_configuration"] = machineDeviceDisabled.Configuration
		fixture["machine_shared_revoked_configuration"] = machineWithdrawnConfig.Configuration
		fixture["exec_descriptor"] = execDescriptor
		fixture["active_exec_descriptor"] = activeExecDescriptor
		fixture["after_disable_exec_descriptor"] = afterDisableExecDescriptor
		fixture["terminal_descriptor"] = terminalDescriptor
		fixture["terminal_viewer_descriptor"] = viewerTerminalDescriptor
		fixture["terminal_interactive_descriptor"] = interactiveTerminalDescriptor
		fixture["terminal_owner_descriptor"] = ownerSharedTerminalDescriptor
		fixture["terminal_viewer_jti"] = viewerJTI
		fixture["terminal_viewer_configuration"] = terminalViewerConfig.Configuration
		fixture["terminal_viewer_machine_configuration"] = terminalViewerMachineConfig.Configuration
		fixture["terminal_interactive_configuration"] = terminalInteractiveConfig.Configuration
		fixture["terminal_interactive_machine_configuration"] = terminalInteractiveMachineConfig.Configuration
		fixture["terminal_revoked_configuration"] = terminalRevokedConfig.Configuration
		fixture["file_descriptor"] = fileDescriptor
		fixture["file_batch_id"] = fileBatchID
		fixture["ssh_descriptor"] = sshDescriptor
		fixture["ssh_host_public_key"] = sshHostPublic
		fixture["ssh_host_private_key"] = base64.RawURLEncoding.EncodeToString(sshHostPrivate)
		fixture["ssh_client_public_key"] = sshClientPublic
		fixture["ssh_client_private_key"] = base64.RawURLEncoding.EncodeToString(sshClientPrivate)
		fixture["owner_exec_descriptor"] = ownerExecDescriptor
		fixture["owner_shared_configuration"] = ownerSharedConfig.Configuration
		fixture["final_shared_exec_descriptor"] = finalSharedExec
		fixture["final_shared_configuration"] = finalSharedConfig.Configuration
		fixture["final_machine_configuration"] = finalMachineConfig.Configuration
		fixture["removed_owner_configuration"] = removedOwnerConfig.Configuration
		fixture["environment_id"] = envID
		fixture["helper_id"] = "network_helper_" + suffix
		fixture["owner_cli_tls_der"] = base64.RawURLEncoding.EncodeToString(cliTLSDER)
		fixture["owner_cli_tls_private"] = base64.RawURLEncoding.EncodeToString(cliTLSPrivate)
		fixture["shared_cli_tls_der"] = base64.RawURLEncoding.EncodeToString(sharedTLSDER)
		fixture["shared_cli_tls_private"] = base64.RawURLEncoding.EncodeToString(sharedTLSPrivate)
		fixture["machine_tls_der"] = base64.RawURLEncoding.EncodeToString(machineTLSDER)
		fixture["machine_tls_private"] = base64.RawURLEncoding.EncodeToString(machineTLSPrivate)
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
		if err = os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_ = cliPublic
	exerciseNativeRelayLifecycle(t, store, service, userID, cliID, regionalNodeID)
}

func networkCertificate(t *testing.T, root ed25519.PrivateKey, account string, role peeridentity.Role, endpoint string, generation, serial uint64, issued, expires time.Time) ([]byte, [32]byte) {
	return networkCertificateWithKeys(t, root, account, role, endpoint, generation, serial, [32]byte{1}, [32]byte{2}, issued, expires)
}

func networkEndpointTLS(t *testing.T, label string, now time.Time) ([]byte, ed25519.PrivateKey, [32]byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: label}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], public)
	return der, private, key
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

func networkDiscoPublic(t *testing.T, nodePrivate []byte) []byte {
	t.Helper()
	mac := hmac.New(sha256.New, nodePrivate)
	_, _ = mac.Write([]byte("github.com/tailscale/tailcat disco key v1"))
	discoPrivate := mac.Sum(nil)
	discoPrivate[0] &= 248
	discoPrivate[31] &= 127
	discoPrivate[31] |= 64
	public, err := curve25519.X25519(discoPrivate, curve25519.Basepoint)
	clear(discoPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return public
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

func assertNetworkPeerAccount(t *testing.T, token, endpointID, accountID string) {
	t.Helper()
	for _, rawPeer := range networkClaims(t, token)["peers"].([]any) {
		identity := rawPeer.(map[string]any)["identity"].(map[string]any)
		if identity["endpoint_id"] == endpointID {
			if identity["account_id"] != accountID {
				t.Fatalf("peer account=%v want=%s", identity, accountID)
			}
			return
		}
	}
	t.Fatalf("peer %s not found", endpointID)
}

func assertNoNetworkCapability(t *testing.T, token, capability string) {
	t.Helper()
	for _, rawPeer := range networkClaims(t, token)["peers"].([]any) {
		for _, rawScope := range rawPeer.(map[string]any)["scopes"].([]any) {
			if rawScope.(map[string]any)["capability"] == capability {
				t.Fatalf("unexpected capability %s", capability)
			}
		}
	}
}

func assertNoNetworkPeer(t *testing.T, token, endpointID string) {
	t.Helper()
	for _, rawPeer := range networkClaims(t, token)["peers"].([]any) {
		if rawPeer.(map[string]any)["identity"].(map[string]any)["endpoint_id"] == endpointID {
			t.Fatalf("unexpected peer %s", endpointID)
		}
	}
}
