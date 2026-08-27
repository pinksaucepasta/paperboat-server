package usermachines

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
)

func TestDeleteMachineRevokesBoundDeviceCredentialsAndState(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_cleanup_" + suffix
	machineID := "mch_cleanup_" + suffix
	siblingMachineID := "mch_cleanup_sibling_" + suffix
	environmentID := "env_cleanup_" + suffix
	cliSessionID := "cls_cleanup_" + suffix
	siblingCLISessionID := "cls_cleanup_sibling_" + suffix
	pairingID := "ump_cleanup_" + suffix
	enrollmentID := "ume_cleanup_" + suffix
	now := time.Now().UTC().Truncate(time.Microsecond)
	publicIdentityKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	siblingPublicIdentityKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
	rootPublicKey := bytes.Repeat([]byte{8}, 32)
	siblingPublicKey := bytes.Repeat([]byte{9}, 32)
	rootFingerprint := sha256.Sum256(rootPublicKey)
	keyID := "aek_" + hex.EncodeToString(rootFingerprint[:])
	siblingFingerprint := sha256.Sum256(siblingPublicKey)
	siblingKeyID := "aek_" + hex.EncodeToString(siblingFingerprint[:])
	certificateFingerprint := sha256.Sum256([]byte("certificate:" + suffix))
	cliCertificateFingerprint := sha256.Sum256([]byte("cli-certificate:" + suffix))
	siblingCertificateFingerprint := sha256.Sum256([]byte("sibling-certificate:" + suffix))
	siblingCLICertificateFingerprint := sha256.Sum256([]byte("sibling-cli-certificate:" + suffix))
	sshClientFingerprint := sha256.Sum256([]byte("ssh-client:" + suffix))
	sshHostFingerprint := sha256.Sum256([]byte("ssh-host:" + suffix))
	sshSetFingerprint := sha256.Sum256([]byte("ssh-set:" + suffix))
	verifierHash := sha256.Sum256([]byte("verifier:" + suffix))
	enrollmentTokenHash := sha256.Sum256([]byte("enrollment-token:" + suffix))
	peerRequestHash := sha256.Sum256([]byte("peer-request:" + suffix))
	siblingPeerRequestHash := sha256.Sum256([]byte("sibling-peer-request:" + suffix))

	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, userID, "workos_"+suffix, "cleanup-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.control_environments (id, workspace_id, owner_user_id, desired_state)
VALUES ($1, $2, $3, 'active')`, environmentID, "workspace_"+suffix, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machines
  (id, user_id, environment_id, display_name, platform, architecture, workspace_root,
   state, seat_state, public_identity_key, setup_roles, setup_mode, configured_capabilities)
VALUES ($1, $2, $3, 'Cleanup test', 'linux', 'amd64', '/workspace', 'offline', 'released',
        $4, ARRAY['interactive']::text[], 'client', ARRAY['file_receive','preview_launch']::text[])`, machineID, userID, environmentID, publicIdentityKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machines
  (id, user_id, environment_id, display_name, platform, architecture, workspace_root,
   state, seat_state, public_identity_key, setup_roles, setup_mode, configured_capabilities)
VALUES ($1, $2, $3, 'Sibling cleanup test', 'linux', 'amd64', '/sibling', 'offline', 'released',
        $4, ARRAY['interactive']::text[], 'client', ARRAY['file_receive']::text[])`, siblingMachineID, userID, environmentID, siblingPublicIdentityKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.account_e2ee_roots (user_id, public_key, fingerprint, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)`, userID, rootPublicKey, rootFingerprint[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.cli_client_sessions
  (id, user_id, client_id, client_label, device_type, os, scopes, state, created_at,
   approved_at, user_machine_id)
VALUES ($1, $2, 'paperboat', 'Cleanup test', 'desktop', 'linux', ARRAY['projects:read'],
        'active', $3, $3, $4)`, cliSessionID, userID, now, machineID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.account_e2ee_keys
  (key_id, user_id, public_key, fingerprint, generation, cli_client_session_id,
   user_machine_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $7)`, keyID, userID, rootPublicKey, rootFingerprint[:], cliSessionID, machineID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.cli_client_sessions
  (id, user_id, client_id, client_label, device_type, os, scopes, state, created_at,
   approved_at, user_machine_id)
VALUES ($1, $2, 'paperboat', 'Sibling cleanup test', 'desktop', 'linux', ARRAY['projects:read'],
        'active', $3, $3, $4)`, siblingCLISessionID, userID, now, siblingMachineID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.account_e2ee_keys
  (key_id, user_id, public_key, fingerprint, generation, cli_client_session_id,
   user_machine_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $7)`, siblingKeyID, userID, siblingPublicKey, siblingFingerprint[:], siblingCLISessionID, siblingMachineID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.cli_access_tokens (token_hash, cli_client_session_id, expires_at, created_at)
VALUES ($1, $2, $3, $4)`, "access_"+suffix, cliSessionID, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.cli_refresh_tokens (token_hash, cli_client_session_id, state, expires_at, created_at)
VALUES ($1, $2, 'active', $3, $4)`, "refresh_"+suffix, cliSessionID, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.managed_ssh_client_keys
  (fingerprint, user_id, cli_client_session_id, algorithm, public_key, created_at)
VALUES ($1, $2, $3, 'ssh-ed25519', $4, $5)`, sshClientFingerprint[:], userID, cliSessionID, strings.Repeat("p", 80), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.peer_endpoint_certificates
  (fingerprint, user_id, key_id, endpoint_id, role, generation, serial, certificate,
   noise_public_key, quic_public_key, issued_at, expires_at)
VALUES ($1, $2, $3, $4, 'machine', 1, 1, $5, $6, $7, $8, $9)`, certificateFingerprint[:], userID, keyID, machineID, bytes.Repeat([]byte{1}, 172), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32), now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, certificate := range []struct {
		fingerprint [sha256.Size]byte
		keyID       string
		endpointID  string
		role        string
		marker      byte
	}{
		{fingerprint: cliCertificateFingerprint, keyID: keyID, endpointID: cliSessionID, role: "cli", marker: 4},
		{fingerprint: siblingCertificateFingerprint, keyID: siblingKeyID, endpointID: siblingMachineID, role: "machine", marker: 5},
		{fingerprint: siblingCLICertificateFingerprint, keyID: siblingKeyID, endpointID: siblingCLISessionID, role: "cli", marker: 6},
	} {
		if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.peer_endpoint_certificates
  (fingerprint, user_id, key_id, endpoint_id, role, generation, serial, certificate,
   noise_public_key, quic_public_key, issued_at, expires_at)
VALUES ($1, $2, $3, $4, $5, 1, 1, $6, $7, $8, $9, $10)`, certificate.fingerprint[:], userID, certificate.keyID, certificate.endpointID, certificate.role, bytes.Repeat([]byte{certificate.marker}, 172), bytes.Repeat([]byte{certificate.marker + 10}, 32), bytes.Repeat([]byte{certificate.marker + 20}, 32), now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	peerNodeID := "edge_cleanup_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.control_tunnel_nodes
  (id, edge_pool, protocol_version, process_epoch, state, ready, last_heartbeat_at)
VALUES ($1, 'development', '1.0', $2, 'ready', true, $3)`, peerNodeID, "epoch_"+suffix, now); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []struct {
		id, operationKey, sessionID, controlling, controlled string
		requestHash                                          [sha256.Size]byte
	}{
		{id: "psi_cleanup_" + suffix, operationKey: "operation_cleanup_peer_" + suffix, sessionID: cliSessionID, controlling: hex.EncodeToString(cliCertificateFingerprint[:]), controlled: hex.EncodeToString(certificateFingerprint[:]), requestHash: peerRequestHash},
		{id: "psi_cleanup_sibling_" + suffix, operationKey: "operation_cleanup_sibling_peer_" + suffix, sessionID: siblingCLISessionID, controlling: hex.EncodeToString(siblingCLICertificateFingerprint[:]), controlled: hex.EncodeToString(siblingCertificateFingerprint[:]), requestHash: siblingPeerRequestHash},
	} {
		controlling, err := hex.DecodeString(peer.controlling)
		if err != nil {
			t.Fatal(err)
		}
		controlled, err := hex.DecodeString(peer.controlled)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.peer_session_intents
  (id, operation_key, request_hash, user_id, cli_client_session_id, environment_id,
   purpose, edge_node_id, controlling_certificate_fingerprint, controlled_certificate_fingerprint,
   attempt_generation, network_generation, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, 'interactive', $7, $8, $9, 1, 1, $10, $11)`, peer.id, peer.operationKey, peer.requestHash[:], userID, peer.sessionID, environmentID, peerNodeID, []byte(controlling), []byte(controlled), now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.machine_control_renewals
  (operation_id, machine_id, installation_generation, credential_jti, issued_at, expires_at)
VALUES ($1, $2, 1, $3, $4, $5)`, "renewal_"+suffix, machineID, "jti_"+suffix, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.machine_ssh_host_key_owners
  (fingerprint, user_machine_id, algorithm, public_key, first_observed_at)
VALUES ($1, $2, 'ssh-ed25519', $3, $4)`, sshHostFingerprint[:], machineID, strings.Repeat("h", 80), now); err != nil {
		t.Fatal(err)
	}
	sshSetID := "sshks_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.machine_ssh_host_key_sets
  (id, user_machine_id, machine_generation, observation_generation, set_fingerprint,
   state, reconciliation_version, observed_at, promoted_at)
VALUES ($1, $2, 1, 1, $3, 'active', 1, $4, $4)`, sshSetID, machineID, sshSetFingerprint[:], now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.machine_ssh_host_keys
  (set_id, user_machine_id, fingerprint, ordinal)
VALUES ($1, $2, $3, 0)`, sshSetID, machineID, sshHostFingerprint[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.machine_ssh_targets
  (user_machine_id, machine_generation, os_user, target_port, created_at, updated_at)
VALUES ($1, 1, 'paperboat', 22, $2, $2)`, machineID, now); err != nil {
		t.Fatal(err)
	}
	terminalID := "umt_cleanup_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machine_terminal_sessions
  (id, user_machine_id, terminal_id, name, is_default, launch_cwd, created_at, updated_at)
VALUES ($1, $2, 'terminal-cleanup', 'cleanup', false, '/workspace', $3, $3)`, terminalID, machineID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machine_pairings
  (id, verifier_hash, user_code, requested_display_name, platform, architecture,
   workspace_root, public_identity_key, state, user_machine_id, expires_at)
VALUES ($1, $2, $3, 'Cleanup test', 'linux', 'amd64', '/workspace', $4, 'pending', $5, $6)`, pairingID, verifierHash[:], "CODE"+suffix, publicIdentityKey, machineID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machine_enrollments
  (id, user_id, operation_id, idempotency_key, bootstrap_token_hash,
   bootstrap_token_ciphertext, state, pairing_id, user_machine_id, expires_at)
VALUES ($1, $2, $3, $4, $5, 'ciphertext', 'awaiting_approval', $6, $7, $8)`, enrollmentID, userID, "operation_"+suffix, "idempotency_"+suffix, enrollmentTokenHash[:], pairingID, machineID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	service := New(store, audit.NewWriter(store), Policy{}, testSeatAuthorizer{})
	if err := service.Delete(ctx, userID, machineID); err != nil {
		t.Fatal(err)
	}
	var targetPeerState, siblingPeerState string
	if err := store.SQL().QueryRowContext(ctx, `
SELECT state FROM paperboat.peer_session_intents
WHERE id = $1`, "psi_cleanup_"+suffix).Scan(&targetPeerState); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `
SELECT state FROM paperboat.peer_session_intents
WHERE id = $1`, "psi_cleanup_sibling_"+suffix).Scan(&siblingPeerState); err != nil {
		t.Fatal(err)
	}
	if targetPeerState != "revoked" || siblingPeerState != "active" {
		t.Fatalf("peer intent states = %q/%q, want revoked/active", targetPeerState, siblingPeerState)
	}

	var machineState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machines WHERE id = $1`, machineID).Scan(&machineState); err != nil {
		t.Fatal(err)
	}
	if machineState != "deleted" {
		t.Fatalf("machine state = %q, want deleted", machineState)
	}
	var sessionState, sessionMachineID string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state, user_machine_id FROM paperboat.cli_client_sessions WHERE id = $1`, cliSessionID).Scan(&sessionState, &sessionMachineID); err != nil {
		t.Fatal(err)
	}
	if sessionState != "revoked" || sessionMachineID != machineID {
		t.Fatalf("CLI session state/machine = %q/%q, want revoked/%q", sessionState, sessionMachineID, machineID)
	}
	var accessRevoked bool
	var refreshState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT cli_access_tokens.revoked_at IS NOT NULL, cli_refresh_tokens.state FROM paperboat.cli_access_tokens JOIN paperboat.cli_refresh_tokens ON cli_refresh_tokens.cli_client_session_id = cli_access_tokens.cli_client_session_id WHERE cli_access_tokens.cli_client_session_id = $1`, cliSessionID).Scan(&accessRevoked, &refreshState); err != nil {
		t.Fatal(err)
	}
	if !accessRevoked || refreshState != "revoked" {
		t.Fatalf("access token revoked/refresh token state = %t/%q, want true/revoked", accessRevoked, refreshState)
	}
	var keyRevoked, certificateRevoked, managedSSHRevoked bool
	if err := store.SQL().QueryRowContext(ctx, `
SELECT k.revoked_at IS NOT NULL, c.revoked_at IS NOT NULL, ssh.state = 'revoked'
FROM paperboat.account_e2ee_keys k
JOIN paperboat.peer_endpoint_certificates c ON c.key_id = k.key_id
JOIN paperboat.managed_ssh_client_keys ssh ON ssh.cli_client_session_id = $1
WHERE k.key_id = $2`, cliSessionID, keyID).Scan(&keyRevoked, &certificateRevoked, &managedSSHRevoked); err != nil {
		t.Fatal(err)
	}
	if !keyRevoked || !certificateRevoked || !managedSSHRevoked {
		t.Fatalf("device authority revoked = key:%t certificate:%t managed_ssh:%t, want all true", keyRevoked, certificateRevoked, managedSSHRevoked)
	}
	for table, column := range map[string]string{
		"machine_control_renewals":    "machine_id",
		"machine_ssh_targets":         "user_machine_id",
		"machine_ssh_host_key_sets":   "user_machine_id",
		"machine_ssh_host_key_owners": "user_machine_id",
		"machine_ssh_host_keys":       "user_machine_id",
	} {
		var count int
		query := fmt.Sprintf("SELECT count(*) FROM paperboat.%s WHERE %s = $1", table, column)
		if err := store.SQL().QueryRowContext(ctx, query, machineID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s rows = %d, want 0", table, count)
		}
	}
	var pairingState, enrollmentState, terminalState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_pairings WHERE id = $1`, pairingID).Scan(&pairingState); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_enrollments WHERE id = $1`, enrollmentID).Scan(&enrollmentState); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT desired_state FROM paperboat.user_machine_terminal_sessions WHERE id = $1`, terminalID).Scan(&terminalState); err != nil {
		t.Fatal(err)
	}
	if pairingState != "expired" || enrollmentState != "deleted" || terminalState != "deleted" {
		t.Fatalf("pairing/enrollment/terminal states = %q/%q/%q, want expired/deleted/deleted", pairingState, enrollmentState, terminalState)
	}
}
