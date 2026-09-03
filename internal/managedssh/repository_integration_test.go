package managedssh

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestSQLRepositoryManagedSSHAuthorityLifecycle(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run managed SSH repository integration tests")
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
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	suffix := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_")) + strings.ReplaceAll(now.Format("150405.000000000"), ".", "")
	userA, userB := "ssh_user_a_"+suffix, "ssh_user_b_"+suffix
	clientA, clientB := "ssh_cli_a_"+suffix, "ssh_cli_b_"+suffix
	machineA, machineB := "ssh_machine_a_"+suffix, "ssh_machine_b_"+suffix
	for _, userID := range []string{userA, userB} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []struct{ id, userID string }{{clientA, userA}, {clientB, userB}} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'SSH test','desktop','test',ARRAY['account:read'],'active',$4,$4)`, value.id, value.userID, "client_"+value.id, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []struct{ id, userID string }{{machineA, userA}, {machineB, userB}} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation) VALUES ($1,$2,$3,$4,'linux','amd64','/workspace','online','occupied',true,1)`, value.id, value.userID, "env_"+value.id, value.id); err != nil {
			t.Fatal(err)
		}
	}
	repository, err := NewSQLRepository(store, audit.NewWriter(store))
	if err != nil {
		t.Fatal(err)
	}
	service, _ := NewService(repository)
	target, err := service.RegisterTarget(ctx, RegisterTargetRequest{OperationID: "operation_target_initial", ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 1, OSUser: "deploy", TargetPort: 22, Now: now})
	if err != nil || target.OSUser != "deploy" || target.TargetPort != 22 || target.ReconciliationVersion != 1 {
		t.Fatalf("initial target=%+v error=%v", target, err)
	}
	if replay, err := service.RegisterTarget(ctx, RegisterTargetRequest{OperationID: "operation_target_initial", ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 1, OSUser: "deploy", TargetPort: 22, Now: now.Add(time.Second)}); err != nil || replay != target {
		t.Fatalf("target replay=%+v error=%v", replay, err)
	}
	if _, err := service.RegisterTarget(ctx, RegisterTargetRequest{OperationID: "operation_target_initial", ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 1, OSUser: "root", TargetPort: 22, Now: now.Add(time.Second)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("target OS-user conflict=%v", err)
	}
	updatedTarget, err := service.UpdateTargetPort(ctx, UpdateTargetPortRequest{OperationID: "operation_target_update", ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 1, TargetPort: 2222, ExpectedReconciliationVersion: 1, Now: now.Add(time.Second)})
	if err != nil || updatedTarget.TargetPort != 2222 || updatedTarget.ReconciliationVersion != 2 {
		t.Fatalf("updated target=%+v error=%v", updatedTarget, err)
	}
	if _, err := service.UpdateTargetPort(ctx, UpdateTargetPortRequest{OperationID: "operation_target_update_conflict", ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 1, TargetPort: 2022, ExpectedReconciliationVersion: 1, Now: now.Add(2 * time.Second)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale target update=%v", err)
	}
	readTarget, err := service.GetTarget(ctx, GetTargetRequest{ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 1})
	if err != nil || readTarget != updatedTarget {
		t.Fatalf("read target=%+v error=%v", readTarget, err)
	}

	clientPublic := publicLine(t, "ed25519")
	registered, err := service.RegisterClient(ctx, RegisterClientRequest{OperationID: "operation_client_register", UserID: userA, CLIClientSessionID: clientA, PublicKey: clientPublic + " device comment", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.RegisterClient(ctx, RegisterClientRequest{OperationID: "operation_client_register", UserID: userA, CLIClientSessionID: clientA, PublicKey: clientPublic, Now: now.Add(time.Second)})
	if err != nil || replayed != registered {
		t.Fatalf("client replay=%+v error=%v", replayed, err)
	}
	if _, err := service.RegisterClient(ctx, RegisterClientRequest{OperationID: "operation_client_register", UserID: userA, CLIClientSessionID: clientA, PublicKey: publicLine(t, "ed25519"), Now: now.Add(time.Second)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("client rotation error=%v", err)
	}
	if _, err := service.RegisterClient(ctx, RegisterClientRequest{OperationID: "operation_client_cross_owner", UserID: userB, CLIClientSessionID: clientB, PublicKey: clientPublic, Now: now.Add(time.Second)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-owner client error=%v", err)
	}
	activeClients, err := service.ListClientKeys(ctx, ListClientKeysRequest{ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 1})
	if err != nil || len(activeClients.Keys) != 1 || activeClients.Keys[0].Fingerprint != registered.Fingerprint {
		t.Fatalf("active clients=%+v error=%v", activeClients, err)
	}
	revoked, err := service.RevokeClient(ctx, RevokeClientRequest{OperationID: "operation_client_revoke", ActorUserID: userA, Fingerprint: registered.Fingerprint, Reason: "client_logout", Now: now.Add(2 * time.Second)})
	if err != nil || revoked.State != "revoked" || revoked.ReconciliationVersion != 2 {
		t.Fatalf("revoked=%+v error=%v", revoked, err)
	}
	if replay, err := service.RevokeClient(ctx, RevokeClientRequest{OperationID: "operation_client_revoke", ActorUserID: userA, Fingerprint: registered.Fingerprint, Reason: "client_logout", Now: now.Add(3 * time.Second)}); err != nil || !replay.RevokedAt.Equal(revoked.RevokedAt) {
		t.Fatalf("revocation replay=%+v error=%v", replay, err)
	}
	if _, err := service.RevokeClient(ctx, RevokeClientRequest{OperationID: "operation_client_revoke", ActorUserID: userA, Fingerprint: registered.Fingerprint, Reason: "key_compromise", Now: now.Add(3 * time.Second)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("revocation reason conflict=%v", err)
	}
	activeClients, err = service.ListClientKeys(ctx, ListClientKeysRequest{ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 1})
	if err != nil || len(activeClients.Keys) != 0 {
		t.Fatalf("active clients after revocation=%+v error=%v", activeClients, err)
	}

	hostOne, hostTwo := publicLine(t, "ed25519"), publicLine(t, "ed25519")
	firstRequest := ObserveHostRequest{OperationID: "operation_host_observe_initial", SetID: "sshks_initial_" + suffix, UserID: userA, UserMachineID: machineA, MachineGeneration: 1, ObservationGeneration: 1, PublicKeys: []string{hostOne}, Now: now}
	first, err := service.ObserveHost(ctx, firstRequest)
	if err != nil || first.State != "active" || !first.PromotedAt.Equal(now) || len(first.Keys) != 1 {
		t.Fatalf("initial set=%+v error=%v", first, err)
	}
	activeHost, err := service.GetActiveHost(ctx, GetHostKeySetRequest{ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 1})
	if err != nil || activeHost.ID != first.ID || len(activeHost.Keys) != 1 {
		t.Fatalf("active host=%+v error=%v", activeHost, err)
	}
	identicalRequest := firstRequest
	identicalRequest.OperationID, identicalRequest.SetID, identicalRequest.ObservationGeneration = "operation_host_observe_identical", "sshks_identical_"+suffix, 2
	identical, err := service.ObserveHost(ctx, identicalRequest)
	if err != nil || identical.ID != first.ID || identical.State != "active" {
		t.Fatalf("identical set=%+v error=%v", identical, err)
	}
	pendingRequest := firstRequest
	pendingRequest.OperationID, pendingRequest.SetID, pendingRequest.ObservationGeneration, pendingRequest.PublicKeys, pendingRequest.Now = "operation_host_observe_pending", "sshks_pending_"+suffix, 3, []string{hostTwo}, now.Add(time.Second)
	pending, err := service.ObserveHost(ctx, pendingRequest)
	if err != nil || pending.State != "pending" || len(pending.Keys) != 1 {
		t.Fatalf("pending set=%+v error=%v", pending, err)
	}
	blocked := pendingRequest
	blocked.OperationID, blocked.SetID, blocked.ObservationGeneration, blocked.PublicKeys = "operation_host_observe_blocked", "sshks_blocked_"+suffix, 4, []string{publicLine(t, "ed25519")}
	if _, err := service.ObserveHost(ctx, blocked); !errors.Is(err, ErrConflict) {
		t.Fatalf("pending replacement error=%v", err)
	}
	crossOwner := ObserveHostRequest{OperationID: "operation_host_cross_owner", SetID: "sshks_cross_owner_" + suffix, UserID: userB, UserMachineID: machineB, MachineGeneration: 1, ObservationGeneration: 1, PublicKeys: []string{hostOne}, Now: now}
	if _, err := service.ObserveHost(ctx, crossOwner); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-machine host key error=%v", err)
	}
	if _, err := service.PromoteHost(ctx, PromoteHostRequest{OperationID: "operation_host_promote", ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 2, SetID: pending.ID, ExpectedFingerprint: pending.Fingerprint, Now: now.Add(2 * time.Second)}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale generation promotion error=%v", err)
	}
	promoted, err := service.PromoteHost(ctx, PromoteHostRequest{OperationID: "operation_host_promote", ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 1, SetID: pending.ID, ExpectedFingerprint: pending.Fingerprint, Now: now.Add(2 * time.Second)})
	if err != nil || promoted.State != "active" || !promoted.PromotedAt.Equal(now.Add(2*time.Second)) || len(promoted.Keys) != 1 {
		t.Fatalf("promoted=%+v error=%v", promoted, err)
	}
	activeHost, err = service.GetActiveHost(ctx, GetHostKeySetRequest{ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 1})
	if err != nil || activeHost.ID != promoted.ID {
		t.Fatalf("promoted active host=%+v error=%v", activeHost, err)
	}
	if _, err := service.GetActiveHost(ctx, GetHostKeySetRequest{ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 2}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale active host error=%v", err)
	}
	stalePendingRequest := pendingRequest
	stalePendingRequest.OperationID, stalePendingRequest.SetID, stalePendingRequest.ObservationGeneration, stalePendingRequest.PublicKeys = "operation_host_observe_stale", "sshks_stale_pending_"+suffix, 5, []string{publicLine(t, "ed25519")}
	stalePending, err := service.ObserveHost(ctx, stalePendingRequest)
	if err != nil || stalePending.State != "pending" {
		t.Fatalf("stale pending=%+v error=%v", stalePending, err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET installation_generation=2 WHERE id=$1`, machineA); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetTarget(ctx, GetTargetRequest{ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 2}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale-generation target read=%v", err)
	}
	reenrolledTarget, err := service.RegisterTarget(ctx, RegisterTargetRequest{OperationID: "operation_target_reenroll", ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 2, OSUser: "paperboat", TargetPort: 2200, Now: now.Add(4 * time.Second)})
	if err != nil || reenrolledTarget.MachineGeneration != 2 || reenrolledTarget.OSUser != "paperboat" || reenrolledTarget.TargetPort != 2200 || reenrolledTarget.ReconciliationVersion != 3 {
		t.Fatalf("reenrolled target=%+v error=%v", reenrolledTarget, err)
	}
	reenrolledRequest := pendingRequest
	reenrolledRequest.OperationID, reenrolledRequest.SetID, reenrolledRequest.MachineGeneration, reenrolledRequest.ObservationGeneration = "operation_host_observe_reenrolled", "sshks_reenrolled_"+suffix, 2, 1
	reenrolledRequest.PublicKeys, reenrolledRequest.Now = []string{publicLine(t, "ed25519")}, now.Add(4*time.Second)
	reenrolled, err := service.ObserveHost(ctx, reenrolledRequest)
	if err != nil || reenrolled.State != "active" || reenrolled.MachineGeneration != 2 {
		t.Fatalf("reenrolled=%+v error=%v", reenrolled, err)
	}
	var stalePendingState, stalePendingReason string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,rejection_reason FROM paperboat.machine_ssh_host_key_sets WHERE id=$1`, stalePending.ID).Scan(&stalePendingState, &stalePendingReason); err != nil || stalePendingState != "rejected" || stalePendingReason != "machine_reenrolled" {
		t.Fatalf("stale pending state=%q reason=%q error=%v", stalePendingState, stalePendingReason, err)
	}
	activeHost, err = service.GetActiveHost(ctx, GetHostKeySetRequest{ActorUserID: userA, UserMachineID: machineA, MachineGeneration: 2})
	if err != nil || activeHost.ID != reenrolled.ID {
		t.Fatalf("reenrolled active host=%+v error=%v", activeHost, err)
	}
	var oldState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.machine_ssh_host_key_sets WHERE id=$1`, first.ID).Scan(&oldState); err != nil || oldState != "superseded" {
		t.Fatalf("old state=%q error=%v", oldState, err)
	}
	var leakedAudit int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.audit_events WHERE resource_type IN ('managed_ssh_client_key','machine_ssh_host_key_set') AND (metadata::text LIKE '%' || $1 || '%' OR metadata::text LIKE '%' || $2 || '%')`, registered.PublicKey, hostOne).Scan(&leakedAudit); err != nil || leakedAudit != 0 {
		t.Fatalf("public key audit leaks=%d error=%v", leakedAudit, err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.audit_events WHERE resource_type='machine_ssh_target' AND (metadata ? 'os_user' OR metadata::text LIKE '%paperboat%')`).Scan(&leakedAudit); err != nil || leakedAudit != 0 {
		t.Fatalf("OS-user audit leaks=%d error=%v", leakedAudit, err)
	}
	var forbiddenColumns int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='paperboat' AND table_name IN ('managed_ssh_client_keys','machine_ssh_host_key_owners','machine_ssh_host_key_sets','machine_ssh_host_keys','machine_ssh_targets') AND column_name ~ '(private|password|secret)'`).Scan(&forbiddenColumns); err != nil || forbiddenColumns != 0 {
		t.Fatalf("forbidden managed SSH columns=%d error=%v", forbiddenColumns, err)
	}
}

func TestSQLRepositoryManagedSSHClientKeySetIsBounded(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run managed SSH repository integration tests")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := t.Context()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	suffix := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_")) + strings.ReplaceAll(now.Format("150405.000000000"), ".", "")
	userID, machineID := "ssh_bounded_user_"+suffix, "ssh_bounded_machine_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation) VALUES ($1,$2,$3,$4,'windows','amd64','C:\\workspace','online','occupied',true,1)`, machineID, userID, "env_"+machineID, machineID); err != nil {
		t.Fatal(err)
	}
	prefix := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(append([]byte{0, 0, 0, 11}, []byte("ssh-ed25519")...))
	prefix += strings.Repeat("A", 80-len(prefix))
	for index := 0; index < 65; index++ {
		sessionID := fmt.Sprintf("ssh_bounded_cli_%02d_%s", index, suffix)
		createdAt := now.Add(time.Duration(index) * time.Second)
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'bounded key','desktop','windows',ARRAY['account:read'],'active',$4,$4)`, sessionID, userID, "client_"+sessionID, createdAt); err != nil {
			t.Fatal(err)
		}
		fingerprint := sha256.Sum256([]byte(sessionID))
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.managed_ssh_client_keys (fingerprint,user_id,cli_client_session_id,algorithm,public_key,reconciliation_version,created_at) VALUES ($1,$2,$3,'ssh-ed25519',$4,1,$5)`, fingerprint[:], userID, sessionID, prefix+fmt.Sprintf("%02d", index), createdAt); err != nil {
			t.Fatal(err)
		}
	}
	repository, err := NewSQLRepository(store, audit.NewWriter(store))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	set, err := service.ListClientKeys(ctx, ListClientKeysRequest{ActorUserID: userID, UserMachineID: machineID, MachineGeneration: 1})
	if err != nil || len(set.Keys) != 64 {
		t.Fatalf("keys=%d err=%v", len(set.Keys), err)
	}
	if !strings.HasSuffix(set.Keys[0].PublicKey, "64") || !strings.HasSuffix(set.Keys[63].PublicKey, "01") {
		t.Fatalf("unexpected bounded order first=%q last=%q", set.Keys[0].PublicKey, set.Keys[63].PublicKey)
	}
}

func TestSQLRepositoryManagedSSHKeyRevokesWithClientSessionAndAccount(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run managed SSH repository integration tests")
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
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	suffix := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_")) + strings.ReplaceAll(now.Format("150405.000000000"), ".", "")
	type authority struct{ userID, clientID, machineID string }
	authorities := []authority{
		{userID: "ssh_session_revoke_user_" + suffix, clientID: "ssh_session_revoke_client_" + suffix, machineID: "ssh_session_revoke_machine_" + suffix},
		{userID: "ssh_account_revoke_user_" + suffix, clientID: "ssh_account_revoke_client_" + suffix, machineID: "ssh_account_revoke_machine_" + suffix},
	}
	for _, value := range authorities {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, value.userID, "workos_"+value.userID, value.userID+"@example.test"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'SSH revocation test','desktop','test',ARRAY['projects:connect'],'active',$4,$4)`, value.clientID, value.userID, "client_"+value.clientID, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation) VALUES ($1,$2,$3,$4,'linux','amd64','/workspace','online','occupied',true,1)`, value.machineID, value.userID, "env_"+value.machineID, value.machineID); err != nil {
			t.Fatal(err)
		}
	}
	repository, err := NewSQLRepository(store, audit.NewWriter(store))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]ClientKey, len(authorities))
	for index, value := range authorities {
		key, err := service.RegisterClient(ctx, RegisterClientRequest{OperationID: "operation_register_" + value.clientID, UserID: value.userID, CLIClientSessionID: value.clientID, PublicKey: publicLine(t, "ed25519"), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		keys[index] = key
	}

	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.cli_client_sessions SET state='revoked', revoked_at=$2, revocation_reason='client_logout' WHERE id=$1`, authorities[0].clientID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.users SET status='suspended' WHERE id=$1`, authorities[1].userID); err != nil {
		t.Fatal(err)
	}
	for index, wantReason := range []string{"client_logout", "account_revoked"} {
		var state, reason string
		var revokedAt time.Time
		var version int64
		if err := store.SQL().QueryRowContext(ctx, `SELECT state,revocation_reason,revoked_at,reconciliation_version FROM paperboat.managed_ssh_client_keys WHERE fingerprint=$1`, keys[index].Fingerprint[:]).Scan(&state, &reason, &revokedAt, &version); err != nil {
			t.Fatal(err)
		}
		if state != "revoked" || reason != wantReason || revokedAt.IsZero() || version != 2 {
			t.Fatalf("managed key %d state=%q reason=%q revoked_at=%s version=%d", index, state, reason, revokedAt, version)
		}
		set, err := service.ListClientKeys(ctx, ListClientKeysRequest{ActorUserID: authorities[index].userID, UserMachineID: authorities[index].machineID, MachineGeneration: 1})
		if index == 0 && (err != nil || len(set.Keys) != 0) {
			t.Fatalf("revoked session keys=%+v error=%v", set, err)
		}
		if index == 1 && !errors.Is(err, ErrUnavailable) {
			t.Fatalf("suspended account managed authority error=%v", err)
		}
	}
}
