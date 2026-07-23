package connectedmachines

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

type testSeatAuthorizer struct{}

func (testSeatAuthorizer) ReserveConnectedMachineSeat(context.Context, *db.Tx, string) error {
	return nil
}

func TestWorkerMarksStaleMachineOfflineAndHeartbeatRestoresIt(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_cm_liveness_"+suffix, "cm_liveness_"+suffix, "env_liveness_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-liveness-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,last_seen_at) VALUES ($1,$2,$3,'Liveness','linux','amd64','/home/test','online','occupied',true,now()-interval '1 minute')`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{OfflineAfter: 10 * time.Second}, nil)
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- service.Worker(5 * time.Millisecond)(workerCtx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.Now().Add(2 * time.Second)
	for {
		var state string
		var online bool
		if err := store.SQL().QueryRowContext(ctx, `SELECT state,online FROM paperboat.connected_machines WHERE id=$1`, machineID).Scan(&state, &online); err != nil {
			t.Fatal(err)
		}
		if state == "offline" && !online {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stale machine remained state=%s online=%v", state, online)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rows, err := store.Queries().MarkConnectedMachineOnlineFromHelper(ctx, dbsqlc.MarkConnectedMachineOnlineFromHelperParams{ID: machineID, EnvironmentID: environmentID}); err != nil || rows != 1 {
		t.Fatalf("restore heartbeat rows=%d err=%v", rows, err)
	}
	var state string
	var online bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,online FROM paperboat.connected_machines WHERE id=$1`, machineID).Scan(&state, &online); err != nil {
		t.Fatal(err)
	}
	if state != "online" || !online {
		t.Fatalf("restored machine state=%s online=%v", state, online)
	}
}

func TestReserveBandwidthConsumesIncludedThenTopups(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID := "usr_cm_bandwidth_"+suffix, "cm_bandwidth_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, userID, "workos_"+suffix, "cm-bandwidth-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.connected_machine_entitlements
  (id, user_id, provider_subscription_id, product_code, state, seat_quantity, allowance_bytes, current_period_start, current_period_end)
VALUES ($1, $2, $3, 'connected-test', 'active', 1, 100, $4, $5)`, "cme_"+suffix, userID, "sub_"+suffix, now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.connected_machines
  (id, user_id, environment_id, display_name, platform, architecture, workspace_root, state, seat_state, online)
VALUES ($1, $2, $3, $4, 'linux', 'amd64', '/home/example', 'online', 'occupied', true)`, machineID, userID, "env_"+suffix, "Machine "+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.connected_machine_bandwidth_topups
  (id, user_id, provider_order_id, purchased_bytes, remaining_bytes)
VALUES ($1, $2, $3, 20, 20)`, "cmbt_"+suffix, userID, "order_"+suffix); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	reservation, err := service.ReserveBandwidth(ctx, machineID, 125)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.GrantedBytes != 120 || !reservation.Exhausted {
		t.Fatalf("reservation = %+v, want 120 bytes and exhausted", reservation)
	}
	var included, topup int64
	if err := store.SQL().QueryRowContext(ctx, `
SELECT consumed_included_bytes, consumed_topup_bytes
FROM paperboat.connected_machine_bandwidth_periods
WHERE connected_machine_id = $1`, machineID).Scan(&included, &topup); err != nil {
		t.Fatal(err)
	}
	if included != 100 || topup != 20 {
		t.Fatalf("period consumed included/topup = %d/%d", included, topup)
	}
	var topupState string
	var remaining int64
	if err := store.SQL().QueryRowContext(ctx, `
SELECT state, remaining_bytes FROM paperboat.connected_machine_bandwidth_topups WHERE id = $1`, "cmbt_"+suffix).Scan(&topupState, &remaining); err != nil {
		t.Fatal(err)
	}
	if topupState != "exhausted" || remaining != 0 {
		t.Fatalf("top-up state/remaining = %q/%d", topupState, remaining)
	}
	reservation, err = service.ReserveBandwidth(ctx, machineID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.GrantedBytes != 0 || !reservation.Exhausted {
		t.Fatalf("exhausted reservation = %+v", reservation)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.connected_machines SET state = 'disconnected' WHERE id = $1`, machineID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReserveBandwidth(ctx, machineID, 1); !errors.Is(err, ErrBandwidthDenied) {
		t.Fatalf("disconnected machine reservation error = %v", err)
	}
}

func TestDashboardEnrollmentIsIdempotentSingleClaimAndRetrySafe(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_enrollment_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "enrollment-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"darwin", "linux"}}, nil)
	service.ConfigureProvisioning(nil, "test-enrollment-key")
	service.ConfigureBootstrapCommand("pb machine bootstrap")
	first, err := service.StartEnrollment(ctx, userID, "idem-1")
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.StartEnrollment(ctx, userID, "idem-1")
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ID != first.ID || replayed.BootstrapToken != first.BootstrapToken || replayed.OperationID != first.OperationID {
		t.Fatalf("idempotent replay changed result: first=%+v replay=%+v", first, replayed)
	}
	pairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: first.BootstrapToken, Verifier: "verifier-1", DisplayName: "Studio", Platform: "darwin", Architecture: "arm64", WorkspaceRoot: "/Users/paperboat", RuntimeVersions: json.RawMessage(`{"helper":"test"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: first.BootstrapToken, Verifier: "verifier-2", DisplayName: "Replay", Platform: "darwin", Architecture: "arm64", WorkspaceRoot: "/Users/paperboat"}); !errors.Is(err, ErrEnrollmentState) {
		t.Fatalf("consumed bootstrap claim error=%v", err)
	}
	status, err := service.Enrollment(ctx, userID, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "awaiting_approval" || status.PairingID != pairing.ID || status.WorkspaceRoot != "/Users/paperboat" {
		t.Fatalf("claimed status=%+v", status)
	}
	if err := service.CancelEnrollment(ctx, userID, first.ID); err != nil {
		t.Fatal(err)
	}
	retried, err := service.RetryEnrollment(ctx, userID, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Generation != 2 || retried.BootstrapToken == first.BootstrapToken || retried.State != "awaiting_bootstrap" {
		t.Fatalf("retry=%+v", retried)
	}
}

func TestDashboardEnrollmentDenialIsAtomicAndNonRetryable(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_enrollment_deny_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1,$2,$3,'active')`, userID, "workos_deny_"+suffix, "enrollment-deny-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"linux"}}, nil)
	service.ConfigureProvisioning(nil, "test-enrollment-key")
	first, err := service.StartEnrollment(ctx, userID, "idem-deny-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	verifier := "verifier-deny-" + suffix
	pairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: first.BootstrapToken, Verifier: verifier, DisplayName: "Denied host", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConsumeInstallation(ctx, verifier); !errors.Is(err, ErrInstallationPending) {
		t.Fatalf("pending installation material error = %v", err)
	}
	if err := service.Deny(ctx, userID, pairing.UserCode); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConsumeInstallation(ctx, verifier); !errors.Is(err, ErrInstallationDenied) {
		t.Fatalf("denied installation material error = %v", err)
	}
	var pairingState, enrollmentState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.connected_machine_pairings WHERE id=$1`, pairing.ID).Scan(&pairingState); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.connected_machine_enrollments WHERE id=$1`, first.ID).Scan(&enrollmentState); err != nil {
		t.Fatal(err)
	}
	if pairingState != "denied" || enrollmentState != "denied" {
		t.Fatalf("pairing=%q enrollment=%q", pairingState, enrollmentState)
	}
	if err := service.Deny(ctx, userID, pairing.UserCode); !errors.Is(err, ErrPairingUsed) {
		t.Fatalf("denial replay error = %v", err)
	}
	if _, err := service.RetryEnrollment(ctx, userID, first.ID); err != nil {
		t.Fatalf("denied enrollment was not retryable: %v", err)
	}
}

func TestDashboardEnrollmentExpiryIsAtomicAndRetryable(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_enrollment_expiry_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1,$2,$3,'active')`, userID, "workos_expiry_"+suffix, "enrollment-expiry-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"linux"}}, testSeatAuthorizer{})
	service.ConfigureProvisioning(nil, "test-enrollment-key")
	first, err := service.StartEnrollment(ctx, userID, "idem-expiry-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	verifier := "verifier-expiry-" + suffix
	pairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: first.BootstrapToken, Verifier: verifier, DisplayName: "Expired host", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.connected_machine_pairings SET expires_at=now()-interval '1 minute' WHERE id=$1`, pairing.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.connected_machine_enrollments SET expires_at=now()-interval '1 minute' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(ctx, userID, pairing.UserCode); !errors.Is(err, ErrPairingExpired) {
		t.Fatalf("approval error = %v", err)
	}
	var pairingState, enrollmentState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.connected_machine_pairings WHERE id=$1`, pairing.ID).Scan(&pairingState); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.connected_machine_enrollments WHERE id=$1`, first.ID).Scan(&enrollmentState); err != nil {
		t.Fatal(err)
	}
	if pairingState != "expired" || enrollmentState != "expired" {
		t.Fatalf("pairing=%q enrollment=%q", pairingState, enrollmentState)
	}
	var machineCount, occupiedSeats int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE seat_state='occupied') FROM paperboat.connected_machines WHERE user_id=$1`, userID).Scan(&machineCount, &occupiedSeats); err != nil {
		t.Fatal(err)
	}
	if machineCount != 0 || occupiedSeats != 0 {
		t.Fatalf("machines=%d occupied_seats=%d", machineCount, occupiedSeats)
	}
	if _, err := service.ConsumeInstallation(ctx, verifier); !errors.Is(err, ErrInstallationExpired) {
		t.Fatalf("expired installation material error = %v", err)
	}
	retried, err := service.RetryEnrollment(ctx, userID, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Generation != first.Generation+1 || retried.State != "awaiting_bootstrap" || retried.BootstrapToken == first.BootstrapToken || retried.PairingID != "" {
		t.Fatalf("retry=%+v", retried)
	}
}

func TestInstallationMaterialIsSingleUseAndExpiryBound(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_install_replay_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1,$2,$3,'active')`, userID, "workos_install_"+suffix, "install-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"linux"}}, nil)
	service.ConfigureProvisioning(nil, "test-install-key")
	start, err := service.StartEnrollment(ctx, userID, "idem-install-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	verifier := "verifier-install-" + suffix
	pairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: start.BootstrapToken, Verifier: verifier, DisplayName: "Install host", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := secrets.Encrypt("test-install-key", `{"bootstrap":"ok"}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.connected_machine_pairings SET state='approved', installation_config_ciphertext=$1 WHERE id=$2`, ciphertext, pairing.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.connected_machine_enrollments SET state='material_issued' WHERE id=$1`, start.ID); err != nil {
		t.Fatal(err)
	}
	material, err := service.ConsumeInstallation(ctx, verifier)
	if err != nil || string(material) != `{"bootstrap":"ok"}` {
		t.Fatalf("material=%s err=%v", material, err)
	}
	if _, err := service.ConsumeInstallation(ctx, verifier); !errors.Is(err, ErrInstallationUnavailable) {
		t.Fatalf("replay error=%v", err)
	}
	var enrollmentState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.connected_machine_enrollments WHERE id=$1`, start.ID).Scan(&enrollmentState); err != nil {
		t.Fatal(err)
	}
	if enrollmentState != "installing" {
		t.Fatalf("enrollment state=%q", enrollmentState)
	}

	second, err := service.StartEnrollment(ctx, userID, "idem-install-expired-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	expiredVerifier := "verifier-install-expired-" + suffix
	expiredPairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: second.BootstrapToken, Verifier: expiredVerifier, DisplayName: "Expired host", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	expiredCiphertext, err := secrets.Encrypt("test-install-key", `{"bootstrap":"expired"}`)
	if err != nil {
		t.Fatal(err)
	}
	expiredHash := sha256.Sum256([]byte(expiredVerifier))
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.connected_machine_pairings SET state='approved', verifier_hash=$1, installation_config_ciphertext=$2, expires_at=now()-interval '1 minute' WHERE id=$3`, expiredHash[:], expiredCiphertext, expiredPairing.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.connected_machine_enrollments SET state='material_issued' WHERE id=$1`, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConsumeInstallation(ctx, expiredVerifier); !errors.Is(err, ErrInstallationExpired) {
		t.Fatalf("expired material error=%v", err)
	}
}

func TestInstallationFailureIsHelperBoundAndRetryPreservesMachine(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_install_failure_"+suffix, "cm_install_failure_"+suffix, "env_install_failure_"+suffix
	pairingID, enrollmentID, helperID := "cmp_install_failure_"+suffix, "cme_install_failure_"+suffix, "helper_install_failure_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_install_failure_"+suffix, "install-failure-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state) VALUES ($1,$2,$3,'Recovery host','linux','amd64','/workspace','offline','occupied')`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machine_pairings (id,verifier_hash,user_code,requested_display_name,platform,architecture,workspace_root,state,connected_machine_id,expires_at) VALUES ($1,$2,$3,'Recovery host','linux','amd64','/workspace','consumed',$4,now()+interval '10 minutes')`, pairingID, []byte("verifier_"+suffix), "CODE"+suffix, machineID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machine_enrollments (id,user_id,operation_id,idempotency_key,bootstrap_token_hash,bootstrap_token_ciphertext,state,pairing_id,connected_machine_id,expires_at) VALUES ($1,$2,$3,$4,$5,$6,'installing',$7,$8,now()+interval '10 minutes')`, enrollmentID, userID, "op_"+suffix, "idem_"+suffix, []byte("token_"+suffix), []byte("cipher_"+suffix), pairingID, machineID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, machineID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port,desired_state,desired_revision,applied_revision) VALUES ($1,$2,'helper_https_wss',$3,'127.0.0.1',38080,'attached',1,0)`, "route_"+suffix, environmentID, "recovery-"+suffix+".example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, helperID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,state,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'consumed',now()+interval '10 minutes')`, "henr_"+suffix, environmentID, helperID, []byte("jti_"+suffix), "op_helper_"+suffix, []byte("request_"+suffix), []byte("grant_"+suffix)); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"linux"}}, nil)
	service.ConfigureProvisioning(nil, "test-install-key")
	service.ConfigureAccess(nil, "https://control.example.test", time.Minute, 0, nil, 0)
	if err := service.ConfigureHelperRoute("example.test", 38080); err != nil {
		t.Fatal(err)
	}
	configureSignedTestArtifact(t, service)
	grantCalls := 0
	service.ConfigureHelperEnrollment(func(context.Context, string, string, string, time.Duration) (HelperEnrollmentGrant, error) {
		grantCalls++
		return HelperEnrollmentGrant{}, errors.New("unexpected helper grant")
	})
	if err := service.FailInstallation(ctx, enrollmentID, environmentID, "helper_wrong", "henr_"+suffix, "service_install"); !errors.Is(err, ErrEnrollmentState) {
		t.Fatalf("cross-helper failure report error = %v", err)
	}
	if err := service.FailInstallation(ctx, enrollmentID, environmentID, helperID, "henr_wrong_"+suffix, "service_install"); !errors.Is(err, ErrEnrollmentState) {
		t.Fatalf("mismatched helper-enrollment failure report error = %v", err)
	}
	if err := service.FailInstallation(ctx, enrollmentID, environmentID, helperID, "", "service_install"); err != nil {
		t.Fatal(err)
	}
	retried, err := service.RetryEnrollment(ctx, userID, enrollmentID)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Generation != 2 || retried.State != "awaiting_bootstrap" || retried.ConnectedMachineID != machineID || retried.PairingID != "" {
		t.Fatalf("retry=%+v", retried)
	}
	retryVerifier := "retry-verifier-" + suffix
	retryPairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: retried.BootstrapToken, Verifier: retryVerifier, DisplayName: "Recovery host", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	recoveredMachine, err := service.Approve(ctx, userID, retryPairing.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if recoveredMachine.ID != machineID || recoveredMachine.EnvironmentID != environmentID || grantCalls != 0 {
		t.Fatalf("machine=%+v helper_grant_calls=%d", recoveredMachine, grantCalls)
	}
	material, err := service.ConsumeInstallation(ctx, retryVerifier)
	if err != nil {
		t.Fatal(err)
	}
	var recoveryMaterial struct {
		MachineID           string `json:"machine_id"`
		MachineEnrollmentID string `json:"machine_enrollment_id"`
		EnvironmentID       string `json:"environment_id"`
		HelperID            string `json:"helper_id"`
		ReuseIdentity       bool   `json:"reuse_identity"`
		Credential          string `json:"enrollment_credential"`
		HelperListenAddress string `json:"helper_listen_address"`
	}
	if json.Unmarshal(material, &recoveryMaterial) != nil || recoveryMaterial.MachineID != machineID || recoveryMaterial.MachineEnrollmentID != enrollmentID || recoveryMaterial.EnvironmentID != environmentID || recoveryMaterial.HelperID != helperID || !recoveryMaterial.ReuseIdentity || recoveryMaterial.Credential != "" || recoveryMaterial.HelperListenAddress != "127.0.0.1:38080" {
		t.Fatalf("recovery material=%s", material)
	}
	var routeCount int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.control_routes WHERE environment_id=$1 AND kind='helper_https_wss' AND public_host=$2 AND target_host='127.0.0.1' AND target_port=38080`, environmentID, strings.ReplaceAll(machineID, "_", "-")+".example.test").Scan(&routeCount); err != nil || routeCount != 1 {
		t.Fatalf("helper route count=%d err=%v", routeCount, err)
	}
	var machineCount, occupiedSeats int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE seat_state='occupied') FROM paperboat.connected_machines WHERE user_id=$1`, userID).Scan(&machineCount, &occupiedSeats); err != nil {
		t.Fatal(err)
	}
	if machineCount != 1 || occupiedSeats != 1 {
		t.Fatalf("machines=%d occupied_seats=%d", machineCount, occupiedSeats)
	}
}

func configureSignedTestArtifact(t *testing.T, service *Service) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("helper"))
	artifact := HelperArtifact{Schema: "paperboat.helper-artifact/v1", Version: "test", Platform: "linux", Architecture: "amd64", URL: "https://updates.example.test/paperboat-helper", ByteLength: 6, SHA256: hex.EncodeToString(digest[:])}
	payload, _ := json.Marshal(struct {
		Architecture string `json:"architecture"`
		ByteLength   int64  `json:"byte_length"`
		Platform     string `json:"platform"`
		Schema       string `json:"schema"`
		SHA256       string `json:"sha256"`
		URL          string `json:"url"`
		Version      string `json:"version"`
	}{artifact.Architecture, artifact.ByteLength, artifact.Platform, artifact.Schema, artifact.SHA256, artifact.URL, artifact.Version})
	artifact.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	encoded, _ := json.Marshal([]HelperArtifact{artifact})
	if err := service.ConfigureHelperArtifacts(string(encoded), base64.RawURLEncoding.EncodeToString(publicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestConnectIssuesEnvironmentBoundDescriptor(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_cm_connect_"+suffix, "cm_connect_"+suffix, "env_connect_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-connect-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Studio Mac','darwin','arm64','/Users/paperboat','online','occupied',true)`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	helperID := "helper_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, machineID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, helperID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,state,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',now()+interval '10 minutes')`, "enroll_"+suffix, environmentID, helperID, []byte("jti_"+suffix), "operation_"+suffix, []byte("request_"+suffix), []byte("grant_"+suffix)); err != nil {
		t.Fatal(err)
	}
	edgeNodeID := "edge_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at) VALUES ($1,'development','1.0',$2,'ready',true,now())`, edgeNodeID, "epoch_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,helper_id,generation,edge_pool,edge_node_id,state) VALUES ($1,$2,1,'development',$3,'admitted')`, environmentID, helperID, edgeNodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation) VALUES ($1,$2,'helper_https_wss',$3,'127.0.0.1',8080,1,1,$4,1)`, "route_"+suffix, environmentID, "machine-"+suffix+".example.test", edgeNodeID); err != nil {
		t.Fatal(err)
	}
	if err := store.Queries().CreateDefaultConnectedMachineTerminalSession(ctx, dbsqlc.CreateDefaultConnectedMachineTerminalSessionParams{ID: "cmts_default_" + machineID, ConnectedMachineID: machineID, LaunchCwd: "/Users/paperboat"}); err != nil {
		t.Fatal(err)
	}
	staleSessionID := "cmts_stale_" + suffix
	if err := store.Queries().CreateConnectedMachineTerminalSession(ctx, dbsqlc.CreateConnectedMachineTerminalSessionParams{ID: staleSessionID, ConnectedMachineID: machineID, TerminalID: "term_stale_" + suffix, Name: "stale", LaunchCwd: "/Users/paperboat"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Queries().QueueConnectedMachineTerminalSessionOperation(ctx, dbsqlc.QueueConnectedMachineTerminalSessionOperationParams{ID: "cmtso_stale_" + suffix, ConnectedMachineID: machineID, TerminalSessionID: staleSessionID, Operation: "delete_history"}); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	service.ConfigureProvisioning(agentunnel.FakeClient{}, "test-key")
	service.ConfigureAccess(agentunnel.FakeCredentialIssuer{}, "https://api.paperboat.test", 15*time.Minute, 1024, []string{"image/png"}, 60)
	signer, err := mint.NewEphemeral(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service.ConfigureTerminalSessions(4, signer, nil)
	response, err := service.Connect(ctx, userID, machineID, "cls_1")
	if err != nil {
		t.Fatal(err)
	}
	if !response.Connectable || response.ConnectedMachineID != machineID || response.Environment["id"] != environmentID || response.Environment["resource_id"] != machineID {
		t.Fatalf("response = %#v", response)
	}
	if response.Terminal["endpoint"] != "wss://machine-"+suffix+".example.test/v1/runtime" || response.Upload["endpoint"] != "https://machine-"+suffix+".example.test/v1/uploads" || response.Terminal["auth"] == nil || response.Upload["auth"] == nil {
		t.Fatalf("descriptor = %#v", response)
	}
	terminalAuth := response.Terminal["auth"].(map[string]any)
	uploadAuth := response.Upload["auth"].(map[string]any)
	for class, token := range map[string]string{"terminal_operation": terminalAuth["token"].(string), "image_stage": uploadAuth["token"].(string)} {
		claims, verifyErr := signer.VerifyCredential(token, "https://api.paperboat.test", class, time.Now().UTC())
		if verifyErr != nil {
			t.Fatalf("verify %s credential: %v", class, verifyErr)
		}
		if claims.EnvironmentID != environmentID || claims.UserID != userID || claims.ClientSessionID != "cls_1" || claims.SessionID != "cmts_default_"+machineID {
			t.Fatalf("%s credential bindings = %#v", class, claims)
		}
	}
}

func TestDisconnectRevokesMintedPapercodeSessionsAndRetriesOfflineConnector(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_cm_revoke_"+suffix, "cm_revoke_"+suffix, "env_revoke_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-revoke-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,agentunnel_route_id,agentunnel_client_id,agentunnel_http_base_url,agentunnel_websocket_base_url) VALUES ($1,$2,$3,'Studio Mac','darwin','arm64','/Users/paperboat','online','occupied',true,'tun_1','cli_1','https://machine.example','wss://machine.example')`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	helperID := "helper_revoke_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, machineID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, helperID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,state,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',now()+interval '10 minutes')`, "enroll_revoke_"+suffix, environmentID, helperID, []byte("jti_revoke_"+suffix), "operation_revoke_"+suffix, []byte("request_revoke_"+suffix), []byte("grant_revoke_"+suffix)); err != nil {
		t.Fatal(err)
	}
	edgeNodeID := "edge_revoke_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at) VALUES ($1,'development','1.0',$2,'ready',true,now())`, edgeNodeID, "epoch_revoke_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,helper_id,generation,edge_pool,edge_node_id,state) VALUES ($1,$2,1,'development',$3,'admitted')`, environmentID, helperID, edgeNodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation) VALUES ($1,$2,'helper_https_wss',$3,'127.0.0.1',8080,1,1,$4,1)`, "route_revoke_"+suffix, environmentID, "machine-revoke-"+suffix+".example.test", edgeNodeID); err != nil {
		t.Fatal(err)
	}
	if err := store.Queries().CreateDefaultConnectedMachineTerminalSession(ctx, dbsqlc.CreateDefaultConnectedMachineTerminalSessionParams{ID: "cmts_default_" + machineID, ConnectedMachineID: machineID, LaunchCwd: "/Users/paperboat"}); err != nil {
		t.Fatal(err)
	}
	issuer := &recordingIssuer{}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	service.ConfigureProvisioning(agentunnel.FakeClient{}, "test-key")
	service.ConfigureAccess(issuer, "https://api.paperboat.test", 5*time.Minute, 1024, []string{"image/png"}, 60)
	if _, err := service.Connect(ctx, userID, machineID, "cls_1"); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.connected_machine_access_sessions WHERE connected_machine_id=$1 AND state='active'`, machineID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active access sessions = %d, want 1", active)
	}
	issuer.failRevocation = true
	if err := service.Disconnect(ctx, userID, machineID); err == nil {
		t.Fatal("Disconnect succeeded while Papercode was unavailable")
	}
	var environmentState, helperState, enrollmentState, connectorState, routeState, machineState, seatState string
	var online bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT e.desired_state,h.state,he.state,c.state,r.desired_state,m.state,m.seat_state,m.online
FROM paperboat.control_environments e
JOIN paperboat.control_helpers h ON h.environment_id=e.id
JOIN paperboat.control_helper_enrollments he ON he.environment_id=e.id
JOIN paperboat.control_connector_generations c ON c.environment_id=e.id
JOIN paperboat.control_routes r ON r.environment_id=e.id
JOIN paperboat.connected_machines m ON m.environment_id=e.id
WHERE e.id=$1`, environmentID).Scan(&environmentState, &helperState, &enrollmentState, &connectorState, &routeState, &machineState, &seatState, &online); err != nil {
		t.Fatal(err)
	}
	if environmentState != "revoked" || helperState != "revoked" || enrollmentState != "revoked" || connectorState != "revoked" || routeState != "detaching" || machineState != "disconnected" || seatState != "released" || online {
		t.Fatalf("disconnect convergence: environment=%s helper=%s enrollment=%s connector=%s route=%s machine=%s seat=%s online=%v", environmentState, helperState, enrollmentState, connectorState, routeState, machineState, seatState, online)
	}
	var propagated bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT papercode_revoked_at IS NOT NULL FROM paperboat.connected_machine_access_sessions WHERE connected_machine_id=$1`, machineID).Scan(&propagated); err != nil {
		t.Fatal(err)
	}
	if propagated {
		t.Fatal("revocation was marked propagated after a failed downstream call")
	}
	issuer.failRevocation = false
	if err := service.RetryPendingRevocations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT papercode_revoked_at IS NOT NULL FROM paperboat.connected_machine_access_sessions WHERE connected_machine_id=$1`, machineID).Scan(&propagated); err != nil {
		t.Fatal(err)
	}
	if !propagated || len(issuer.revocations) != 2 {
		t.Fatalf("propagated=%v revocations=%d, want true and 2", propagated, len(issuer.revocations))
	}
}

func TestEntitlementLossRevokesBYODControlPlaneWithoutActiveSessions(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID, helperID := "usr_cm_seat_"+suffix, "cm_seat_"+suffix, "env_seat_"+suffix, "helper_seat_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-seat-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,revoked_at) VALUES ($1,$2,$3,'Seat Loss','linux','amd64','/srv/workspace','revoked','released',false,now())`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, machineID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, helperID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,state,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',now()+interval '10 minutes')`, "enroll_seat_"+suffix, environmentID, helperID, []byte("jti_seat_"+suffix), "operation_seat_"+suffix, []byte("request_seat_"+suffix), []byte("grant_seat_"+suffix)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,helper_id,generation,edge_pool,state) VALUES ($1,$2,1,'development','admitted')`, environmentID, helperID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port) VALUES ($1,$2,'helper_https_wss',$3,'127.0.0.1',8080)`, "route_seat_"+suffix, environmentID, "seat-"+suffix+".example.test"); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	if err := service.ReconcileConnectedMachineEntitlement(ctx, userID); err != nil {
		t.Fatal(err)
	}
	var environmentState, helperState, enrollmentState, connectorState, routeState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT e.desired_state,h.state,he.state,c.state,r.desired_state
FROM paperboat.control_environments e
JOIN paperboat.control_helpers h ON h.environment_id=e.id
JOIN paperboat.control_helper_enrollments he ON he.environment_id=e.id
JOIN paperboat.control_connector_generations c ON c.environment_id=e.id
JOIN paperboat.control_routes r ON r.environment_id=e.id
WHERE e.id=$1`, environmentID).Scan(&environmentState, &helperState, &enrollmentState, &connectorState, &routeState); err != nil {
		t.Fatal(err)
	}
	if environmentState != "revoked" || helperState != "revoked" || enrollmentState != "revoked" || connectorState != "revoked" || routeState != "detached" {
		t.Fatalf("seat-loss convergence: environment=%s helper=%s enrollment=%s connector=%s route=%s", environmentState, helperState, enrollmentState, connectorState, routeState)
	}
}

func TestSeatReductionRevokesNewestExcessMachine(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_cm_seat_reduction_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-seat-reduction-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machine_entitlements
  (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end)
VALUES ($1,$2,$3,'connected-machine-seat','active',1,1048576,now()-interval '1 day',now()+interval '1 month')`, "ent_seat_reduction_"+suffix, userID, "sub_seat_reduction_"+suffix); err != nil {
		t.Fatal(err)
	}

	type machineFixture struct {
		id, environmentID, helperID, label string
		enrolledOffset                     string
	}
	machines := []machineFixture{
		{"cm_old_" + suffix, "env_old_" + suffix, "helper_old_" + suffix, "Old", "2 days"},
		{"cm_new_" + suffix, "env_new_" + suffix, "helper_new_" + suffix, "New", "1 day"},
	}
	for _, machine := range machines {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machines
  (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,enrolled_at,created_at)
VALUES ($1,$2,$3,$4,'linux','amd64','/srv/workspace','online','occupied',true,now()-$5::interval,now()-$5::interval)`, machine.id, userID, machine.environmentID, machine.label, machine.enrolledOffset); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, machine.environmentID, machine.id, userID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, machine.helperID, machine.environmentID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,helper_id,generation,edge_pool,state) VALUES ($1,$2,1,'development','admitted')`, machine.environmentID, machine.helperID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port) VALUES ($1,$2,'helper_https_wss',$3,'127.0.0.1',8080)`, "route_"+machine.id, machine.environmentID, machine.id+".example.test"); err != nil {
			t.Fatal(err)
		}
	}

	service := New(store, audit.NewWriter(store), Policy{}, nil)
	if err := service.ReconcileConnectedMachineEntitlement(ctx, userID); err != nil {
		t.Fatal(err)
	}
	for index, machine := range machines {
		var machineState, seatState, environmentState, helperState, connectorState, routeState string
		var online bool
		if err := store.SQL().QueryRowContext(ctx, `SELECT m.state,m.seat_state,m.online,e.desired_state,h.state,c.state,r.desired_state
FROM paperboat.connected_machines m
JOIN paperboat.control_environments e ON e.id=m.environment_id
JOIN paperboat.control_helpers h ON h.environment_id=e.id
JOIN paperboat.control_connector_generations c ON c.environment_id=e.id
JOIN paperboat.control_routes r ON r.environment_id=e.id
WHERE m.id=$1`, machine.id).Scan(&machineState, &seatState, &online, &environmentState, &helperState, &connectorState, &routeState); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			if machineState != "online" || seatState != "occupied" || !online || environmentState != "active" || helperState != "active" || connectorState != "admitted" || routeState != "attached" {
				t.Fatalf("kept machine states = %s/%s/%v/%s/%s/%s/%s", machineState, seatState, online, environmentState, helperState, connectorState, routeState)
			}
			continue
		}
		if machineState != "revoked" || seatState != "released" || online || environmentState != "revoked" || helperState != "revoked" || connectorState != "revoked" || routeState != "detached" {
			t.Fatalf("excess machine states = %s/%s/%v/%s/%s/%s/%s", machineState, seatState, online, environmentState, helperState, connectorState, routeState)
		}
	}
}

type recordingIssuer struct {
	agentunnel.FakeCredentialIssuer
	failRevocation bool
	revocations    []agentunnel.CredentialRevocationInput
}

func (i *recordingIssuer) RevokeCLI(_ context.Context, input agentunnel.CredentialRevocationInput) error {
	i.revocations = append(i.revocations, input)
	if i.failRevocation {
		return errors.New("papercode unavailable")
	}
	return nil
}

func testStore(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run connected-machine integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	return store
}
