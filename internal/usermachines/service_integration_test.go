package usermachines

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/access"
	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/naming"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

type testSeatAuthorizer struct{}

var integrationPublicIdentityKey = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))

func (testSeatAuthorizer) ReserveUserMachineSeat(context.Context, *db.Tx, string) error {
	return nil
}

func TestSetupIsIdempotentAndUnpairPreservesInteractiveIdentity(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_machine_setup_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "machine-setup-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_entitlements (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end) VALUES ($1,$2,$3,'connected-test','active',1,1048576,now()-interval '1 hour',now()+interval '1 hour')`, "ume_setup_"+suffix, userID, "sub_setup_"+suffix); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := SetupInput{SetupMode: "receive", DisplayName: "Studio", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/home/paperboat", PublicIdentityKey: base64.RawURLEncoding.EncodeToString(public), RuntimeVersions: json.RawMessage(`{"pb":"test"}`)}
	service := New(store, audit.NewWriter(store), Policy{AllowedPlatforms: []string{"linux"}}, testSeatAuthorizer{})
	service.ConfigureAccess(nil, "https://api.paperboat.test", 5*time.Minute)
	if err := service.ConfigureRuntimeRoute("runtime.example.test", 38080); err != nil {
		t.Fatal(err)
	}
	configureSignedTestArtifact(t, service)
	first, err := service.Setup(ctx, userID, input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Alias != "studio" {
		t.Fatalf("first alias=%q", first.Alias)
	}
	if _, err := service.CreateConfiguredTerminalSession(ctx, userID, first.ID, "forbidden", "receive-terminal"); !errors.Is(err, ErrMachineCapabilityUnavailable) {
		t.Fatalf("receive terminal session error = %v, want ErrMachineCapabilityUnavailable", err)
	}
	var firstVersion int64
	if err := store.SQL().QueryRowContext(ctx, `SELECT version FROM paperboat.user_machines WHERE id=$1`, first.ID).Scan(&firstVersion); err != nil {
		t.Fatal(err)
	}
	second, err := service.Setup(ctx, userID, input)
	if err != nil {
		t.Fatal(err)
	}
	var secondVersion, machineCount int64
	if err := store.SQL().QueryRowContext(ctx, `SELECT version FROM paperboat.user_machines WHERE id=$1`, first.ID).Scan(&secondVersion); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.user_machines WHERE public_identity_key=$1`, input.PublicIdentityKey).Scan(&machineCount); err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || secondVersion != firstVersion || machineCount != 1 || !reflect.DeepEqual(second.SetupRoles, []string{"interactive"}) {
		t.Fatalf("first=%+v second=%+v versions=%d/%d count=%d", first, second, firstVersion, secondVersion, machineCount)
	}
	replacementPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replacement := input
	replacement.PublicIdentityKey = base64.RawURLEncoding.EncodeToString(replacementPublic)
	if _, err := service.Setup(ctx, userID, replacement); !errors.Is(err, ErrMachineNameConflict) {
		t.Fatalf("replacement setup error = %v, want ErrMachineNameConflict", err)
	}
	collisionPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	collision := input
	collision.DisplayName = "Studio!!!"
	collision.PublicIdentityKey = base64.RawURLEncoding.EncodeToString(collisionPublic)
	collidingMachine, err := service.Setup(ctx, userID, collision)
	if err != nil {
		t.Fatal(err)
	}
	if collidingMachine.Alias != "studio-2" {
		t.Fatalf("collision alias=%q", collidingMachine.Alias)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET setup_mode='host',setup_roles=ARRAY['host','interactive'],configured_capabilities=ARRAY['file_receive','preview_launch','terminal_host','codex_host','session_host','keep_awake'],observed_capabilities=ARRAY['file_receive','preview_launch','terminal_host','codex_host','session_host','keep_awake'],seat_state='occupied' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	unpaired, err := service.Unpair(ctx, userID, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(unpaired.SetupRoles, []string{"interactive"}) || unpaired.PublicIdentityKey != input.PublicIdentityKey || unpaired.InstallationGeneration != 2 || unpaired.SeatState != "released" {
		t.Fatalf("unpaired=%+v", unpaired)
	}
	if unpaired.SetupMode != "receive" || !unpaired.Capabilities.FileReceive.Configured || !unpaired.Capabilities.PreviewLaunch.Configured || unpaired.Capabilities.TerminalHost.Configured {
		t.Fatalf("unpaired capabilities=%+v mode=%q", unpaired.Capabilities, unpaired.SetupMode)
	}
	var environmentState, routeState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT e.desired_state,r.desired_state FROM paperboat.control_environments e JOIN paperboat.control_routes r ON r.environment_id=e.id AND r.kind='runtime_https_wss' WHERE e.id=$1`, unpaired.EnvironmentID).Scan(&environmentState, &routeState); err != nil {
		t.Fatal(err)
	}
	if environmentState != "active" || routeState != "attached" {
		t.Fatalf("downgrade environment=%q route=%q", environmentState, routeState)
	}
	sessionInput := input
	sessionInput.SetupMode = "session"
	if _, err := service.Setup(ctx, userID, sessionInput); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT desired_state FROM paperboat.control_routes WHERE environment_id=$1 AND kind='runtime_https_wss'`, unpaired.EnvironmentID).Scan(&routeState); err != nil {
		t.Fatal(err)
	}
	if routeState != "detaching" && routeState != "detached" {
		t.Fatalf("session route=%q", routeState)
	}
	if _, err := service.Setup(ctx, userID, input); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT desired_state FROM paperboat.control_routes WHERE environment_id=$1 AND kind='runtime_https_wss'`, unpaired.EnvironmentID).Scan(&routeState); err != nil {
		t.Fatal(err)
	}
	if routeState != "attached" {
		t.Fatalf("receive route=%q", routeState)
	}
}

func TestOnlineReceiveMachineCanUpgradeToHost(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_receive_upgrade_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "receive-upgrade-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_entitlements (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end) VALUES ($1,$2,$3,'connected-test','active',1,1048576,now()-interval '1 hour',now()+interval '1 hour')`, "ume_receive_upgrade_"+suffix, userID, "sub_receive_upgrade_"+suffix); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(public)
	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"linux"}}, testSeatAuthorizer{})
	service.ConfigureProvisioning(access.FakeClient{}, "receive-upgrade-key")
	service.ConfigureAccess(nil, "https://api.paperboat.test", 5*time.Minute)
	service.ConfigureHelperEnrollment(func(context.Context, string, string, string, time.Duration) (HelperEnrollmentGrant, error) {
		return HelperEnrollmentGrant{EnrollmentID: "henr_receive_upgrade_" + suffix, HelperID: "helper_receive_upgrade_" + suffix, Credential: "receive-upgrade-credential", ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}, nil
	})
	if err := service.ConfigureRuntimeRoute("runtime.example.test", 38080); err != nil {
		t.Fatal(err)
	}
	configureSignedTestArtifact(t, service)
	machine, err := service.Setup(ctx, userID, SetupInput{SetupMode: "receive", DisplayName: "Studio", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/home/paperboat", PublicIdentityKey: publicKey, RuntimeVersions: json.RawMessage(`{"pb":"test"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET state='online', online=true, observed_capabilities=configured_capabilities WHERE id=$1`, machine.ID); err != nil {
		t.Fatal(err)
	}
	pairing, err := service.CreatePairing(ctx, PairingInput{Verifier: "receive-upgrade-verifier-" + suffix, DisplayName: "Studio", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/home/paperboat", PublicIdentityKey: publicKey, RuntimeVersions: json.RawMessage(`{"pb":"test"}`)})
	if err != nil {
		t.Fatal(err)
	}
	upgraded, err := service.Approve(ctx, userID, pairing.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.ID != machine.ID || upgraded.SetupMode != "host" || upgraded.SeatState != "occupied" || !upgraded.Capabilities.TerminalHost.Configured {
		t.Fatalf("upgraded=%+v", upgraded)
	}
}

func TestWorkerMarksStaleMachineOfflineAndHeartbeatRestoresIt(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, userMachineID, environmentID := "usr_um_liveness_"+suffix, "um_liveness_"+suffix, "env_liveness_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-liveness-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,last_seen_at) VALUES ($1,$2,$3,'Liveness','linux','amd64','/home/test','online','occupied',true,now()-interval '1 minute')`, userMachineID, userID, environmentID); err != nil {
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
		if err := store.SQL().QueryRowContext(ctx, `SELECT state,online FROM paperboat.user_machines WHERE id=$1`, userMachineID).Scan(&state, &online); err != nil {
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
	if rows, err := store.Queries().MarkUserMachineOnlineFromHelper(ctx, dbsqlc.MarkUserMachineOnlineFromHelperParams{ID: userMachineID, EnvironmentID: environmentID}); err != nil || rows != 1 {
		t.Fatalf("restore heartbeat rows=%d err=%v", rows, err)
	}
	var state string
	var online bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,online FROM paperboat.user_machines WHERE id=$1`, userMachineID).Scan(&state, &online); err != nil {
		t.Fatal(err)
	}
	if state != "online" || !online {
		t.Fatalf("restored machine state=%s online=%v", state, online)
	}
}

func TestCreateTerminalSessionMapsDuplicateNameToConflict(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID := "usr_um_session_"+suffix, "um_session_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "session-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,configured_capabilities,observed_capabilities) VALUES ($1,$2,$3,'Sessions','linux','amd64','/home/test','online','occupied',true,ARRAY['terminal_host'],ARRAY['terminal_host'])`, machineID, userID, "env_session_"+suffix); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	if _, err := service.CreateTerminalSession(ctx, userID, machineID, "benchmark", "create-one", 4); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateTerminalSession(ctx, userID, machineID, "benchmark", "create-two", 4); !errors.Is(err, ErrTerminalSessionConflict) {
		t.Fatalf("duplicate name error = %v, want %v", err, ErrTerminalSessionConflict)
	}
}

func TestCreateTerminalSessionEvictsClosedSessionAtRetentionLimit(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID := "usr_um_limit_"+suffix, "um_limit_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "limit-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,configured_capabilities,observed_capabilities) VALUES ($1,$2,$3,'Limit','linux','amd64','/home/test','online','occupied',true,ARRAY['terminal_host'],ARRAY['terminal_host'])`, machineID, userID, "env_limit_"+suffix); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	first, err := service.CreateTerminalSession(ctx, userID, machineID, "first", "limit-first", 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateTerminalSession(ctx, userID, machineID, "second", "limit-second", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_terminal_sessions SET desired_state='closed',updated_at=now()-interval '1 day' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTerminalSession(ctx, userID, machineID, "third", "limit-third", 2)
	if err != nil {
		t.Fatal(err)
	}
	if created.EvictedSession == nil || created.EvictedSession.ID != first.ID {
		t.Fatalf("evicted session = %#v, want %s", created.EvictedSession, first.ID)
	}
	items, err := service.ListTerminalSessions(ctx, userID, machineID)
	if err != nil || len(items) != 2 {
		t.Fatalf("retained sessions = %d, %v", len(items), err)
	}
}

func TestCreateTerminalSessionAllocatesNameWhenOmitted(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID := "usr_um_auto_session_"+suffix, "um_auto_session_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "auto-session-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,configured_capabilities,observed_capabilities) VALUES ($1,$2,$3,'Auto Sessions','linux','amd64','/home/test','online','occupied',true,ARRAY['terminal_host'],ARRAY['terminal_host'])`, machineID, userID, "env_auto_session_"+suffix); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	first, err := service.CreateTerminalSession(ctx, userID, machineID, "", "create-auto-one", 4)
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != naming.Session(1) {
		t.Fatalf("first session = %+v", first)
	}
	replay, err := service.CreateTerminalSession(ctx, userID, machineID, "", "create-auto-one", 4)
	if err != nil || replay.ID != first.ID || replay.Name != first.Name {
		t.Fatalf("idempotent replay = %+v, %v", replay, err)
	}
	second, err := service.CreateTerminalSession(ctx, userID, machineID, "", "create-auto-two", 4)
	if err != nil || second.Name != naming.Session(2) {
		t.Fatalf("second session = %+v, %v", second, err)
	}
	claimed, err := service.CreateTerminalSession(ctx, userID, machineID, naming.Session(3), "create-claimed", 4)
	if err != nil || claimed.Name != naming.Session(3) {
		t.Fatalf("custom generated-looking name = %+v, %v", claimed, err)
	}
	automatic, err := service.CreateTerminalSession(ctx, userID, machineID, "", "create-auto-three", 4)
	if err != nil || automatic.Name != naming.Session(4) {
		t.Fatalf("automatic collision retry = %+v, %v", automatic, err)
	}
}

func TestAvailabilityPolicyLifecycle(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_availability_" + suffix
	machineID := "um_availability_" + suffix
	environmentID := "env_availability_" + suffix
	helperID := "helper_availability_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "availability-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Availability','linux','amd64','/home/test','online','occupied',true)`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, machineID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, helperID, environmentID); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)

	resolution, err := service.ResolveAvailabilityPolicy(ctx, helperID, environmentID)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Schema != AvailabilityPolicySchemaV1 || resolution.UserMachineID != machineID || resolution.Mode != "keep_awake" || resolution.Version != 0 {
		t.Fatalf("default resolution = %+v", resolution)
	}
	if _, err := service.ResolveAvailabilityPolicy(ctx, "wrong-helper", environmentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-helper resolution error = %v", err)
	}
	initialObservedAt := time.Now().UTC().Truncate(time.Microsecond)
	initialObservation := AvailabilityObservation{Schema: AvailabilityPolicySchemaV1, Mode: "keep_awake", Version: 0, Status: "applied", ObservedAt: initialObservedAt, HostServiceVersion: "1.2.3", HostServiceScope: "system", UpdateHealth: "healthy"}
	if err := service.RecordAvailabilityObservation(ctx, environmentID, machineID, initialObservation); err != nil {
		t.Fatalf("initial version-zero observation: %v", err)
	}

	first, err := service.SetAvailabilityPolicy(ctx, userID, machineID, "availability-first", "keep_awake", 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.DesiredMode != "keep_awake" || first.DesiredVersion != 1 || first.Status != "pending" {
		t.Fatalf("first policy = %+v", first)
	}
	second, err := service.SetAvailabilityPolicy(ctx, userID, machineID, "availability-second", "allow_sleep", 1)
	if err != nil {
		t.Fatal(err)
	}
	if second.DesiredMode != "allow_sleep" || second.DesiredVersion != 2 {
		t.Fatalf("second policy = %+v", second)
	}
	replayed, err := service.SetAvailabilityPolicy(ctx, userID, machineID, "availability-first", "keep_awake", 0)
	if err != nil {
		t.Fatal(err)
	}
	replayedObservedAt, firstObservedAt := replayed.ObservedAt, first.ObservedAt
	replayed.ObservedAt, first.ObservedAt = nil, nil
	if replayedObservedAt == nil || firstObservedAt == nil || !replayedObservedAt.Equal(*firstObservedAt) || !reflect.DeepEqual(replayed, first) {
		t.Fatalf("durable replay = %+v, want original %+v", replayed, first)
	}
	if _, err := service.SetAvailabilityPolicy(ctx, userID, machineID, "availability-first", "allow_sleep", 0); !errors.Is(err, ErrAvailabilityIdempotencyConflict) {
		t.Fatalf("reused key error = %v", err)
	}
	if _, err := service.SetAvailabilityPolicy(ctx, userID, machineID, "availability-stale", "keep_awake", 1); !errors.Is(err, ErrAvailabilityVersionConflict) {
		t.Fatalf("stale version error = %v", err)
	} else {
		var versionErr *AvailabilityVersionError
		if !errors.As(err, &versionErr) || versionErr.CurrentVersion != 2 {
			t.Fatalf("stale version details = %#v", err)
		}
	}

	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	observation := AvailabilityObservation{Schema: AvailabilityPolicySchemaV1, Mode: "allow_sleep", Version: 2, Status: "applied", ObservedAt: observedAt, HostServiceVersion: "1.2.3", HostServiceScope: "system", UpdateRollbacks: 2, UpdateHealth: "recovery_required"}
	if err := service.RecordAvailabilityObservation(ctx, environmentID, machineID, observation); err != nil {
		t.Fatal(err)
	}
	if err := service.RecordAvailabilityObservation(ctx, environmentID, machineID, observation); err != nil {
		t.Fatalf("exact observation replay: %v", err)
	}
	higherRollbacks := observation
	higherRollbacks.ObservedAt = observedAt.Add(time.Second)
	higherRollbacks.UpdateRollbacks = 3
	if err := service.RecordAvailabilityObservation(ctx, environmentID, machineID, higherRollbacks); err != nil {
		t.Fatalf("new rollback observation: %v", err)
	}
	if err := service.RecordAvailabilityObservation(ctx, environmentID, machineID, observation); !errors.Is(err, ErrAvailabilityObservationStale) {
		t.Fatalf("decreasing rollback observation error = %v", err)
	}
	recovered := higherRollbacks
	recovered.ObservedAt = observedAt.Add(2 * time.Second)
	recovered.Status = "applied"
	recovered.HostServiceVersion = "1.2.4"
	recovered.UpdateHealth = "healthy"
	if err := service.RecordAvailabilityObservation(ctx, environmentID, machineID, recovered); err != nil {
		t.Fatalf("same-policy health update: %v", err)
	}
	for name, candidate := range map[string]AvailabilityObservation{
		"stale":      {Schema: AvailabilityPolicySchemaV1, Mode: "keep_awake", Version: 1, Status: "applied", ObservedAt: observedAt, HostServiceVersion: "1.2.3", HostServiceScope: "system"},
		"future":     {Schema: AvailabilityPolicySchemaV1, Mode: "allow_sleep", Version: 3, Status: "applied", ObservedAt: observedAt, HostServiceVersion: "1.2.3", HostServiceScope: "system"},
		"same-older": {Schema: AvailabilityPolicySchemaV1, Mode: "allow_sleep", Version: 2, Status: "error", ErrorCode: "apply_failed", ObservedAt: observedAt, HostServiceVersion: "1.2.3", HostServiceScope: "system", UpdateRollbacks: 3, UpdateHealth: "recovery_required"},
	} {
		if err := service.RecordAvailabilityObservation(ctx, environmentID, machineID, candidate); !errors.Is(err, ErrAvailabilityObservationStale) {
			t.Errorf("%s observation error = %v", name, err)
		}
	}

	machine, err := store.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: machineID, UserID: userID})
	if err != nil {
		t.Fatal(err)
	}
	availability := mapAvailability(machine)
	if availability.Status != "applied" || availability.ObservedMode != "allow_sleep" || availability.ObservedVersion != 2 || availability.HostServiceVersion != "1.2.4" || availability.UpdateRollbacks != 3 || availability.UpdateHealth != "healthy" {
		t.Fatalf("observed availability = %+v", availability)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET online=false WHERE id=$1`, machineID); err != nil {
		t.Fatal(err)
	}
	machine, err = store.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: machineID, UserID: userID})
	if err != nil {
		t.Fatal(err)
	}
	if offline := mapAvailability(machine); offline.Status != "offline" || offline.DesiredVersion != 2 || offline.ObservedVersion != 2 {
		t.Fatalf("offline availability = %+v", offline)
	}
}

func TestReserveBandwidthConsumesIncludedThenTopups(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, userMachineID := "usr_um_bandwidth_"+suffix, "um_bandwidth_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, userID, "workos_"+suffix, "cm-bandwidth-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machine_entitlements
  (id, user_id, provider_subscription_id, product_code, state, seat_quantity, allowance_bytes, current_period_start, current_period_end)
VALUES ($1, $2, $3, 'connected-test', 'active', 1, 100, $4, $5)`, "ume_"+suffix, userID, "sub_"+suffix, now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machines
  (id, user_id, environment_id, display_name, platform, architecture, workspace_root, state, seat_state, online)
VALUES ($1, $2, $3, $4, 'linux', 'amd64', '/home/example', 'online', 'occupied', true)`, userMachineID, userID, "env_"+suffix, "UserMachine "+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET observed_capabilities=ARRAY['file_receive'] WHERE id=$1`, userMachineID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machine_bandwidth_topups
  (id, user_id, provider_order_id, purchased_bytes, remaining_bytes)
VALUES ($1, $2, $3, 20, 20)`, "cmbt_"+suffix, userID, "order_"+suffix); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	reservation, err := service.ReserveBandwidth(ctx, userMachineID, 125)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.GrantedBytes != 120 || !reservation.Exhausted {
		t.Fatalf("reservation = %+v, want 120 bytes and exhausted", reservation)
	}
	var included, topup int64
	if err := store.SQL().QueryRowContext(ctx, `
SELECT consumed_included_bytes, consumed_topup_bytes
FROM paperboat.user_machine_bandwidth_periods
WHERE user_machine_id = $1`, userMachineID).Scan(&included, &topup); err != nil {
		t.Fatal(err)
	}
	if included != 100 || topup != 20 {
		t.Fatalf("period consumed included/topup = %d/%d", included, topup)
	}
	var topupState string
	var remaining int64
	if err := store.SQL().QueryRowContext(ctx, `
SELECT state, remaining_bytes FROM paperboat.user_machine_bandwidth_topups WHERE id = $1`, "cmbt_"+suffix).Scan(&topupState, &remaining); err != nil {
		t.Fatal(err)
	}
	if topupState != "exhausted" || remaining != 0 {
		t.Fatalf("top-up state/remaining = %q/%d", topupState, remaining)
	}
	reservation, err = service.ReserveBandwidth(ctx, userMachineID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.GrantedBytes != 0 || !reservation.Exhausted {
		t.Fatalf("exhausted reservation = %+v", reservation)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET state = 'disconnected' WHERE id = $1`, userMachineID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReserveBandwidth(ctx, userMachineID, 1); !errors.Is(err, ErrBandwidthDenied) {
		t.Fatalf("disuser machine reservation error = %v", err)
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
	pairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: first.BootstrapToken, Verifier: "verifier-1", DisplayName: "Studio", Platform: "darwin", Architecture: "arm64", WorkspaceRoot: "/Users/paperboat", RuntimeVersions: json.RawMessage(`{"pb":"test"}`), PublicIdentityKey: integrationPublicIdentityKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: first.BootstrapToken, Verifier: "verifier-2", DisplayName: "Replay", Platform: "darwin", Architecture: "arm64", WorkspaceRoot: "/Users/paperboat", PublicIdentityKey: integrationPublicIdentityKey}); !errors.Is(err, ErrEnrollmentState) {
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
	pairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: first.BootstrapToken, Verifier: verifier, DisplayName: "Denied host", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/workspace", PublicIdentityKey: integrationPublicIdentityKey})
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
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_pairings WHERE id=$1`, pairing.ID).Scan(&pairingState); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_enrollments WHERE id=$1`, first.ID).Scan(&enrollmentState); err != nil {
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
	pairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: first.BootstrapToken, Verifier: verifier, DisplayName: "Expired host", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/workspace", PublicIdentityKey: integrationPublicIdentityKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_pairings SET expires_at=now()-interval '1 minute' WHERE id=$1`, pairing.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_enrollments SET expires_at=now()-interval '1 minute' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(ctx, userID, pairing.UserCode); !errors.Is(err, ErrPairingExpired) {
		t.Fatalf("approval error = %v", err)
	}
	var pairingState, enrollmentState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_pairings WHERE id=$1`, pairing.ID).Scan(&pairingState); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_enrollments WHERE id=$1`, first.ID).Scan(&enrollmentState); err != nil {
		t.Fatal(err)
	}
	if pairingState != "expired" || enrollmentState != "expired" {
		t.Fatalf("pairing=%q enrollment=%q", pairingState, enrollmentState)
	}
	var machineCount, occupiedSeats int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE seat_state='occupied') FROM paperboat.user_machines WHERE user_id=$1`, userID).Scan(&machineCount, &occupiedSeats); err != nil {
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
	pairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: start.BootstrapToken, Verifier: verifier, DisplayName: "Install host", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/workspace", PublicIdentityKey: integrationPublicIdentityKey})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := secrets.Encrypt("test-install-key", `{"bootstrap":"ok"}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_pairings SET state='approved', installation_config_ciphertext=$1 WHERE id=$2`, ciphertext, pairing.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_enrollments SET state='material_issued' WHERE id=$1`, start.ID); err != nil {
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
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_enrollments WHERE id=$1`, start.ID).Scan(&enrollmentState); err != nil {
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
	expiredPairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: second.BootstrapToken, Verifier: expiredVerifier, DisplayName: "Expired host", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/workspace", PublicIdentityKey: integrationPublicIdentityKey})
	if err != nil {
		t.Fatal(err)
	}
	expiredCiphertext, err := secrets.Encrypt("test-install-key", `{"bootstrap":"expired"}`)
	if err != nil {
		t.Fatal(err)
	}
	expiredHash := sha256.Sum256([]byte(expiredVerifier))
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_pairings SET state='approved', verifier_hash=$1, installation_config_ciphertext=$2, expires_at=now()-interval '1 minute' WHERE id=$3`, expiredHash[:], expiredCiphertext, expiredPairing.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_enrollments SET state='material_issued' WHERE id=$1`, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConsumeInstallation(ctx, expiredVerifier); !errors.Is(err, ErrInstallationExpired) {
		t.Fatalf("expired material error=%v", err)
	}
}

func TestInstallationFailureRevokesIdentityReleasesSeatAndRetryIssuesNewIdentity(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, userMachineID, environmentID := "usr_install_failure_"+suffix, "um_install_failure_"+suffix, "env_install_failure_"+suffix
	pairingID, enrollmentID, helperID := "ump_install_failure_"+suffix, "ume_install_failure_"+suffix, "helper_install_failure_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_install_failure_"+suffix, "install-failure-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,public_identity_key) VALUES ($1,$2,$3,'Recovery host','linux','amd64','/workspace','offline','occupied',$4)`, userMachineID, userID, environmentID, integrationPublicIdentityKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_pairings (id,verifier_hash,user_code,requested_display_name,platform,architecture,workspace_root,public_identity_key,state,user_machine_id,expires_at) VALUES ($1,$2,$3,'Recovery host','linux','amd64','/workspace',$4,'consumed',$5,now()+interval '10 minutes')`, pairingID, []byte("verifier_"+suffix), "CODE"+suffix, integrationPublicIdentityKey, userMachineID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_enrollments (id,user_id,operation_id,idempotency_key,bootstrap_token_hash,bootstrap_token_ciphertext,state,pairing_id,user_machine_id,expires_at) VALUES ($1,$2,$3,$4,$5,$6,'installing',$7,$8,now()+interval '10 minutes')`, enrollmentID, userID, "op_"+suffix, "idem_"+suffix, []byte("token_"+suffix), []byte("cipher_"+suffix), pairingID, userMachineID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, userMachineID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port,desired_state,desired_revision,applied_revision) VALUES ($1,$2,'runtime_https_wss',$3,'127.0.0.1',38080,'attached',1,0)`, "route_"+suffix, environmentID, "recovery-"+suffix+".example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, helperID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,state,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'consumed',now()+interval '10 minutes')`, "henr_"+suffix, environmentID, helperID, []byte("jti_"+suffix), "op_helper_"+suffix, []byte("request_"+suffix), []byte("grant_"+suffix)); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"linux"}}, testSeatAuthorizer{})
	service.ConfigureProvisioning(nil, "test-install-key")
	service.ConfigureAccess(nil, "https://control.example.test", time.Minute)
	if err := service.ConfigureRuntimeRoute("example.test", 38080); err != nil {
		t.Fatal(err)
	}
	configureSignedTestArtifact(t, service)
	grantCalls := 0
	service.ConfigureHelperEnrollment(func(context.Context, string, string, string, time.Duration) (HelperEnrollmentGrant, error) {
		grantCalls++
		newHelperID, newEnrollmentID := "helper_install_retry_"+suffix, "henr_retry_"+suffix
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'pending')`, newHelperID, environmentID); err != nil {
			return HelperEnrollmentGrant{}, err
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,state,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',now()+interval '10 minutes')`, newEnrollmentID, environmentID, newHelperID, []byte("jti_retry_"+suffix), "op_helper_retry_"+suffix, []byte("request_retry_"+suffix), []byte("grant_retry_"+suffix)); err != nil {
			return HelperEnrollmentGrant{}, err
		}
		return HelperEnrollmentGrant{EnrollmentID: newEnrollmentID, HelperID: newHelperID, Credential: "retry-credential", ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}, nil
	})
	if err := service.FailInstallation(ctx, enrollmentID, environmentID, "helper_wrong", "henr_"+suffix, "service_install"); !errors.Is(err, ErrEnrollmentState) {
		t.Fatalf("cross-helper failure report error = %v", err)
	}
	if err := service.FailInstallation(ctx, enrollmentID, environmentID, helperID, "henr_wrong_"+suffix, "service_install"); !errors.Is(err, ErrEnrollmentState) {
		t.Fatalf("mismatched helper-enrollment failure report error = %v", err)
	}
	if err := service.FailInstallation(ctx, enrollmentID, environmentID, helperID, "", "service_install"); !errors.Is(err, ErrEnrollmentState) {
		t.Fatalf("unbound failure report error = %v", err)
	}
	if err := service.FailInstallation(ctx, enrollmentID, environmentID, helperID, "henr_"+suffix, "service_install"); err != nil {
		t.Fatal(err)
	}
	var failedEnrollmentState, failedMachineSeat, failedHelperState, failedGrantState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT e.state,m.seat_state,h.state,he.state FROM paperboat.user_machine_enrollments e JOIN paperboat.user_machines m ON m.id=e.user_machine_id JOIN paperboat.control_helpers h ON h.environment_id=m.environment_id JOIN paperboat.control_helper_enrollments he ON he.helper_id=h.id WHERE e.id=$1 AND h.id=$2 AND he.id=$3`, enrollmentID, helperID, "henr_"+suffix).Scan(&failedEnrollmentState, &failedMachineSeat, &failedHelperState, &failedGrantState); err != nil {
		t.Fatal(err)
	}
	if failedEnrollmentState != "failed_retryable" || failedMachineSeat != "released" || failedHelperState != "revoked" || failedGrantState != "revoked" {
		t.Fatalf("failure cleanup enrollment=%s seat=%s helper=%s grant=%s", failedEnrollmentState, failedMachineSeat, failedHelperState, failedGrantState)
	}
	retried, err := service.RetryEnrollment(ctx, userID, enrollmentID)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Generation != 2 || retried.State != "awaiting_bootstrap" || retried.UserMachineID != userMachineID || retried.PairingID != "" {
		t.Fatalf("retry=%+v", retried)
	}
	retryVerifier := "retry-verifier-" + suffix
	retryPairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: retried.BootstrapToken, Verifier: retryVerifier, DisplayName: "Recovery host", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/workspace", PublicIdentityKey: integrationPublicIdentityKey})
	if err != nil {
		t.Fatal(err)
	}
	recoveredMachine, err := service.Approve(ctx, userID, retryPairing.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if recoveredMachine.ID != userMachineID || recoveredMachine.EnvironmentID != environmentID || grantCalls != 1 {
		t.Fatalf("machine=%+v helper_grant_calls=%d", recoveredMachine, grantCalls)
	}
	material, err := service.ConsumeInstallation(ctx, retryVerifier)
	if err != nil {
		t.Fatal(err)
	}
	var recoveryMaterial struct {
		UserMachineID           string `json:"user_machine_id"`
		UserMachineEnrollmentID string `json:"user_machine_enrollment_id"`
		EnvironmentID           string `json:"environment_id"`
		HelperID                string `json:"helper_id"`
		ReuseIdentity           bool   `json:"reuse_identity"`
		Credential              string `json:"enrollment_credential"`
		HelperListenAddress     string `json:"helper_listen_address"`
	}
	if json.Unmarshal(material, &recoveryMaterial) != nil || recoveryMaterial.UserMachineID != userMachineID || recoveryMaterial.UserMachineEnrollmentID != enrollmentID || recoveryMaterial.EnvironmentID != environmentID || recoveryMaterial.HelperID != "helper_install_retry_"+suffix || recoveryMaterial.ReuseIdentity || recoveryMaterial.Credential != "retry-credential" || recoveryMaterial.HelperListenAddress != "127.0.0.1:38080" {
		t.Fatalf("recovery material=%s", material)
	}
	var routeCount int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.control_routes WHERE environment_id=$1 AND kind='runtime_https_wss' AND public_host=$2 AND target_host='127.0.0.1' AND target_port=38080`, environmentID, "recovery-"+suffix+".example.test").Scan(&routeCount); err != nil || routeCount != 1 {
		t.Fatalf("runtime route count=%d err=%v", routeCount, err)
	}
	var machineCount, occupiedSeats int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE seat_state='occupied') FROM paperboat.user_machines WHERE user_id=$1`, userID).Scan(&machineCount, &occupiedSeats); err != nil {
		t.Fatal(err)
	}
	if machineCount != 1 || occupiedSeats != 1 {
		t.Fatalf("machines=%d occupied_seats=%d", machineCount, occupiedSeats)
	}
}

func configureSignedTestArtifact(t *testing.T, service *Service) {
	t.Helper()
	if err := service.ConfigureMachineArtifacts("https://updates.example.test/paperboat", "test"); err != nil {
		t.Fatal(err)
	}
}

func TestConnectIssuesEnvironmentBoundDescriptor(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, userMachineID, environmentID := "usr_um_connect_"+suffix, "um_connect_"+suffix, "env_connect_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-connect-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Studio Mac','darwin','arm64','/Users/paperboat','online','occupied',true)`, userMachineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET observed_capabilities=configured_capabilities WHERE id=$1`, userMachineID); err != nil {
		t.Fatal(err)
	}
	sourceMachineID := "um_source_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Source Mac','darwin','arm64','/Users/source','online','occupied',true)`, sourceMachineID, userID, "env_source_"+suffix); err != nil {
		t.Fatal(err)
	}
	helperID := "helper_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, userMachineID, userID); err != nil {
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
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,generation,edge_pool,edge_node_id,state) VALUES ($1,$2,1,'development',$3,'admitted')`, environmentID, userMachineID, edgeNodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation) VALUES ($1,$2,'runtime_https_wss',$3,'127.0.0.1',8080,1,1,$4,1)`, "route_"+suffix, environmentID, "machine-"+suffix+".example.test", edgeNodeID); err != nil {
		t.Fatal(err)
	}
	terminalSessionID := "umts_connect_" + suffix
	if _, err := store.Queries().CreateUserMachineTerminalSession(ctx, dbsqlc.CreateUserMachineTerminalSessionParams{ID: terminalSessionID, UserMachineID: userMachineID, TerminalID: "term_connect_" + suffix, Name: "bright-beacon", LaunchCwd: "/Users/paperboat"}); err != nil {
		t.Fatal(err)
	}
	staleSessionID := "umts_stale_" + suffix
	if _, err := store.Queries().CreateUserMachineTerminalSession(ctx, dbsqlc.CreateUserMachineTerminalSessionParams{ID: staleSessionID, UserMachineID: userMachineID, TerminalID: "term_stale_" + suffix, Name: "stale", LaunchCwd: "/Users/paperboat"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Queries().QueueUserMachineTerminalSessionOperation(ctx, dbsqlc.QueueUserMachineTerminalSessionOperationParams{ID: "umtso_stale_" + suffix, UserMachineID: userMachineID, TerminalSessionID: staleSessionID, Operation: "delete_history"}); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	service.ConfigureProvisioning(access.FakeClient{}, "test-key")
	service.ConfigureAccess(access.FakeCredentialIssuer{}, "https://api.paperboat.test", 15*time.Minute)
	signer, err := mint.NewEphemeral(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service.ConfigureTerminalSessions(4, signer, nil)
	response, err := service.ConnectTerminalSession(ctx, userID, sourceMachineID, userMachineID, "cls_1", terminalSessionID)
	if err != nil {
		t.Fatal(err)
	}
	if !response.Connectable || response.UserMachineID != userMachineID || response.Environment["id"] != environmentID || response.Environment["resource_id"] != userMachineID {
		t.Fatalf("response = %#v", response)
	}
	terminalEndpoints, _ := response.Terminal["endpoints"].(map[string]any)
	if terminalEndpoints["wss"] != "wss://machine-"+suffix+".example.test/v1/runtime" || terminalEndpoints["quic"] != "quic://machine-"+suffix+".example.test:443" || response.FileTransfer["endpoint"] != "https://machine-"+suffix+".example.test/v1/file-transfers" || response.Terminal["auth"] == nil || response.FileTransfer["auth"] == nil {
		t.Fatalf("descriptor = %#v", response)
	}
	terminalAuth := response.Terminal["auth"].(map[string]any)
	transferAuth := response.FileTransfer["auth"].(map[string]any)
	for class, token := range map[string]string{"terminal_operation": terminalAuth["token"].(string), "file_transfer": transferAuth["token"].(string)} {
		claims, verifyErr := signer.VerifyCredential(token, "https://api.paperboat.test", class, time.Now().UTC())
		if verifyErr != nil {
			t.Fatalf("verify %s credential: %v", class, verifyErr)
		}
		if claims.EnvironmentID != environmentID || claims.UserID != userID || claims.CLIClientSessionID != "cls_1" || claims.SessionID != terminalSessionID || class == "file_transfer" && claims.SourceMachineID != sourceMachineID {
			t.Fatalf("%s credential bindings = %#v", class, claims)
		}
	}
}

func TestCreateAndConnectTerminalSessionCompositionIsIdempotent(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, userMachineID, environmentID := "usr_um_mc_"+suffix, "um_mc_"+suffix, "env_mc_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "mc-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Studio Mac','darwin','arm64','/Users/paperboat','online','occupied',true)`, userMachineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET observed_capabilities=configured_capabilities WHERE id=$1`, userMachineID); err != nil {
		t.Fatal(err)
	}
	sourceMachineID := "um_mc_source_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Source Mac','darwin','arm64','/Users/source','online','occupied',true)`, sourceMachineID, userID, "env_mc_source_"+suffix); err != nil {
		t.Fatal(err)
	}
	helperID := "helper_mc_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, userMachineID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, helperID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,state,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',now()+interval '10 minutes')`, "enroll_mc_"+suffix, environmentID, helperID, []byte("jti_mc_"+suffix), "operation_mc_"+suffix, []byte("request_mc_"+suffix), []byte("grant_mc_"+suffix)); err != nil {
		t.Fatal(err)
	}
	edgeNodeID := "edge_mc_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at) VALUES ($1,'development','1.0',$2,'ready',true,now())`, edgeNodeID, "epoch_mc_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,generation,edge_pool,edge_node_id,state) VALUES ($1,$2,1,'development',$3,'admitted')`, environmentID, userMachineID, edgeNodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation) VALUES ($1,$2,'runtime_https_wss',$3,'127.0.0.1',8080,1,1,$4,1)`, "route_mc_"+suffix, environmentID, "machine-mc-"+suffix+".example.test", edgeNodeID); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	service.ConfigureProvisioning(access.FakeClient{}, "test-key")
	service.ConfigureAccess(access.FakeCredentialIssuer{}, "https://api.paperboat.test", 15*time.Minute)
	signer, err := mint.NewEphemeral(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service.ConfigureTerminalSessions(4, signer, nil)

	created, err := service.CreateConfiguredTerminalSession(ctx, userID, userMachineID, "bench-run", "pb-mc-key")
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := service.ConnectTerminalSession(ctx, userID, sourceMachineID, userMachineID, "cls_mc_1", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !descriptor.Connectable || descriptor.Terminal["session_id"] != created.ID {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	replay, err := service.CreateConfiguredTerminalSession(ctx, userID, userMachineID, "bench-run", "pb-mc-key")
	if err != nil || replay.ID != created.ID {
		t.Fatalf("idempotent replay = %+v, %v", replay, err)
	}
}

func TestExecDescriptorPersistsExactRevocableCredential(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_exec_"+suffix, "um_exec_"+suffix, "env_exec_"+suffix
	sourceMachineID, helperID, edgeNodeID := "um_exec_source_"+suffix, "helper_exec_"+suffix, "edge_exec_"+suffix
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, []any{userID, "workos_exec_" + suffix, "exec-" + suffix + "@example.test"}},
		{`INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Exec Host','linux','amd64','/workspace','online','occupied',true)`, []any{machineID, userID, environmentID}},
		{`UPDATE paperboat.user_machines SET observed_capabilities=configured_capabilities WHERE id=$1`, []any{machineID}},
		{`INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Exec Source','linux','amd64','/source','online','occupied',true)`, []any{sourceMachineID, userID, "env_exec_source_" + suffix}},
		{`INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, []any{environmentID, machineID, userID}},
		{`INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, []any{helperID, environmentID}},
		{`INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at) VALUES ($1,'development','1.0',$2,'ready',true,now())`, []any{edgeNodeID, "epoch_exec_" + suffix}},
		{`INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,generation,edge_pool,edge_node_id,state) VALUES ($1,$2,1,'development',$3,'admitted')`, []any{environmentID, machineID, edgeNodeID}},
		{`INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation) VALUES ($1,$2,'runtime_https_wss',$3,'127.0.0.1',8080,1,1,$4,1)`, []any{"route_exec_" + suffix, environmentID, "exec-" + suffix + ".example.test", edgeNodeID}},
	}
	for _, statement := range statements {
		if _, err := store.SQL().ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	signer, err := mint.NewEphemeral(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	service.ConfigureAccess(access.FakeCredentialIssuer{}, "https://api.paperboat.test", 5*time.Minute)
	service.ConfigureTerminalSessions(4, signer, nil)
	operationID := "operation_exec_" + suffix
	descriptor, err := service.ExecDescriptor(ctx, userID, sourceMachineID, machineID, "cli_exec_1", operationID)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := descriptor.Auth["token"].(string)
	claims, err := signer.VerifyCredential(token, "https://api.paperboat.test", "exec_operation", time.Now().UTC())
	if err != nil || claims.OperationID != operationID || claims.MachineID != machineID || claims.UserID != userID || claims.CLIClientSessionID != "cli_exec_1" {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	var sessionID, state string
	if err := store.SQL().QueryRowContext(ctx, `SELECT helper_terminal_session_id,state FROM paperboat.user_machine_access_sessions WHERE user_machine_id=$1`, machineID).Scan(&sessionID, &state); err != nil || sessionID != claims.JTI || state != "active" {
		t.Fatalf("session id=%q state=%q err=%v", sessionID, state, err)
	}
	if err := service.RevokeUserMachineSessions(ctx, machineID, "test_revocation"); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_access_sessions WHERE user_machine_id=$1`, machineID).Scan(&state); err != nil || state != "revoked" {
		t.Fatalf("revoked state=%q err=%v", state, err)
	}
}

func TestTransferDefaultsAndBrokerPreserveMachineOwnershipAndRouteHost(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_transfer_" + suffix
	foreignUserID := "usr_transfer_foreign_" + suffix
	for _, user := range []struct{ id, email string }{{userID, "transfer-" + suffix + "@example.test"}, {foreignUserID, "transfer-foreign-" + suffix + "@example.test"}} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, user.id, "workos_"+user.id, user.email); err != nil {
			t.Fatal(err)
		}
	}
	type machineFixture struct{ id, environmentID, ownerID, name string }
	source := machineFixture{"um_transfer_source_" + suffix, "env_transfer_source_" + suffix, userID, "Source"}
	destination := machineFixture{"um_transfer_destination_" + suffix, "env_transfer_destination_" + suffix, userID, "Destination"}
	host := machineFixture{"um_transfer_host_" + suffix, "env_transfer_host_" + suffix, userID, "Host"}
	foreign := machineFixture{"um_transfer_foreign_" + suffix, "env_transfer_foreign_" + suffix, foreignUserID, "Foreign"}
	for _, machine := range []machineFixture{source, destination, host, foreign} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,$4,'linux','amd64','/home/test','online','occupied',true)`, machine.id, machine.ownerID, machine.environmentID, machine.name); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET observed_capabilities=configured_capabilities WHERE id=$1`, machine.id); err != nil {
			t.Fatal(err)
		}
	}
	addRoute := func(machine machineFixture, publicHost string) {
		helperID := "helper_" + machine.id
		edgeID := "edge_" + machine.id
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, machine.environmentID, machine.id, machine.ownerID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, helperID, machine.environmentID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at) VALUES ($1,'development','1.0',$2,'ready',true,now())`, edgeID, "epoch_"+machine.id); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,generation,edge_pool,edge_node_id,state) VALUES ($1,$2,1,'development',$3,'admitted')`, machine.environmentID, machine.id, edgeID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation) VALUES ($1,$2,'runtime_https_wss',$3,'127.0.0.1',8080,1,1,$4,1)`, "route_"+machine.id, machine.environmentID, publicHost, edgeID); err != nil {
			t.Fatal(err)
		}
	}
	addRoute(destination, "destination-"+suffix+".example.test")
	addRoute(host, "host-"+suffix+".example.test")
	sessionID := "umts_transfer_" + suffix
	if _, err := store.Queries().CreateUserMachineTerminalSession(ctx, dbsqlc.CreateUserMachineTerminalSessionParams{ID: sessionID, UserMachineID: host.id, TerminalID: "term_" + suffix, Name: "transfer", LaunchCwd: "/home/test"}); err != nil {
		t.Fatal(err)
	}

	signer, err := mint.NewEphemeral(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	policy := accessdescriptor.FileTransferPolicy{Revision: "file-transfer-v1", MaxFileBytes: 50 << 20, MaxBatchFiles: 10, MaxBatchBytes: 500 << 20, MaxConcurrentTransfers: 2, RetentionSeconds: 604800, DeliveryTimeoutSeconds: 600, MaxPendingSpoolBytes: 1 << 30}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	service.ConfigureAccess(nil, "https://api.paperboat.test", 2*time.Minute)
	service.ConfigureTerminalSessions(4, signer, nil)
	service.ConfigureFileTransfer(policy)

	if _, err := service.SetTransferDestinationDefault(ctx, userID, foreign.id); !errors.Is(err, ErrTransferDestinationInvalid) {
		t.Fatalf("foreign default error = %v", err)
	}
	if selected, err := service.SetTransferDestinationDefault(ctx, userID, destination.id); err != nil || selected.ID != destination.id {
		t.Fatalf("set user default = %+v, %v", selected, err)
	}
	if selected, err := service.TransferDestinationDefault(ctx, userID); err != nil || selected.ID != destination.id {
		t.Fatalf("get user default = %+v, %v", selected, err)
	}
	if selected, err := service.SetTerminalSessionTransferDestination(ctx, userID, sessionID, destination.id); err != nil || selected.ID != destination.id {
		t.Fatalf("set session default = %+v, %v", selected, err)
	}
	if selected, err := service.TerminalSessionTransferDestination(ctx, userID, sessionID); err != nil || selected.ID != destination.id {
		t.Fatalf("get session default = %+v, %v", selected, err)
	}

	direct, err := service.FileTransferDescriptor(ctx, userID, source.id, destination.id, "cli_1", "")
	if err != nil {
		t.Fatal(err)
	}
	if direct.Endpoint != "https://destination-"+suffix+".example.test/v1/file-transfers" || direct.DestinationMachineID != destination.id || direct.Policy != policy {
		t.Fatalf("direct descriptor = %+v", direct)
	}
	session, err := service.FileTransferDescriptor(ctx, userID, source.id, destination.id, "cli_1", sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if session.Endpoint != "https://host-"+suffix+".example.test/v1/file-transfers" || session.DestinationMachineID != destination.id {
		t.Fatalf("session descriptor = %+v", session)
	}
	token, _ := session.Auth["token"].(string)
	claims, err := signer.VerifyCredential(token, "https://api.paperboat.test", "file_transfer", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if claims.MachineID != host.id || claims.SourceMachineID != source.id || claims.SessionID != sessionID || claims.UserID != userID {
		t.Fatalf("session credential bindings = %+v", claims)
	}
	if _, err := service.FileTransferDescriptor(ctx, userID, foreign.id, destination.id, "cli_1", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign source error = %v", err)
	}

	if err := service.ClearTerminalSessionTransferDestination(ctx, userID, sessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.TerminalSessionTransferDestination(ctx, userID, sessionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cleared session default error = %v", err)
	}
	if err := service.ClearTransferDestinationDefault(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.TransferDestinationDefault(ctx, userID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cleared user default error = %v", err)
	}
}

func TestDisconnectRevokesMintedHelperSessionsAndRetriesOfflineConnector(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, userMachineID, environmentID := "usr_um_revoke_"+suffix, "um_revoke_"+suffix, "env_revoke_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-revoke-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,provider_route_route_id,provider_route_client_id,provider_route_http_base_url,provider_route_websocket_base_url) VALUES ($1,$2,$3,'Studio Mac','darwin','arm64','/Users/paperboat','online','occupied',true,'tun_1','cli_1','https://machine.example','wss://machine.example')`, userMachineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET observed_capabilities=configured_capabilities WHERE id=$1`, userMachineID); err != nil {
		t.Fatal(err)
	}
	sourceMachineID := "um_source_revoke_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Source Mac','darwin','arm64','/Users/source','online','occupied',true)`, sourceMachineID, userID, "env_source_revoke_"+suffix); err != nil {
		t.Fatal(err)
	}
	helperID := "helper_revoke_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, userMachineID, userID); err != nil {
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
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,generation,edge_pool,edge_node_id,state) VALUES ($1,$2,1,'development',$3,'admitted')`, environmentID, userMachineID, edgeNodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation) VALUES ($1,$2,'runtime_https_wss',$3,'127.0.0.1',8080,1,1,$4,1)`, "route_revoke_"+suffix, environmentID, "machine-revoke-"+suffix+".example.test", edgeNodeID); err != nil {
		t.Fatal(err)
	}
	terminalSessionID := "umts_revoke_" + suffix
	if _, err := store.Queries().CreateUserMachineTerminalSession(ctx, dbsqlc.CreateUserMachineTerminalSessionParams{ID: terminalSessionID, UserMachineID: userMachineID, TerminalID: "term_revoke_" + suffix, Name: "bright-beacon", LaunchCwd: "/Users/paperboat"}); err != nil {
		t.Fatal(err)
	}
	issuer := &recordingIssuer{}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	service.ConfigureProvisioning(access.FakeClient{}, "test-key")
	service.ConfigureAccess(issuer, "https://api.paperboat.test", 5*time.Minute)
	if _, err := service.ConnectTerminalSession(ctx, userID, sourceMachineID, userMachineID, "cls_1", terminalSessionID); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.user_machine_access_sessions WHERE user_machine_id=$1 AND state='active'`, userMachineID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active access sessions = %d, want 1", active)
	}
	issuer.failRevocation = true
	if err := service.Disconnect(ctx, userID, userMachineID); err == nil {
		t.Fatal("Disconnect succeeded while Helper was unavailable")
	}
	var environmentState, helperState, enrollmentState, connectorState, routeState, machineState, seatState string
	var online bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT e.desired_state,h.state,he.state,c.state,r.desired_state,m.state,m.seat_state,m.online
FROM paperboat.control_environments e
JOIN paperboat.control_helpers h ON h.environment_id=e.id
JOIN paperboat.control_helper_enrollments he ON he.environment_id=e.id
JOIN paperboat.control_connector_generations c ON c.environment_id=e.id
JOIN paperboat.control_routes r ON r.environment_id=e.id
JOIN paperboat.user_machines m ON m.environment_id=e.id
WHERE e.id=$1`, environmentID).Scan(&environmentState, &helperState, &enrollmentState, &connectorState, &routeState, &machineState, &seatState, &online); err != nil {
		t.Fatal(err)
	}
	if environmentState != "revoked" || helperState != "revoked" || enrollmentState != "revoked" || connectorState != "revoked" || routeState != "detaching" || machineState != "disconnected" || seatState != "released" || online {
		t.Fatalf("disconnect convergence: environment=%s helper=%s enrollment=%s connector=%s route=%s machine=%s seat=%s online=%v", environmentState, helperState, enrollmentState, connectorState, routeState, machineState, seatState, online)
	}
	var propagated bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT helper_revoked_at IS NOT NULL FROM paperboat.user_machine_access_sessions WHERE user_machine_id=$1`, userMachineID).Scan(&propagated); err != nil {
		t.Fatal(err)
	}
	if propagated {
		t.Fatal("revocation was marked propagated after a failed downstream call")
	}
	issuer.failRevocation = false
	if err := service.RetryPendingRevocations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT helper_revoked_at IS NOT NULL FROM paperboat.user_machine_access_sessions WHERE user_machine_id=$1`, userMachineID).Scan(&propagated); err != nil {
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
	userID, userMachineID, environmentID, helperID := "usr_um_seat_"+suffix, "um_seat_"+suffix, "env_seat_"+suffix, "helper_seat_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-seat-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,revoked_at) VALUES ($1,$2,$3,'Seat Loss','linux','amd64','/srv/workspace','revoked','released',false,now())`, userMachineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, userMachineID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, helperID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,state,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',now()+interval '10 minutes')`, "enroll_seat_"+suffix, environmentID, helperID, []byte("jti_seat_"+suffix), "operation_seat_"+suffix, []byte("request_seat_"+suffix), []byte("grant_seat_"+suffix)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,generation,edge_pool,state) VALUES ($1,$2,1,'development','admitted')`, environmentID, helperID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port) VALUES ($1,$2,'runtime_https_wss',$3,'127.0.0.1',8080)`, "route_seat_"+suffix, environmentID, "seat-"+suffix+".example.test"); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	if err := service.ReconcileUserMachineEntitlement(ctx, userID); err != nil {
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
	userID := "usr_um_seat_reduction_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-seat-reduction-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_entitlements
  (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end)
VALUES ($1,$2,$3,'user-machine-seat','active',1,1048576,now()-interval '1 day',now()+interval '1 month')`, "ent_seat_reduction_"+suffix, userID, "sub_seat_reduction_"+suffix); err != nil {
		t.Fatal(err)
	}

	type machineFixture struct {
		id, environmentID, helperID, label string
		enrolledOffset                     string
	}
	machines := []machineFixture{
		{"um_old_" + suffix, "env_old_" + suffix, "helper_old_" + suffix, "Old", "2 days"},
		{"um_new_" + suffix, "env_new_" + suffix, "helper_new_" + suffix, "New", "1 day"},
	}
	for _, machine := range machines {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines
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
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,generation,edge_pool,state) VALUES ($1,$2,1,'development','admitted')`, machine.environmentID, machine.helperID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port) VALUES ($1,$2,'runtime_https_wss',$3,'127.0.0.1',8080)`, "route_"+machine.id, machine.environmentID, machine.id+".example.test"); err != nil {
			t.Fatal(err)
		}
	}

	service := New(store, audit.NewWriter(store), Policy{}, nil)
	if err := service.ReconcileUserMachineEntitlement(ctx, userID); err != nil {
		t.Fatal(err)
	}
	for index, machine := range machines {
		var machineState, seatState, environmentState, helperState, connectorState, routeState string
		var online bool
		if err := store.SQL().QueryRowContext(ctx, `SELECT m.state,m.seat_state,m.online,e.desired_state,h.state,c.state,r.desired_state
FROM paperboat.user_machines m
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
	access.FakeCredentialIssuer
	failRevocation bool
	revocations    []access.CredentialRevocationInput
}

func (i *recordingIssuer) RevokeCLI(_ context.Context, input access.CredentialRevocationInput) error {
	i.revocations = append(i.revocations, input)
	if i.failRevocation {
		return errors.New("helper unavailable")
	}
	return nil
}

func testStore(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run user-machine integration tests")
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
