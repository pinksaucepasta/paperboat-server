package usermachines

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/access"
	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	authservice "github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
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

func TestRenameMachineUsesOnlyActiveNames(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_machine_rename_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_rename_"+suffix, "machine-rename-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	for _, machine := range []struct{ id, environmentID, name string }{
		{"mch_rename_active_" + suffix, "env_rename_active_" + suffix, "Active"},
		{"mch_rename_other_" + suffix, "env_rename_other_" + suffix, "Other"},
		{"mch_rename_deleted_" + suffix, "env_rename_deleted_" + suffix, "Reusable"},
	} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state) VALUES ($1,$2,$3,$4,'linux','amd64','/workspace','offline','released')`, machine.id, userID, machine.environmentID, machine.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET state='deleted',deleted_at=now() WHERE id=$1`, "mch_rename_deleted_"+suffix); err != nil {
		t.Fatal(err)
	}

	service := New(store, audit.NewWriter(store), Policy{}, testSeatAuthorizer{})
	renamed, err := service.Rename(ctx, userID, "mch_rename_other_"+suffix, "  Reusable  ")
	if err != nil {
		t.Fatal(err)
	}
	if renamed.DisplayName != "Reusable" {
		t.Fatalf("display name = %q, want Reusable", renamed.DisplayName)
	}
	if _, err := service.Rename(ctx, userID, renamed.ID, "active"); !errors.Is(err, ErrMachineNameConflict) {
		t.Fatalf("active-name rename error = %v, want ErrMachineNameConflict", err)
	}
	if _, err := service.Rename(ctx, userID, renamed.ID, " "); !errors.Is(err, ErrInvalidMachineName) {
		t.Fatalf("blank-name rename error = %v, want ErrInvalidMachineName", err)
	}
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
	input := SetupInput{SetupMode: "client", DisplayName: "Studio", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/home/paperboat", PublicIdentityKey: base64.RawURLEncoding.EncodeToString(public), RuntimeVersions: json.RawMessage(`{"pb":"test"}`)}
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
	if _, err := service.CreateConfiguredTerminalSession(ctx, userID, first.ID, "forbidden", "client-terminal"); !errors.Is(err, ErrMachineCapabilityUnavailable) {
		t.Fatalf("client terminal session error = %v, want ErrMachineCapabilityUnavailable", err)
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
	if unpaired.SetupMode != "client" || !unpaired.Capabilities.FileReceive.Configured || !unpaired.Capabilities.PreviewLaunch.Configured || unpaired.Capabilities.TerminalHost.Configured {
		t.Fatalf("unpaired capabilities=%+v mode=%q", unpaired.Capabilities, unpaired.SetupMode)
	}
	var environmentState, routeState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT e.desired_state,r.desired_state FROM paperboat.control_environments e JOIN paperboat.control_routes r ON r.environment_id=e.id AND r.kind='runtime_https_wss' WHERE e.id=$1`, unpaired.EnvironmentID).Scan(&environmentState, &routeState); err != nil {
		t.Fatal(err)
	}
	if environmentState != "active" || routeState != "attached" {
		t.Fatalf("downgrade environment=%q route=%q", environmentState, routeState)
	}
	obsoleteMode := input
	obsoleteMode.SetupMode = "session"
	if _, err := service.Setup(ctx, userID, obsoleteMode); !errors.Is(err, ErrInvalidSetup) {
		t.Fatalf("obsolete setup mode error = %v, want ErrInvalidSetup", err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT desired_state FROM paperboat.control_routes WHERE environment_id=$1 AND kind='runtime_https_wss'`, unpaired.EnvironmentID).Scan(&routeState); err != nil {
		t.Fatal(err)
	}
	if routeState != "attached" {
		t.Fatalf("client route=%q", routeState)
	}
}

func TestOnlineClientMachineCanUpgradeToHost(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_client_upgrade_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "client-upgrade-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_entitlements (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end) VALUES ($1,$2,$3,'connected-test','active',1,1048576,now()-interval '1 hour',now()+interval '1 hour')`, "ume_client_upgrade_"+suffix, userID, "sub_client_upgrade_"+suffix); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(public)
	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"linux"}}, testSeatAuthorizer{})
	service.ConfigureProvisioning(access.FakeClient{}, "client-upgrade-key")
	service.ConfigureAccess(nil, "https://api.paperboat.test", 5*time.Minute)
	service.ConfigureHelperEnrollment(func(context.Context, string, string, string, time.Duration) (HelperEnrollmentGrant, error) {
		return HelperEnrollmentGrant{EnrollmentID: "henr_client_upgrade_" + suffix, HelperID: "helper_client_upgrade_" + suffix, Credential: "client-upgrade-credential", ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}, nil
	})
	if err := service.ConfigureRuntimeRoute("runtime.example.test", 38080); err != nil {
		t.Fatal(err)
	}
	configureSignedTestArtifact(t, service)
	machine, err := service.Setup(ctx, userID, SetupInput{SetupMode: "client", DisplayName: "Studio", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/home/paperboat", PublicIdentityKey: publicKey, RuntimeVersions: json.RawMessage(`{"pb":"test"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET state='online', online=true, observed_capabilities=configured_capabilities WHERE id=$1`, machine.ID); err != nil {
		t.Fatal(err)
	}
	pairing, err := service.CreatePairing(ctx, PairingInput{Verifier: "client-upgrade-verifier-" + suffix, DisplayName: "Studio", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/home/paperboat", PublicIdentityKey: publicKey, RuntimeVersions: json.RawMessage(`{"pb":"test"}`)})
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

func TestAuthenticatedClientToHostSetupIsBoundIdempotentAndRollsBack(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, clientSessionID := "usr_authenticated_host_"+suffix, "cls_authenticated_host_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "authenticated-host-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'Host setup test','desktop','linux',ARRAY['projects:connect'],'active',$4,$4)`, clientSessionID, userID, "client_"+suffix, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_entitlements (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end) VALUES ($1,$2,$3,'connected-test','active',1,1048576,now()-interval '1 hour',now()+interval '1 hour')`, "ume_authenticated_host_"+suffix, userID, "sub_authenticated_host_"+suffix); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(public)
	setupSigner, err := mint.NewEphemeral(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	setupEnrollments := controlplane.NewEnrollmentService(store, setupSigner, audit.NewWriter(store), "https://api.paperboat.test", "authenticated-host-setup-enrollment-key")
	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"linux"}}, testSeatAuthorizer{})
	service.ConfigureProvisioning(access.FakeClient{}, "authenticated-host-key")
	service.ConfigureAccess(nil, "https://api.paperboat.test", 5*time.Minute)
	service.ConfigureOneShotCLIAuth("paperboat-cli", []string{"account:read", "projects:connect", "session:refresh"}, 5*time.Minute, 24*time.Hour, "authenticated-host-cli-hash-key")
	service.ConfigureHelperEnrollment(func(_ context.Context, gotUserID, operationKey, environmentID string, _ time.Duration) (HelperEnrollmentGrant, error) {
		if gotUserID != userID || !strings.Contains(operationKey, clientSessionID) || environmentID == "" {
			t.Fatalf("helper grant binding user=%q operation=%q environment=%q", gotUserID, operationKey, environmentID)
		}
		return HelperEnrollmentGrant{EnrollmentID: "henr_authenticated_" + suffix, HelperID: "helper_authenticated_" + suffix, Credential: strings.Repeat("c", 48), ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}, nil
	})
	service.ConfigureAuthenticatedHelperEnrollment(
		func(ctx context.Context, gotUserID, operationKey, environmentID string, lifetime time.Duration, guard HelperEnrollmentAuthorityGuard) (HelperEnrollmentGrant, error) {
			if gotUserID != userID || !strings.HasPrefix(operationKey, "authenticated-host-setup:ump_") || environmentID == "" {
				return HelperEnrollmentGrant{}, fmt.Errorf("helper grant binding user=%q operation=%q environment=%q", gotUserID, operationKey, environmentID)
			}
			return PersistAuthenticatedHelperEnrollment(ctx, store, environmentID, guard, func(ctx context.Context) (HelperEnrollmentGrant, error) {
				grant, issueErr := setupEnrollments.Issue(ctx, gotUserID, operationKey, environmentID, lifetime)
				return HelperEnrollmentGrant{EnrollmentID: grant.EnrollmentID, HelperID: grant.HelperID, Credential: grant.Credential, ExpiresAt: grant.ExpiresAt}, issueErr
			})
		},
		func(context.Context, string, string, string, string, time.Duration, HelperEnrollmentAuthorityGuard) (HelperEnrollmentGrant, error) {
			return HelperEnrollmentGrant{}, errors.New("unexpected authenticated helper recovery")
		},
	)
	if err := service.ConfigureRuntimeRoute("runtime.example.test", 38080); err != nil {
		t.Fatal(err)
	}
	configureSignedTestArtifact(t, service)
	input := SetupInput{SetupMode: "client", DisplayName: "Studio", Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/home/paperboat", PublicIdentityKey: publicKey, RuntimeVersions: json.RawMessage(`{"pb":"test"}`)}
	clientMachine, err := service.Setup(ctx, userID, input)
	if err != nil {
		t.Fatal(err)
	}
	input.SetupMode = "host"
	hostMachine, err := service.Setup(ctx, userID, input)
	if err != nil {
		t.Fatal(err)
	}
	if hostMachine.ID != clientMachine.ID || hostMachine.SetupMode != "host" || !slices.Contains(hostMachine.SetupRoles, "host") || hostMachine.SeatState != "occupied" || hostMachine.InstallationGeneration != clientMachine.InstallationGeneration+1 || hostMachine.Installation == nil {
		t.Fatalf("authenticated Host transition = %+v, previous = %+v", hostMachine, clientMachine)
	}
	verifier := "authenticated-host-verifier-" + suffix
	request := AuthenticatedHostSetupInput{OperationID: "host-setup-operation-" + suffix, Verifier: verifier, PublicIdentityKey: publicKey, InstallationGeneration: hostMachine.InstallationGeneration, SetupMode: "host", Artifact: hostMachine.Installation.Artifact}
	first, err := service.PrepareAuthenticatedHostSetup(ctx, userID, clientSessionID, hostMachine.ID, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.PrepareAuthenticatedHostSetup(ctx, userID, clientSessionID, hostMachine.ID, request)
	if err != nil || second.ExpiresAt != first.ExpiresAt {
		t.Fatalf("idempotent prepare = %+v, err=%v; first=%+v", second, err, first)
	}
	var pairingCount int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.user_machine_pairings WHERE authenticated_setup_cli_session_id=$1 AND authenticated_setup_operation_id=$2`, clientSessionID, request.OperationID).Scan(&pairingCount); err != nil || pairingCount != 1 {
		t.Fatalf("authenticated pairing count=%d err=%v", pairingCount, err)
	}
	if _, err := service.ConsumeInstallation(ctx, verifier); !errors.Is(err, ErrInstallationUnavailable) {
		t.Fatalf("authenticated Host material accepted a legacy identity-less consume: %v", err)
	}
	material, err := service.ConsumeInstallationForIdentity(ctx, verifier, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	var fields struct {
		MachineID     string                    `json:"user_machine_id"`
		Generation    int64                     `json:"installation_generation"`
		SetupMode     string                    `json:"setup_mode"`
		ClientSession installationClientSession `json:"client_session"`
	}
	if err := json.Unmarshal(material, &fields); err != nil || fields.MachineID != hostMachine.ID || fields.Generation != hostMachine.InstallationGeneration || fields.SetupMode != "host" {
		t.Fatalf("material=%s fields=%+v err=%v", material, fields, err)
	}
	if fields.ClientSession.SessionID == "" || fields.ClientSession.AccessToken == "" || fields.ClientSession.RefreshToken == "" {
		t.Fatalf("authenticated Host client session is incomplete: %+v", fields.ClientSession)
	}
	bootstrapDeviceAuth := authservice.NewDeviceService(store, audit.NewWriter(store), config.Default().CLIAuth, []string{"authenticated-host-cli-hash-key"})
	principal, err := bootstrapDeviceAuth.Authenticate(ctx, fields.ClientSession.AccessToken)
	if err != nil || principal.SessionID != fields.ClientSession.SessionID || principal.User.ID != userID {
		t.Fatalf("authenticated Host bootstrap CLI access token rejected: principal=%+v err=%v", principal, err)
	}
	var sessionState string
	var freshBootstrap bool
	var boundMachine sql.NullString
	var accessTokens, refreshTokens int
	if err := store.SQL().QueryRowContext(ctx, `SELECT state, fresh_e2ee_bootstrap, user_machine_id FROM paperboat.cli_client_sessions WHERE id=$1`, fields.ClientSession.SessionID).Scan(&sessionState, &freshBootstrap, &boundMachine); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM paperboat.cli_access_tokens WHERE cli_client_session_id=$1), (SELECT count(*) FROM paperboat.cli_refresh_tokens WHERE cli_client_session_id=$1)`, fields.ClientSession.SessionID).Scan(&accessTokens, &refreshTokens); err != nil {
		t.Fatal(err)
	}
	if sessionState != "active" || !freshBootstrap || !boundMachine.Valid || boundMachine.String != hostMachine.ID || accessTokens != 1 || refreshTokens != 1 {
		t.Fatalf("authenticated Host bootstrap CLI session state=%q fresh=%v machine=%v access_tokens=%d refresh_tokens=%d", sessionState, freshBootstrap, boundMachine, accessTokens, refreshTokens)
	}
	conflict := request
	conflict.Verifier += "-different"
	if _, err := service.PrepareAuthenticatedHostSetup(ctx, userID, clientSessionID, hostMachine.ID, conflict); !errors.Is(err, ErrHostSetupOperationConflict) {
		t.Fatalf("operation conflict error=%v", err)
	}
	conflict = request
	conflict.Artifact.Version += "-different"
	service.ConfigureMachineArtifactVersionResolver(func() string { return conflict.Artifact.Version })
	if _, err := service.PrepareAuthenticatedHostSetup(ctx, userID, clientSessionID, hostMachine.ID, conflict); !errors.Is(err, ErrHostSetupOperationConflict) {
		t.Fatalf("artifact conflict error=%v", err)
	}
	service.ConfigureMachineArtifactVersionResolver(nil)
	input.SetupMode = "client"
	rolledBack, err := service.Setup(ctx, userID, input)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.SetupMode != "client" || !reflect.DeepEqual(rolledBack.SetupRoles, []string{"interactive"}) || rolledBack.SeatState != "released" || rolledBack.InstallationGeneration != hostMachine.InstallationGeneration+1 || rolledBack.Installation == nil {
		t.Fatalf("Client rollback=%+v", rolledBack)
	}
	var pairingState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_pairings WHERE authenticated_setup_cli_session_id=$1 AND authenticated_setup_operation_id=$2`, clientSessionID, request.OperationID).Scan(&pairingState); err != nil || pairingState != "expired" {
		t.Fatalf("rolled-back authenticated pairing state=%q err=%v", pairingState, err)
	}
	if _, err := service.ConsumeInstallationForIdentity(ctx, verifier, publicKey); !errors.Is(err, ErrInstallationExpired) {
		t.Fatalf("rolled-back authenticated material remained recoverable: %v", err)
	}

	// Pairing creation and material persistence are separate short transactions
	// because helper enrollment can perform its own database work. Hold material
	// construction between them and prove a concurrent downgrade wins the second
	// lock, expires the pairing, and leaves no consumable Host authority.
	input.SetupMode = "host"
	raceHost, err := service.Setup(ctx, userID, input)
	if err != nil {
		t.Fatal(err)
	}
	raceHelperID, raceEnrollmentID := "helper_authenticated_race_"+suffix, "henr_authenticated_race_"+suffix
	authorityPersisted, releaseAuthority := make(chan struct{}), make(chan struct{})
	var authorityPersistedOnce sync.Once
	service.ConfigureAuthenticatedHelperEnrollment(
		func(ctx context.Context, gotUserID, operationKey, environmentID string, _ time.Duration, guard HelperEnrollmentAuthorityGuard) (HelperEnrollmentGrant, error) {
			expiresAt := time.Now().UTC().Add(10 * time.Minute)
			err := store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
				if err := guard(ctx, tx, ""); err != nil {
					return err
				}
				if _, err := tx.Queries().CreateControlHelper(ctx, dbsqlc.CreateControlHelperParams{ID: raceHelperID, EnvironmentID: environmentID}); err != nil {
					return err
				}
				if _, err := tx.Queries().CreateControlHelperEnrollment(ctx, dbsqlc.CreateControlHelperEnrollmentParams{
					ID: raceEnrollmentID, EnvironmentID: environmentID, HelperID: raceHelperID,
					JtiHash: []byte("race-jti-" + suffix), OperationKey: "helper-enrollment:" + gotUserID + ":" + operationKey,
					RequestHash: []byte("race-request-" + suffix), GrantCiphertext: []byte("race-grant-" + suffix), ExpiresAt: expiresAt,
				}); err != nil {
					return err
				}
				if err := guard(ctx, tx, raceEnrollmentID); err != nil {
					return err
				}
				authorityPersistedOnce.Do(func() { close(authorityPersisted) })
				select {
				case <-releaseAuthority:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			return HelperEnrollmentGrant{EnrollmentID: raceEnrollmentID, HelperID: raceHelperID, Credential: strings.Repeat("r", 48), ExpiresAt: expiresAt}, err
		},
		func(context.Context, string, string, string, string, time.Duration, HelperEnrollmentAuthorityGuard) (HelperEnrollmentGrant, error) {
			return HelperEnrollmentGrant{}, errors.New("unexpected authenticated helper recovery")
		},
	)
	raceVerifier := "authenticated-host-race-verifier-" + suffix
	raceRequest := AuthenticatedHostSetupInput{OperationID: "host-setup-race-operation-" + suffix, Verifier: raceVerifier, PublicIdentityKey: publicKey, InstallationGeneration: raceHost.InstallationGeneration, SetupMode: "host", Artifact: raceHost.Installation.Artifact}
	type prepareResult struct {
		value AuthenticatedHostSetupInstallation
		err   error
	}
	raceStartedAt := time.Now()
	raceCtx, cancelRace := context.WithTimeout(ctx, 60*time.Second)
	defer cancelRace()
	var releaseAuthorityOnce sync.Once
	releaseInitialAuthority := func() { releaseAuthorityOnce.Do(func() { close(releaseAuthority) }) }
	defer releaseInitialAuthority()
	prepareDone := make(chan prepareResult, 1)
	go func() {
		value, prepareErr := service.PrepareAuthenticatedHostSetup(raceCtx, userID, clientSessionID, raceHost.ID, raceRequest)
		prepareDone <- prepareResult{value: value, err: prepareErr}
	}()
	select {
	case <-authorityPersisted:
	case <-raceCtx.Done():
		fatalWithPostgresLocks(t, store, "authenticated Host helper authority was not persisted after %s: %v", time.Since(raceStartedAt), raceCtx.Err())
	}
	authorityPersistedAt := time.Now()
	input.SetupMode = "client"
	type rollbackResult struct {
		value UserMachine
		err   error
	}
	rollbackDone := make(chan rollbackResult, 1)
	go func() {
		value, rollbackErr := service.Setup(raceCtx, userID, input)
		rollbackDone <- rollbackResult{value: value, err: rollbackErr}
	}()
	if err := waitForUserMachineRowLock(raceCtx, store, raceHost.ID); err != nil {
		fatalWithPostgresLocks(t, store, "Client rollback did not acquire the machine row before authority release after %s: %v", time.Since(authorityPersistedAt), err)
	}
	rollbackLockedAt := time.Now()
	releaseInitialAuthority()
	authorityReleasedAt := time.Now()
	postReleaseCtx, cancelPostRelease := context.WithTimeout(raceCtx, 30*time.Second)
	defer cancelPostRelease()
	var rolledBackConcurrently rollbackResult
	select {
	case rolledBackConcurrently = <-rollbackDone:
	case <-postReleaseCtx.Done():
		fatalWithPostgresLocks(t, store, "concurrent Client rollback did not finish within the post-release bound; authority=%s machine_lock=%s post_release=%s: %v", authorityPersistedAt.Sub(raceStartedAt), rollbackLockedAt.Sub(authorityPersistedAt), time.Since(authorityReleasedAt), postReleaseCtx.Err())
	}
	rollbackFinishedAt := time.Now()
	if rolledBackConcurrently.err != nil {
		t.Fatal(rolledBackConcurrently.err)
	}
	concurrentRollback := rolledBackConcurrently.value
	if concurrentRollback.SetupMode != "client" || concurrentRollback.InstallationGeneration != raceHost.InstallationGeneration+1 {
		t.Fatalf("concurrent Client rollback=%+v", concurrentRollback)
	}
	var prepared prepareResult
	select {
	case prepared = <-prepareDone:
	case <-postReleaseCtx.Done():
		fatalWithPostgresLocks(t, store, "authenticated Host material construction did not finish within the post-release bound; rollback=%s post_release=%s: %v", rollbackFinishedAt.Sub(authorityReleasedAt), time.Since(authorityReleasedAt), postReleaseCtx.Err())
	}
	t.Logf("authenticated Host issuance race completed: authority=%s machine_lock=%s rollback_after_release=%s total_after_release=%s", authorityPersistedAt.Sub(raceStartedAt), rollbackLockedAt.Sub(authorityPersistedAt), rollbackFinishedAt.Sub(authorityReleasedAt), time.Since(authorityReleasedAt))
	if prepared.err != nil && !errors.Is(prepared.err, ErrInvalidHostSetupInstallation) && !errors.Is(prepared.err, ErrHostSetupOperationConflict) {
		t.Fatalf("stale Host issuance result=%+v err=%v", prepared.value, prepared.err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_pairings WHERE authenticated_setup_cli_session_id=$1 AND authenticated_setup_operation_id=$2`, clientSessionID, raceRequest.OperationID).Scan(&pairingState); err != nil || pairingState != "expired" {
		t.Fatalf("concurrent rollback pairing state=%q err=%v", pairingState, err)
	}
	if _, err := service.ConsumeInstallationForIdentity(ctx, raceVerifier, publicKey); !errors.Is(err, ErrInstallationExpired) {
		t.Fatalf("concurrently rolled-back Host material remained consumable: %v", err)
	}
	var grantState string
	var grantRevokedAt sql.NullTime
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,revoked_at FROM paperboat.control_helper_enrollments WHERE id=$1 AND helper_id=$2`, raceEnrollmentID, raceHelperID).Scan(&grantState, &grantRevokedAt); err != nil || grantState != "revoked" || !grantRevokedAt.Valid {
		t.Fatalf("concurrently rolled-back helper grant state=%q revoked_at=%v err=%v", grantState, grantRevokedAt, err)
	}

	// A consumed authenticated setup may recover material after a lost response.
	// Persist a real replacement grant under the recovery guard, race a Client
	// downgrade against it, and prove neither that grant nor refreshed material
	// survives the downgrade.
	input.SetupMode = "host"
	recoveryHost, err := service.Setup(ctx, userID, input)
	if err != nil {
		t.Fatal(err)
	}
	var recoverySeedGrant HelperEnrollmentGrant
	service.ConfigureAuthenticatedHelperEnrollment(
		func(ctx context.Context, gotUserID, operationKey, environmentID string, lifetime time.Duration, guard HelperEnrollmentAuthorityGuard) (HelperEnrollmentGrant, error) {
			grant, issueErr := PersistAuthenticatedHelperEnrollment(ctx, store, environmentID, guard, func(ctx context.Context) (HelperEnrollmentGrant, error) {
				issued, err := setupEnrollments.Issue(ctx, gotUserID, operationKey, environmentID, lifetime)
				return HelperEnrollmentGrant{EnrollmentID: issued.EnrollmentID, HelperID: issued.HelperID, Credential: issued.Credential, ExpiresAt: issued.ExpiresAt}, err
			})
			if issueErr == nil {
				recoverySeedGrant = grant
			}
			return grant, issueErr
		},
		func(context.Context, string, string, string, string, time.Duration, HelperEnrollmentAuthorityGuard) (HelperEnrollmentGrant, error) {
			return HelperEnrollmentGrant{}, errors.New("unexpected authenticated helper recovery")
		},
	)
	recoveryVerifier := "authenticated-host-recovery-verifier-" + suffix
	recoveryRequest := AuthenticatedHostSetupInput{OperationID: "host-setup-recovery-operation-" + suffix, Verifier: recoveryVerifier, PublicIdentityKey: publicKey, InstallationGeneration: recoveryHost.InstallationGeneration, SetupMode: "host", Artifact: recoveryHost.Installation.Artifact}
	if _, err := service.PrepareAuthenticatedHostSetup(ctx, userID, clientSessionID, recoveryHost.ID, recoveryRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConsumeInstallationForIdentity(ctx, recoveryVerifier, publicKey); err != nil {
		t.Fatal(err)
	}
	if recoverySeedGrant.EnrollmentID == "" || recoverySeedGrant.HelperID == "" {
		t.Fatalf("authenticated recovery seed grant=%+v", recoverySeedGrant)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_helper_enrollments SET state='revoked',revoked_at=now() WHERE id=$1 AND state='pending'`, recoverySeedGrant.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_pairings SET expires_at=now()-interval '1 second' WHERE authenticated_setup_cli_session_id=$1 AND authenticated_setup_operation_id=$2`, clientSessionID, recoveryRequest.OperationID); err != nil {
		t.Fatal(err)
	}
	recoveryEnrollmentID := "henr_authenticated_recovery_race_" + suffix
	recoveryAuthorityPersisted, releaseRecoveryAuthority := make(chan struct{}), make(chan struct{})
	var recoveryAuthorityPersistedOnce sync.Once
	service.ConfigureAuthenticatedHelperEnrollment(
		func(ctx context.Context, gotUserID, operationKey, environmentID string, _ time.Duration, guard HelperEnrollmentAuthorityGuard) (HelperEnrollmentGrant, error) {
			expiresAt := time.Now().UTC().Add(10 * time.Minute)
			err := store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
				if err := guard(ctx, tx, ""); err != nil {
					return err
				}
				if _, err := tx.Queries().CreateControlHelperEnrollment(ctx, dbsqlc.CreateControlHelperEnrollmentParams{
					ID: recoveryEnrollmentID, EnvironmentID: environmentID, HelperID: recoverySeedGrant.HelperID,
					JtiHash: []byte("recovery-race-jti-" + suffix), OperationKey: "helper-enrollment:" + gotUserID + ":" + operationKey,
					RequestHash: []byte("recovery-race-request-" + suffix), GrantCiphertext: []byte("recovery-race-grant-" + suffix), ExpiresAt: expiresAt,
				}); err != nil {
					return err
				}
				if err := guard(ctx, tx, recoveryEnrollmentID); err != nil {
					return err
				}
				recoveryAuthorityPersistedOnce.Do(func() { close(recoveryAuthorityPersisted) })
				select {
				case <-releaseRecoveryAuthority:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			return HelperEnrollmentGrant{EnrollmentID: recoveryEnrollmentID, HelperID: recoverySeedGrant.HelperID, Credential: strings.Repeat("z", 48), ExpiresAt: expiresAt}, err
		},
		func(context.Context, string, string, string, string, time.Duration, HelperEnrollmentAuthorityGuard) (HelperEnrollmentGrant, error) {
			return HelperEnrollmentGrant{}, errors.New("unexpected authenticated helper recovery")
		},
	)
	type recoveryResult struct {
		material json.RawMessage
		err      error
	}
	recoveryStartedAt := time.Now()
	recoveryCtx, cancelRecovery := context.WithTimeout(ctx, 60*time.Second)
	defer cancelRecovery()
	var releaseRecoveryAuthorityOnce sync.Once
	releaseRecoveredAuthority := func() { releaseRecoveryAuthorityOnce.Do(func() { close(releaseRecoveryAuthority) }) }
	defer releaseRecoveredAuthority()
	recoveryDone := make(chan recoveryResult, 1)
	go func() {
		material, recoveryErr := service.ConsumeInstallationForIdentityState(recoveryCtx, recoveryVerifier, publicKey, false)
		recoveryDone <- recoveryResult{material: material, err: recoveryErr}
	}()
	select {
	case <-recoveryAuthorityPersisted:
	case <-recoveryCtx.Done():
		fatalWithPostgresLocks(t, store, "authenticated Host recovery helper authority was not persisted after %s: %v", time.Since(recoveryStartedAt), recoveryCtx.Err())
	}
	recoveryAuthorityPersistedAt := time.Now()
	input.SetupMode = "client"
	recoveryRollbackDone := make(chan rollbackResult, 1)
	go func() {
		value, rollbackErr := service.Setup(recoveryCtx, userID, input)
		recoveryRollbackDone <- rollbackResult{value: value, err: rollbackErr}
	}()
	if err := waitForUserMachineRowLock(recoveryCtx, store, recoveryHost.ID); err != nil {
		fatalWithPostgresLocks(t, store, "Client rollback did not acquire the machine row before recovery authority release after %s: %v", time.Since(recoveryAuthorityPersistedAt), err)
	}
	recoveryRollbackLockedAt := time.Now()
	releaseRecoveredAuthority()
	recoveryAuthorityReleasedAt := time.Now()
	recoveryPostReleaseCtx, cancelRecoveryPostRelease := context.WithTimeout(recoveryCtx, 30*time.Second)
	defer cancelRecoveryPostRelease()
	var recovered recoveryResult
	select {
	case recovered = <-recoveryDone:
	case <-recoveryPostReleaseCtx.Done():
		fatalWithPostgresLocks(t, store, "authenticated Host material recovery did not finish within the post-release bound; authority=%s machine_lock=%s post_release=%s: %v", recoveryAuthorityPersistedAt.Sub(recoveryStartedAt), recoveryRollbackLockedAt.Sub(recoveryAuthorityPersistedAt), time.Since(recoveryAuthorityReleasedAt), recoveryPostReleaseCtx.Err())
	}
	recoveryFinishedAt := time.Now()
	if recovered.err != nil && !errors.Is(recovered.err, ErrInstallationUnavailable) {
		t.Fatalf("stale authenticated Host recovery err=%v material=%s", recovered.err, recovered.material)
	}
	select {
	case rolledBackConcurrently = <-recoveryRollbackDone:
	case <-recoveryPostReleaseCtx.Done():
		fatalWithPostgresLocks(t, store, "Client rollback racing authenticated recovery did not finish within the post-release bound; recovery=%s post_release=%s: %v", recoveryFinishedAt.Sub(recoveryAuthorityReleasedAt), time.Since(recoveryAuthorityReleasedAt), recoveryPostReleaseCtx.Err())
	}
	t.Logf("authenticated Host recovery race completed: authority=%s machine_lock=%s recovery_after_release=%s total_after_release=%s", recoveryAuthorityPersistedAt.Sub(recoveryStartedAt), recoveryRollbackLockedAt.Sub(recoveryAuthorityPersistedAt), recoveryFinishedAt.Sub(recoveryAuthorityReleasedAt), time.Since(recoveryAuthorityReleasedAt))
	if rolledBackConcurrently.err != nil || rolledBackConcurrently.value.SetupMode != "client" || rolledBackConcurrently.value.InstallationGeneration != recoveryHost.InstallationGeneration+1 {
		t.Fatalf("Client rollback racing authenticated recovery=%+v err=%v", rolledBackConcurrently.value, rolledBackConcurrently.err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_pairings WHERE authenticated_setup_cli_session_id=$1 AND authenticated_setup_operation_id=$2`, clientSessionID, recoveryRequest.OperationID).Scan(&pairingState); err != nil || pairingState != "expired" {
		t.Fatalf("recovery-race pairing state=%q err=%v", pairingState, err)
	}
	if _, err := service.ConsumeInstallationForIdentity(ctx, recoveryVerifier, publicKey); !errors.Is(err, ErrInstallationExpired) {
		t.Fatalf("rolled-back recovered Host material remained consumable: %v", err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,revoked_at FROM paperboat.control_helper_enrollments WHERE id=$1 AND helper_id=$2`, recoveryEnrollmentID, recoverySeedGrant.HelperID).Scan(&grantState, &grantRevokedAt); err != nil || grantState != "revoked" || !grantRevokedAt.Valid {
		t.Fatalf("rolled-back recovery helper grant state=%q revoked_at=%v err=%v", grantState, grantRevokedAt, err)
	}

	// The authenticated CLI session is part of the authority binding. Pause
	// after the helper credential is minted but before it is bound, queue session
	// revocation on the pairing lock, then prove the exact disclosed credential
	// is revoked before either operation returns authority to the caller.
	input.SetupMode = "host"
	sessionHost, err := service.Setup(ctx, userID, input)
	if err != nil {
		t.Fatal(err)
	}
	sessionSigner, err := mint.NewEphemeral(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sessionEnrollmentService := controlplane.NewEnrollmentService(store, sessionSigner, audit.NewWriter(store), "https://api.paperboat.test", "authenticated-session-enrollment-key")
	var sessionGrant controlplane.EnrollmentGrant
	sessionGrantPersisted, releaseSessionGrant := make(chan struct{}), make(chan struct{})
	var sessionGrantPersistedOnce, releaseSessionGrantOnce sync.Once
	releasePersistedSessionGrant := func() { releaseSessionGrantOnce.Do(func() { close(releaseSessionGrant) }) }
	defer releasePersistedSessionGrant()
	service.ConfigureAuthenticatedHelperEnrollment(
		func(ctx context.Context, gotUserID, operationKey, environmentID string, lifetime time.Duration, guard HelperEnrollmentAuthorityGuard) (HelperEnrollmentGrant, error) {
			return PersistAuthenticatedHelperEnrollment(ctx, store, environmentID, guard, func(ctx context.Context) (HelperEnrollmentGrant, error) {
				grant, err := sessionEnrollmentService.Issue(ctx, gotUserID, operationKey, environmentID, lifetime)
				if err != nil {
					return HelperEnrollmentGrant{}, err
				}
				sessionGrant = grant
				sessionGrantPersistedOnce.Do(func() { close(sessionGrantPersisted) })
				select {
				case <-releaseSessionGrant:
					return HelperEnrollmentGrant{EnrollmentID: grant.EnrollmentID, HelperID: grant.HelperID, Credential: grant.Credential, ExpiresAt: grant.ExpiresAt}, nil
				case <-ctx.Done():
					return HelperEnrollmentGrant{}, ctx.Err()
				}
			})
		},
		func(context.Context, string, string, string, string, time.Duration, HelperEnrollmentAuthorityGuard) (HelperEnrollmentGrant, error) {
			return HelperEnrollmentGrant{}, errors.New("unexpected authenticated helper recovery")
		},
	)
	sessionVerifier := "authenticated-host-session-verifier-" + suffix
	sessionRequest := AuthenticatedHostSetupInput{OperationID: "host-setup-session-operation-" + suffix, Verifier: sessionVerifier, PublicIdentityKey: publicKey, InstallationGeneration: sessionHost.InstallationGeneration, SetupMode: "host", Artifact: sessionHost.Installation.Artifact}
	sessionCtx, cancelSessionRace := context.WithTimeout(ctx, 60*time.Second)
	defer cancelSessionRace()
	sessionPrepareDone := make(chan prepareResult, 1)
	go func() {
		value, prepareErr := service.PrepareAuthenticatedHostSetup(sessionCtx, userID, clientSessionID, sessionHost.ID, sessionRequest)
		sessionPrepareDone <- prepareResult{value: value, err: prepareErr}
	}()
	select {
	case <-sessionGrantPersisted:
	case <-sessionCtx.Done():
		fatalWithPostgresLocks(t, store, "authenticated Host session-race grant was not persisted: %v", sessionCtx.Err())
	}
	deviceAuth := authservice.NewDeviceService(store, audit.NewWriter(store), config.Default().CLIAuth, []string{"authenticated-host-session-hash-key"})
	sessionRevokeDone := make(chan error, 1)
	go func() {
		sessionRevokeDone <- deviceAuth.RevokeClient(sessionCtx, userID, clientSessionID, "authenticated_host_test")
	}()
	if err := waitForCLIClientSessionRowLock(sessionCtx, store, clientSessionID); err != nil {
		fatalWithPostgresLocks(t, store, "CLI session revocation did not acquire the session row before helper binding: %v", err)
	}
	releasePersistedSessionGrant()
	select {
	case err := <-sessionRevokeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-sessionCtx.Done():
		fatalWithPostgresLocks(t, store, "CLI session revocation did not finish after helper binding: %v", sessionCtx.Err())
	}
	select {
	case prepared := <-sessionPrepareDone:
		if prepared.err != nil && !errors.Is(prepared.err, ErrInvalidHostSetupInstallation) && !errors.Is(prepared.err, ErrHostSetupOperationConflict) {
			t.Fatalf("session-raced Host preparation=%+v err=%v", prepared.value, prepared.err)
		}
	case <-sessionCtx.Done():
		fatalWithPostgresLocks(t, store, "authenticated Host preparation did not finish after CLI session revocation: %v", sessionCtx.Err())
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_pairings WHERE authenticated_setup_cli_session_id=$1 AND authenticated_setup_operation_id=$2`, clientSessionID, sessionRequest.OperationID).Scan(&pairingState); err != nil || pairingState != "expired" {
		t.Fatalf("CLI session revocation pairing state=%q err=%v", pairingState, err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,revoked_at FROM paperboat.control_helper_enrollments WHERE id=$1`, sessionGrant.EnrollmentID).Scan(&grantState, &grantRevokedAt); err != nil || grantState != "revoked" || !grantRevokedAt.Valid {
		t.Fatalf("CLI-session-revoked helper grant state=%q revoked_at=%v err=%v", grantState, grantRevokedAt, err)
	}
	_, sessionHelperPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessionEnrollmentService.Exchange(ctx, sessionGrant.Credential, sessionHelperPrivate.Public().(ed25519.PublicKey)); !errors.Is(err, controlplane.ErrEnrollmentUsed) {
		t.Fatalf("CLI-session-revoked helper credential remained exchangeable: %v", err)
	}
	if _, err := service.ConsumeInstallationForIdentity(ctx, sessionVerifier, publicKey); !errors.Is(err, ErrInstallationExpired) {
		t.Fatalf("CLI-session-revoked Host material remained consumable: %v", err)
	}
}

func TestPersistAuthenticatedHelperEnrollmentCompensatesBindFailure(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_authenticated_compensation_" + suffix
	machineID := "mch_authenticated_compensation_" + suffix
	environmentID := "env_authenticated_compensation_" + suffix
	sessionID := "cls_authenticated_compensation_" + suffix
	pairingID := "ump_authenticated_compensation_" + suffix
	publicKeyHash := sha256.Sum256([]byte("authenticated-compensation-public-key-" + suffix))
	publicKey := base64.RawURLEncoding.EncodeToString(publicKeyHash[:])
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_authenticated_compensation_"+suffix, "authenticated-compensation-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'Host compensation','desktop','linux',ARRAY['projects:connect'],'active',now(),now())`, sessionID, userID, "client_authenticated_compensation_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,setup_roles,setup_mode,public_identity_key,installation_generation) VALUES ($1,$2,$3,'Host compensation','linux','amd64','/workspace','offline','occupied',ARRAY['host','interactive'],'host',$4,2)`, machineID, userID, environmentID, publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, machineID, userID); err != nil {
		t.Fatal(err)
	}
	verifierHash := sha256.Sum256([]byte("authenticated-compensation-verifier-" + suffix))
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_pairings (
id,verifier_hash,user_code,requested_display_name,platform,architecture,workspace_root,runtime_versions,state,approved_by_user_id,user_machine_id,public_identity_key,expires_at,approved_at,
authenticated_setup_cli_session_id,authenticated_setup_operation_id,authenticated_setup_generation,authenticated_setup_mode
) VALUES ($1,$2,$3,'Host compensation','linux','amd64','/workspace','{}','approved',$4,$5,$6,now()+interval '10 minutes',now(),$7,$8,2,'host')`, pairingID, verifierHash[:], "COMP"+suffix, userID, machineID, publicKey, sessionID, "authenticated-compensation-operation-"+suffix); err != nil {
		t.Fatal(err)
	}
	signer, err := mint.NewEphemeral(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	enrollments := controlplane.NewEnrollmentService(store, signer, audit.NewWriter(store), "https://api.paperboat.test", "authenticated-compensation-enrollment-key")
	bindFailure := errors.New("injected authenticated Host helper bind failure")
	guard := func(ctx context.Context, tx *db.Tx, helperEnrollmentID string) error {
		pairing, err := tx.Queries().GetUserMachinePairingForVerifier(ctx, verifierHash[:])
		if err != nil {
			return err
		}
		if pairing.ID != pairingID || pairing.State != "approved" {
			return ErrHostSetupOperationConflict
		}
		if helperEnrollmentID != "" {
			return bindFailure
		}
		return nil
	}
	var issued controlplane.EnrollmentGrant
	_, err = PersistAuthenticatedHelperEnrollment(ctx, store, environmentID, guard, func(ctx context.Context) (HelperEnrollmentGrant, error) {
		grant, issueErr := enrollments.Issue(ctx, userID, "authenticated-compensation:"+suffix, environmentID, 10*time.Minute)
		issued = grant
		return HelperEnrollmentGrant{EnrollmentID: grant.EnrollmentID, HelperID: grant.HelperID, Credential: grant.Credential, ExpiresAt: grant.ExpiresAt}, issueErr
	})
	if !errors.Is(err, bindFailure) {
		t.Fatalf("authenticated helper bind failure=%v", err)
	}
	var enrollmentState string
	var revokedAt sql.NullTime
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,revoked_at FROM paperboat.control_helper_enrollments WHERE id=$1`, issued.EnrollmentID).Scan(&enrollmentState, &revokedAt); err != nil || enrollmentState != "revoked" || !revokedAt.Valid {
		t.Fatalf("compensated helper grant state=%q revoked_at=%v err=%v", enrollmentState, revokedAt, err)
	}
	var boundEnrollmentID sql.NullString
	if err := store.SQL().QueryRowContext(ctx, `SELECT authenticated_setup_helper_enrollment_id FROM paperboat.user_machine_pairings WHERE id=$1`, pairingID).Scan(&boundEnrollmentID); err != nil || boundEnrollmentID.Valid {
		t.Fatalf("failed helper grant remained bound=%v err=%v", boundEnrollmentID, err)
	}
	_, helperPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollments.Exchange(ctx, issued.Credential, helperPrivate.Public().(ed25519.PublicKey)); !errors.Is(err, controlplane.ErrEnrollmentUsed) {
		t.Fatalf("compensated helper credential remained exchangeable: %v", err)
	}
	foreignEnvironmentID := "env_authenticated_compensation_foreign_" + suffix
	foreignHelperID := "helper_authenticated_compensation_foreign_" + suffix
	foreignEnrollmentID := "henr_authenticated_compensation_foreign_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, foreignEnvironmentID, "workspace_authenticated_compensation_foreign_"+suffix, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id) VALUES ($1,$2)`, foreignHelperID, foreignEnvironmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,now()+interval '10 minutes')`, foreignEnrollmentID, foreignEnvironmentID, foreignHelperID, []byte("foreign-jti-"+suffix), "foreign-operation-"+suffix, []byte("foreign-request-"+suffix), []byte("foreign-grant-"+suffix)); err != nil {
		t.Fatal(err)
	}
	if err := store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		n, err := tx.Queries().BindAuthenticatedHostSetupHelperEnrollment(ctx, dbsqlc.BindAuthenticatedHostSetupHelperEnrollmentParams{ID: pairingID, HelperEnrollmentID: sql.NullString{String: foreignEnrollmentID, Valid: true}})
		if err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("foreign-environment helper binding changed %d pairings", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	validEnrollmentID := "henr_authenticated_compensation_bound_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,now()+interval '10 minutes')`, validEnrollmentID, environmentID, issued.HelperID, []byte("bound-jti-"+suffix), "bound-operation-"+suffix, []byte("bound-request-"+suffix), []byte("bound-grant-"+suffix)); err != nil {
		t.Fatal(err)
	}
	if err := store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		n, err := tx.Queries().BindAuthenticatedHostSetupHelperEnrollment(ctx, dbsqlc.BindAuthenticatedHostSetupHelperEnrollmentParams{ID: pairingID, HelperEnrollmentID: sql.NullString{String: validEnrollmentID, Valid: true}})
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("same-environment helper binding changed %d pairings", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_helper_enrollments SET state='revoked',revoked_at=now() WHERE id=$1`, validEnrollmentID); err != nil {
		t.Fatal(err)
	}
	replacementEnrollmentID := "henr_authenticated_compensation_replacement_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,now()+interval '10 minutes')`, replacementEnrollmentID, environmentID, issued.HelperID, []byte("replacement-jti-"+suffix), "replacement-operation-"+suffix, []byte("replacement-request-"+suffix), []byte("replacement-grant-"+suffix)); err != nil {
		t.Fatal(err)
	}
	if err := store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		n, err := tx.Queries().BindAuthenticatedHostSetupHelperEnrollment(ctx, dbsqlc.BindAuthenticatedHostSetupHelperEnrollmentParams{ID: pairingID, HelperEnrollmentID: sql.NullString{String: replacementEnrollmentID, Valid: true}})
		if err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("authenticated helper overwrite changed %d pairings", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_pairings SET state='consumed',installation_config_consumed_at=now() WHERE id=$1`, pairingID); err != nil {
		t.Fatal(err)
	}
	if err := store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		n, err := tx.Queries().BindAuthenticatedHostSetupHelperEnrollment(ctx, dbsqlc.BindAuthenticatedHostSetupHelperEnrollmentParams{ID: pairingID, HelperEnrollmentID: sql.NullString{String: replacementEnrollmentID, Valid: true}})
		if err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("authenticated helper replacement without an active recovery changed %d pairings", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_pairings SET installation_recovery_operation_key=$2 WHERE id=$1`, pairingID, "authenticated-compensation-recovery-"+suffix); err != nil {
		t.Fatal(err)
	}
	if err := store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		n, err := tx.Queries().BindAuthenticatedHostSetupHelperEnrollment(ctx, dbsqlc.BindAuthenticatedHostSetupHelperEnrollmentParams{ID: pairingID, HelperEnrollmentID: sql.NullString{String: replacementEnrollmentID, Valid: true}})
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("authenticated recovery terminal helper replacement changed %d pairings", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var recoveredBinding sql.NullString
	if err := store.SQL().QueryRowContext(ctx, `SELECT authenticated_setup_helper_enrollment_id FROM paperboat.user_machine_pairings WHERE id=$1`, pairingID).Scan(&recoveredBinding); err != nil || !recoveredBinding.Valid || recoveredBinding.String != replacementEnrollmentID {
		t.Fatalf("authenticated recovery helper binding=%v err=%v", recoveredBinding, err)
	}
	competingPairingID := "ump_authenticated_compensation_competing_" + suffix
	competingVerifierHash := sha256.Sum256([]byte("authenticated-compensation-competing-verifier-" + suffix))
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_pairings (
id,verifier_hash,user_code,requested_display_name,platform,architecture,workspace_root,runtime_versions,state,approved_by_user_id,user_machine_id,public_identity_key,expires_at,approved_at,
authenticated_setup_cli_session_id,authenticated_setup_operation_id,authenticated_setup_generation,authenticated_setup_mode
) VALUES ($1,$2,$3,'Host compensation','linux','amd64','/workspace','{}','approved',$4,$5,$6,now()+interval '10 minutes',now(),$7,$8,2,'host')`, competingPairingID, competingVerifierHash[:], "COMQ"+suffix, userID, machineID, publicKey, sessionID, "authenticated-compensation-competing-operation-"+suffix); err != nil {
		t.Fatal(err)
	}
	if err := store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		n, err := tx.Queries().BindAuthenticatedHostSetupHelperEnrollment(ctx, dbsqlc.BindAuthenticatedHostSetupHelperEnrollmentParams{ID: competingPairingID, HelperEnrollmentID: sql.NullString{String: replacementEnrollmentID, Valid: true}})
		if err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("one helper enrollment bound to %d competing authenticated pairings", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Queries().ExpireAuthenticatedHostSetupPairingsForCLISession(ctx, dbsqlc.ExpireAuthenticatedHostSetupPairingsForCLISessionParams{Now: time.Now().UTC(), CLIClientSessionID: sql.NullString{String: sessionID, Valid: true}}); err != nil {
		t.Fatal(err)
	}
	var replacementState string
	var replacementRevokedAt sql.NullTime
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,revoked_at FROM paperboat.control_helper_enrollments WHERE id=$1`, replacementEnrollmentID).Scan(&replacementState, &replacementRevokedAt); err != nil || replacementState != "revoked" || !replacementRevokedAt.Valid {
		t.Fatalf("authenticated recovery replacement grant state=%q revoked_at=%v err=%v", replacementState, replacementRevokedAt, err)
	}
}

func TestEntitlementRevocationExpiresAuthenticatedHostGrant(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_entitlement_host_"+suffix, "mch_entitlement_host_"+suffix, "env_entitlement_host_"+suffix
	sessionID, pairingID := "cls_entitlement_host_"+suffix, "ump_entitlement_host_"+suffix
	publicKeyHash := sha256.Sum256([]byte("entitlement-host-public-key-" + suffix))
	publicKey := base64.RawURLEncoding.EncodeToString(publicKeyHash[:])
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_entitlement_host_"+suffix, "entitlement-host-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'Entitlement Host','desktop','linux',ARRAY['projects:connect'],'active',now(),now())`, sessionID, userID, "client_entitlement_host_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,setup_roles,setup_mode,public_identity_key,installation_generation) VALUES ($1,$2,$3,'Entitlement Host','linux','amd64','/workspace','offline','occupied',ARRAY['host','interactive'],'host',$4,2)`, machineID, userID, environmentID, publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, machineID, userID); err != nil {
		t.Fatal(err)
	}
	signer, err := mint.NewEphemeral(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	enrollments := controlplane.NewEnrollmentService(store, signer, audit.NewWriter(store), "https://api.paperboat.test", "entitlement-host-enrollment-key")
	grant, err := enrollments.Issue(ctx, userID, "entitlement-host-grant:"+suffix, environmentID, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifierHash := sha256.Sum256([]byte("entitlement-host-verifier-" + suffix))
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_pairings (
id,verifier_hash,user_code,requested_display_name,platform,architecture,workspace_root,runtime_versions,state,approved_by_user_id,user_machine_id,public_identity_key,expires_at,approved_at,
authenticated_setup_cli_session_id,authenticated_setup_operation_id,authenticated_setup_generation,authenticated_setup_mode,authenticated_setup_helper_enrollment_id
) VALUES ($1,$2,$3,'Entitlement Host','linux','amd64','/workspace','{}','approved',$4,$5,$6,now()+interval '10 minutes',now(),$7,$8,2,'host',$9)`, pairingID, verifierHash[:], "ENTL"+suffix, userID, machineID, publicKey, sessionID, "entitlement-host-operation-"+suffix, grant.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	revoked, err := store.Queries().RevokeUserMachinesForEntitlement(ctx, userID)
	if err != nil || !reflect.DeepEqual(revoked, []string{machineID}) {
		t.Fatalf("entitlement-revoked machines=%v err=%v", revoked, err)
	}
	var machineState, pairingState, grantState string
	var firstRevokedAt sql.NullTime
	if err := store.SQL().QueryRowContext(ctx, `SELECT m.state,p.state,e.state,e.revoked_at FROM paperboat.user_machines m JOIN paperboat.user_machine_pairings p ON p.user_machine_id=m.id JOIN paperboat.control_helper_enrollments e ON e.id=p.authenticated_setup_helper_enrollment_id WHERE m.id=$1`, machineID).Scan(&machineState, &pairingState, &grantState, &firstRevokedAt); err != nil {
		t.Fatal(err)
	}
	if machineState != "revoked" || pairingState != "expired" || grantState != "revoked" || !firstRevokedAt.Valid {
		t.Fatalf("entitlement revocation states machine=%q pairing=%q grant=%q revoked_at=%v", machineState, pairingState, grantState, firstRevokedAt)
	}
	_, helperPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollments.Exchange(ctx, grant.Credential, helperPrivate.Public().(ed25519.PublicKey)); !errors.Is(err, controlplane.ErrEnrollmentUsed) {
		t.Fatalf("entitlement-revoked helper credential remained exchangeable: %v", err)
	}
	if replay, err := store.Queries().RevokeUserMachinesForEntitlement(ctx, userID); err != nil || len(replay) != 0 {
		t.Fatalf("entitlement revocation replay=%v err=%v", replay, err)
	}
	var replayRevokedAt sql.NullTime
	if err := store.SQL().QueryRowContext(ctx, `SELECT revoked_at FROM paperboat.control_helper_enrollments WHERE id=$1`, grant.EnrollmentID).Scan(&replayRevokedAt); err != nil || !replayRevokedAt.Valid || !replayRevokedAt.Time.Equal(firstRevokedAt.Time) {
		t.Fatalf("entitlement revocation replay timestamp=%v first=%v err=%v", replayRevokedAt, firstRevokedAt, err)
	}
}

func TestClientRolePairingRevokesAuthenticatedHostAuthority(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_client_pairing_host_"+suffix, "mch_client_pairing_host_"+suffix, "env_client_pairing_host_"+suffix
	sessionID, authenticatedPairingID := "cls_client_pairing_host_"+suffix, "ump_client_pairing_host_authenticated_"+suffix
	helperID, helperEnrollmentID := "hlp_client_pairing_host_"+suffix, "enr_client_pairing_host_"+suffix
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(public)
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_client_pairing_host_"+suffix, "client-pairing-host-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'Client pairing Host rollback','desktop','linux',ARRAY['projects:connect'],'active',now(),now())`, sessionID, userID, "client_client_pairing_host_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_entitlements (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end) VALUES ($1,$2,$3,'connected-test','active',1,1048576,now()-interval '1 hour',now()+interval '1 hour')`, "ume_client_pairing_host_"+suffix, userID, "sub_client_pairing_host_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,runtime_versions,setup_roles,setup_mode,configured_capabilities,public_identity_key,installation_generation) VALUES ($1,$2,$3,'Client pairing Host','linux','amd64','/workspace','offline','occupied','{}',ARRAY['host','interactive'],'host',ARRAY['file_receive','preview_launch','terminal_host','codex_host','session_host','keep_awake'],$4,2)`, machineID, userID, environmentID, publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id,desired_state) VALUES ($1,$2,$3,'active')`, environmentID, machineID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id) VALUES ($1,$2)`, helperID, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helper_enrollments (id,environment_id,helper_id,jti_hash,operation_key,request_hash,grant_ciphertext,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,now()+interval '10 minutes')`, helperEnrollmentID, environmentID, helperID, []byte("client-pairing-host-jti-"+suffix), "client-pairing-host-grant-"+suffix, []byte("client-pairing-host-request-"+suffix), []byte("client-pairing-host-ciphertext-"+suffix)); err != nil {
		t.Fatal(err)
	}
	authenticatedVerifierHash := sha256.Sum256([]byte("client-pairing-host-authenticated-verifier-" + suffix))
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_pairings (
id,verifier_hash,user_code,requested_display_name,platform,architecture,workspace_root,runtime_versions,state,approved_by_user_id,user_machine_id,public_identity_key,expires_at,approved_at,
authenticated_setup_cli_session_id,authenticated_setup_operation_id,authenticated_setup_generation,authenticated_setup_mode,authenticated_setup_helper_enrollment_id
) VALUES ($1,$2,$3,'Client pairing Host','linux','amd64','/workspace','{}','approved',$4,$5,$6,now()+interval '10 minutes',now(),$7,$8,2,'host',$9)`, authenticatedPairingID, authenticatedVerifierHash[:], "CPHA"+suffix, userID, machineID, publicKey, sessionID, "client-pairing-host-authenticated-operation-"+suffix, helperEnrollmentID); err != nil {
		t.Fatal(err)
	}
	legacyPairingID, legacyUserCode := "ump_client_pairing_host_legacy_"+suffix, "CPHL"+suffix
	legacyVerifierHash := sha256.Sum256([]byte("client-pairing-host-legacy-verifier-" + suffix))
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_pairings (id,verifier_hash,user_code,requested_display_name,platform,architecture,workspace_root,runtime_versions,state,public_identity_key,expires_at) VALUES ($1,$2,$3,'Client pairing Host','linux','amd64','/workspace','{}','pending',$4,now()+interval '10 minutes')`, legacyPairingID, legacyVerifierHash[:], legacyUserCode, publicKey); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"linux"}}, testSeatAuthorizer{})
	service.ConfigureProvisioning(access.FakeClient{}, "client-pairing-host-key")
	service.ConfigureAccess(nil, "https://api.paperboat.test", 5*time.Minute)
	service.ConfigureHelperEnrollment(func(context.Context, string, string, string, time.Duration) (HelperEnrollmentGrant, error) {
		return HelperEnrollmentGrant{EnrollmentID: "enr_client_pairing_material_" + suffix, HelperID: "hlp_client_pairing_material_" + suffix, Credential: strings.Repeat("m", 48), ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}, nil
	})
	if err := service.ConfigureRuntimeRoute("runtime.example.test", 38080); err != nil {
		t.Fatal(err)
	}
	configureSignedTestArtifact(t, service)
	rolledBack, err := service.approve(ctx, userID, legacyUserCode, "client")
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.ID != machineID || rolledBack.SetupMode != "client" || rolledBack.SeatState != "released" || slices.Contains(rolledBack.SetupRoles, "host") || rolledBack.InstallationGeneration != 3 {
		t.Fatalf("client-role pairing rollback=%+v", rolledBack)
	}
	var pairingState, grantState string
	var grantRevokedAt sql.NullTime
	if err := store.SQL().QueryRowContext(ctx, `SELECT pairing.state,enrollment.state,enrollment.revoked_at FROM paperboat.user_machine_pairings pairing JOIN paperboat.control_helper_enrollments enrollment ON enrollment.id=pairing.authenticated_setup_helper_enrollment_id WHERE pairing.id=$1`, authenticatedPairingID).Scan(&pairingState, &grantState, &grantRevokedAt); err != nil {
		t.Fatal(err)
	}
	if pairingState != "expired" || grantState != "revoked" || !grantRevokedAt.Valid {
		t.Fatalf("client-role pairing authority state pairing=%q grant=%q revoked_at=%v", pairingState, grantState, grantRevokedAt)
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

func TestDashboardEnrollmentApprovalFailureIsRetryable(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_enrollment_approval_failure_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1,$2,$3,'active')`, userID, "workos_approval_failure_"+suffix, "enrollment-approval-failure-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.user_machines
  (id, user_id, environment_id, display_name, alias, platform, architecture, workspace_root, state, seat_state)
VALUES ($1,$2,$3,'Studio','studio','linux','amd64','/workspace','offline','released')`, "mch_enrollment_approval_failure_"+suffix, userID, "env_enrollment_approval_failure_"+suffix); err != nil {
		t.Fatal(err)
	}

	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"linux"}}, testSeatAuthorizer{})
	service.ConfigureProvisioning(nil, "test-enrollment-key")
	first, err := service.StartEnrollment(ctx, userID, "idem-approval-failure-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.CreatePairing(ctx, PairingInput{
		EnrollmentToken:   first.BootstrapToken,
		Verifier:          "verifier-approval-failure-" + suffix,
		DisplayName:       "Studio",
		Platform:          "linux",
		Architecture:      "amd64",
		WorkspaceRoot:     "/workspace",
		RuntimeVersions:   json.RawMessage(`{"pb":"test"}`),
		PublicIdentityKey: base64.RawURLEncoding.EncodeToString(public),
	})
	if !errors.Is(err, ErrMachineNameConflict) {
		t.Fatalf("automatic approval error = %v, want ErrMachineNameConflict", err)
	}

	status, err := service.Enrollment(ctx, userID, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "failed_retryable" || status.PairingID == "" {
		t.Fatalf("failed enrollment status = %+v, want failed_retryable with pairing", status)
	}
	var pairingState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_pairings WHERE id=$1`, status.PairingID).Scan(&pairingState); err != nil {
		t.Fatal(err)
	}
	if pairingState != "expired" {
		t.Fatalf("failed enrollment pairing state = %q, want expired", pairingState)
	}

	retried, err := service.RetryEnrollment(ctx, userID, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retried.State != "awaiting_bootstrap" || retried.Generation != first.Generation+1 || retried.PairingID != "" || retried.BootstrapToken == first.BootstrapToken {
		t.Fatalf("retry = %+v, want fresh awaiting_bootstrap enrollment", retried)
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
	replayed, err := service.ConsumeInstallation(ctx, verifier)
	if err != nil || string(replayed) != string(material) {
		t.Fatalf("same-verifier recovery material=%s err=%v", replayed, err)
	}
	if _, err := service.ConsumeInstallation(ctx, verifier+"-wrong"); !errors.Is(err, ErrInstallationUnavailable) {
		t.Fatalf("different-verifier replay error=%v", err)
	}
	var enrollmentState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_enrollments WHERE id=$1`, start.ID).Scan(&enrollmentState); err != nil {
		t.Fatal(err)
	}
	if enrollmentState != "installing" {
		t.Fatalf("enrollment state=%q", enrollmentState)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_enrollments SET state='ready' WHERE id=$1`, start.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConsumeInstallation(ctx, verifier); !errors.Is(err, ErrInstallationUnavailable) {
		t.Fatalf("completed enrollment replay error=%v", err)
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

func TestExpiredInstallationRecoveryIsCrashSafeConcurrentAndIdentityBound(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_install_recovery_" + suffix
	publicIdentityDigest := sha256.Sum256([]byte("install-recovery-identity-" + suffix))
	publicIdentityKey := base64.RawURLEncoding.EncodeToString(publicIdentityDigest[:])
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_install_recovery_"+suffix, "install-recovery-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_entitlements (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end) VALUES ($1,$2,$3,'connected-test','active',1,1048576,now()-interval '1 hour',now()+interval '1 hour')`, "ent_install_recovery_"+suffix, userID, "sub_install_recovery_"+suffix); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{PairingLifetime: 10 * time.Minute, AllowedPlatforms: []string{"windows"}}, testSeatAuthorizer{})
	service.ConfigureProvisioning(access.FakeClient{}, "test-install-recovery-key")
	service.ConfigureAccess(nil, "https://api.paperboat.test", 5*time.Minute)
	service.ConfigureOneShotCLIAuth("paperboat-cli", []string{"account:read", "projects:connect", "session:refresh"}, 5*time.Minute, 24*time.Hour, "test-cli-hash-key")
	if err := service.ConfigureRuntimeRoute("runtime.example.test", 38080); err != nil {
		t.Fatal(err)
	}
	configureSignedTestArtifact(t, service)
	var grantMu sync.Mutex
	grantCalls := map[string]int{}
	service.ConfigureHelperEnrollment(func(_ context.Context, _ string, operationKey, environmentID string, _ time.Duration) (HelperEnrollmentGrant, error) {
		grantMu.Lock()
		grantCalls[operationKey]++
		grantMu.Unlock()
		kind := "initial"
		if strings.HasPrefix(operationKey, "byod-recovery:") {
			kind = "recovered"
		}
		if kind == "initial" {
			if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active') ON CONFLICT (id) DO NOTHING`, "helper_initial_"+suffix, environmentID); err != nil {
				return HelperEnrollmentGrant{}, err
			}
		}
		return HelperEnrollmentGrant{EnrollmentID: "henr_" + kind + "_" + suffix, HelperID: "helper_" + kind + "_" + suffix, Credential: strings.Repeat(kind, 8), ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}, nil
	})
	service.ConfigureHelperRecovery(func(_ context.Context, _ string, operationKey, _ string, existingHelperID string, _ time.Duration) (HelperEnrollmentGrant, error) {
		if existingHelperID != "helper_initial_"+suffix {
			return HelperEnrollmentGrant{}, ErrInstallationUnavailable
		}
		grantMu.Lock()
		grantCalls[operationKey]++
		grantMu.Unlock()
		return HelperEnrollmentGrant{EnrollmentID: "henr_recovered_" + suffix, HelperID: "helper_recovered_" + suffix, Credential: strings.Repeat("recovered", 8), ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}, nil
	})
	start, err := service.StartEnrollmentWithOptions(ctx, userID, "idem-install-recovery-"+suffix, EnrollmentOptions{Role: "client", Shell: "powershell"})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "verifier-install-recovery-" + suffix
	pairing, err := service.CreatePairing(ctx, PairingInput{EnrollmentToken: start.BootstrapToken, Verifier: verifier, DisplayName: "Victus recovery", Platform: "windows", Architecture: "amd64", WorkspaceRoot: `C:\Users\Pujan`, PublicIdentityKey: publicIdentityKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(ctx, userID, pairing.UserCode); err != nil {
		t.Fatal(err)
	}
	originalBody, err := service.ConsumeInstallationForIdentityState(ctx, verifier, publicIdentityKey, false)
	if err != nil {
		t.Fatal(err)
	}
	type recoveryMaterial struct {
		UserMachineID           string                    `json:"user_machine_id"`
		UserMachineEnrollmentID string                    `json:"user_machine_enrollment_id"`
		EnvironmentID           string                    `json:"environment_id"`
		HelperID                string                    `json:"helper_id"`
		ReuseIdentity           bool                      `json:"reuse_identity"`
		ClientSession           installationClientSession `json:"client_session"`
	}
	var original recoveryMaterial
	if err := json.Unmarshal(originalBody, &original); err != nil {
		t.Fatal(err)
	}
	if original.ClientSession.SessionID == "" || original.ClientSession.RefreshToken == "" || original.ClientSession.AccessToken == "" {
		t.Fatalf("original client session is incomplete: %+v", original.ClientSession)
	}
	// A journal that already persisted the runtime identity may recover only
	// against the exact helper bound into its original signed material. This
	// path refreshes the CLI access token without issuing a replacement helper.
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_pairings
SET expires_at=now()-interval '1 minute', installation_config_consumed_at=now()-interval '1 hour'
WHERE id=$1`, pairing.ID); err != nil {
		t.Fatal(err)
	}
	reusedBody, err := service.ConsumeInstallationForIdentityState(ctx, verifier, publicIdentityKey, true)
	if err != nil {
		t.Fatal(err)
	}
	var reused recoveryMaterial
	if err := json.Unmarshal(reusedBody, &reused); err != nil {
		t.Fatal(err)
	}
	if reused.HelperID != original.HelperID || !reused.ReuseIdentity {
		t.Fatalf("runtime-enrolled recovery changed helper binding: original=%+v recovered=%+v", original, reused)
	}
	if reused.ClientSession.SessionID != original.ClientSession.SessionID || reused.ClientSession.RefreshToken != original.ClientSession.RefreshToken || reused.ClientSession.AccessToken == original.ClientSession.AccessToken {
		t.Fatalf("runtime-enrolled recovery client session mismatch: original=%+v recovered=%+v", original.ClientSession, reused.ClientSession)
	}
	grantMu.Lock()
	for operation, calls := range grantCalls {
		if strings.HasPrefix(operation, "byod-recovery:") && calls != 0 {
			grantMu.Unlock()
			t.Fatalf("runtime-enrolled recovery issued helper grant %q %d times", operation, calls)
		}
	}
	grantMu.Unlock()
	originalBody, original = reusedBody, reused
	// Simulate a server process dying after BeginUserMachineInstallationRecovery
	// committed but before it issued or stored replacement material. Every retry
	// must reuse this operation key and leave old ciphertext intact until swap.
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_pairings
SET expires_at=now()-interval '1 minute', installation_config_consumed_at=now()-interval '1 hour', installation_recovery_operation_key=NULL
WHERE id=$1`, pairing.ID); err != nil {
		t.Fatal(err)
	}
	storedPairing, err := store.Queries().GetUserMachinePairingByID(ctx, pairing.ID)
	if err != nil {
		t.Fatal(err)
	}
	recoveryOperation := installationRecoveryOperationKey(storedPairing.ID, storedPairing.ExpiresAt)
	begun, err := store.Queries().BeginUserMachineInstallationRecovery(ctx, dbsqlc.BeginUserMachineInstallationRecoveryParams{
		ID: storedPairing.ID, VerifierHash: storedPairing.VerifierHash, PublicIdentityKey: storedPairing.PublicIdentityKey,
		OperationKey: sql.NullString{String: recoveryOperation, Valid: true}, RecoveryAfter: sql.NullTime{Time: time.Now().UTC().Add(-installationRecoveryGrace), Valid: true}, ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	})
	if err != nil || !begun.InstallationRecoveryOperationKey.Valid || begun.InstallationRecoveryOperationKey.String != recoveryOperation {
		t.Fatalf("begin recovery pairing=%+v err=%v", begun, err)
	}
	type result struct {
		body json.RawMessage
		err  error
	}
	startGate := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-startGate
			body, recoverErr := service.ConsumeInstallationForIdentityState(ctx, verifier, publicIdentityKey, false)
			results <- result{body: body, err: recoverErr}
		}()
	}
	close(startGate)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent recovery errors: %v / %v", first.err, second.err)
	}
	if !bytes.Equal(first.body, second.body) {
		t.Fatalf("concurrent recovery returned different committed material")
	}
	var recovered recoveryMaterial
	if err := json.Unmarshal(first.body, &recovered); err != nil {
		t.Fatal(err)
	}
	if recovered.UserMachineID != original.UserMachineID || recovered.UserMachineEnrollmentID != original.UserMachineEnrollmentID || recovered.EnvironmentID != original.EnvironmentID {
		t.Fatalf("recovery changed machine binding: original=%+v recovered=%+v", original, recovered)
	}
	if recovered.HelperID == original.HelperID {
		t.Fatal("runtime-not-enrolled recovery did not rotate the helper enrollment")
	}
	if recovered.ClientSession.SessionID != original.ClientSession.SessionID || recovered.ClientSession.RefreshToken != original.ClientSession.RefreshToken || recovered.ClientSession.AccessToken == original.ClientSession.AccessToken {
		t.Fatalf("recovery client session mismatch: original=%+v recovered=%+v", original.ClientSession, recovered.ClientSession)
	}
	grantMu.Lock()
	recoveryGrantCalls := grantCalls[recoveryOperation]
	if recoveryGrantCalls < 1 || recoveryGrantCalls > 2 {
		t.Fatalf("recovery grant calls=%d, want one or two idempotent calls", recoveryGrantCalls)
	}
	for operation, calls := range grantCalls {
		if strings.HasPrefix(operation, "byod-recovery:") && operation != recoveryOperation && calls != 0 {
			t.Fatalf("unexpected recovery operation %q called %d times", operation, calls)
		}
	}
	grantMu.Unlock()
	var operation sql.NullString
	var activeAccessTokens, revokedAccessTokens int
	if err := store.SQL().QueryRowContext(ctx, `SELECT installation_recovery_operation_key FROM paperboat.user_machine_pairings WHERE id=$1`, pairing.ID).Scan(&operation); err != nil {
		t.Fatal(err)
	}
	if operation.Valid {
		t.Fatalf("recovery operation was not cleared: %q", operation.String)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE revoked_at IS NULL),count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM paperboat.cli_access_tokens WHERE cli_client_session_id=$1`, original.ClientSession.SessionID).Scan(&activeAccessTokens, &revokedAccessTokens); err != nil {
		t.Fatal(err)
	}
	if activeAccessTokens != 1 || revokedAccessTokens < 1 {
		t.Fatalf("access token states active=%d revoked=%d", activeAccessTokens, revokedAccessTokens)
	}
	replayed, err := service.ConsumeInstallationForIdentityState(ctx, verifier, publicIdentityKey, false)
	if err != nil || !bytes.Equal(replayed, first.body) {
		t.Fatalf("recovery replay changed material: %s err=%v", replayed, err)
	}
	if _, err := service.ConsumeInstallationForIdentityState(ctx, verifier, publicIdentityKey+"wrong", false); !errors.Is(err, ErrInstallationUnavailable) {
		t.Fatalf("wrong identity recovery error=%v", err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machine_pairings SET expires_at=now()-interval '1 minute',installation_config_consumed_at=now()-interval '25 hours' WHERE id=$1`, pairing.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConsumeInstallationForIdentityState(ctx, verifier, publicIdentityKey, false); !errors.Is(err, ErrInstallationExpired) {
		t.Fatalf("recovery beyond fixed grace error=%v", err)
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

func TestMachineControlInitialReplayRotatesAfterExpiryWithoutCrossMachineCollision(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_machine_control_" + suffix
	machineID := "mch_machine_control_" + suffix
	otherMachineID := "mch_machine_control_other_" + suffix
	environmentID := "env_machine_control_" + suffix
	otherEnvironmentID := "env_machine_control_other_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_machine_control_"+suffix, "machine-control-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	insertMachine := func(id, env string, key ed25519.PublicKey) {
		t.Helper()
		_, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,setup_mode,setup_roles,configured_capabilities,observed_capabilities,public_identity_key,installation_generation) VALUES ($1,$2,$3,$4,'windows','amd64','C:\workspace','offline','released','client',ARRAY['interactive']::text[],ARRAY['file_receive','preview_launch']::text[],ARRAY[]::text[],$5,3)`, id, userID, env, id, base64.RawURLEncoding.EncodeToString(key))
		if err != nil {
			t.Fatal(err)
		}
	}
	insertMachine(machineID, environmentID, publicKey)
	insertMachine(otherMachineID, otherEnvironmentID, otherPublicKey)
	machine, err := store.Queries().GetActiveUserMachineForControl(ctx, machineID)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := mint.NewEphemeral(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	service.ConfigureMachineControl(signer, "https://api.example.test")
	now := time.Date(2026, 8, 23, 1, 2, 3, 0, time.UTC)
	service.now = func() time.Time { return now }
	operationID := "machine-control-initial-" + suffix
	first, err := service.mintMachineControl(ctx, machine, operationID)
	if err != nil {
		t.Fatal(err)
	}
	firstClaims, err := signer.VerifyCredential(first.Credential, "https://api.example.test", "machine_control", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if firstClaims.MachineID != machineID || firstClaims.EnvironmentID != environmentID || firstClaims.UserID != userID || firstClaims.InstallationGeneration != 3 || firstClaims.KeyThumbprint != machineKeyThumbprint(machine) {
		t.Fatalf("first claims=%+v", firstClaims)
	}

	now = now.Add(machineControlTTL + time.Minute)
	second, err := service.mintMachineControl(ctx, machine, operationID)
	if err != nil {
		t.Fatal(err)
	}
	if second.Credential == first.Credential || !second.ExpiresAt.After(now) {
		t.Fatalf("expired replay did not rotate: first=%+v second=%+v", first, second)
	}
	secondClaims, err := signer.VerifyCredential(second.Credential, "https://api.example.test", "machine_control", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if secondClaims.JTI == firstClaims.JTI || secondClaims.MachineID != machineID || secondClaims.EnvironmentID != environmentID || secondClaims.UserID != userID || secondClaims.InstallationGeneration != 3 || secondClaims.KeyThumbprint != machineKeyThumbprint(machine) {
		t.Fatalf("rotated claims=%+v first=%+v", secondClaims, firstClaims)
	}

	now = now.Add(time.Minute)
	replay, err := service.mintMachineControl(ctx, machine, operationID)
	if err != nil || replay.Credential == "" {
		t.Fatalf("valid replay credential=%+v err=%v", replay, err)
	}
	replayClaims, err := signer.VerifyCredential(replay.Credential, "https://api.example.test", "machine_control", now)
	if err != nil || replayClaims.JTI != secondClaims.JTI || !replay.ExpiresAt.Equal(second.ExpiresAt) {
		t.Fatalf("valid replay claims=%+v credential=%+v err=%v", replayClaims, replay, err)
	}
	if replayClaims.SessionGeneration != secondClaims.SessionGeneration || replayClaims.SessionGeneration <= firstClaims.SessionGeneration {
		t.Fatalf("session generations first=%d second=%d replay=%d", firstClaims.SessionGeneration, secondClaims.SessionGeneration, replayClaims.SessionGeneration)
	}

	newOperationID := "machine-control-reconnect-" + suffix
	reconnected, err := service.mintMachineControl(ctx, machine, newOperationID)
	if err != nil {
		t.Fatal(err)
	}
	reconnectedClaims, err := signer.VerifyCredential(reconnected.Credential, "https://api.example.test", "machine_control", now)
	if err != nil || reconnectedClaims.SessionGeneration != replayClaims.SessionGeneration+1 {
		t.Fatalf("reconnected claims=%+v err=%v", reconnectedClaims, err)
	}
	if _, err := store.Queries().GetCurrentMachineControlSession(ctx, dbsqlc.GetCurrentMachineControlSessionParams{MachineID: machineID, InstallationGeneration: 3, CredentialJti: replayClaims.JTI, Now: now}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("superseded credential lookup err=%v, want sql.ErrNoRows", err)
	}
	current, err := store.Queries().GetCurrentMachineControlSession(ctx, dbsqlc.GetCurrentMachineControlSessionParams{MachineID: machineID, InstallationGeneration: 3, CredentialJti: reconnectedClaims.JTI, Now: now})
	if err != nil || current.SessionGeneration != reconnectedClaims.SessionGeneration {
		t.Fatalf("current session=%+v err=%v", current, err)
	}
	if _, err := service.mintMachineControl(ctx, machine, operationID); !errors.Is(err, ErrMachineControlInvalid) {
		t.Fatalf("superseded operation replay err=%v, want ErrMachineControlInvalid", err)
	}

	otherMachine, err := store.Queries().GetActiveUserMachineForControl(ctx, otherMachineID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.mintMachineControl(ctx, otherMachine, operationID); !errors.Is(err, ErrMachineControlInvalid) {
		t.Fatalf("cross-machine operation reuse error=%v, want ErrMachineControlInvalid", err)
	}
	var storedMachine, storedJTI string
	if err := store.SQL().QueryRowContext(ctx, `SELECT machine_id,credential_jti FROM paperboat.machine_control_renewals WHERE operation_id=$1`, operationID).Scan(&storedMachine, &storedJTI); err != nil {
		t.Fatal(err)
	}
	if storedMachine != machineID || storedJTI != secondClaims.JTI {
		t.Fatalf("cross-machine attempt changed reservation machine=%q jti=%q", storedMachine, storedJTI)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET setup_roles=ARRAY['host','interactive']::text[],setup_mode='host' WHERE id=$1`, machineID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Unpair(ctx, userID, machineID); err != nil {
		t.Fatal(err)
	}
	if err := service.Delete(ctx, userID, machineID); err != nil {
		t.Fatal(err)
	}
	for table := range map[string]struct{}{
		"machine_control_sessions": {},
		"machine_control_renewals": {},
	} {
		var count int
		if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.`+table+` WHERE machine_id=$1`, machineID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s rows=%d, want 0 after delete", table, count)
		}
	}
	if err := service.Delete(ctx, userID, machineID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete replay error=%v, want ErrNotFound", err)
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

func fatalWithPostgresLocks(t *testing.T, store *db.DB, format string, args ...any) {
	t.Helper()
	message := fmt.Sprintf(format, args...)
	t.Fatalf("%s\nPostgreSQL lock state:\n%s", message, postgresLockDiagnostics(store))
}

func postgresLockDiagnostics(store *db.DB) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rows, err := store.SQL().QueryContext(ctx, `
SELECT activity.pid,
       activity.state,
       coalesce(activity.wait_event_type, ''),
       coalesce(activity.wait_event, ''),
       pg_blocking_pids(activity.pid)::text,
       coalesce(lock.locktype, ''),
       coalesce(lock.mode, ''),
       coalesce(lock.granted, false),
       coalesce(lock.relation::regclass::text, ''),
       coalesce(lock.page::text, ''),
       coalesce(lock.tuple::text, ''),
       left(regexp_replace(activity.query, E'[\\n\\r]+', ' ', 'g'), 240)
FROM pg_stat_activity AS activity
LEFT JOIN pg_locks AS lock ON lock.pid = activity.pid
WHERE activity.datname = current_database()
  AND activity.pid <> pg_backend_pid()
  AND activity.state <> 'idle'
ORDER BY activity.pid, lock.granted, lock.locktype, lock.mode
LIMIT 100`)
	if err != nil {
		return "diagnostic query failed: " + err.Error()
	}
	defer rows.Close()
	var result strings.Builder
	for rows.Next() {
		var pid int
		var state, waitType, waitEvent, blockers, lockType, lockMode, relation, page, tuple, query string
		var granted bool
		if err := rows.Scan(&pid, &state, &waitType, &waitEvent, &blockers, &lockType, &lockMode, &granted, &relation, &page, &tuple, &query); err != nil {
			return "diagnostic scan failed: " + err.Error()
		}
		fmt.Fprintf(&result, "pid=%d state=%s wait=%s/%s blockers=%s lock=%s/%s granted=%t relation=%s page=%s tuple=%s query=%q\n", pid, state, waitType, waitEvent, blockers, lockType, lockMode, granted, relation, page, tuple, query)
	}
	if err := rows.Err(); err != nil {
		return "diagnostic rows failed: " + err.Error()
	}
	if result.Len() == 0 {
		return "no non-idle PostgreSQL sessions"
	}
	return result.String()
}

func waitForUserMachineRowLock(ctx context.Context, store *db.DB, machineID string) error {
	return waitForPostgresRowLock(ctx, store, `SELECT id FROM paperboat.user_machines WHERE id=$1 FOR UPDATE NOWAIT`, machineID)
}

func waitForCLIClientSessionRowLock(ctx context.Context, store *db.DB, sessionID string) error {
	return waitForPostgresRowLock(ctx, store, `SELECT id FROM paperboat.cli_client_sessions WHERE id=$1 FOR UPDATE NOWAIT`, sessionID)
}

func waitForPostgresRowLock(ctx context.Context, store *db.DB, query, id string) error {
	for {
		var lockedID string
		err := store.SQL().QueryRowContext(ctx, query, id).Scan(&lockedID)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
			return nil
		}
		if err != nil {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func testStore(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run user-machine integration tests")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
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
