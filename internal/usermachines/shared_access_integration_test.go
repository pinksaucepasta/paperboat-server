package usermachines

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

func TestPostgresSharedMachineSessionIsolationAndRevocation(t *testing.T) {
	store := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	suffix := fmt.Sprint(time.Now().UnixNano())
	owner, member, team, machine := "sm_owner_"+suffix, "sm_member_"+suffix, "sm_team_"+suffix, "sm_machine_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) SELECT x,x,x||'@invalid.test','active' FROM unnest($1::text[]) x`, []string{owner, member}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,configured_capabilities,observed_capabilities) VALUES($1,$2,$3,'Shared host','linux','amd64','/workspace','online','occupied',true,ARRAY['terminal_host','file_receive'],ARRAY['terminal_host','file_receive'])`, machine, owner, "env_"+suffix); err != nil {
		t.Fatal(err)
	}
	authority := teams.NewService(store)
	current, err := authority.Create(ctx, owner, teams.CreateRequest{OperationID: "create", TeamID: team})
	if err != nil {
		t.Fatal(err)
	}
	invite, err := authority.Invite(ctx, owner, team, teams.InviteRequest{OperationID: "invite", ExpectedGeneration: current.Generation, AccountID: member})
	if err != nil {
		t.Fatal(err)
	}
	current, err = authority.Accept(ctx, member, invite.InvitationID, teams.AcceptRequest{OperationID: "accept"})
	if err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	if _, err = service.CreateTerminalSession(ctx, member, machine, "same-name", "before-share", 4); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unshared session creation: %v", err)
	}
	current, err = authority.Machine(ctx, owner, team, teams.MachineRequest{OperationID: "share", ExpectedGeneration: current.Generation, MachineID: machine, Action: "share"})
	if err != nil {
		t.Fatal(err)
	}
	current, err = authority.GrantMachine(ctx, owner, team, teams.MachineGrantRequest{OperationID: "terminal-grant", ExpectedGeneration: current.Generation, MachineID: machine, Audience: "selected_member", AccountID: member, Capabilities: []string{"terminal"}, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	visible, total, err := service.List(ctx, member, 50, 0)
	if err != nil || total != 1 || len(visible) != 1 || visible[0].CanManage || len(visible[0].Permissions) != 1 || visible[0].Permissions[0] != "terminal" {
		t.Fatalf("shared machine visibility/permissions: total=%d count=%d err=%v", total, len(visible), err)
	}
	renamed, err := service.Rename(ctx, owner, machine, "shared-host")
	if err != nil || !renamed.CanManage || len(renamed.Permissions) != 6 {
		t.Fatalf("rename lost management presentation: %v", err)
	}
	first, err := service.CreateTerminalSession(ctx, owner, machine, "same-name", "owner-session", 4)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateTerminalSession(ctx, member, machine, "same-name", "member-session", 4)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("members share implicit terminal")
	}
	if _, err = service.RenameTerminalSession(ctx, member, machine, first.ID, "stolen"); !errors.Is(err, ErrTerminalSessionNotFound) {
		t.Fatalf("foreign session rename: %v", err)
	}
	if _, err = service.CloseTerminalSession(ctx, member, machine, first.ID); !errors.Is(err, ErrTerminalSessionNotFound) {
		t.Fatalf("foreign session close: %v", err)
	}
	if _, err = service.DeleteTerminalSession(ctx, member, machine, first.ID); !errors.Is(err, ErrTerminalSessionNotFound) {
		t.Fatalf("foreign session delete: %v", err)
	}
	if _, err = service.terminalSession(ctx, member, machine, first.ID); !errors.Is(err, ErrTerminalSessionNotFound) {
		t.Fatalf("foreign attachment: %v", err)
	}
	sessions, err := service.ListTerminalSessions(ctx, member, machine)
	if err != nil || len(sessions) != 1 || sessions[0].ID != second.ID {
		t.Fatalf("session visibility: count=%d err=%v", len(sessions), err)
	}
	persist := func(actor, id, capability string) error {
		return service.createAccessSession(ctx, dbsqlc.CreateUserMachineAccessSessionParams{ID: id, UserMachineID: machine, UserID: actor, EnvironmentID: "env_" + suffix, CLIClientSessionID: "cli_" + actor, HttpBaseUrl: "https://invalid.test", HelperTerminalSessionID: "jti_" + id, ExpiresAt: time.Now().Add(time.Minute), Capabilities: []string{capability}, OperationID: second.ID})
	}
	if err = persist(member, "denied_"+suffix, "exec"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ungranted exec issuance: %v", err)
	}
	ownAccess, sharedAccess := "own_"+suffix, "shared_"+suffix
	if err = persist(owner, ownAccess, "terminal"); err != nil {
		t.Fatal(err)
	}
	if err = persist(member, sharedAccess, "terminal"); err != nil {
		t.Fatal(err)
	}
	current, err = authority.GrantMachine(ctx, owner, team, teams.MachineGrantRequest{OperationID: "revoke-terminal", ExpectedGeneration: current.Generation, MachineID: machine, Audience: "selected_member", AccountID: member, Capabilities: []string{"terminal"}, Active: false})
	if err != nil {
		t.Fatal(err)
	}
	var ownState, sharedState string
	if err = store.SQL().QueryRowContext(ctx, `SELECT a.state,b.state FROM paperboat.user_machine_access_sessions a,paperboat.user_machine_access_sessions b WHERE a.id=$1 AND b.id=$2`, ownAccess, sharedAccess).Scan(&ownState, &sharedState); err != nil {
		t.Fatal(err)
	}
	if ownState != "active" || sharedState != "revoked" {
		t.Fatalf("revocation affected unrelated access: own=%s shared=%s", ownState, sharedState)
	}
	if err = persist(member, "reconnect_"+suffix, "terminal"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked reconnect: %v", err)
	}
	if _, err = service.terminalSession(ctx, member, machine, second.ID); !errors.Is(err, ErrTerminalSessionNotFound) {
		t.Fatalf("revoked session visible: %v", err)
	}
	current, err = authority.Machine(ctx, owner, team, teams.MachineRequest{OperationID: "team-ownership", ExpectedGeneration: current.Generation, MachineID: machine, Action: "transfer_to_team", Confirmation: machine})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.RequestMaintenanceApproval(ctx, member, machine, "denied-update", "update", "2026.09.08.1", "test", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("use grant permits update administration: %v", err)
	}
	current, err = authority.Mutate(ctx, owner, team, teams.MutationRequest{OperationID: "admin", ExpectedGeneration: current.Generation, Action: "role", AccountID: member, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	managed, err := store.Queries().GetUserMachineForUpdate(ctx, dbsqlc.GetUserMachineForUpdateParams{ID: machine, UserID: member})
	if err != nil {
		t.Fatal(err)
	}
	desired := DeviceCapabilitySelection{Terminal: true, FileReceive: true}
	if _, err = service.SetDeviceCapabilities(ctx, member, machine, "admin-capabilities", desired, managed.CapabilitiesDesiredVersion); err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetAvailabilityPolicy(ctx, member, machine, "admin-availability", "allow_sleep", managed.AvailabilityDesiredVersion); err != nil {
		t.Fatal(err)
	}
	approval, err := service.RequestMaintenanceApproval(ctx, owner, machine, "shared-update", "update", "2026.09.08.1", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.DecideMaintenanceApproval(ctx, member, machine, approval.ID, "approved"); err != nil {
		t.Fatal(err)
	}
	_, err = authority.Mutate(ctx, owner, team, teams.MutationRequest{OperationID: "remove-admin", ExpectedGeneration: current.Generation, Action: "remove", AccountID: member})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetDeviceCapabilities(ctx, member, machine, "admin-capabilities", desired, managed.CapabilitiesDesiredVersion); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed administrator replayed capabilities: %v", err)
	}
	if _, err = service.SetAvailabilityPolicy(ctx, member, machine, "admin-availability", "allow_sleep", managed.AvailabilityDesiredVersion); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed administrator replayed availability: %v", err)
	}
	if _, err = store.Queries().ConsumeUserMachineMaintenanceApproval(ctx, dbsqlc.ConsumeUserMachineMaintenanceApprovalParams{ID: approval.ID, UserMachineID: machine}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("removed administrator's pending authorization consumed: %v", err)
	}
}
