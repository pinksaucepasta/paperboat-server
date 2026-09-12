package teams

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestMachineGrantExactCapabilities(t *testing.T) {
	valid := MachineGrantRequest{MachineID: "machine", Audience: "all_members", Capabilities: []string{"terminal", "exec", "managed_ssh", "files", "preview_manage", "tunnel_manage"}}
	if !validMachineGrant(valid) {
		t.Fatal("complete exact capability list rejected")
	}
	for _, cap := range []string{"use", "manage", "env", "publish", "reshare", "terminal_attach", "ssh", "private_access", "*"} {
		r := valid
		r.Capabilities = []string{cap}
		if validMachineGrant(r) {
			t.Errorf("implicit capability %q accepted", cap)
		}
	}
	for _, mutate := range []func(*MachineGrantRequest){func(r *MachineGrantRequest) { r.AccountID = "member" }, func(r *MachineGrantRequest) { r.Audience = "selected_member" }, func(r *MachineGrantRequest) { r.Capabilities = []string{"terminal", "terminal"} }, func(r *MachineGrantRequest) { r.Capabilities = nil }} {
		r := valid
		mutate(&r)
		if validMachineGrant(r) {
			t.Fatalf("invalid grant accepted: %+v", r)
		}
	}
	valid.Audience = "selected_member"
	valid.AccountID = "member"
	if !validMachineGrant(valid) {
		t.Fatal("selected-member grant rejected")
	}
}

func TestPostgresTeamMachineAuthority(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	if err = db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	owner, enroller, memberID, outsider := "tm_owner_"+suffix, "tm_enroller_"+suffix, "tm_member_"+suffix, "tm_outside_"+suffix
	team, otherTeam, machine, personal := "tm_team_"+suffix, "tm_other_"+suffix, "tm_machine_"+suffix, "tm_personal_"+suffix
	accounts := []string{owner, enroller, memberID, outsider}
	teamIDs := []string{team, otherTeam}
	machineIDs := []string{machine, personal}
	defer func() {
		c, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		tx, e := store.SQL().BeginTx(c, nil)
		if e != nil {
			t.Error(e)
			return
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(c, `ALTER TABLE paperboat.audit_events DISABLE TRIGGER audit_events_append_only`); e != nil {
			t.Error(e)
			return
		}
		if _, e = tx.ExecContext(c, `DELETE FROM paperboat.audit_events WHERE resource_type='team' AND resource_id=ANY($1::text[]) AND actor_user_id=ANY($2::text[])`, teamIDs, accounts); e != nil {
			t.Error(e)
			return
		}
		if _, e = tx.ExecContext(c, `ALTER TABLE paperboat.audit_events ENABLE TRIGGER audit_events_append_only`); e != nil {
			t.Error(e)
			return
		}
		if _, e = tx.ExecContext(c, `DELETE FROM paperboat.user_machines WHERE id=ANY($1::text[])`, machineIDs); e != nil {
			t.Error(e)
			return
		}
		if _, e = tx.ExecContext(c, `DELETE FROM paperboat.teams WHERE team_id=ANY($1::text[])`, teamIDs); e != nil {
			t.Error(e)
			return
		}
		if _, e = tx.ExecContext(c, `DELETE FROM paperboat.users WHERE id=ANY($1::text[])`, accounts); e != nil {
			t.Error(e)
			return
		}
		if e = tx.Commit(); e != nil {
			t.Error(e)
		}
	}()
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) SELECT x,x,x||'@invalid.test','active' FROM unnest($1::text[]) x`, accounts); err != nil {
		t.Fatal(err)
	}
	s := NewService(store)
	current, err := s.Create(ctx, owner, CreateRequest{OperationID: "create", TeamID: team})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Create(ctx, outsider, CreateRequest{OperationID: "create", TeamID: otherTeam}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{enroller, memberID} {
		invitation, e := s.Invite(ctx, owner, team, InviteRequest{OperationID: "invite_" + account, ExpectedGeneration: current.Generation, AccountID: account})
		if e != nil {
			t.Fatal(e)
		}
		current, e = s.Accept(ctx, account, invitation.InvitationID, AcceptRequest{OperationID: "accept"})
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, id := range machineIDs {
		if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state) VALUES($1,$2,$3,$1,'linux','amd64','/workspace','offline','released')`, id, enroller, "env_"+id); err != nil {
			t.Fatal(err)
		}
	}
	check := func(account, selectedTeam, id, capability string, want bool) {
		t.Helper()
		_, e := s.Authorize(ctx, account, selectedTeam, "machine", id, capability)
		if want && e != nil || !want && !errors.Is(e, ErrForbidden) {
			t.Fatalf("authorize %s/%s/%s/%s want %v: %v", account, selectedTeam, id, capability, want, e)
		}
	}
	machineAction := func(account, id, action string) {
		t.Helper()
		var e error
		current, e = s.Machine(ctx, account, team, MachineRequest{OperationID: action + "_" + id, ExpectedGeneration: current.Generation, MachineID: id, Action: action, Confirmation: id})
		if e != nil {
			t.Fatalf("%s: %v", action, e)
		}
	}
	grant := func(actor, id, audience, target string, caps []string, active bool, op string) {
		t.Helper()
		var e error
		current, e = s.GrantMachine(ctx, actor, team, MachineGrantRequest{OperationID: op, ExpectedGeneration: current.Generation, MachineID: id, Audience: audience, AccountID: target, Capabilities: caps, Active: active})
		if e != nil {
			t.Fatal(e)
		}
	}
	// Ordinary personal owners can share and withdraw, but cannot take team property.
	machineAction(enroller, machine, "share")
	machineAction(enroller, personal, "share")
	check(owner, team, machine, "terminal", false)
	grant(enroller, machine, "selected_member", memberID, []string{"terminal", "files"}, true, "selected")
	check(memberID, team, machine, "terminal", true)
	check(memberID, team, machine, "exec", false)
	check(owner, team, machine, "terminal", false)
	check(outsider, team, machine, "terminal", false)
	check(memberID, otherTeam, machine, "terminal", false)
	if _, err = s.GrantMachine(ctx, memberID, team, MachineGrantRequest{OperationID: "escalate", ExpectedGeneration: current.Generation, MachineID: machine, Audience: "all_members", Capabilities: []string{"exec"}, Active: true}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member reshared: %v", err)
	}
	grant(owner, machine, "all_members", "", []string{"exec", "managed_ssh", "preview_manage", "tunnel_manage"}, true, "all")
	for _, capability := range []string{"exec", "managed_ssh", "preview_manage", "tunnel_manage"} {
		check(owner, team, machine, capability, true)
		check(memberID, team, machine, capability, true)
	}
	grant(owner, machine, "all_members", "", []string{"terminal"}, true, "all_terminal")
	grant(owner, machine, "selected_member", memberID, []string{"terminal", "files"}, false, "revoke_selected")
	check(memberID, team, machine, "terminal", true)
	check(memberID, team, machine, "files", false)
	machineAction(enroller, personal, "unshare")
	check(enroller, "", personal, "files", true)
	// Transfer is explicit, and requires both personal ownership and team admin authority.
	if _, err = s.Machine(ctx, enroller, team, MachineRequest{OperationID: "denied_transfer", ExpectedGeneration: current.Generation, MachineID: machine, Action: "transfer_to_team", Confirmation: machine}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary member transferred ownership: %v", err)
	}
	current, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "make_admin", ExpectedGeneration: current.Generation, Action: "role", AccountID: enroller, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	// Even paused public publication must have an explicit disposition before
	// ownership changes; a machine-use grant cannot inherit public authority.
	publicTunnel := "public_" + suffix
	if _, err = store.SQL().ExecContext(ctx, `WITH endpoint AS (SELECT gen_random_uuid()::text AS id) INSERT INTO paperboat.tunnels(id,account_id,name,desired_state,access_mode,stable_endpoint_id,stable_endpoint,created_by_host_id,created_by_actor_id) SELECT $1,$2,'public-transfer-test','paused','public',id,'https://'||id||'.example.test',$3,$2 FROM endpoint`, publicTunnel, enroller, machine); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Machine(ctx, enroller, team, MachineRequest{OperationID: "denied_public_transfer", ExpectedGeneration: current.Generation, MachineID: machine, Action: "transfer_to_team", Confirmation: machine}); !errors.Is(err, ErrMachinePublication) {
		t.Fatalf("public transfer: %v", err)
	}
	if _, err = store.SQL().ExecContext(ctx, `DELETE FROM paperboat.tunnels WHERE id=$1`, publicTunnel); err != nil {
		t.Fatal(err)
	}
	machineAction(enroller, machine, "transfer_to_team")
	check(enroller, "", machine, "terminal", false)
	current, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "remove_enroller", ExpectedGeneration: current.Generation, Action: "remove", AccountID: enroller})
	if err != nil {
		t.Fatal(err)
	}
	check(enroller, team, machine, "terminal", false)
	check(memberID, team, machine, "terminal", true)
	var canManage bool
	if err = store.SQL().QueryRowContext(ctx, `SELECT paperboat.machine_management_allowed($1,$2)`, enroller, machine).Scan(&canManage); err != nil || canManage {
		t.Fatalf("former enroller retains control: %v %v", canManage, err)
	}
	if _, err = store.Queries().AddUserMachineInteractiveRole(ctx, dbsqlc.AddUserMachineInteractiveRoleParams{ID: machine, UserID: enroller, SetupMode: "client", DisplayName: "retaken", RuntimeVersions: []byte(`{}`), ConfiguredCapabilities: []string{"file_receive"}}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("former enroller reused setup to modify team enrollment: %v", err)
	}
	if err = store.SQL().QueryRowContext(ctx, `SELECT paperboat.machine_management_allowed($1,$2)`, owner, machine).Scan(&canManage); err != nil || !canManage {
		t.Fatalf("current owner lacks control: %v %v", canManage, err)
	}
	// Team deletion revokes team-owned enrollment, with no personal takeover.
	current, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "delete", ExpectedGeneration: current.Generation, Action: "delete", Confirmation: team})
	if err != nil {
		t.Fatal(err)
	}
	check(memberID, team, machine, "terminal", false)
	check(enroller, "", machine, "terminal", false)
	check(enroller, "", personal, "files", true)
	var retained string
	var revoked bool
	if err = store.SQL().QueryRowContext(ctx, `SELECT owner_team_id,revoked_at IS NOT NULL FROM paperboat.user_machines WHERE id=$1`, machine).Scan(&retained, &revoked); err != nil || retained != team || !revoked {
		t.Fatalf("deletion ownership/revocation: %s %v %v", retained, revoked, err)
	}
}
