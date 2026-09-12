package teams

import (
	"context"
	"errors"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTerminalSessionGrantExclusionAndRegrant(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err = db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	owner, member, other, outsider, admin, team, project, session := "ts_owner_"+suffix, "ts_member_"+suffix, "ts_other_"+suffix, "ts_outside_"+suffix, "ts_admin_"+suffix, "ts_team_"+suffix, "ts_project_"+suffix, "pts_shared_"+suffix
	machine, machineSession := "ts_machine_"+suffix, "umts_shared_"+suffix
	defer func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.teams WHERE team_id=$1`, team)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.projects WHERE id=$1`, project)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=ANY($1::text[])`, []string{owner, member, other, outsider, admin})
	}()
	for _, setup := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO paperboat.users(id,workos_subject,primary_email,status) SELECT x,x,x||'@invalid.test','active' FROM unnest($1::text[]) x`, []any{[]string{owner, member, other, outsider, admin}}},
		{`INSERT INTO paperboat.projects(id,user_id,name,state,idempotency_key) VALUES($1,$2,'shared','ready',$1)`, []any{project, owner}},
		{`INSERT INTO paperboat.project_terminal_sessions(id,project_id,terminal_id,name,owner_account) VALUES($1,$2,$1,'shared',$3)`, []any{session, project, owner}},
		{`INSERT INTO paperboat.teams(team_id,owner_account,generation) VALUES($1,$2,1)`, []any{team, admin}},
		{`INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true),($1,$3,1,'member',true),($1,$4,1,'member',true),($1,$5,1,'admin',true)`, []any{team, owner, member, other, admin}},
		{`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,configured_capabilities,observed_capabilities,installation_generation) VALUES($1,$2,$3,'terminal target','linux','amd64','/workspace','online','occupied',true,ARRAY['terminal_host'],ARRAY['terminal_host'],3)`, []any{machine, owner, project}},
		{`INSERT INTO paperboat.user_machine_terminal_sessions(id,user_machine_id,terminal_id,name,owner_account,launch_cwd) VALUES($1,$2,$1,'machine-shell',$3,'/workspace')`, []any{machineSession, machine, owner}},
	} {
		if _, err = store.SQL().ExecContext(ctx, setup.q, setup.args...); err != nil {
			t.Fatal(err)
		}
	}
	service := NewService(store)
	state, err := service.Get(ctx, owner, team)
	if err != nil {
		t.Fatal(err)
	}
	state, err = service.GrantTerminalSession(ctx, owner, team, TerminalSessionGrantRequest{OperationID: "all", ExpectedGeneration: state.Generation, TerminalSessionID: session, RuntimeGeneration: 1, Audience: "all_members", Role: "interactive", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := service.ResolveTerminalSession(ctx, member, session)
	if err != nil || decision.Role != "interactive" || decision.TargetKind != "hosted" || decision.TargetID != project {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	if _, err = service.ResolveTerminalSession(ctx, outsider, session); !errors.Is(err, ErrNotFound) {
		t.Fatalf("outsider resolved shared session: %v", err)
	}
	state, err = service.GrantTerminalSession(ctx, owner, team, TerminalSessionGrantRequest{OperationID: "machine", ExpectedGeneration: state.Generation, TerminalSessionID: machineSession, RuntimeGeneration: 1, Audience: "selected_member", AccountID: member, Role: "viewer", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	machineDecision, err := service.ResolveTerminalSession(ctx, member, machineSession)
	if err != nil || machineDecision.TargetKind != "machine" || machineDecision.TargetID != machine {
		t.Fatalf("machine decision=%#v err=%v", machineDecision, err)
	}
	insertAccess := func(id, actor, terminal string, d TerminalSessionDecision) {
		t.Helper()
		_, insertErr := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_access_sessions(id,user_machine_id,user_id,environment_id,cli_client_session_id,http_base_url,helper_terminal_session_id,capabilities,operation_id,expires_at,team_id,terminal_session_id,terminal_role,terminal_grant_generation,terminal_binding_generation,terminal_membership_generation,terminal_team_generation) VALUES($1,$2,$3,$4,$5,'https://machine.invalid',$6,ARRAY[]::text[],$7,now()+interval '5 minutes',$8,$9,$10,$11,$12,$13,$14)`, id, machine, actor, project, "cli_"+actor, "jti_"+id, terminal, team, terminal, d.Role, d.GrantGeneration, d.BindingGeneration, d.MembershipGeneration, d.TeamGeneration)
		if insertErr != nil {
			t.Fatal(insertErr)
		}
	}
	insertAccess("access_toggle_"+suffix, member, machineSession, machineDecision)
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET configured_capabilities=ARRAY[]::text[] WHERE id=$1`, machine); err != nil {
		t.Fatal(err)
	}
	var accessState string
	if err = store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_access_sessions WHERE id=$1`, "access_toggle_"+suffix).Scan(&accessState); err != nil || accessState != "revoked" {
		t.Fatalf("device toggle access state=%q err=%v", accessState, err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET configured_capabilities=ARRAY['terminal_host'] WHERE id=$1`, machine); err != nil {
		t.Fatal(err)
	}
	insertAccess("access_other_session_"+suffix, member, machineSession, machineDecision)
	memberDecision, err := service.ResolveTerminalSession(ctx, member, session)
	if err != nil {
		t.Fatal(err)
	}
	otherDecision, err := service.ResolveTerminalSession(ctx, other, session)
	if err != nil {
		t.Fatal(err)
	}
	insertAccess("access_member_"+suffix, member, session, memberDecision)
	insertAccess("access_other_"+suffix, other, session, otherDecision)
	if _, err = service.GrantTerminalSession(ctx, admin, team, TerminalSessionGrantRequest{OperationID: "admin", ExpectedGeneration: state.Generation, TerminalSessionID: session, RuntimeGeneration: 1, Audience: "selected_member", AccountID: member, Role: "interactive", Active: true}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin changed personal session: %v", err)
	}
	state, err = service.GrantTerminalSession(ctx, owner, team, TerminalSessionGrantRequest{OperationID: "downgrade", ExpectedGeneration: state.Generation, TerminalSessionID: session, RuntimeGeneration: 1, Audience: "selected_member", AccountID: member, Role: "viewer", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	decision, err = service.ResolveTerminalSession(ctx, member, session)
	if err != nil || decision.Role != "viewer" {
		t.Fatalf("selected viewer did not override interactive team grant: %#v %v", decision, err)
	}
	var memberState, otherState, otherSessionState string
	if err = store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_access_sessions WHERE id=$1`, "access_member_"+suffix).Scan(&memberState); err != nil {
		t.Fatal(err)
	}
	if err = store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_access_sessions WHERE id=$1`, "access_other_"+suffix).Scan(&otherState); err != nil {
		t.Fatal(err)
	}
	if err = store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.user_machine_access_sessions WHERE id=$1`, "access_other_session_"+suffix).Scan(&otherSessionState); err != nil {
		t.Fatal(err)
	}
	if memberState != "revoked" || otherState != "active" || otherSessionState != "active" {
		t.Fatalf("targeted role fencing member=%s unrelated_participant=%s unrelated_session=%s", memberState, otherState, otherSessionState)
	}
	state, err = service.RemoveTerminalParticipant(ctx, owner, team, session, member, "remove", state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.ResolveTerminalSession(ctx, member, session); !errors.Is(err, ErrNotFound) {
		t.Fatalf("all-member exclusion ignored: %v", err)
	}
	state, err = service.GrantTerminalSession(ctx, owner, team, TerminalSessionGrantRequest{OperationID: "regrant", ExpectedGeneration: state.Generation, TerminalSessionID: session, RuntimeGeneration: 1, Audience: "selected_member", AccountID: member, Role: "interactive", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	decision, err = service.ResolveTerminalSession(ctx, member, session)
	if err != nil || decision.Role != "interactive" {
		t.Fatalf("regrant=%#v %v", decision, err)
	}
	ended, err := service.EndTerminalSessionSharing(ctx, owner, team, session, "end", state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.EndTerminalSessionSharing(ctx, owner, team, session, "end", state.Generation); err != nil {
		t.Fatalf("idempotent end failed: %v", err)
	}
	if ended.Generation <= state.Generation {
		t.Fatal("end did not advance team generation")
	}
	reopened, err := service.GrantTerminalSession(ctx, owner, team, TerminalSessionGrantRequest{OperationID: "reopen", ExpectedGeneration: ended.Generation, TerminalSessionID: session, RuntimeGeneration: 2, Audience: "all_members", Role: "viewer", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	var oldSelectedCount int
	if err = store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.team_terminal_session_grants WHERE team_id=$1 AND terminal_session_id=$2 AND audience='selected_member'`, team, session).Scan(&oldSelectedCount); err != nil {
		t.Fatal(err)
	}
	if oldSelectedCount != 0 {
		t.Fatal("new process sharing epoch retained old selected permissions or exclusions")
	}
	if decision, err = service.ResolveTerminalSession(ctx, member, session); err != nil || decision.Role != "viewer" {
		t.Fatalf("new all-member epoch did not cover prior selected member: %#v %v", decision, err)
	}
	removed, err := service.Mutate(ctx, admin, team, MutationRequest{OperationID: "remove-owner", ExpectedGeneration: reopened.Generation, Action: "remove", AccountID: owner})
	if err != nil {
		t.Fatal(err)
	}
	var bindingActive bool
	if err = store.SQL().QueryRowContext(ctx, `SELECT active FROM paperboat.team_resource_bindings WHERE team_id=$1 AND resource_kind='terminal_session' AND resource_id=$2`, team, session).Scan(&bindingActive); err != nil {
		t.Fatal(err)
	}
	if bindingActive {
		t.Fatal("departing session owner left sharing active")
	}
	if _, err = service.ResolveTerminalSession(ctx, member, session); !errors.Is(err, ErrNotFound) {
		t.Fatalf("owner departure left member access: generation=%d err=%v", removed.Generation, err)
	}
}
