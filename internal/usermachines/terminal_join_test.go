package usermachines

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

func TestTerminalJoinRejectsInvalidIdentifiersBeforeStorage(t *testing.T) {
	s := &Service{}
	for _, in := range []TerminalJoinObservation{{}, {"access", "session", "../private"}, {"access", "session", strings.Repeat("a", 129)}} {
		if err := s.RecordTerminalJoin(context.Background(), "env", "machine", in); !errors.Is(err, ErrTerminalJoinInvalid) {
			t.Fatalf("invalid=%v", err)
		}
	}
}
func TestPostgresTerminalJoinExactAuthorityAndIdempotency(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err = db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	owner, member, team, machine, session, access, project := "join_owner_"+suffix, "join_member_"+suffix, "join_team_"+suffix, "join_machine_"+suffix, "join_session_"+suffix, "join_access_"+suffix, "join_project_"+suffix
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, e := database.SQL().BeginTx(clean, nil)
		if e != nil {
			t.Error(e)
			return
		}
		defer tx.Rollback()
		for _, item := range []struct {
			q    string
			args []any
		}{
			{`ALTER TABLE paperboat.audit_events DISABLE TRIGGER audit_events_append_only`, nil},
			{`DELETE FROM paperboat.audit_events WHERE resource_type='team' AND resource_id=$1`, []any{team}},
			{`DELETE FROM paperboat.user_machine_access_sessions WHERE id=$1`, []any{access}},
			{`DELETE FROM paperboat.teams WHERE team_id=$1`, []any{team}},
			{`DELETE FROM paperboat.user_machine_terminal_sessions WHERE id=$1`, []any{session}},
			{`DELETE FROM paperboat.user_machines WHERE id=$1`, []any{machine}},
			{`DELETE FROM paperboat.projects WHERE id=$1`, []any{project}},
			{`DELETE FROM paperboat.team_operations WHERE account_id=ANY($1::text[])`, []any{[]string{owner, member}}},
			{`DELETE FROM paperboat.users WHERE id=ANY($1::text[])`, []any{[]string{owner, member}}},
			{`ALTER TABLE paperboat.audit_events ENABLE TRIGGER audit_events_append_only`, nil},
		} {
			if _, e = tx.ExecContext(clean, item.q, item.args...); e != nil {
				t.Error(e)
				return
			}
		}
		if e = tx.Commit(); e != nil {
			t.Error(e)
		}
	}()
	for _, item := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO paperboat.users(id,workos_subject,primary_email,status) SELECT x,x,x||'@invalid.test','active' FROM unnest($1::text[]) x`, []any{[]string{owner, member}}},
		{`INSERT INTO paperboat.projects(id,user_id,name,state,idempotency_key) VALUES($1,$2,'join','ready',$1)`, []any{project, owner}},
		{`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,configured_capabilities,observed_capabilities) VALUES($1,$2,$3,'join','linux','amd64','/workspace','online','occupied',true,ARRAY['terminal_host'],ARRAY['terminal_host'])`, []any{machine, owner, project}},
		{`INSERT INTO paperboat.user_machine_terminal_sessions(id,user_machine_id,terminal_id,name,owner_account,launch_cwd) VALUES($1,$2,$1,'join',$3,'/workspace')`, []any{session, machine, owner}},
	} {
		if _, err = database.SQL().ExecContext(ctx, item.q, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	teamService := teams.NewService(database)
	state, err := teamService.Create(ctx, owner, teams.CreateRequest{TeamID: team, OperationID: "create"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.SQL().ExecContext(ctx, `INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true)`, team, member); err != nil {
		t.Fatal(err)
	}
	_, err = teamService.GrantTerminalSession(ctx, owner, team, teams.TerminalSessionGrantRequest{OperationID: "grant", ExpectedGeneration: state.Generation, TerminalSessionID: session, RuntimeGeneration: 1, Audience: "all_members", Role: "viewer", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := teamService.ResolveTerminalSession(ctx, member, session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_access_sessions(id,user_machine_id,user_id,environment_id,cli_client_session_id,http_base_url,helper_terminal_session_id,capabilities,operation_id,expires_at,team_id,terminal_session_id,terminal_role,terminal_grant_generation,terminal_binding_generation,terminal_membership_generation,terminal_team_generation) VALUES($1,$2,$3,$4,$5,'https://machine.invalid',$6,ARRAY[]::text[],$7,now()+interval '5 minutes',$8,$7,'viewer',$9,$10,$11,$12)`, access, machine, member, project, "cli_"+suffix, "jti_"+suffix, session, team, decision.GrantGeneration, decision.BindingGeneration, decision.MembershipGeneration, decision.TeamGeneration); err != nil {
		t.Fatal(err)
	}
	s := &Service{db: database}
	join := TerminalJoinObservation{access, session, "att_one"}
	for _, target := range []struct {
		environment, machine string
		join                 TerminalJoinObservation
	}{
		{project, "wrong_machine", join}, {"wrong_environment", machine, join}, {project, machine, TerminalJoinObservation{access, "wrong_session", "att_one"}},
	} {
		if err = s.RecordTerminalJoin(ctx, target.environment, target.machine, target.join); !errors.Is(err, ErrTerminalSessionNotFound) {
			t.Fatalf("wrong authority: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		if err = s.RecordTerminalJoin(ctx, project, machine, join); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	var actor string
	if err = database.SQL().QueryRowContext(ctx, `SELECT count(*),min(actor_user_id) FROM paperboat.audit_events WHERE resource_id=$1 AND event_type='team.terminal_session_joined'`, team).Scan(&count, &actor); err != nil || count != 1 || actor != member {
		t.Fatalf("audit count=%d actor=%s err=%v", count, actor, err)
	}
	if _, err = database.SQL().ExecContext(ctx, `UPDATE paperboat.team_members SET active=false,membership_generation=membership_generation+1 WHERE team_id=$1 AND account_id=$2`, team, member); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordTerminalJoin(ctx, project, machine, join); !errors.Is(err, ErrTerminalSessionNotFound) {
		t.Fatalf("revoked replay: %v", err)
	}
}
