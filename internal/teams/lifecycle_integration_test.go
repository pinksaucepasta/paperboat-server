package teams

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestPostgresUnifiedLifecycleNoRevivedAuthority(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err = db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
	owner, departing, remaining, team, other := "lc_owner_"+suffix, "lc_depart_"+suffix, "lc_remain_"+suffix, "lc_team_"+suffix, "lc_other_"+suffix

	defer func() {
		clean, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		tx, e := store.SQL().BeginTx(clean, nil)
		if e != nil {
			t.Error(e)
			return
		}
		defer tx.Rollback()
		for _, item := range []struct {
			query string
			args  []any
		}{
			{`ALTER TABLE paperboat.audit_events DISABLE TRIGGER audit_events_append_only`, nil},
			{`DELETE FROM paperboat.audit_events WHERE actor_user_id=ANY($1::text[])`, []any{[]string{owner, departing, remaining}}},
			{`DELETE FROM paperboat.team_inbox_requests WHERE team_id=ANY($1::text[])`, []any{[]string{team, other}}},
			{`DELETE FROM paperboat.tunnels WHERE account_id=ANY($1::text[])`, []any{[]string{owner, departing, remaining}}},
			{`DELETE FROM paperboat.user_machines WHERE user_id=ANY($1::text[])`, []any{[]string{owner, departing, remaining}}},
			{`DELETE FROM paperboat.control_environments WHERE owner_user_id=ANY($1::text[])`, []any{[]string{owner, departing, remaining}}},
			{`DELETE FROM paperboat.teams WHERE team_id=ANY($1::text[])`, []any{[]string{team, other}}},
			{`DELETE FROM paperboat.users WHERE id=ANY($1::text[])`, []any{[]string{owner, departing, remaining}}},
			{`ALTER TABLE paperboat.audit_events ENABLE TRIGGER audit_events_append_only`, nil},
		} {
			if _, e = tx.ExecContext(clean, item.query, item.args...); e != nil {
				t.Error(e)
				return
			}
		}
		if e = tx.Commit(); e != nil {
			t.Error(e)
		}
	}()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := store.SQL().ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO paperboat.users(id,workos_subject,primary_email,status) SELECT x,x,x||'@invalid.test','active' FROM unnest($1::text[]) x`, []string{owner, departing, remaining})
	s := NewService(store)
	state, err := s.Create(ctx, owner, CreateRequest{OperationID: "create", TeamID: team})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Create(ctx, owner, CreateRequest{OperationID: "other", TeamID: other})
	if err != nil {
		t.Fatal(err)
	}
	join := func(account, op string) {
		t.Helper()
		i, e := s.Invite(ctx, owner, team, InviteRequest{OperationID: op, ExpectedGeneration: state.Generation, AccountID: account})
		if e != nil {
			t.Fatal(e)
		}
		state, e = s.Accept(ctx, account, i.InvitationID, AcceptRequest{OperationID: op})
		if e != nil {
			t.Fatal(e)
		}
	}
	join(departing, "join_depart")
	join(remaining, "join_remain")
	// More than a receipt's byte limit of live grants must not block unrelated
	// administration. Receipts retain identity/generation, not the grant inventory.
	exec(`INSERT INTO paperboat.team_resource_bindings(team_id,resource_kind,resource_id,owner_account) SELECT $1,'terminal_session','lc_session_'||$1||n,$2 FROM generate_series(1,20) n`, team, departing)
	exec(`INSERT INTO paperboat.team_terminal_session_grants(team_id,terminal_session_id,audience,role) SELECT team_id,resource_id,'all_members','viewer' FROM paperboat.team_resource_bindings WHERE team_id=$1`, team)

	exec(`INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true),($1,$3,1,'member',true)`, other, departing, remaining)
	for _, binding := range [][2]string{{"depart_tunnel_" + team, departing}, {"remain_tunnel_" + team, remaining}, {"other_tunnel_" + team, departing}} {
		exec(`WITH endpoint AS (SELECT gen_random_uuid() AS id) INSERT INTO paperboat.tunnels(id,account_id,name,access_mode,stable_endpoint_id,stable_endpoint,created_by_host_id,created_by_actor_id) SELECT $1,$2,$1,'team',id,'https://'||id||'.invalid.test','fixture-host',$2 FROM endpoint`, binding[0], binding[1])
	}
	exec(`INSERT INTO paperboat.team_resource_bindings(team_id,resource_kind,resource_id,owner_account) VALUES($1,'tunnel','depart_tunnel_'||$1,$2),($1,'tunnel','remain_tunnel_'||$1,$3),($4,'tunnel','other_tunnel_'||$1,$2)`, team, departing, remaining, other)
	exec(`INSERT INTO paperboat.team_resource_grants(team_id,account_id,resource_kind,resource_id,permission,generation,active) SELECT team_id,$2,resource_kind,resource_id,'use',1,true FROM paperboat.team_resource_bindings WHERE team_id=$1 AND resource_kind='tunnel'`, team, remaining)

	exec(`INSERT INTO paperboat.team_resource_grants(team_id,account_id,resource_kind,resource_id,permission,generation,active) VALUES($1,$2,'tunnel',$3,'use',1,true)`, other, remaining, "other_tunnel_"+team)
	exec(`INSERT INTO paperboat.environment_vault_teams(team_id,key_epoch) VALUES($1,1)`, team)
	exec(`INSERT INTO paperboat.environment_vault_team_members(team_id,account_id,grant_epoch) VALUES($1,$2,1)`, team, departing)
	repo := "lc_repo_" + suffix
	exec(`INSERT INTO paperboat.control_config_repositories(id,owner_user_id,provider,external_ref,display_name) VALUES($1,$2,'github',$1,'fixture')`, repo, departing)
	exec(`INSERT INTO paperboat.team_config_defaults(team_id,provider,external_repository_id,display_name,branch,updated_by) VALUES($1,'github','fixture','fixture','main',$2)`, team, owner)
	exec(`INSERT INTO paperboat.team_config_default_adoptions(team_id,account_id,default_version,repository_id) VALUES($1,$2,1,$3)`, team, departing, repo)

	source, destination := "lc_source_"+suffix, "lc_destination_"+suffix
	for _, pair := range [][2]string{{source, departing}, {destination, remaining}} {
		exec(`INSERT INTO paperboat.control_environments(id,workspace_id,owner_user_id) VALUES($1,$1,$2)`, "env_"+pair[0], pair[1])
		exec(`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state) VALUES($1,$2,$3,'fixture','linux','amd64','/workspace','offline','released')`, pair[0], pair[1], "env_"+pair[0])
	}
	exec(`INSERT INTO paperboat.control_config_assignments(id,machine_id,environment_id,repository_id,adopted_team_id,adopted_default_version) VALUES($1,$1,$2,$3,$4,1)`, source, "env_"+source, repo, team)
	exec(`INSERT INTO paperboat.control_config_assignments(id,machine_id,environment_id,repository_id) VALUES($1,$1,$2,$3)`, destination, "env_"+destination, repo)
	exec(`INSERT INTO paperboat.team_inbox_requests(request_id,operation_id,team_id,sender_account,recipient_account,source_machine_id,destination_machine_id,batch_id,manifest_digest,manifest,status,decision_kind,policy_generation,expires_at)
 SELECT 'lc_request_'||$1||status,status,$1,$2,$3,$4,$5,status,repeat('a',64),'[{}]'::jsonb,status,'manual',1,now()+interval '1 hour' FROM unnest(ARRAY['pending','approved','consumed','completed']) status`, team, departing, remaining, source, destination)
	state, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "remove", ExpectedGeneration: state.Generation, Action: "remove", AccountID: departing})
	if err != nil {
		t.Fatal(err)
	}
	if state.ENVStatus != "rotation_pending" {
		t.Fatalf("ENV status=%s", state.ENVStatus)
	}
	assertCount := func(q string, want int, args ...any) {
		t.Helper()
		var got int
		if e := store.SQL().QueryRowContext(ctx, q, args...).Scan(&got); e != nil || got != want {
			t.Fatalf("count=%d want=%d error=%v", got, want, e)
		}
	}
	assertCount(`SELECT count(*) FROM paperboat.team_terminal_session_grants WHERE team_id=$1 AND active`, 0, team)
	assertCount(`SELECT count(*) FROM paperboat.team_resource_bindings WHERE team_id=$1 AND owner_account=$2 AND active`, 0, team, departing)
	assertCount(`SELECT count(*) FROM paperboat.team_resource_bindings WHERE team_id=$1 AND owner_account=$2 AND active`, 1, team, remaining)
	assertCount(`SELECT count(*) FROM paperboat.team_resource_bindings WHERE team_id=$1 AND active`, 1, other)
	assertCount(`SELECT count(*) FROM paperboat.team_resource_grants WHERE team_id=$1 AND active`, 1, team)
	assertCount(`SELECT count(*) FROM paperboat.team_config_default_adoptions WHERE team_id=$1`, 0, team)

	assertCount(`SELECT count(*) FROM paperboat.team_inbox_requests WHERE team_id=$1 AND status='revoked'`, 3, team)
	assertCount(`SELECT count(*) FROM paperboat.team_inbox_requests WHERE team_id=$1 AND status='completed'`, 1, team)
	assertCount(`SELECT count(*) FROM paperboat.control_config_assignments WHERE machine_id=$1 AND revoked_at IS NOT NULL`, 1, source)
	assertCount(`SELECT count(*) FROM paperboat.control_config_assignments WHERE machine_id=$1 AND revoked_at IS NULL`, 1, destination)

	for _, scope := range [][2]string{{team, "remain_tunnel_" + team}, {other, "other_tunnel_" + team}} {
		if _, e := s.Authorize(ctx, remaining, scope[0], "tunnel", scope[1], "use"); e != nil {
			t.Fatalf("unrelated tunnel access lost: %v", e)
		}
	}
	if _, e := s.Authorize(ctx, remaining, team, "tunnel", "depart_tunnel_"+team, "use"); !errors.Is(e, ErrForbidden) {
		t.Fatalf("departing personal share remained: %v", e)
	}
	assertCount(`SELECT count(*) FROM paperboat.tunnels WHERE id=$1 AND account_id=$2 AND deleted_at IS NULL`, 1, "depart_tunnel_"+team, departing)
	join(departing, "rejoin")
	assertCount(`SELECT count(*) FROM paperboat.team_terminal_session_grants WHERE team_id=$1 AND active`, 0, team)
	assertCount(`SELECT count(*) FROM paperboat.team_config_default_adoptions WHERE team_id=$1`, 0, team)
	if _, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "leave_owner", ExpectedGeneration: state.Generation, Action: "leave"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("owner departure=%v", err)
	}
	state, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "transfer", ExpectedGeneration: state.Generation, Action: "transfer", AccountID: remaining})
	if err != nil {
		t.Fatal(err)
	}
	state, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "leave_former_owner", ExpectedGeneration: state.Generation, Action: "leave"})
	if err != nil {
		t.Fatal(err)
	}
	state, err = s.Mutate(ctx, remaining, team, MutationRequest{OperationID: "delete", ExpectedGeneration: state.Generation, Action: "delete", Confirmation: team})
	if err != nil {
		t.Fatal(err)
	}
	if !state.Deleted || state.ENVStatus != "deleted" {
		t.Fatalf("deleted state=%+v", state)
	}
	assertCount(`SELECT count(*) FROM paperboat.team_config_defaults WHERE team_id=$1`, 0, team)
	assertCount(`SELECT count(*) FROM paperboat.control_config_repositories WHERE id=$1 AND owner_user_id=$2 AND state='active'`, 1, repo, departing)
	assertCount(`SELECT count(*) FROM paperboat.team_resource_bindings WHERE team_id=$1 AND active`, 1, other)
}
