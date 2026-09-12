package teams

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestPermissionImplications(t *testing.T) {
	for _, tc := range []struct {
		kind, grant, want string
		yes               bool
	}{{"env", "write", "read", true}, {"env", "read", "write", false}, {"env", "write", "manage", false}, {"preview", "use", "manage", false}, {"preview", "manage", "use", true}, {"lazy_policy", "manage", "use", true}, {"lazy_policy", "use", "manage", false}, {"lazy_policy", "manage", "execute", false}, {"tunnel", "manage", "execute", false}, {"tunnel", "write", "use", false}, {"personal", "manage", "use", false},
		// Inspector actions are exact-match only.
		{"preview", "inspect", "inspect", true}, {"preview", "replay", "replay", true}, {"tunnel", "inspect", "inspect", true}, {"tunnel", "replay", "replay", true},
		{"preview", "use", "inspect", false}, {"preview", "use", "replay", false}, {"preview", "manage", "inspect", false}, {"preview", "manage", "replay", false},
		{"tunnel", "use", "inspect", false}, {"tunnel", "manage", "replay", false},
		{"preview", "inspect", "replay", false}, {"preview", "replay", "inspect", false}, {"tunnel", "inspect", "replay", false},
		{"preview", "inspect", "use", false}, {"preview", "inspect", "manage", false},
		{"env", "write", "inspect", false}, {"lazy_policy", "manage", "inspect", false}, {"personal", "inspect", "inspect", false}} {
		if got := permits(tc.kind, tc.grant, tc.want); got != tc.yes {
			t.Errorf("%s %s -> %s: %v", tc.kind, tc.grant, tc.want, got)
		}
	}
}
func TestCurrentMemberAndGeneration(t *testing.T) {
	team := Team{Generation: 3, OwnerAccount: "owner", Members: []Member{{AccountID: "owner", Role: "owner", Active: true}, {AccountID: "revoked", Role: "admin"}}}
	if _, err := check(team, "revoked", 3); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := check(team, "owner", 2); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	team.Deleted = true
	if _, err := check(team, "owner", 3); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
}
func TestPostgresTeamAuthorityLifecycle(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN for isolated team transaction verification")
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
	owner, admin, ordinary, other, team := "ta_owner_"+suffix, "ta_admin_"+suffix, "ta_member_"+suffix, "ta_other_"+suffix, "ta_team_"+suffix
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cleanupTx, e := store.SQL().BeginTx(clean, nil)
		if e != nil {
			t.Errorf("cleanup begin: %v", e)
			return
		}
		defer cleanupTx.Rollback()
		if _, e = cleanupTx.ExecContext(clean, `ALTER TABLE paperboat.audit_events DISABLE TRIGGER audit_events_append_only`); e != nil {
			t.Errorf("cleanup audit lock: %v", e)
			return
		}
		for _, q := range []string{`DELETE FROM paperboat.audit_events WHERE resource_type='team' AND resource_id=$1 AND actor_user_id IN($2,$3,$4,$5)`, `DELETE FROM paperboat.teams WHERE team_id=$1 AND $2<>'' AND $3<>'' AND $4<>'' AND $5<>''`, `DELETE FROM paperboat.users WHERE id IN($2,$3,$4,$5) AND $1<>''`} {
			if _, err := cleanupTx.ExecContext(clean, q, team, owner, admin, ordinary, other); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
		if _, e = cleanupTx.ExecContext(clean, `ALTER TABLE paperboat.audit_events ENABLE TRIGGER audit_events_append_only`); e != nil {
			t.Errorf("restore audit trigger: %v", e)
			return
		}
		if e = cleanupTx.Commit(); e != nil {
			t.Errorf("cleanup commit: %v", e)
		}
	}()
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) SELECT x,x,x||'@invalid.test','active' FROM unnest($1::text[]) x`, []string{owner, admin, ordinary, other}); err != nil {
		t.Fatal(err)
	}
	s := NewService(store)
	state, err := s.Create(ctx, owner, CreateRequest{OperationID: "create", TeamID: team})
	if err != nil {
		t.Fatal(err)
	}
	invite := func(actor, recipient, op string) Invitation {
		t.Helper()
		i, e := s.Invite(ctx, actor, team, InviteRequest{OperationID: op, ExpectedGeneration: state.Generation, AccountID: recipient})
		if e != nil {
			t.Fatal(e)
		}
		state, e = s.Get(ctx, owner, team)
		if e != nil {
			t.Fatal(e)
		}
		return i
	}
	accept := func(recipient string, i Invitation, op string) {
		t.Helper()
		var e error
		state, e = s.Accept(ctx, recipient, i.InvitationID, AcceptRequest{OperationID: op})
		if e != nil {
			t.Fatal(e)
		}
	}
	i := invite(owner, admin, "invite_admin")
	if _, err = s.Accept(ctx, other, i.InvitationID, AcceptRequest{OperationID: "wrong_recipient"}); !errors.Is(err, ErrForbidden) {
		t.Fatal("wrong recipient", err)
	}
	accept(admin, i, "accept_admin")
	if _, err = s.Accept(ctx, admin, i.InvitationID, AcceptRequest{OperationID: "reuse_invite"}); !errors.Is(err, ErrExpired) {
		t.Fatal("reused invitation", err)
	}
	state, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "promote", Action: "role", ExpectedGeneration: state.Generation, AccountID: admin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	i = invite(admin, ordinary, "invite_member")
	accept(ordinary, i, "accept_member")
	denied := []struct{ actor, action, target, role string }{{ordinary, "role", ordinary, "admin"}, {ordinary, "remove", admin, ""}, {admin, "role", ordinary, "admin"}, {admin, "remove", owner, ""}, {admin, "transfer", ordinary, ""}, {admin, "delete", "", ""}, {owner, "leave", "", ""}}
	for n, tc := range denied {
		_, err = s.Mutate(ctx, tc.actor, team, MutationRequest{OperationID: "deny_" + string(rune('a'+n)), Action: tc.action, ExpectedGeneration: state.Generation, AccountID: tc.target, Role: tc.role, Confirmation: team})
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s %s: %v", tc.actor, tc.action, err)
		}
	}
	if _, err = s.Invite(ctx, ordinary, team, InviteRequest{OperationID: "member_invite", ExpectedGeneration: state.Generation, AccountID: other}); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if _, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "stale", Action: "role", ExpectedGeneration: state.Generation - 1, AccountID: admin, Role: "member"}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	// Membership and administrative roles alone never create ENV grants.
	if _, err = s.Authorize(ctx, owner, team, "env", team, "read"); !errors.Is(err, ErrForbidden) {
		t.Fatal("role became grant", err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.team_resource_bindings(team_id,resource_kind,resource_id,owner_account) VALUES($1,'env',$1,$2)`, team, owner); err != nil {
		t.Fatal(err)
	}
	readGrant := GrantRequest{OperationID: "read_grant", ExpectedGeneration: state.Generation, AccountID: ordinary, ResourceKind: "env", ResourceID: team, Permission: "read", Active: true}
	state, err = s.Grant(ctx, admin, team, readGrant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authorize(ctx, ordinary, team, "env", team, "read"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authorize(ctx, ordinary, team, "env", team, "write"); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if _, err = s.Authorize(ctx, ordinary, team, "env", "wrong_team", "read"); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	state, err = s.Grant(ctx, admin, team, GrantRequest{OperationID: "write_grant", ExpectedGeneration: state.Generation, AccountID: ordinary, ResourceKind: "env", ResourceID: team, Permission: "write", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authorize(ctx, ordinary, team, "env", team, "write"); err != nil {
		t.Fatal(err)
	}
	state, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "demote_admin", Action: "role", ExpectedGeneration: state.Generation, AccountID: admin, Role: "member"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Grant(ctx, admin, team, readGrant); !errors.Is(err, ErrForbidden) {
		t.Fatalf("demoted admin replay accepted: %v", err)
	}
	state, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "restore_admin", Action: "role", ExpectedGeneration: state.Generation, AccountID: admin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	concurrentGeneration := state.Generation
	results := make(chan error, 2)
	for _, actor := range []string{owner, admin} {
		go func(actor string) {
			_, e := s.Grant(ctx, actor, team, GrantRequest{OperationID: "concurrent", ExpectedGeneration: concurrentGeneration, AccountID: ordinary, ResourceKind: "env", ResourceID: team, Permission: "write", Active: true})
			results <- e
		}(actor)
	}
	succeeded, conflicted := 0, 0
	for range 2 {
		e := <-results
		if e == nil {
			succeeded++
		} else if errors.Is(e, ErrConflict) {
			conflicted++
		} else {
			t.Fatal(e)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent writes: %d succeeded %d conflicted", succeeded, conflicted)
	}
	state, err = s.Get(ctx, owner, team)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_vault_teams(team_id,key_epoch) VALUES($1,1)`, team); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_vault_team_members(team_id,account_id,grant_epoch) VALUES($1,$2,1)`, team, ordinary); err != nil {
		t.Fatal(err)
	}
	state, err = s.Mutate(ctx, admin, team, MutationRequest{OperationID: "remove_member", Action: "remove", ExpectedGeneration: state.Generation, AccountID: ordinary})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authorize(ctx, ordinary, team, "env", team, "read"); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	var pending bool
	if err = store.SQL().QueryRowContext(ctx, `SELECT rotation_required FROM paperboat.environment_vault_teams WHERE team_id=$1`, team).Scan(&pending); err != nil || !pending {
		t.Fatalf("removal must fence pending rekey: %v %v", pending, err)
	}
	// Acceptance after removal does not restore old grants or administrative roles.
	i = invite(owner, ordinary, "reinvite")
	accept(ordinary, i, "reaccept")
	if _, err = s.Authorize(ctx, ordinary, team, "env", team, "read"); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	transfer := MutationRequest{OperationID: "transfer", Action: "transfer", ExpectedGeneration: state.Generation, AccountID: ordinary}
	state, err = s.Mutate(ctx, owner, team, transfer)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := s.Mutate(ctx, owner, team, transfer)
	if err != nil || replayed.Generation != state.Generation {
		t.Fatal("transfer retry", err)
	}
	if _, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "old_owner", Action: "delete", ExpectedGeneration: state.Generation, Confirmation: team}); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if _, err = s.Mutate(ctx, ordinary, team, MutationRequest{OperationID: "bad_confirm", Action: "delete", ExpectedGeneration: state.Generation}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	del := MutationRequest{OperationID: "delete", Action: "delete", ExpectedGeneration: state.Generation, Confirmation: team}
	state, err = s.Mutate(ctx, ordinary, team, del)
	if err != nil || !state.Deleted {
		t.Fatal("delete", err)
	}
	if _, err = s.Mutate(ctx, ordinary, team, del); err != nil {
		t.Fatal("delete retry", err)
	}
	var users int
	if err = store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.users WHERE id=ANY($1::text[])`, []string{owner, admin, ordinary, other}).Scan(&users); err != nil || users != 4 {
		t.Fatal("team delete changed personal accounts", users, err)
	}
}

func TestReplayRechecksCurrentRole(t *testing.T) {
	original := Team{TeamID: "team", Generation: 2, OwnerAccount: "owner", Members: []Member{{AccountID: "admin", Role: "admin", Active: true}}}
	current := original
	current.Members = []Member{{AccountID: "admin", Role: "member", Active: true}}
	if err := replayAuthority(current, original, "admin", "grant", GrantRequest{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("demoted admin retry: %v", err)
	}
	current.Members = []Member{{AccountID: "admin", Role: "admin", Active: false}}
	if err := replayAuthority(current, original, "admin", "grant", GrantRequest{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("removed admin retry: %v", err)
	}
	current = original
	current.OwnerAccount = "new_owner"
	if err := replayAuthority(current, current, "owner", "transfer", MutationRequest{AccountID: "new_owner"}); err != nil {
		t.Fatal(err)
	}
	current.Generation++
	if err := replayAuthority(current, original, "owner", "transfer", MutationRequest{AccountID: "new_owner"}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

func TestPostgresInvitationExpiryAndResourceAttachment(t *testing.T) {
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
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	owner, recipient, team, tunnel := "tr_owner_"+suffix, "tr_recipient_"+suffix, "tr_team_"+suffix, "tr_tunnel_"+suffix
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
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
		for _, q := range []string{`DELETE FROM paperboat.audit_events WHERE resource_type='team' AND resource_id=$1 AND actor_user_id IN($2,$3)`, `DELETE FROM paperboat.teams WHERE team_id=$1 AND $2<>'' AND $3<>''`, `DELETE FROM paperboat.users WHERE id IN($2,$3) AND $1<>''`} {
			if _, e = tx.ExecContext(c, q, team, owner, recipient); e != nil {
				t.Error(e)
				return
			}
		}
		if _, e = tx.ExecContext(c, `ALTER TABLE paperboat.audit_events ENABLE TRIGGER audit_events_append_only`); e != nil {
			t.Error(e)
			return
		}
		if e = tx.Commit(); e != nil {
			t.Error(e)
		}
	}()
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) SELECT x,x,x||'@invalid.test','active' FROM unnest($1::text[]) x`, []string{owner, recipient}); err != nil {
		t.Fatal(err)
	}
	s := NewService(store)
	state, err := s.Create(ctx, owner, CreateRequest{OperationID: "create", TeamID: team})
	if err != nil {
		t.Fatal(err)
	}
	i, err := s.Invite(ctx, owner, team, InviteRequest{OperationID: "expire", ExpectedGeneration: state.Generation, AccountID: recipient})
	if err != nil {
		t.Fatal(err)
	}
	state.Generation = i.Generation
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.team_invitations SET expires_at=now()-interval '1 second' WHERE invitation_id=$1`, i.InvitationID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Accept(ctx, recipient, i.InvitationID, AcceptRequest{OperationID: "expired_accept"}); !errors.Is(err, ErrExpired) {
		t.Fatal("expired invite accepted", err)
	}
	i, err = s.Invite(ctx, owner, team, InviteRequest{OperationID: "cancel", ExpectedGeneration: state.Generation, AccountID: recipient})
	if err != nil {
		t.Fatal(err)
	}
	state.Generation = i.Generation
	state, err = s.CancelInvite(ctx, owner, team, i.InvitationID, MutationRequest{OperationID: "cancel_invite", ExpectedGeneration: state.Generation})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Accept(ctx, recipient, i.InvitationID, AcceptRequest{OperationID: "cancelled_accept"}); !errors.Is(err, ErrExpired) {
		t.Fatal("cancelled invite accepted", err)
	}
	i, err = s.Invite(ctx, owner, team, InviteRequest{OperationID: "join", ExpectedGeneration: state.Generation, AccountID: recipient})
	if err != nil {
		t.Fatal(err)
	}
	state, err = s.Accept(ctx, recipient, i.InvitationID, AcceptRequest{OperationID: "accept"})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "00000000-0000-4000-8000-" + suffix[len(suffix)-12:]
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.tunnels(id,account_id,name,access_mode,stable_endpoint_id,stable_endpoint,created_by_host_id,created_by_actor_id) VALUES($1,$2,'attachment test','private',$3,'https://'||$3||'.invalid.test','test-host',$2)`, tunnel, owner, endpoint); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authorize(ctx, recipient, team, "tunnel", tunnel, "use"); !errors.Is(err, ErrForbidden) {
		t.Fatal("membership shared personal tunnel", err)
	}
	state, err = s.Mutate(ctx, owner, team, MutationRequest{OperationID: "promote", ExpectedGeneration: state.Generation, Action: "role", AccountID: recipient, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Attach(ctx, recipient, team, AttachRequest{OperationID: "foreign_attach", ExpectedGeneration: state.Generation, ResourceKind: "tunnel", ResourceID: tunnel, Active: true}); !errors.Is(err, ErrForbidden) {
		t.Fatal("admin attached foreign personal asset", err)
	}
	state, err = s.Attach(ctx, owner, team, AttachRequest{OperationID: "attach", ExpectedGeneration: state.Generation, ResourceKind: "tunnel", ResourceID: tunnel, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authorize(ctx, recipient, team, "tunnel", tunnel, "use"); !errors.Is(err, ErrForbidden) {
		t.Fatal("attachment implicitly granted resource", err)
	}
	state, err = s.Grant(ctx, owner, team, GrantRequest{OperationID: "use", ExpectedGeneration: state.Generation, AccountID: recipient, ResourceKind: "tunnel", ResourceID: tunnel, Permission: "use", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := s.Authorize(ctx, recipient, team, "tunnel", tunnel, "use")
	if err != nil || decision.TeamGeneration != state.Generation || decision.GrantGeneration == 0 || decision.BindingGeneration == 0 {
		t.Fatal("grant decision", decision, err)
	}
	if _, err = s.Authorize(ctx, recipient, team, "tunnel", tunnel, "manage"); !errors.Is(err, ErrForbidden) {
		t.Fatal("use grant became manage", err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.tunnels SET desired_state='deleted',deleted_at=now() WHERE id=$1`, tunnel); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authorize(ctx, recipient, team, "tunnel", tunnel, "use"); !errors.Is(err, ErrForbidden) {
		t.Fatal("deleted resource retained grant", err)
	}
}

func TestPostgresTeamHistoryBounds(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	owner, recipient, team := "tb_owner_"+suffix, "tb_recipient_"+suffix, "tb_team_"+suffix
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
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
		for _, q := range []string{`DELETE FROM paperboat.audit_events WHERE resource_type='team' AND resource_id=$1 AND actor_user_id IN($2,$3)`, `DELETE FROM paperboat.teams WHERE team_id=$1 AND $2<>'' AND $3<>''`, `DELETE FROM paperboat.users WHERE id IN($2,$3) AND $1<>''`} {
			if _, e = tx.ExecContext(c, q, team, owner, recipient); e != nil {
				t.Error(e)
				return
			}
		}
		if _, e = tx.ExecContext(c, `ALTER TABLE paperboat.audit_events ENABLE TRIGGER audit_events_append_only`); e != nil {
			t.Error(e)
			return
		}
		if e = tx.Commit(); e != nil {
			t.Error(e)
		}
	}()
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) SELECT x,x,x||'@invalid.test','active' FROM unnest($1::text[]) x`, []string{owner, recipient}); err != nil {
		t.Fatal(err)
	}
	s := NewService(store)
	create := CreateRequest{OperationID: "create", TeamID: team}
	state, err := s.Create(ctx, owner, create)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.team_operations(account_id,operation_id,request_digest,result,created_at) SELECT $1,'bulk_'||lpad(n::text,5,'0'),decode(repeat('00',32),'hex'),convert_to('{}','UTF8'),clock_timestamp() FROM generate_series(1,$2::int) n`, owner, MaximumOperationReceipts); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.team_invitations(invitation_id,team_id,recipient_account,created_by,expires_at,cancelled_at) SELECT $1||'_history_'||lpad(n::text,5,'0'),$1,$2,$2,now()-interval '2 hours',now()-interval '1 hour'+n*interval '1 millisecond' FROM generate_series(1,$3::int) n`, team, owner, MaximumInvitationHistory+1); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.team_invitations(invitation_id,team_id,recipient_account,created_by,expires_at) VALUES($1||'_pending',$1,$2,$2,now()+interval '1 hour')`, team, owner); err != nil {
		t.Fatal(err)
	}
	request := InviteRequest{OperationID: "new_invite", ExpectedGeneration: state.Generation, AccountID: recipient}
	invitation, err := s.Invite(ctx, owner, team, request)
	if err != nil {
		t.Fatal(err)
	}
	var count, terminal, pending int
	if err = store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.team_operations WHERE account_id=$1`, owner).Scan(&count); err != nil || count != MaximumOperationReceipts {
		t.Fatal("receipt bound", count, err)
	}
	if err = store.SQL().QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE accepted_at IS NOT NULL OR cancelled_at IS NOT NULL),count(*) FILTER(WHERE accepted_at IS NULL AND cancelled_at IS NULL) FROM paperboat.team_invitations WHERE team_id=$1`, team).Scan(&terminal, &pending); err != nil || terminal != MaximumInvitationHistory || pending != 2 {
		t.Fatal("invitation bounds", terminal, pending, err)
	}
	replayed, err := s.Invite(ctx, owner, team, request)
	if err != nil || replayed.InvitationID != invitation.InvitationID {
		t.Fatal("recent exact retry lost", err)
	}
	if _, err = s.Create(ctx, owner, create); !errors.Is(err, ErrConflict) {
		t.Fatal("evicted create repeated", err)
	}
	if _, err = s.Accept(ctx, owner, team+"_history_00001", AcceptRequest{OperationID: "old_invite"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("evicted invitation became reusable", err)
	}
	_, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.team_operations(account_id,operation_id,request_digest,result) VALUES($1,'oversized',decode(repeat('00',32),'hex'),convert_to(repeat('x',$2),'UTF8'))`, owner, MaximumReceiptBytes+1)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("oversized receipt was not constraint rejected: %v", err)
	}
}
