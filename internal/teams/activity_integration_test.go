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

func TestPostgresTeamActivityAuthorizationPaginationRetention(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err = db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	owner, admin, ordinary, outsider, team := "act_owner_"+suffix, "act_admin_"+suffix, "act_member_"+suffix, "act_other_"+suffix, "act_team_"+suffix
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, e := store.SQL().BeginTx(clean, nil)
		if e != nil {
			t.Error(e)
			return
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(clean, `ALTER TABLE paperboat.audit_events DISABLE TRIGGER audit_events_append_only`); e != nil {
			t.Error(e)
			return
		}
		if _, e = tx.ExecContext(clean, `DELETE FROM paperboat.audit_events WHERE resource_id=$1`, team); e != nil {
			t.Error(e)
			return
		}
		if _, e = tx.ExecContext(clean, `DELETE FROM paperboat.teams WHERE team_id=$1`, team); e != nil {
			t.Error(e)
			return
		}
		if _, e = tx.ExecContext(clean, `DELETE FROM paperboat.users WHERE id=ANY($1::text[])`, []string{owner, admin, ordinary, outsider}); e != nil {
			t.Error(e)
			return
		}
		if _, e = tx.ExecContext(clean, `ALTER TABLE paperboat.audit_events ENABLE TRIGGER audit_events_append_only`); e != nil {
			t.Error(e)
			return
		}
		if e = tx.Commit(); e != nil {
			t.Error(e)
		}
	}()
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) SELECT x,x,x||'@invalid.test','active' FROM unnest($1::text[]) x`, []string{owner, admin, ordinary, outsider}); err != nil {
		t.Fatal(err)
	}
	s := NewService(store)
	if _, err = s.Create(ctx, owner, CreateRequest{TeamID: team, OperationID: "create"}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'admin',true),($1,$3,1,'member',true)`, team, admin, ordinary); err != nil {
		t.Fatal(err)
	}
	write := func(op string, metadata map[string]any) error {
		return store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			return AuditTx(ctx, tx, owner, team, "grant", op, metadata)
		})
	}
	if err = write("grant", map[string]any{"active": true}); err != nil {
		t.Fatal(err)
	}
	if err = write("grant", map[string]any{"active": true}); err != nil {
		t.Fatal(err)
	}
	if err = write("unsafe", map[string]any{"terminal_contents": "sensitive-marker"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsafe write: %v", err)
	}
	first, err := s.Activity(ctx, owner, team, "", 1)
	if err != nil || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	if err = write("concurrent", map[string]any{"role": "viewer"}); err != nil {
		t.Fatal(err)
	}
	second, err := s.Activity(ctx, admin, team, first.NextCursor, 1)
	if err != nil || len(second.Items) != 1 || second.Items[0].Action != "create" || second.NextCursor != "" {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	if _, err = s.Activity(ctx, ordinary, team, "", 1); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary: %v", err)
	}
	if _, err = s.Activity(ctx, outsider, team, "", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("outsider: %v", err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.team_members SET active=false WHERE team_id=$1 AND account_id=$2`, team, admin); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Activity(ctx, admin, team, first.NextCursor, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed admin: %v", err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.audit_events(id,actor_user_id,actor_type,event_type,resource_type,resource_id,metadata,created_at) VALUES($1,$2,'user','team.old','team',$3,'{}',now()-interval '91 days')`, "old_"+suffix, owner, team); err != nil {
		t.Fatal(err)
	}
	page, err := s.Activity(ctx, owner, team, "", 200)
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("retained=%+v err=%v", page, err)
	}
	if _, err = store.SQL().ExecContext(ctx, `DELETE FROM paperboat.audit_events WHERE id=$1`, first.Items[0].ID); err == nil {
		t.Fatal("fresh event deleted")
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.audit_events SET metadata='{}' WHERE id=$1`, "old_"+suffix); err == nil {
		t.Fatal("expired event modified")
	}
	if _, err = s.PruneActivity(ctx); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err = store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.audit_events WHERE id=$1`, "old_"+suffix).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("expired remaining=%d err=%v", remaining, err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.teams SET deleted_at=now() WHERE team_id=$1`, team); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Activity(ctx, owner, team, "", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
}
