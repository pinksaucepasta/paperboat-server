package lazyaccess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestPolicyPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if os.Getenv("PAPERBOAT_TEST_SCHEMA_READY") != "1" {
		if err = db.Migrate(ctx, store); err != nil {
			t.Fatal(err)
		}
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	owner := "usr_lazy_" + suffix
	machine := "mach_lazy_" + suffix
	environment := "env_lazy_" + suffix
	now := time.Now().UTC().Truncate(time.Microsecond)
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.lazy_access_policies WHERE account_id=$1`, owner)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.lazy_environment_identities WHERE environment_id=$1`, environment)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.user_machines WHERE id=$1`, machine)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=$1`, owner)
	})
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$1,$1||'@test.invalid','active')`, owner); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,installation_generation) VALUES($1,$2,$3,$1,'linux','amd64','/workspace','online','occupied',4)`, machine, owner, environment); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(store, "preview.example.test")
	if err != nil {
		t.Fatal(err)
	}
	svc.now = func() time.Time { return now }
	in := UpsertRequest{MachineID: machine, Target: Target{Scheme: "http", Address: "127.0.0.1:3210"}, AccessMode: "private", ExpiresAt: now.Add(time.Hour)}
	p, err := svc.Upsert(ctx, owner, in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.Hostname, "p3210-") || p.InstallationGeneration != 4 || p.Generation != 1 {
		t.Fatalf("policy=%#v", p)
	}
	if got, err := svc.Get(ctx, owner, p.ID); err != nil || got.Hostname != p.Hostname {
		t.Fatalf("get=%#v err=%v", got, err)
	}
	svc.now = func() time.Time { return now.Add(2 * time.Hour) }
	if got, err := svc.Get(ctx, owner, p.ID); err != nil || got.Hostname != p.Hostname {
		t.Fatalf("expired reservation is not inspectable: %v", err)
	}
	svc.now = func() time.Time { return now }
	in.ID = p.ID
	in.ExpectedGeneration = 1
	in.AccessMode = "team"
	in.Target.Scheme = "https"
	updated, err := svc.Upsert(ctx, owner, in)
	if err != nil || updated.Generation != 2 || updated.Target.Scheme != "https" {
		t.Fatalf("update=%#v err=%v", updated, err)
	}
	if _, err = svc.Upsert(ctx, owner, in); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update err=%v", err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET installation_generation=5 WHERE id=$1`, machine); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Get(ctx, owner, p.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("old installation remained approved: %v", err)
	}
	in.ExpectedGeneration = 2
	reapproved, err := svc.Upsert(ctx, owner, in)
	if err != nil || reapproved.Generation != 3 || reapproved.InstallationGeneration != 5 || reapproved.Hostname != p.Hostname {
		t.Fatalf("reapproval=%#v err=%v", reapproved, err)
	}
	if err = svc.Delete(ctx, owner, p.ID, 3); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Get(ctx, owner, p.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("tombstone get err=%v", err)
	}
	var retained int
	if err = store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.lazy_access_policies WHERE id=$1 AND deleted_at IS NOT NULL`, p.ID).Scan(&retained); err != nil || retained != 1 {
		t.Fatalf("tombstone=%d err=%v", retained, err)
	}
}
