package previewtunnelstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestExistingSharedPreviewManagementOnPostgres(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	store, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	owner, member, team, machine := "pm_owner_"+suffix, "pm_member_"+suffix, "pm_team_"+suffix, "pm_machine_"+suffix
	defer func() {
		// Audit events are append-only and retain their actor FK. Their fixture
		// accounts remain until the isolated test database is removed.
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`DELETE FROM paperboat.user_machines WHERE id=$1`, []any{machine}},
			{`DELETE FROM paperboat.teams WHERE team_id=$1`, []any{team}},
		} {
			if _, err := database.Pool().Exec(cleanup, statement.query, statement.args...); err != nil {
				t.Errorf("clean preview management fixture: %v", err)
			}
		}
	}()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := database.Pool().Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$1,$1||'@invalid.test','active'),($2,$2,$2||'@invalid.test','active')`, owner, member)
	exec(`INSERT INTO paperboat.teams(team_id,owner_account,generation) VALUES($1,$2,1)`, team, owner)
	exec(`INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'admin',true),($1,$3,1,'member',true)`, team, owner, member)
	exec(`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,online,configured_capabilities) VALUES($1,$2,$1,$1,'linux','amd64','/workspace','online',true,ARRAY['preview_launch']::text[])`, machine, owner)
	exec(`INSERT INTO paperboat.team_resource_bindings(team_id,resource_kind,resource_id,owner_account) VALUES($1,'machine',$2,$3)`, team, machine, owner)
	exec(`INSERT INTO paperboat.team_machine_grants(team_id,machine_id,audience,account_id,capabilities) VALUES($1,$2,'selected_member',$3,ARRAY['preview_manage']::text[])`, team, machine, member)
	now := time.Now().UTC()
	created, err := store.CreatePreviewLeaseV1(ctx, CreatePreviewLeaseV1Input{
		OperationID: "op_pm_" + suffix, LeaseID: "prv_pm_" + suffix, AuditEventID: "aud_pm_" + suffix, AccountID: owner, ActorID: owner, ActorType: "user", OwnerDeviceID: machine, OwnerSessionID: "session_" + suffix,
		TargetScheme: "http", TargetAddress: "127.0.0.1:3000", AccessMode: "private", EndpointID: "pep_pm_" + suffix, Endpoint: "https://pm-" + suffix + ".preview.example.test", LeaseDeadline: now.Add(time.Minute), RequestHash: sha256Bytes(suffix), IdempotencyKey: "create_" + suffix, CorrelationID: "cor_" + suffix, RequestID: "req_" + suffix, SourceDeviceID: machine, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	account, err := store.ResolvePreviewManagementAccountV1(ctx, member, created.Lease.ID)
	if err != nil || account != owner {
		t.Fatalf("existing shared preview resolution account=%q err=%v", account, err)
	}
	rows, err := store.ListPreviewLeasesV1(ctx, ListPreviewLeasesV1Input{AccountID: member, Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].ID != created.Lease.ID {
		t.Fatalf("shared preview list count=%d err=%v", len(rows), err)
	}
	stop := StopPreviewLeaseV1Input{ManagementAccountID: member, OperationID: "op_stop_pm_" + suffix, AuditEventID: "aud_stop_pm_" + suffix, AccountID: owner, ActorID: member, ActorType: "user", PreviewID: created.Lease.ID, OwnerDeviceID: machine, OwnerSessionID: created.Lease.OwnerSessionID, ExpectedGeneration: 1, RequestHash: sha256Bytes("stop" + suffix), IdempotencyKey: "stop_" + suffix, CorrelationID: "cor_" + suffix, RequestID: "req_" + suffix, SourceDeviceID: "client_" + suffix, Now: now.Add(time.Second)}
	exec(`UPDATE paperboat.team_machine_grants SET active=false WHERE team_id=$1`, team)
	if _, err := store.StopPreviewLeaseV1(ctx, stop); !errors.Is(err, ErrNotFound) {
		t.Fatalf("withdrawn grant after resolution: %v", err)
	}
	exec(`UPDATE paperboat.team_machine_grants SET active=true WHERE team_id=$1`, team)
	exec(`UPDATE paperboat.preview_leases SET access_mode='public' WHERE id=$1`, created.Lease.ID)
	if _, err := store.ResolvePreviewManagementAccountV1(ctx, member, created.Lease.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("public management from machine grant: %v", err)
	}
	exec(`UPDATE paperboat.preview_leases SET access_mode='private' WHERE id=$1`, created.Lease.ID)
	exec(`UPDATE paperboat.user_machines SET owner_team_id=$1 WHERE id=$2`, team, machine)
	if _, err := store.ResolvePreviewManagementAccountV1(ctx, owner, created.Lease.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("team owner without use grant: %v", err)
	}
	stopped, err := store.StopPreviewLeaseV1(ctx, stop)
	if err != nil || stopped.Lease.TerminalState != "stopped" || stopped.Lease.AccountID != owner {
		t.Fatalf("shared stop state=%q err=%v", stopped.Lease.TerminalState, err)
	}
	var auditActor string
	if err := database.Pool().QueryRow(ctx, `SELECT actor_id FROM paperboat.audit_events WHERE id=$1`, stop.AuditEventID).Scan(&auditActor); err != nil || auditActor != member {
		t.Fatalf("shared stop audit actor=%q err=%v", auditActor, err)
	}
	exec(`UPDATE paperboat.team_members SET active=false WHERE team_id=$1 AND account_id=$2`, team, member)
	if _, err := store.StopPreviewLeaseV1(ctx, stop); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed member stop replay: %v", err)
	}
}
