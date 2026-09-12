package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

// TestTask43ServeTerminalJoinLifecycle is an opt-in producer for the native
// attachment fixture. It serves only the production runtime-observation
// handler on an ephemeral loopback listener; coordination and credentials use
// private files in PAPERBOAT_TASK43_DIR.
func TestTask43ServeTerminalJoinLifecycle(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("PAPERBOAT_TASK43_DIR"))
	if directory == "" {
		t.Skip("Task 43 terminal join fixture is opt-in")
	}
	if !filepath.IsAbs(directory) {
		t.Fatal("PAPERBOAT_TASK43_DIR must be absolute")
	}
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	owner, member := "task43_join_owner_"+suffix, "task43_join_member_"+suffix
	teamID, machineID := "task43_join_team_"+suffix, "task43_join_machine_"+suffix
	terminalID, accessID, environmentID := "task43_join_terminal_"+suffix, "task43_join_access_"+suffix, "task43_join_environment_"+suffix
	clientID := "task43_join_client_" + suffix
	defer func() {
		clean, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		tx, cleanErr := database.SQL().BeginTx(clean, nil)
		if cleanErr != nil {
			t.Error(cleanErr)
			return
		}
		defer tx.Rollback()
		for _, item := range []struct {
			query string
			args  []any
		}{
			{`ALTER TABLE paperboat.audit_events DISABLE TRIGGER audit_events_append_only`, nil},
			{`DELETE FROM paperboat.audit_events WHERE resource_id=$1 OR actor_user_id=ANY($2::text[])`, []any{teamID, []string{owner, member}}},
			{`DELETE FROM paperboat.user_machine_access_sessions WHERE id=$1`, []any{accessID}},
			{`DELETE FROM paperboat.teams WHERE team_id=$1`, []any{teamID}},
			{`DELETE FROM paperboat.user_machine_terminal_sessions WHERE id=$1`, []any{terminalID}},
			{`DELETE FROM paperboat.user_machines WHERE id=$1`, []any{machineID}},
			{`DELETE FROM paperboat.control_environments WHERE id=$1`, []any{environmentID}},
			{`DELETE FROM paperboat.team_operations WHERE account_id=ANY($1::text[])`, []any{[]string{owner, member}}},
			{`DELETE FROM paperboat.users WHERE id=ANY($1::text[])`, []any{[]string{owner, member}}},
			{`ALTER TABLE paperboat.audit_events ENABLE TRIGGER audit_events_append_only`, nil},
		} {
			if _, cleanErr = tx.ExecContext(clean, item.query, item.args...); cleanErr != nil {
				t.Error(cleanErr)
				return
			}
		}
		if cleanErr = tx.Commit(); cleanErr != nil {
			t.Error(cleanErr)
		}
	}()
	cleanupFiles := []string{"fixture.json", "fixture.json.tmp", "joined", "fail", "done", "stop"}
	defer func() {
		for _, name := range cleanupFiles {
			_ = os.Remove(filepath.Join(directory, name))
		}
	}()
	for _, item := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.users(id,workos_subject,primary_email,status) SELECT x,x,x||'@invalid.test','active' FROM unnest($1::text[]) x`, []any{[]string{owner, member}}},
		{`INSERT INTO paperboat.control_environments(id,workspace_id,owner_user_id) VALUES($1,$1,$2)`, []any{environmentID, owner}},
		{`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,configured_capabilities,observed_capabilities,machine_kind) VALUES($1,$2,$3,'task43 join','linux','amd64','/workspace','online','occupied',true,ARRAY['terminal_host'],ARRAY['terminal_host'],'hosted')`, []any{machineID, owner, environmentID}},
		{`INSERT INTO paperboat.user_machine_terminal_sessions(id,user_machine_id,terminal_id,name,owner_account,launch_cwd) VALUES($1,$2,$1,'task43-join',$3,'/workspace')`, []any{terminalID, machineID, owner}},
	} {
		if _, err := database.SQL().ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	writer := audit.NewWriter(database)
	teamService := teams.NewService(database)
	state, err := teamService.Create(ctx, owner, teams.CreateRequest{TeamID: teamID, OperationID: "task43-create"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.SQL().ExecContext(ctx, `INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true)`, teamID, member); err != nil {
		t.Fatal(err)
	}
	if _, err := teamService.GrantTerminalSession(ctx, owner, teamID, teams.TerminalSessionGrantRequest{OperationID: "task43-grant", ExpectedGeneration: state.Generation, TerminalSessionID: terminalID, RuntimeGeneration: 1, Audience: "all_members", Role: "viewer", Active: true}); err != nil {
		t.Fatal(err)
	}
	decision, err := teamService.ResolveTerminalSession(ctx, member, terminalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_access_sessions(id,user_machine_id,user_id,environment_id,cli_client_session_id,http_base_url,helper_terminal_session_id,capabilities,operation_id,expires_at,team_id,terminal_session_id,terminal_role,terminal_grant_generation,terminal_binding_generation,terminal_membership_generation,terminal_team_generation) VALUES($1,$2,$3,$4,$5,'http://127.0.0.1',$6,ARRAY[]::text[],$6,now()+interval '3 minutes',$7,$6,'viewer',$8,$9,$10,$11)`, accessID, machineID, member, environmentID, clientID, terminalID, teamID, decision.GrantGeneration, decision.BindingGeneration, decision.MembershipGeneration, decision.TeamGeneration); err != nil {
		t.Fatal(err)
	}
	signer, err := mint.NewEphemeral(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://127.0.0.1"
	enrollment := controlplane.NewEnrollmentService(database, signer, writer, issuer, "task43-terminal-join-encryption-key")
	grant, err := enrollment.Issue(ctx, owner, "task43-enroll", environmentID, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	proofPrivate := ed25519.NewKeyFromSeed([]byte(strings.Repeat("j", ed25519.SeedSize)))
	identity, err := enrollment.Exchange(ctx, grant.Credential, proofPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	machines := usermachines.New(database, writer, usermachines.Policy{}, nil)
	handler := runtimeObservation(metering.NewRuntimeRepository(database, "task43-terminal-join-encryption-key"), enrollment, 10, machines)
	server := httptest.NewServer(handler)
	defer server.Close()
	fixture := struct {
		Endpoint               string `json:"endpoint"`
		EnvironmentID          string `json:"environment_id"`
		MachineID              string `json:"machine_id"`
		AccessSessionID        string `json:"access_session_id"`
		TerminalSessionID      string `json:"terminal_session_id"`
		ActorAccount           string `json:"actor_account"`
		ClientID               string `json:"client_id"`
		IdentityToken          string `json:"identity_token"`
		ProofPrivateKeyBase64  string `json:"proof_private_key_base64"`
		ProofHelperID          string `json:"proof_helper_id"`
		InstallationGeneration int64  `json:"installation_generation"`
	}{server.URL + "/v1/runtime-observations", environmentID, machineID, accessID, terminalID, member, clientID, identity.Credential, base64.RawURLEncoding.EncodeToString(proofPrivate), identity.HelperID, 1}
	encoded, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	temporary, final := filepath.Join(directory, "fixture.json.tmp"), filepath.Join(directory, "fixture.json")
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, final); err != nil {
		t.Fatal(err)
	}
	waitTask43Marker(t, ctx, directory, "joined")
	assertTask43JoinAudit(t, database, teamID, member, 1)
	triggerTag := suffix[len(suffix)-12:]
	functionName, triggerName := "reject_task43_join_"+triggerTag, "reject_task43_join_trigger_"+triggerTag
	if _, err := database.SQL().ExecContext(ctx, `CREATE FUNCTION paperboat.`+functionName+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'intentional terminal join audit failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = database.SQL().ExecContext(context.Background(), `DROP TRIGGER IF EXISTS `+triggerName+` ON paperboat.audit_events`)
		_, _ = database.SQL().ExecContext(context.Background(), `DROP FUNCTION IF EXISTS paperboat.`+functionName+`()`)
	}()
	if _, err := database.SQL().ExecContext(ctx, `CREATE TRIGGER `+triggerName+` BEFORE INSERT ON paperboat.audit_events FOR EACH ROW WHEN (NEW.resource_id='`+teamID+`' AND NEW.event_type='team.terminal_session_joined') EXECUTE FUNCTION paperboat.`+functionName+`()`); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "fail"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	waitTask43Marker(t, ctx, directory, "done")
	assertTask43JoinAudit(t, database, teamID, member, 1)
	var leaked int
	if err := database.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.audit_events WHERE resource_id=$1 AND metadata::text ~* '(terminal_content|keystroke|replay_content|private_key|identity_token)'`, teamID).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("sensitive audit metadata count=%d error=%v", leaked, err)
	}
}

func waitTask43Marker(t *testing.T, ctx context.Context, directory, name string) {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(filepath.Join(directory, "stop")); err == nil {
			t.Fatalf("consumer stopped before %s", name)
		}
		if _, err := os.Stat(filepath.Join(directory, name)); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %s: %v", name, ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertTask43JoinAudit(t *testing.T, database *db.DB, teamID, actor string, want int) {
	t.Helper()
	var count int
	var gotActor string
	if err := database.SQL().QueryRow(`SELECT count(*),coalesce(min(actor_user_id),'') FROM paperboat.audit_events WHERE resource_id=$1 AND event_type='team.terminal_session_joined'`, teamID).Scan(&count, &gotActor); err != nil || count != want || gotActor != actor {
		t.Fatalf("join audit count=%d actor=%q error=%v", count, gotActor, err)
	}
}
