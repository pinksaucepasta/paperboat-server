package previewattachment

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/browseraccess"
	"github.com/pinksaucepasta/paperboat-server/internal/browseringress"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

// This is live SQL composition evidence. Connector cryptography and browser
// provider login are exercised at their separate connected boundaries.
func TestLazyBrowserIngressPostgres(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN")
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
	if os.Getenv("PAPERBOAT_TEST_SCHEMA_READY") != "1" {
		if err = db.Migrate(ctx, database); err != nil {
			t.Fatal(err)
		}
	}
	f := previewCarrierPostgresFixture{suffix: fmt.Sprint(time.Now().UnixNano())}
	now := time.Now().UTC()
	if err = f.insert(ctx, database, now); err != nil {
		t.Fatal(err)
	}
	// Immutable audit rows and their actor remain until the owning isolated test
	// database is dropped; all mutable runtime fixtures are removed here.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, item := range []struct {
			query string
			id    string
		}{
			{`DELETE FROM browser_access_transactions WHERE resource_kind='lazy_policy' AND resource_id=$1`, "lazy_" + f.suffix},
			{`DELETE FROM browser_access_sessions WHERE resource_kind='lazy_policy' AND resource_id=$1`, "lazy_" + f.suffix},
			{`DELETE FROM browser_machine_credentials WHERE resource_kind='lazy_policy' AND resource_id=$1`, "lazy_" + f.suffix},
			{`DELETE FROM teams WHERE team_id=$1`, "team_lazy_" + f.suffix},
			{`DELETE FROM users WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM audit_events WHERE actor_user_id=$1)`, "viewer_lazy_" + f.suffix},
			{`DELETE FROM lazy_activations WHERE policy_id=$1`, "lazy_" + f.suffix},
			{`DELETE FROM lazy_access_policies WHERE id=$1`, "lazy_" + f.suffix},
			{`DELETE FROM lazy_runtime_owners WHERE account_id=$1`, f.accountID},
			{`DELETE FROM sessions WHERE user_id=$1`, f.accountID},
			{`DELETE FROM preview_leases WHERE account_id=$1`, f.accountID},
			{`DELETE FROM user_machines WHERE user_id=$1`, f.accountID},
			{`DELETE FROM operations WHERE account_id=$1`, f.accountID},
			{`DELETE FROM team_operations WHERE account_id=$1`, f.accountID},
			{`DELETE FROM users WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM audit_events WHERE actor_user_id=$1)`, f.accountID},
			{`DELETE FROM control_tunnel_nodes WHERE id=$1`, f.nodeID},
		} {
			if _, err := database.SQL().ExecContext(cleanupCtx, item.query, item.id); err != nil {
				t.Error("fixture cleanup:", err)
			}
		}
	}()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := database.SQL().ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`UPDATE preview_leases SET access_mode='private' WHERE id=$1`, f.previewID[0])
	exec(`INSERT INTO machine_control_renewals(operation_id,machine_id,installation_generation,credential_jti,issued_at,expires_at,session_generation) VALUES($1,$2,1,$1,$3,$4,1)`, "renew_"+f.suffix, f.machineID, now.Add(-time.Minute), now.Add(time.Hour))
	exec(`INSERT INTO machine_control_sessions(machine_id,installation_generation,session_generation,operation_id,credential_jti,issued_at,expires_at) SELECT machine_id,installation_generation,session_generation,operation_id,credential_jti,issued_at,expires_at FROM machine_control_renewals WHERE operation_id=$1`, "renew_"+f.suffix)
	repo, _ := NewSQLRepository(database)
	attachment := f.attachment(1, f.epochOne)
	attachment.AccessMode = "private"
	if _, err = repo.CreatePending(ctx, attachment); err != nil {
		t.Fatal(err)
	}

	session := "ses_browser_" + f.suffix
	exec(`INSERT INTO sessions(id,user_id,session_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, session, f.accountID, "fixture_hash_"+f.suffix, "csrf_"+f.suffix, now.Add(time.Hour))
	access, err := browseraccess.NewService(database, "https://login.example.test")
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(attachment.Endpoint, "https://")
	policy := "lazy_" + f.suffix
	boot := "boot_lazy_" + f.suffix
	exec(`INSERT INTO lazy_access_policies(id,hostname,account_id,environment_id,machine_id,installation_generation,generation,target_scheme,target_address,access_mode,ownership_mode,expires_at) VALUES($1,$2,$3,$4,$5,1,1,'http','127.0.0.1:3000','private','persistent_port',$6)`, policy, host, f.accountID, f.envID, f.machineID, now.Add(time.Hour))
	begin, err := access.Begin(ctx, browseraccess.BeginRequest{Host: host, ReturnPath: "/app"})
	if err != nil {
		t.Fatal(err)
	}
	issue, err := access.Issue(ctx, browseraccess.IssueRequest{TransactionID: begin.TransactionID, Principal: auth.Session{ID: session, UserID: f.accountID}})
	if err != nil {
		t.Fatal(err)
	}
	login, err := access.Redeem(ctx, browseraccess.RedeemRequest{TransactionID: begin.TransactionID, State: begin.State, Handoff: issue.Handoff, Host: host})
	if err != nil {
		t.Fatal(err)
	}

	a, err := access.Authorize(ctx, browseraccess.AuthorizeRequest{Token: login.Token, Host: host, ResourceKind: "lazy_policy"})
	if err != nil || a.ResourceID != policy || a.RouteID != policy {
		t.Fatalf("dormant policy authority: %+v %v", a, err)
	}
	ingress := browseringress.Service{DB: database, Access: access}
	if _, err = ingress.Resolve(ctx, a, f.nodeID, f.epochOne); err == nil {
		t.Fatal("dormant policy forwarded")
	}
	// Neither an offline daemon nor an absent ready lease blocks authorized login.
	var activations int
	if err = database.SQL().QueryRowContext(ctx, `SELECT count(*) FROM lazy_activations WHERE policy_id=$1`, policy).Scan(&activations); err != nil || activations != 0 {
		t.Fatalf("browser lookup created activation: %d %v", activations, err)
	}
	machine, err := access.IssueMachineCredential(ctx, browseraccess.MachineCredentialRequest{AccountID: f.accountID, Host: host, ResourceKind: "lazy_policy", ResourceID: policy, RouteID: policy, Action: "use", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO lazy_runtime_owners(machine_id,account_id,installation_generation,boot_id,started_at,expires_at) VALUES($1,$2,1,$3,$4,$5)`, f.machineID, f.accountID, boot, now, now.Add(30*time.Second))
	exec(`INSERT INTO lazy_activations(policy_id,policy_generation,boot_id,activation_id,deadline,preview_id,state,cooldown_until) VALUES($1,1,$2,$3,$4,$5,'ready',$4)`, policy, boot, "activation_"+f.suffix, now.Add(10*time.Second), f.previewID[0])
	exec(`UPDATE preview_lease_carrier_attachments SET state='ready',edge_ready=true,origin_ready=true,ready_at=now() WHERE account_id=$1 AND preview_id=$2`, f.accountID, f.previewID[0])
	d, err := ingress.Resolve(ctx, a, f.nodeID, f.epochOne)
	if err != nil {
		t.Fatal(err)
	}
	if d.Binding.PublicationID != f.previewID[0] || d.Binding.RouteID != attachment.RouteID || d.PolicyGeneration != 1 {
		t.Fatalf("incorrect lazy binding: %+v", d.Binding)
	}
	open := connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: attachment.AccountID, TunnelID: attachment.TunnelID, ConnectorID: attachment.ConnectorID, SessionID: attachment.SessionID, ProcessGeneration: attachment.ProcessGeneration, Generation: attachment.ConfigGeneration, RouteID: attachment.RouteID, RequestID: "lazy-browser-request", Kind: "http_browser"}
	if err = d.Authorize(d, open, f.nodeID, f.epochOne, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []string{d.GrantID, machine.CredentialID} {
		refresh, err := access.AuthorizeGrant(ctx, grant, host, "preview", f.previewID[0], attachment.RouteID)
		if err != nil || refresh.ResourceKind != "lazy_policy" || refresh.ResourceID != policy {
			t.Fatalf("daemon reverse policy mapping: %+v %v", refresh, err)
		}
		if _, err = access.AuthorizeGrant(ctx, grant, host, "preview", f.previewID[1], attachment.RouteID); err == nil {
			t.Fatal("grant adopted another preview")
		}
		if _, err = access.AuthorizeGrant(ctx, grant, host, "preview", f.previewID[0], "wrong-route"); err == nil {
			t.Fatal("grant adopted another route")
		}
	}
	if _, err = access.IssueMachineCredential(ctx, browseraccess.MachineCredentialRequest{AccountID: f.accountID, Host: host, ResourceKind: "preview", ResourceID: f.previewID[0], RouteID: attachment.RouteID, Action: "use", TTL: time.Minute}); err == nil {
		t.Fatal("lazy lease accepted an independent explicit preview grant")
	}
	// Application target and daemon boot are independently fenced.
	exec(`UPDATE preview_leases SET target_address='127.0.0.1:3001' WHERE id=$1`, f.previewID[0])
	if _, err = access.AuthorizeGrant(ctx, d.GrantID, host, "preview", f.previewID[0], attachment.RouteID); err == nil {
		t.Fatal("changed origin accepted")
	}
	exec(`UPDATE preview_leases SET target_address='127.0.0.1:3000' WHERE id=$1`, f.previewID[0])
	exec(`UPDATE lazy_runtime_owners SET boot_id=$2 WHERE machine_id=$1`, f.machineID, boot+"new")
	if _, err = access.AuthorizeGrant(ctx, d.GrantID, host, "preview", f.previewID[0], attachment.RouteID); err == nil {
		t.Fatal("old boot grant forwarded")
	}
	if _, err = ingress.Resolve(ctx, a, f.nodeID, f.epochOne); err == nil {
		t.Fatal("old boot ingress forwarded")
	}
	exec(`UPDATE lazy_runtime_owners SET boot_id=$2 WHERE machine_id=$1`, f.machineID, boot)
	// Heartbeats retain policy identity; idle cleanup removes forwarding only.
	exec(`DELETE FROM lazy_activations WHERE policy_id=$1`, policy)
	if _, err = access.Authorize(ctx, browseraccess.AuthorizeRequest{Token: login.Token, Host: host, ResourceKind: "lazy_policy", ResourceID: policy}); err != nil {
		t.Fatal("idle cleanup revoked policy browser session:", err)
	}
	if _, err = access.AuthorizeGrant(ctx, d.GrantID, host, "preview", f.previewID[0], attachment.RouteID); err == nil {
		t.Fatal("retired lazy lease still authorized")
	}
	// Team authority must be explicit on the policy, without an active preview.
	viewer, team := "viewer_lazy_"+f.suffix, "team_lazy_"+f.suffix
	exec(`INSERT INTO users(id,workos_subject,primary_email,status) VALUES($1,$1,$1||'@example.test','active')`, viewer)
	exec(`UPDATE lazy_access_policies SET access_mode='team',generation=2 WHERE id=$1`, policy)
	exec(`INSERT INTO teams(team_id,owner_account,generation) VALUES($1,$2,1)`, team, f.accountID)
	exec(`INSERT INTO team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true),($1,$3,1,'member',true)`, team, viewer, f.accountID)
	ts := teams.NewService(database)
	state, err := ts.Attach(ctx, f.accountID, team, teams.AttachRequest{OperationID: "attach_lazy_" + f.suffix, ExpectedGeneration: 1, ResourceKind: "lazy_policy", ResourceID: policy, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	request := browseraccess.MachineCredentialRequest{AccountID: viewer, Host: host, ResourceKind: "lazy_policy", ResourceID: policy, RouteID: policy, Action: "use", TTL: time.Minute}
	if _, err = access.IssueMachineCredential(ctx, request); err == nil {
		t.Fatal("team membership without policy grant authorized")
	}
	state, err = ts.Grant(ctx, f.accountID, team, teams.GrantRequest{OperationID: "grant_lazy_" + f.suffix, ExpectedGeneration: state.Generation, AccountID: viewer, ResourceKind: "lazy_policy", ResourceID: policy, Permission: "use", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	teamMachine, err := access.IssueMachineCredential(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = access.AuthorizeMachineCredential(ctx, teamMachine.Token, host, "lazy_policy", policy, policy, "use"); err != nil {
		t.Fatal(err)
	}
	if _, err = ts.Grant(ctx, f.accountID, team, teams.GrantRequest{OperationID: "revoke_lazy_" + f.suffix, ExpectedGeneration: state.Generation, AccountID: viewer, ResourceKind: "lazy_policy", ResourceID: policy, Permission: "use", Active: false}); err != nil {
		t.Fatal(err)
	}
	if _, err = access.AuthorizeMachineCredential(ctx, teamMachine.Token, host, "lazy_policy", policy, policy, "use"); err == nil {
		t.Fatal("revoked policy grant remained authorized")
	}
	// Policy mutation and deletion deny dormant authorization too.
	if _, err = access.Authorize(ctx, browseraccess.AuthorizeRequest{Token: login.Token, Host: host, ResourceKind: "lazy_policy", ResourceID: policy}); err == nil {
		t.Fatal("old policy generation remained authorized")
	}
	// Retain a usable private old lease to prove deletion cannot fall back to
	// explicit preview authority at the reserved hostname.
	exec(`UPDATE lazy_access_policies SET access_mode='private' WHERE id=$1`, policy)
	exec(`UPDATE lazy_access_policies SET deleted_at=now() WHERE id=$1`, policy)
	if _, err = access.IssueMachineCredential(ctx, request); err == nil {
		t.Fatal("deleted policy authorized")
	}
	deletedBegin, err := access.Begin(ctx, browseraccess.BeginRequest{Host: host, ReturnPath: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = access.Issue(ctx, browseraccess.IssueRequest{TransactionID: deletedBegin.TransactionID, Principal: auth.Session{ID: session, UserID: f.accountID}}); err == nil {
		t.Fatal("deleted reserved policy fell back to preview login")
	}
}
