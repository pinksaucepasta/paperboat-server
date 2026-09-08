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
)

// This is live SQL composition evidence. Connector cryptography and browser
// provider login are exercised at their separate connected boundaries.
func TestBrowserPreviewIngressPostgres(t *testing.T) {
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
	defer func() {
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM sessions WHERE user_id=$1`, f.accountID)
		if _, e := database.SQL().ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, f.accountID); e != nil {
			t.Error(e)
		}
		if _, e := database.SQL().ExecContext(context.Background(), `DELETE FROM control_tunnel_nodes WHERE id=$1`, f.nodeID); e != nil {
			t.Error(e)
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
	exec(`UPDATE preview_lease_carrier_attachments SET state='ready',edge_ready=true,origin_ready=true,ready_at=now() WHERE account_id=$1 AND preview_id=$2`, f.accountID, f.previewID[0])
	session := "ses_browser_" + f.suffix
	exec(`INSERT INTO sessions(id,user_id,session_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, session, f.accountID, "fixture_hash_"+f.suffix, "csrf_"+f.suffix, now.Add(time.Hour))
	access, err := browseraccess.NewService(database, "https://login.example.test")
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(attachment.Endpoint, "https://")
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
	a, err := access.Authorize(ctx, browseraccess.AuthorizeRequest{Token: login.Token, Host: host, ResourceKind: "preview", ResourceID: attachment.PreviewID, RouteID: attachment.RouteID})
	if err != nil {
		t.Fatal(err)
	}
	ingress := browseringress.Service{DB: database, Access: access}
	d, err := ingress.Resolve(ctx, a, f.nodeID, f.epochOne)
	if err != nil {
		t.Fatal(err)
	}
	open := connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: attachment.AccountID, TunnelID: attachment.TunnelID, ConnectorID: attachment.ConnectorID, SessionID: attachment.SessionID, ProcessGeneration: attachment.ProcessGeneration, Generation: attachment.ConfigGeneration, RouteID: attachment.RouteID, RequestID: "browser-request", Kind: "http_browser"}
	if d.Authorize(d, open, f.nodeID, f.epochOne, time.Now().UTC()) != nil || d.Binding.PublicationID != attachment.PreviewID || d.Binding.OriginAddress != "127.0.0.1:3000" {
		t.Fatal("incorrect complete browser binding")
	}
	// Heartbeat revision does not change the viewer's authority dimensions.
	exec(`UPDATE preview_leases SET generation=generation+1,lease_deadline=lease_deadline+interval '1 minute' WHERE id=$1`, attachment.PreviewID)
	exec(`UPDATE preview_lease_carrier_attachments SET lease_generation=lease_generation+1,expires_at=expires_at+interval '1 minute' WHERE preview_id=$1`, attachment.PreviewID)
	a, err = access.AuthorizeGrant(ctx, d.GrantID, host, "preview", attachment.PreviewID, attachment.RouteID)
	if err != nil {
		t.Fatal(err)
	}
	next, err := ingress.Resolve(ctx, a, f.nodeID, f.epochOne)
	if err != nil {
		t.Fatal(err)
	}
	d.IssuedAt, d.ExpiresAt = next.IssuedAt, next.ExpiresAt
	if d.Authorize(next, open, f.nodeID, f.epochOne, time.Now().UTC()) != nil {
		t.Fatal("heartbeat changed browser authority")
	}
	exec(`UPDATE preview_leases SET target_address='127.0.0.1:3999' WHERE id=$1`, attachment.PreviewID)
	if _, err = access.AuthorizeGrant(ctx, d.GrantID, host, "preview", attachment.PreviewID, attachment.RouteID); err == nil {
		t.Fatal("changed preview target retained browser authority")
	}
	exec(`UPDATE preview_leases SET target_address='127.0.0.1:3000' WHERE id=$1`, attachment.PreviewID)
	exec(`UPDATE user_machines SET revoked_at=now() WHERE id=$1`, f.machineID)
	if _, err = ingress.Resolve(ctx, a, f.nodeID, f.epochOne); err == nil {
		t.Fatal("revoked machine retained browser ingress")
	}
	exec(`UPDATE user_machines SET revoked_at=NULL WHERE id=$1`, f.machineID)
	if _, err = ingress.Resolve(ctx, a, f.nodeID, f.epochTwo); err == nil {
		t.Fatal("wrong edge epoch authorized")
	}
	exec(`UPDATE sessions SET revoked_at=now() WHERE id=$1`, session)
	if _, err = access.AuthorizeGrant(ctx, d.GrantID, host, "preview", attachment.PreviewID, attachment.RouteID); err == nil {
		t.Fatal("revoked login retained viewer authority")
	}
}
