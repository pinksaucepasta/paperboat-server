package inspectaccess

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/previewattachment"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

// TestInspectorAuthorizationPostgres proves end-to-end inspector authorization
// with five real accounts against isolated PostgreSQL: owner (by ownership),
// explicitly authorized teammate (inspect+replay), view-only teammate (use
// grant: denied both), unrelated user (denied), and revoked member (denied
// after revocation). Denials mint nothing; inspect-only credentials cannot
// replay; single-grant removal preserves the other action; generation changes
// fence outstanding credentials; expiry and machine binding fail closed.
func TestInspectorAuthorizationPostgres(t *testing.T) {
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
	owner := "usr_ia_owner_" + suffix
	mate := "usr_ia_mate_" + suffix
	viewer := "usr_ia_viewer_" + suffix
	stranger := "usr_ia_stranger_" + suffix
	exm := "usr_ia_ex_" + suffix
	team := "team_ia_" + suffix
	lease := "prv_ia_" + suffix
	operation := "op_ia_" + suffix
	session := "owner-session-ia-" + suffix
	machine := "mch_ia_" + suffix
	node := "edge-ia-" + suffix
	tunnel := "tun_ia_" + suffix
	route := "rte_ia_" + suffix
	endpoint := "https://ia-" + suffix + ".preview.example.test"
	host := "00000000-0000-8000-8000-" + suffix[len(suffix)-12:] + ".tunnels.example.test"
	now := time.Now().UTC().Truncate(time.Microsecond)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := store.SQL().ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	credentialCount := func() int {
		t.Helper()
		var n int
		if e := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.inspector_credentials`).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = store.SQL().ExecContext(c, `DELETE FROM paperboat.inspector_credentials WHERE account_id IN($1,$2,$3,$4,$5)`, owner, mate, viewer, stranger, exm)
		_, _ = store.SQL().ExecContext(c, `DELETE FROM paperboat.teams WHERE team_id=$1`, team)
		_, _ = store.SQL().ExecContext(c, `DELETE FROM paperboat.preview_leases WHERE id=$1`, lease)
		_, _ = store.SQL().ExecContext(c, `DELETE FROM paperboat.operations WHERE id=$1`, operation)
		_, _ = store.SQL().ExecContext(c, `DELETE FROM paperboat.tunnels WHERE id=$1`, tunnel)
		_, _ = store.SQL().ExecContext(c, `DELETE FROM paperboat.control_tunnel_nodes WHERE id=$1`, node)
		_, _ = store.SQL().ExecContext(c, `DELETE FROM paperboat.user_machines WHERE id=$1`, machine)
		_, _ = store.SQL().ExecContext(c, `DELETE FROM paperboat.users WHERE id IN($1,$2,$3,$4,$5)`, owner, mate, viewer, stranger, exm)
	})
	exec(`INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$1,$1||'@test.invalid','active'),($2,$2,$2||'@test.invalid','active'),($3,$3,$3||'@test.invalid','active'),($4,$4,$4||'@test.invalid','active'),($5,$5,$5||'@test.invalid','active')`, owner, mate, viewer, stranger, exm)
	key := sha256.Sum256([]byte("inspector-machine-key:" + suffix))
	publicKey := base64.RawURLEncoding.EncodeToString(key[:])
	thumbprint := sha256.Sum256(key[:])
	exec(`INSERT INTO paperboat.user_machines  (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,public_identity_key,installation_generation,worker_generation,worker_service_scope,connector_state) VALUES($1,$2,$3,$4,'linux','amd64','/workspace','online','occupied',true,$5,1,1,'system','ready')`, machine, owner, "env_ia_"+suffix, "Inspector "+suffix, publicKey)
	exec(`INSERT INTO paperboat.control_tunnel_nodes(id,edge_pool,protocol_version,process_epoch,endpoint_host,endpoint_tcp_port,endpoint_quic_port,relay_id,relay_region,relay_name,carrier_endpoint_host,carrier_endpoint_tcp_port,carrier_endpoint_quic_port,carrier_server_spki_sha256,carrier_server_certificate_chain_pem,signaling_host,stun_host,stun_port,state,ready,capacity,last_heartbeat_at) VALUES($1,'test','1.0',$2,'edge.example.test',24001,24002,$3,'test','Inspector test','edge.example.test',25001,25002,'sha256:'||repeat('b',64),'test-public-certificate-chain','edge.example.test','edge.example.test',3478,'ready',true,'{}',$4)`, node, "epoch-ia-"+suffix, "relay-ia-"+suffix, now)
	exec(`INSERT INTO paperboat.preview_leases(id,endpoint_id,endpoint,account_id,actor_id,owner_device_id,owner_session_id,target_scheme,target_address,access_mode,lease_deadline,allocation_state,edge_state,origin_state,terminal_state,created_at,last_renewed_at) VALUES($1,$2,$3,$4,$4,$5,$6,'http','127.0.0.1:3000','team',$7,'ready','ready','ready','active',$8,$8)`, lease, "pep_ia_"+suffix, endpoint, owner, machine, session, now.Add(time.Hour), now)
	operationHash := sha256.Sum256([]byte("ia-operation:" + operation))
	exec(`INSERT INTO paperboat.operations(id,account_id,idempotency_key,request_hash,operation_type,resource_kind,resource_id,phase,state,progress,retrying,outcome,correlation_id,created_at,updated_at) VALUES($1,$2,$1,$3,'preview.create','preview_lease',$4,'connecting','running',60,false,'changed',$5,$6,$6)`, operation, owner, operationHash[:], lease, "cor_"+operation, now)
	exec(`INSERT INTO paperboat.preview_lease_create_operations(account_id,preview_id,operation_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, owner, lease, operation)
	repo, err := previewattachment.NewSQLRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	request := previewattachment.Request{PreviewID: lease, OperationID: operation, OwnerDeviceID: machine, OwnerSessionID: session, IdempotencyKey: operation, RequestID: "req_" + operation, CorrelationID: "cor_" + operation}
	hash, err := request.Hash(owner)
	if err != nil {
		t.Fatal(err)
	}
	routeID := "pvc-rte-ia-" + suffix
	if _, err = repo.CreatePending(ctx, previewattachment.Attachment{
		Schema: previewattachment.Schema, Kind: previewattachment.Kind,
		Binding:        previewattachment.Binding{AccountID: owner, PreviewID: lease, OperationID: operation, OwnerDeviceID: machine, OwnerSessionID: session, HostID: machine, LeaseGeneration: 1, TunnelID: "pvc-tun-ia-" + suffix, ConnectorID: "pvc-con-ia-" + suffix, SessionID: "pvc-ses-ia-" + suffix, ProcessGeneration: 1, ConfigGeneration: 1, RouteID: routeID, RouteGeneration: 7, EdgeNodeID: node, EdgeProcessEpoch: "epoch-ia-" + suffix, EdgeCarrierServerSPKISHA256: "sha256:" + strings.Repeat("b", 64), EdgeCarrierServerCertificateChainPEM: "test-public-certificate-chain", MachineIdentityPublicKey: publicKey, MachineIdentityThumbprint: "sha256:" + base64.RawURLEncoding.EncodeToString(thumbprint[:])},
		IdempotencyKey: operation, RequestID: "req_" + operation, CorrelationID: "cor_" + operation, RequestHash: hash, Endpoint: endpoint, Target: previewattachment.Target{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "team", ConfigContentHash: "sha256:" + strings.Repeat("a", 64), EdgeEndpoints: []string{"h2://edge.example.test:25001", "h3://edge.example.test:25002"}, AttachmentGeneration: 1, IssuedAt: now, ExpiresAt: now.Add(20 * time.Minute), State: previewattachment.StatePending,
	}); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE paperboat.preview_lease_carrier_attachments SET state='ready',edge_ready=true,origin_ready=true,ready_at=$3 WHERE account_id=$1 AND preview_id=$2`, owner, lease, now)
	exec(`INSERT INTO paperboat.tunnels(id,account_id,name,desired_state,access_mode,generation,stable_endpoint_id,stable_endpoint,created_by_host_id,created_by_actor_id,created_at,updated_at) VALUES($1,$2,$1,'active','team',3,$3,$4,'host',$2,$5,$5)`, tunnel, owner, strings.TrimSuffix(host, ".tunnels.example.test"), "https://"+host, now)
	exec(`INSERT INTO paperboat.tunnel_routes(id,tunnel_id,name,protocol,match_type,origin_scheme,origin_address,generation,desired_state,created_by_actor_id,updated_by_actor_id,created_at,updated_at) VALUES($1,$2,'web','http','catch_all','http','127.0.0.1:3000',7,'active',$3,$3,$4,$4)`, route, tunnel, owner, now)
	exec(`INSERT INTO paperboat.teams(team_id,owner_account,generation) VALUES($1,$2,1)`, team, owner)
	exec(`INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true),($1,$3,1,'member',true),($1,$4,1,'member',true),($1,$5,1,'member',true)`, team, owner, mate, viewer, exm)
	exec(`INSERT INTO paperboat.team_resource_bindings(team_id,resource_kind,resource_id,owner_account,active,generation) VALUES($1,'preview',$2,$3,true,1),($1,'tunnel',$4,$3,true,1)`, team, lease, owner, tunnel)
	// The view-only teammate holds use grants: viewing must never imply
	// inspect or replay.
	exec(`INSERT INTO paperboat.team_resource_grants(team_id,account_id,resource_kind,resource_id,permission,generation,active) VALUES($1,$2,'preview',$3,'use',1,true),($1,$2,'tunnel',$4,'use',1,true)`, team, viewer, lease, tunnel)
	// One inspector grant travels the real teams issuance path (permission
	// validation, generation fencing, audit); the rest use direct fixtures.
	teamSvc := teams.NewService(store)
	var teamGen uint64
	if e := store.SQL().QueryRowContext(ctx, `SELECT generation FROM paperboat.teams WHERE team_id=$1`, team).Scan(&teamGen); e != nil {
		t.Fatal(e)
	}
	if _, err = teamSvc.Grant(ctx, owner, team, teams.GrantRequest{OperationID: "op_grant_ia_" + suffix, ExpectedGeneration: teamGen, AccountID: mate, ResourceKind: "preview", ResourceID: lease, Permission: "inspect", Active: true}); err != nil {
		t.Fatalf("teams grant inspect via API: %v", err)
	}
	exec(`INSERT INTO paperboat.team_resource_grants(team_id,account_id,resource_kind,resource_id,permission,generation,active) VALUES($1,$2,'preview',$3,'replay',1,true),($1,$2,'tunnel',$4,'inspect',1,true),($1,$2,'tunnel',$4,'replay',1,true),($1,$5,'preview',$3,'inspect',1,true)`, team, mate, lease, tunnel, exm)

	svc := NewService(store)
	svc.now = func() time.Time { return now }
	issue := func(account, kind, id, route, action string) (IssueResult, error) {
		return svc.Issue(ctx, IssueRequest{AccountID: account, ResourceKind: kind, ResourceID: id, RouteID: route, Action: action, TTL: 5 * time.Minute})
	}
	authorize := func(machine, token, kind, id, route, action string) (Decision, error) {
		return svc.Authorize(ctx, AuthorizeRequest{MachineAccount: machine, Token: token, ResourceKind: kind, ResourceID: id, RouteID: route, Action: action})
	}

	// Owner holds both actions by ownership on both resources, with the stable
	// attachment route triple and a 10-second decision.
	ownerPreview, err := issue(owner, "preview", lease, lease, "inspect")
	if err != nil {
		t.Fatalf("owner issue inspect: %v", err)
	}
	ownerDecision, err := authorize(owner, ownerPreview.Token, "preview", lease, lease, "inspect")
	if err != nil {
		t.Fatalf("owner authorize: %v", err)
	}
	if ownerDecision.AccountID != owner || ownerDecision.OwnerAccountID != owner || ownerDecision.ResourceGeneration != 7 || ownerDecision.RouteGeneration != 7 || ownerDecision.TargetGeneration != 7 || ownerDecision.ExpiresAt.Sub(now) > 10*time.Second {
		t.Fatalf("owner decision=%+v", ownerDecision)
	}
	if _, err = issue(owner, "tunnel", tunnel, route, "replay"); err != nil {
		t.Fatalf("owner issue tunnel replay: %v", err)
	}

	// Authorized teammate holds both actions on both resources.
	matePreviewReplay, err := issue(mate, "preview", lease, lease, "replay")
	if err != nil {
		t.Fatalf("mate issue replay: %v", err)
	}
	if _, err = authorize(owner, matePreviewReplay.Token, "preview", lease, lease, "replay"); err != nil {
		t.Fatalf("mate authorize replay: %v", err)
	}
	if _, err = issue(mate, "tunnel", tunnel, route, "inspect"); err != nil {
		t.Fatalf("mate issue tunnel inspect: %v", err)
	}

	// View-only teammate and unrelated user are denied without side effects.
	before := credentialCount()
	if _, err = issue(viewer, "preview", lease, lease, "inspect"); err == nil {
		t.Fatal("use-granted viewer issued inspect")
	}
	if _, err = issue(viewer, "tunnel", tunnel, route, "replay"); err == nil {
		t.Fatal("use-granted viewer issued replay")
	}
	if _, err = issue(stranger, "preview", lease, lease, "inspect"); err == nil {
		t.Fatal("unrelated user issued inspect")
	}
	if _, err = authorize(owner, "iat_forged", "preview", lease, lease, "inspect"); err == nil {
		t.Fatal("forged token authorized")
	}
	if got := credentialCount(); got != before {
		t.Fatalf("denials minted credentials: before=%d after=%d", before, got)
	}

	// Wrong selectors, wrong action and foreign machine account fail closed.
	if _, err = authorize(owner, matePreviewReplay.Token, "preview", lease, lease, "inspect"); err == nil {
		t.Fatal("replay credential authorized for inspect")
	}
	if _, err = authorize(owner, matePreviewReplay.Token, "tunnel", tunnel, route, "replay"); err == nil {
		t.Fatal("preview credential authorized for tunnel")
	}
	if _, err = authorize(stranger, matePreviewReplay.Token, "preview", lease, lease, "replay"); err == nil {
		t.Fatal("foreign machine account authorized")
	}

	// Removing one grant preserves the other action: revoke mate's preview
	// replay grant only. Outstanding replay credentials die immediately while
	// inspect (and the tunnel replay grant) keep working.
	exec(`UPDATE paperboat.team_resource_grants SET active=false,generation=generation+1 WHERE team_id=$1 AND account_id=$2 AND resource_kind='preview' AND resource_id=$3 AND permission='replay'`, team, mate, lease)
	if _, err = authorize(owner, matePreviewReplay.Token, "preview", lease, lease, "replay"); err == nil {
		t.Fatal("revoked replay credential still authorized")
	}
	if _, err = issue(mate, "preview", lease, lease, "replay"); err == nil {
		t.Fatal("revoked replay re-issued")
	}
	matePreviewInspect, err := issue(mate, "preview", lease, lease, "inspect")
	if err != nil {
		t.Fatalf("mate inspect after replay revocation: %v", err)
	}
	if _, err = authorize(owner, matePreviewInspect.Token, "preview", lease, lease, "inspect"); err != nil {
		t.Fatalf("mate inspect after replay revocation: %v", err)
	}

	// Inspect-only cannot replay: the ex-member path first proves a teammate
	// with only inspect is denied replay issuance.
	exmInspect, err := issue(exm, "preview", lease, lease, "inspect")
	if err != nil {
		t.Fatalf("exmember issue inspect: %v", err)
	}
	if _, err = issue(exm, "preview", lease, lease, "replay"); err == nil {
		t.Fatal("inspect-only member issued replay")
	}
	_ = exmInspect

	// Revoked member loses everything immediately: deactivate membership.
	exec(`UPDATE paperboat.team_members SET active=false WHERE team_id=$1 AND account_id=$2`, team, exm)
	if _, err = authorize(owner, exmInspect.Token, "preview", lease, lease, "inspect"); err == nil {
		t.Fatal("removed member credential still authorized")
	}
	if _, err = issue(exm, "preview", lease, lease, "inspect"); err == nil {
		t.Fatal("removed member re-issued")
	}

	// Generation fencing is real: bumping the tunnel route generation denies
	// outstanding credentials; fresh issuance picks up the new triple.
	mateTunnelReplay, err := issue(mate, "tunnel", tunnel, route, "replay")
	if err != nil {
		t.Fatalf("mate tunnel replay issue: %v", err)
	}
	exec(`UPDATE paperboat.tunnel_routes SET generation=generation+1 WHERE id=$1`, route)
	if _, err = authorize(owner, mateTunnelReplay.Token, "tunnel", tunnel, route, "replay"); err == nil {
		t.Fatal("stale-generation credential authorized")
	}
	fresh, err := issue(mate, "tunnel", tunnel, route, "replay")
	if err != nil {
		t.Fatalf("re-issue after generation change: %v", err)
	}
	decision, err := authorize(owner, fresh.Token, "tunnel", tunnel, route, "replay")
	if err != nil || decision.RouteGeneration != 8 {
		t.Fatalf("fresh decision=%+v err=%v", decision, err)
	}

	// Expiry fails closed, and credential revocation is holder/owner-only.
	svc.now = func() time.Time { return now.Add(6 * time.Minute) }
	if _, err = authorize(owner, fresh.Token, "tunnel", tunnel, route, "replay"); err == nil {
		t.Fatal("expired credential authorized")
	}
	svc.now = func() time.Time { return now }
	if err = svc.RevokeCredential(ctx, stranger, fresh.CredentialID); err == nil {
		t.Fatal("unrelated user revoked a credential")
	}
	if err = svc.RevokeCredential(ctx, mate, fresh.CredentialID); err != nil {
		t.Fatalf("holder revoke: %v", err)
	}
	if _, err = authorize(owner, fresh.Token, "tunnel", tunnel, route, "replay"); err == nil {
		t.Fatal("revoked credential authorized")
	}
	if _, err = svc.Cleanup(ctx, 100000); err == nil {
		t.Fatal("oversized cleanup accepted")
	}
}
