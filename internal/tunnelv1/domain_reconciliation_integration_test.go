package tunnelv1

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/testutil"
)

type fixedDNSResolver struct {
	observation DNSObservation
	err         error
}

func (r fixedDNSResolver) Observe(context.Context, string, string, string, string) (DNSObservation, error) {
	return r.observation, r.err
}

func TestTunnelDomainDNSStateMachineOnPostgres(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run domain DNS integration")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	accountA, accountB := "usr_dns_a_"+suffix, "usr_dns_b_"+suffix
	for _, account := range []string{accountA, accountB} {
		if _, err := database.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1,$2,$3,'active')`, account, "sub_"+account, account+"@example.test"); err != nil {
			t.Fatal(err)
		}
		defer func(account string) {
			_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, account)
		}(account)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	insertTunnelRoute := func(account, tunnel, route string) {
		t.Helper()
		endpointID := testutil.EndpointUUID("domain-reconciliation:" + tunnel)
		if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.tunnels
 (id,account_id,name,stable_endpoint_id,stable_endpoint,created_by_host_id,created_by_actor_id,summary_transitioned_at,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$2,$7,$7,$7)`, tunnel, account, tunnel, endpointID, "https://"+endpointID+".tunnels.example.test", "mch_"+suffix, now); err != nil {
			t.Fatal(err)
		}
		if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.tunnel_routes
 (id,tunnel_id,name,protocol,match_type,match_hostname,origin_scheme,origin_address,created_by_actor_id,updated_by_actor_id,created_at,updated_at)
VALUES ($1,$2,'web','http','exact','app.example.test','http','127.0.0.1:3000',$3,$3,$4,$4)`, route, tunnel, account, now); err != nil {
			t.Fatal(err)
		}
	}
	tunnelA, routeA := "tun_dns_a_"+suffix, "rte_dns_a_"+suffix
	tunnelB, routeB := "tun_dns_b_"+suffix, "rte_dns_b_"+suffix
	insertTunnelRoute(accountA, tunnelA, routeA)
	insertTunnelRoute(accountB, tunnelB, routeB)

	hostname, target := "*.apps-"+suffix+".example.test", "stable.paperboat.example"
	expected := fmt.Sprintf(`[{"name":%q,"type":"CNAME","value":%q,"ttl":300}]`, hostname, target)
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.tunnel_domains
 (id,account_id,tunnel_id,route_id,hostname,match_type,ownership_challenge_reference,dns_target,
  dns_provider,expected_records,dns_next_check_at,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,'one_label_wildcard','dns-challenge://test',$6,'cloudflare',$7::jsonb,$8,$8,$8)`,
		"dom_dns_a_"+suffix, accountA, tunnelA, routeA, hostname, target, expected, now); err != nil {
		t.Fatal(err)
	}
	domainID := "dom_dns_a_" + suffix
	for _, operation := range []struct{ id, kind string }{
		{id: "op_dns_create_" + suffix, kind: "domain.create"},
		{id: "op_dns_verify_" + suffix, kind: "domain.verify"},
	} {
		if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.operations
 (id,account_id,idempotency_key,request_hash,operation_type,resource_kind,resource_id,phase,state,progress,outcome,correlation_id,created_at,updated_at)
VALUES ($1,$2,$3,decode(repeat('42',32),'hex'),$4,'domain_binding',$5,'waiting_for_dns','running',35,'changed',$6,$7,$7)`,
			operation.id, accountA, "idem_"+operation.id, operation.kind, domainID, "cor_"+operation.id, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.tunnel_domains
 (id,account_id,tunnel_id,route_id,hostname,match_type,ownership_challenge_reference,dns_target,
  dns_provider,expected_records,dns_next_check_at,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,'exact','dns-challenge://other',$6,'generic',$7::jsonb,$8,$8,$8)`,
		"dom_dns_conflict_"+suffix, accountB, tunnelB, routeB, hostname, target, expected, now); err == nil {
		t.Fatal("cross-account live hostname claim unexpectedly succeeded")
	}

	reconciler, err := NewDomainReconciler(database, fixedDNSResolver{observation: DNSObservation{Records: []string{"CNAME " + target}, TTL: 11 * time.Minute}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := reconciler.Reconcile(ctx, 10); err != nil || changed != 1 {
		t.Fatalf("reconcile = %d, %v", changed, err)
	}
	var ownership, certificate string
	var ttl, attempts int
	if err := database.SQL().QueryRowContext(ctx, `SELECT ownership_state,certificate_state,dns_ttl_seconds,verification_attempts FROM paperboat.tunnel_domains WHERE id=$1`, domainID).Scan(&ownership, &certificate, &ttl, &attempts); err != nil {
		t.Fatal(err)
	}
	if ownership != "verified" || certificate != "issuing" || ttl != 660 || attempts != 0 {
		t.Fatalf("state = %s/%s ttl=%d attempts=%d", ownership, certificate, ttl, attempts)
	}
	var createState, createPhase, verifyState, verifyPhase string
	if err := database.SQL().QueryRowContext(ctx, `SELECT state,phase FROM paperboat.operations WHERE id=$1`, "op_dns_create_"+suffix).Scan(&createState, &createPhase); err != nil {
		t.Fatal(err)
	}
	if err := database.SQL().QueryRowContext(ctx, `SELECT state,phase FROM paperboat.operations WHERE id=$1`, "op_dns_verify_"+suffix).Scan(&verifyState, &verifyPhase); err != nil {
		t.Fatal(err)
	}
	if createState != "running" || createPhase != "issuing_certificate" || verifyState != "succeeded" || verifyPhase != "ready" {
		t.Fatalf("operation lifecycle create=%s/%s verify=%s/%s", createState, createPhase, verifyState, verifyPhase)
	}
	var published int
	if err := database.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.tunnel_domains WHERE id=$1 AND ownership_state='verified' AND certificate_state='ready' AND conflict_state='clear'`, domainID).Scan(&published); err != nil || published != 0 {
		t.Fatalf("issuing domain published early count=%d error=%v", published, err)
	}

	// Transient resolver failures have a bounded grace window. They retain the
	// verified route temporarily, increment consecutive failures, and an exact
	// success resets the counter before authoritative drift is evaluated.
	for failure := 1; failure < domainDNSTransientFailureGrace; failure++ {
		failureNow := now.Add(time.Duration(failure) * time.Minute)
		if _, err := database.SQL().ExecContext(ctx, `UPDATE paperboat.tunnel_domains SET dns_next_check_at=$2 WHERE id=$1`, domainID, failureNow); err != nil {
			t.Fatal(err)
		}
		transient, err := NewDomainReconciler(database, fixedDNSResolver{observation: DNSObservation{FailureCode: "dns_unavailable"}, err: context.DeadlineExceeded}, func() time.Time { return failureNow })
		if err != nil {
			t.Fatal(err)
		}
		if changed, err := transient.Reconcile(ctx, 10); err != nil || changed != 1 {
			t.Fatalf("transient reconcile %d = %d, %v", failure, changed, err)
		}
		if err := database.SQL().QueryRowContext(ctx, `SELECT ownership_state,verification_attempts FROM paperboat.tunnel_domains WHERE id=$1`, domainID).Scan(&ownership, &attempts); err != nil {
			t.Fatal(err)
		}
		if ownership != "verified" || attempts != failure {
			t.Fatalf("transient %d state=%s attempts=%d", failure, ownership, attempts)
		}
	}
	recoveryNow := now.Add(domainDNSTransientFailureGrace * time.Minute)
	if _, err := database.SQL().ExecContext(ctx, `UPDATE paperboat.tunnel_domains SET dns_next_check_at=$2 WHERE id=$1`, domainID, recoveryNow); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewDomainReconciler(database, fixedDNSResolver{observation: DNSObservation{Records: []string{"CNAME " + target}, TTL: 11 * time.Minute}}, func() time.Time { return recoveryNow })
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := recovered.Reconcile(ctx, 10); err != nil || changed != 1 {
		t.Fatalf("recovery reconcile = %d, %v", changed, err)
	}
	if err := database.SQL().QueryRowContext(ctx, `SELECT ownership_state,verification_attempts FROM paperboat.tunnel_domains WHERE id=$1`, domainID).Scan(&ownership, &attempts); err != nil || ownership != "verified" || attempts != 0 {
		t.Fatalf("recovery state=%s attempts=%d error=%v", ownership, attempts, err)
	}

	// A later authoritative wrong target withdraws the domain immediately while
	// retaining its last successful verification timestamp for diagnostics.
	driftNow := recoveryNow.Add(time.Minute)
	if _, err := database.SQL().ExecContext(ctx, `UPDATE paperboat.tunnel_domains SET dns_next_check_at=$2 WHERE id=$1`, domainID, driftNow); err != nil {
		t.Fatal(err)
	}
	drifted, err := NewDomainReconciler(database, fixedDNSResolver{observation: DNSObservation{Records: []string{"CNAME attacker.example"}, FailureCode: "wrong_record", TTL: 11 * time.Minute}}, func() time.Time { return driftNow })
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := drifted.Reconcile(ctx, 10); err != nil || changed != 1 {
		t.Fatalf("drift reconcile = %d, %v", changed, err)
	}
	var lastVerified time.Time
	var conflict string
	if err := database.SQL().QueryRowContext(ctx, `SELECT ownership_state,conflict_state,last_verified_at FROM paperboat.tunnel_domains WHERE id=$1`, domainID).Scan(&ownership, &conflict, &lastVerified); err != nil {
		t.Fatal(err)
	}
	if ownership != "failed" || conflict != "conflicted" || !lastVerified.Equal(recoveryNow) {
		t.Fatalf("drift state=%s/%s last_verified_at=%s want=%s", ownership, conflict, lastVerified, recoveryNow)
	}

	// The exact child is a distinct claim and is allowed to prove control on its
	// own. It does not inherit ownership from the verified wildcard.
	exactHost := "child.apps-" + suffix + ".example.test"
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.tunnel_domains
 (id,account_id,tunnel_id,route_id,hostname,match_type,ownership_challenge_reference,dns_target,
  dns_provider,expected_records,dns_next_check_at,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,'exact','dns-challenge://child',$6,'generic',$7::jsonb,$8,$8,$8)`,
		"dom_dns_child_"+suffix, accountB, tunnelB, routeB, exactHost, target,
		fmt.Sprintf(`[{"name":%q,"type":"CNAME","value":%q,"ttl":300}]`, exactHost, target), now); err != nil {
		t.Fatal(err)
	}
	var childState string
	if err := database.SQL().QueryRowContext(ctx, `SELECT ownership_state FROM paperboat.tunnel_domains WHERE id=$1`, "dom_dns_child_"+suffix).Scan(&childState); err != nil || childState != "pending" {
		t.Fatalf("exact child state = %q, %v", childState, err)
	}
}
