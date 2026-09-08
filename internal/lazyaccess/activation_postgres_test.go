package lazyaccess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
)

type canceledLazyDispatch struct {
	entered  chan string
	canceled chan struct{}
}

func (d *canceledLazyDispatch) Dispatch(ctx context.Context, r previewv1.DispatchRequest) (previewv1.DispatchOutcome, error) {
	d.entered <- r.PreviewID
	<-ctx.Done()
	close(d.canceled)
	return previewv1.DispatchOutcome{}, ctx.Err()
}

type acceptedLazyDispatch struct{}

func (acceptedLazyDispatch) Dispatch(_ context.Context, r previewv1.DispatchRequest) (previewv1.DispatchOutcome, error) {
	return previewv1.DispatchOutcome{Schema: previewv1.Schema, Kind: previewv1.PreviewDispatchKind, PreviewID: r.PreviewID, OperationID: r.OperationID, State: "accepted", Generation: r.ExpectedGeneration}, nil
}

func TestActivationPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	other, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if os.Getenv("PAPERBOAT_TEST_SCHEMA_READY") != "1" {
		if err = db.Migrate(ctx, database); err != nil {
			t.Fatal(err)
		}
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	owner, machine, environment := "usr_lazact_"+suffix, "machine_lazact_"+suffix, "env_lazact_"+suffix
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := database.SQL().ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, q := range []string{
			`DELETE FROM lazy_activations WHERE policy_id IN (SELECT id FROM lazy_access_policies WHERE account_id=$1)`,
			`DELETE FROM lazy_access_policies WHERE account_id=$1`,
			`DELETE FROM lazy_runtime_owners WHERE account_id=$1`,
			`DELETE FROM lazy_environment_identities WHERE environment_id IN (SELECT environment_id FROM user_machines WHERE user_id=$1)`,
			`DELETE FROM preview_leases WHERE account_id=$1`,
			`DELETE FROM user_machines WHERE user_id=$1`,
			`DELETE FROM operations WHERE account_id=$1`,
			`DELETE FROM users WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM audit_events WHERE actor_user_id=$1)`,
		} {
			if _, err := database.SQL().ExecContext(cleanup, q, owner); err != nil {
				t.Error("cleanup:", err)
			}
		}
	}()
	exec(`INSERT INTO users(id,workos_subject,primary_email,status) VALUES($1,$1,$1||'@example.test','active')`, owner)
	exec(`INSERT INTO user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation) VALUES($1,$2,$3,$1,'linux','amd64','/workspace','online','occupied',true,1)`, machine, owner, environment)
	policies, err := NewService(database, "preview.example.test")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policies.Upsert(ctx, owner, UpsertRequest{MachineID: machine, Target: Target{Scheme: "http", Address: "127.0.0.1:3300"}, AccessMode: "private", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	first, second := &Activator{DB: database}, &Activator{DB: other}
	req := ActivationRequest{PolicyID: p.ID, OwnerAccountID: owner, PolicyGeneration: p.Generation, AuthorityDeadline: time.Now().Add(5 * time.Minute), Check: func(context.Context) error { return nil }}
	if _, err = first.claim(ctx, req, "offline"); !activationCode(err, "host_offline") {
		t.Fatalf("offline: %v", err)
	}
	started := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	observation := RuntimeObservation{Schema: "paperboat.lazy-runtime/v1", BootID: "boot_lazy_activation_" + suffix, InstallationGeneration: 1, StartedAt: started}
	if err = first.RecordLazyRuntimeObservation(ctx, environment, machine, observation); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE user_machines SET online=false WHERE id=$1`, machine)
	if _, err = first.claim(ctx, req, "offline_registered_"+suffix); !activationCode(err, "host_offline") {
		t.Fatalf("registered offline machine: %v", err)
	}
	exec(`UPDATE user_machines SET online=true WHERE id=$1`, machine)
	mutated := observation
	mutated.StartedAt = started.Add(time.Millisecond)
	if err = first.RecordLazyRuntimeObservation(ctx, environment, machine, mutated); !errors.Is(err, ErrConflict) {
		t.Fatalf("same boot changed start: %v", err)
	}
	var wg sync.WaitGroup
	claims := make(chan activationClaim, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := first
			if i%2 == 1 {
				owner = second
			}
			c, e := owner.claim(ctx, req, fmt.Sprintf("waiter_%s_%d", suffix, i))
			claims <- c
			errs <- e
		}(i)
	}
	wg.Wait()
	close(claims)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	leaders := 0
	var claim activationClaim
	for c := range claims {
		if claim.id != "" && c.id != claim.id {
			t.Fatal("concurrent servers created separate activations")
		}
		if c.leader {
			leaders++
		}
		claim = c
	}
	if leaders != 1 {
		t.Fatalf("leaders=%d", leaders)
	}
	exec(`WITH refreshed AS (UPDATE lazy_activations SET deadline=now()+interval '10 seconds' WHERE activation_id=$1) UPDATE lazy_activation_waiters SET expires_at=now()+interval '10 seconds' WHERE activation_id=$1`, claim.id)
	exec(`INSERT INTO lazy_activation_waiters(waiter_id,activation_id,expires_at) SELECT 'bounded_'||$2||'_'||n,$1,now()+interval '10 seconds' FROM generate_series(1,30) n`, claim.id, suffix)
	if _, err = second.claim(ctx, req, "overflow_"+suffix); !errors.Is(err, ErrCapacity) {
		t.Fatalf("waiter bound: %v", err)
	}
	if !first.current(ctx, claim) {
		t.Fatal("current activation denied")
	}
	exec(`DELETE FROM lazy_activation_waiters WHERE activation_id=$1`, claim.id)
	if first.current(ctx, claim) {
		t.Fatal("activation survived last waiter")
	}
	exec(`UPDATE lazy_activations SET state='failed',error_code='origin_unavailable',cooldown_until=now()+interval '2 seconds' WHERE policy_id=$1`, p.ID)
	if _, err = first.claim(ctx, req, "cooldown_"+suffix); !activationCode(err, "activation_cooldown") {
		t.Fatalf("cooldown: %v", err)
	}
	newer := observation
	newer.BootID += "new"
	newer.StartedAt = started.Add(time.Millisecond)
	if err = first.RecordLazyRuntimeObservation(ctx, environment, machine, newer); err != nil {
		t.Fatal(err)
	}
	if err = first.RecordLazyRuntimeObservation(ctx, environment, machine, observation); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale boot restored: %v", err)
	}
	replacement, err := first.claim(ctx, req, "replacement_"+suffix)
	if err != nil || !replacement.leader || replacement.id == claim.id {
		t.Fatalf("new boot did not invalidate cooldown: %+v %v", replacement, err)
	}
	if first.current(ctx, claim) {
		t.Fatal("old activation survived boot replacement")
	}
	// Construct capacity rows together so a forwarded test DB's round trips
	// cannot expire earlier slots while fixture policies are being created.
	for i := 0; i < 3; i++ {
		if _, err = policies.Upsert(ctx, owner, UpsertRequest{MachineID: machine, Target: Target{Scheme: "http", Address: fmt.Sprintf("127.0.0.1:%d", 3301+i)}, AccessMode: "private", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	overflow, err := policies.Upsert(ctx, owner, UpsertRequest{MachineID: machine, Target: Target{Scheme: "http", Address: "127.0.0.1:3305"}, AccessMode: "private", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err = first.RecordLazyRuntimeObservation(ctx, environment, machine, newer); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE lazy_activations SET deadline=now()+interval '10 seconds' WHERE policy_id=$1`, p.ID)
	exec(`INSERT INTO lazy_activations(policy_id,policy_generation,boot_id,activation_id,deadline,state,cooldown_until) SELECT id,generation,$2,'capacity_'||id,now()+interval '10 seconds','running',now() FROM lazy_access_policies WHERE account_id=$1 AND id NOT IN ($3,$4)`, owner, newer.BootID, p.ID, overflow.ID)
	overflowReq := req
	overflowReq.PolicyID = overflow.ID
	if _, err = first.claim(ctx, overflowReq, "env_overflow_"+suffix); !errors.Is(err, ErrCapacity) {
		t.Fatalf("environment activation bound: %v", err)
	}
	exec(`DELETE FROM lazy_activations WHERE policy_id IN (SELECT id FROM lazy_access_policies WHERE account_id=$1)`, owner)
	// A real persisted lease and dispatch are canceled when the final HTTP waiter
	// leaves. The fixture only replaces the remote dispatch, not lease creation,
	// transaction ownership, cancellation or lease cleanup.
	store, err := previewtunnelstore.New(database)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &canceledLazyDispatch{entered: make(chan string, 1), canceled: make(chan struct{})}
	leases, err := previewv1.NewService(store, previewv1.Config{EndpointDomain: "preview.example.test", CursorKey: make([]byte, 32), Dispatcher: dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	first.Leases = leases
	if err = first.RecordLazyRuntimeObservation(ctx, environment, machine, newer); err != nil {
		t.Fatal(err)
	}
	requestCtx, requestCancel := context.WithCancel(ctx)
	defer requestCancel()
	returned := make(chan error, 1)
	go func() { _, err := first.Activate(requestCtx, req); returned <- err }()
	var preview string
	select {
	case preview = <-dispatcher.entered:
	case e := <-returned:
		t.Fatalf("activation ended before dispatch: %v", e)
	case <-time.After(ActivationTimeout + time.Second):
		t.Fatal("dispatch not reached within activation deadline")
	}
	var userDeadline time.Time
	if err = database.SQL().QueryRowContext(ctx, `SELECT user_deadline FROM preview_leases WHERE id=$1`, preview).Scan(&userDeadline); err != nil {
		t.Fatal(err)
	}
	if userDeadline.After(req.AuthorityDeadline.Add(time.Microsecond)) {
		t.Fatal("lease outlived initiating authority")
	}
	requestCancel()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled request retained waiter")
	}
	select {
	case <-dispatcher.canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("last waiter did not cancel dispatch")
	}
	cleanupDeadline := time.Now().Add(8 * time.Second)
	for {
		var active bool
		if err = database.SQL().QueryRowContext(ctx, `SELECT terminal_state='active' FROM preview_leases WHERE id=$1`, preview).Scan(&active); err != nil {
			t.Fatal(err)
		}
		var state string
		if err = database.SQL().QueryRowContext(ctx, `SELECT state FROM lazy_activations WHERE policy_id=$1`, p.ID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if !active && state == "failed" {
			break
		}
		if time.Now().After(cleanupDeadline) {
			t.Fatalf("canceled lease leaked: active=%v activation=%s", active, state)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
	// Existing lease reconciliation revokes a current lazy lease after policy
	// change even when no viewer stream is available to drive an auth refresh.
	if err = first.RecordLazyRuntimeObservation(ctx, environment, machine, newer); err != nil {
		t.Fatal(err)
	}
	leases.ConfigureDispatcher(acceptedLazyDispatch{})
	authority := previewtunnelapi.RequestContext{Actor: previewtunnelapi.Actor{AccountID: owner, ActorID: owner, Role: "user", Scopes: []string{"previews:read", "previews:write"}}, RequestID: "reconcile_" + suffix, CorrelationID: "reconcile_" + suffix}
	end := time.Now().UTC().Add(5 * time.Minute)
	created, err := leases.Create(ctx, authority, previewv1.CreateRequest{OwnerDeviceID: machine, OwnerSessionID: "lazy_" + newer.BootID, Target: previewv1.Target{Scheme: p.Target.Scheme, Address: p.Target.Address}, AccessMode: p.AccessMode, ExpiresAt: &end, IdempotencyKey: "reconcile_" + suffix, ReservedEndpoint: "https://" + p.Hostname, Lazy: &previewv1.LazyBinding{PolicyID: p.ID, PolicyGeneration: p.Generation, InstallationGeneration: p.InstallationGeneration, BootID: newer.BootID}})
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE lazy_activations SET state='ready',preview_id=$2,policy_generation=$3,boot_id=$4 WHERE policy_id=$1`, p.ID, created.Preview.ID, p.Generation, newer.BootID)
	if _, err = leases.Reconcile(ctx, "task27_fixture", "reconcile_current_"+suffix, "reconcile_current_"+suffix); err != nil {
		t.Fatal(err)
	}
	current, err := leases.Get(ctx, authority, created.Preview.ID)
	if err != nil || current.Preview.State == "owner_disconnected" {
		t.Fatalf("current lazy lease falsely revoked: %+v %v", current.Preview, err)
	}
	exec(`UPDATE lazy_access_policies SET generation=generation+1 WHERE id=$1`, p.ID)
	if _, err = leases.Reconcile(ctx, "task27_fixture", "reconcile_revoked_"+suffix, "reconcile_revoked_"+suffix); err != nil {
		t.Fatal(err)
	}
	current, err = leases.Get(ctx, authority, created.Preview.ID)
	if err != nil || current.Preview.State != "owner_disconnected" {
		t.Fatalf("policy revoke left lease alive: %+v %v", current.Preview, err)
	}

}
func activationCode(err error, code string) bool {
	var state *ActivationError
	return errors.As(err, &state) && state.Code == code
}
