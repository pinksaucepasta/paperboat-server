package controlplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestRouteIntentOwnershipAndRevisionCAS(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_") + time.Now().Format("150405.000000000")
	owner, other, environmentID := "route_owner_"+suffix, "route_other_"+suffix, "route_env_"+suffix
	for _, user := range []string{owner, other} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, user, "workos_"+user, user+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3)`, environmentID, "workspace_"+suffix, owner); err != nil {
		t.Fatal(err)
	}
	service := NewRouteService(store, nil)
	route, err := service.Create(ctx, owner, "route-create-01", environmentID, "preview_public_https_wss", "Preview.Example.Test.", "127.0.0.1", 8080)
	if err != nil || route.PublicHost != "preview.example.test" || route.DesiredRevision != 1 {
		t.Fatalf("route = %#v, %v", route, err)
	}
	replay, err := service.Create(ctx, owner, "route-create-01", environmentID, "preview_public_https_wss", "Preview.Example.Test.", "127.0.0.1", 8080)
	if err != nil || replay.ID != route.ID {
		t.Fatalf("create replay = %#v, %v", replay, err)
	}
	if _, err := service.Create(ctx, owner, "route-create-01", environmentID, "helper_https_wss", "other.example.test", "127.0.0.1", 8080); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("create conflict = %v", err)
	}
	if _, err := service.Transition(ctx, other, "route-transition-other", route.ID, "detaching", 1); !errors.Is(err, ErrRouteDenied) {
		t.Fatalf("cross-owner transition = %v", err)
	}
	detaching, err := service.Transition(ctx, owner, "route-transition-01", route.ID, "detaching", 1)
	if err != nil || detaching.DesiredRevision != 2 {
		t.Fatalf("detaching = %#v, %v", detaching, err)
	}
	replayedTransition, err := service.Transition(ctx, owner, "route-transition-01", route.ID, "detaching", 1)
	if err != nil || replayedTransition.DesiredRevision != 2 {
		t.Fatalf("transition replay = %#v, %v", replayedTransition, err)
	}
	if _, err := service.Transition(ctx, owner, "route-transition-02", route.ID, "detached", 1); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("stale transition = %v", err)
	}
}

func TestRouteIntentConcurrentExactCreateReplaysOneResult(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_") + time.Now().Format("150405.000000000")
	user, environmentID := "route_concurrent_"+suffix, "route_concurrent_env_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, user, "workos_"+user, user+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3)`, environmentID, "workspace_"+suffix, user); err != nil {
		t.Fatal(err)
	}
	service := NewRouteService(store, nil)
	results := make(chan dbsqlc.ControlRoute, 2)
	errs := make(chan error, 2)
	var group sync.WaitGroup
	operationKey := "route-concurrent-op-" + suffix
	publicHost := "concurrent-" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "") + ".example.test"
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			route, err := service.Create(ctx, user, operationKey, environmentID, "preview_public_https_wss", publicHost, "127.0.0.1", 8080)
			results <- route
			errs <- err
		}()
	}
	group.Wait()
	close(results)
	close(errs)
	var first dbsqlc.ControlRoute
	for route := range results {
		if first.ID == "" {
			first = route
		} else if route.ID != first.ID {
			t.Fatalf("concurrent route IDs = %q and %q", first.ID, route.ID)
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent create error = %v", err)
		}
	}
	transitionResults := make(chan dbsqlc.ControlRoute, 2)
	transitionErrors := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			route, err := service.Transition(ctx, user, "route-concurrent-transition-"+suffix, first.ID, "detaching", 1)
			transitionResults <- route
			transitionErrors <- err
		}()
	}
	group.Wait()
	close(transitionResults)
	close(transitionErrors)
	for route := range transitionResults {
		if route.ID != first.ID || route.DesiredRevision != 2 {
			t.Fatalf("concurrent transition = %#v", route)
		}
	}
	for err := range transitionErrors {
		if err != nil {
			t.Fatalf("concurrent transition error = %v", err)
		}
	}
}
