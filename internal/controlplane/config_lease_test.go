package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConfigRepositoryLeaseSerializesFencesAndRevokes(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_")
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	user := "lease_user_" + suffix
	repositoryID := "lease_repo_" + suffix
	environmentA, environmentB := "lease_env_a_"+suffix, "lease_env_b_"+suffix
	helperA, helperB := "lease_helper_a_"+suffix, "lease_helper_b_"+suffix
	assignmentA, assignmentB := "lease_assignment_a_"+suffix, "lease_assignment_b_"+suffix

	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, user, "workos_"+user, user+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_config_repositories (id,owner_user_id,provider,external_ref,display_name) VALUES ($1,$2,'github',$3,'Config')`, repositoryID, user, repositoryID); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ environment, helper, assignment string }{
		{environmentA, helperA, assignmentA}, {environmentB, helperB, assignmentB},
	} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3)`, fixture.environment, "workspace_"+fixture.environment, user); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state,generation) VALUES ($1,$2,'active',1)`, fixture.helper, fixture.environment); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_config_assignments (id,environment_id,repository_id,consent_state,warning_revision) VALUES ($1,$2,$3,'not_required','hosted')`, fixture.assignment, fixture.environment, repositoryID); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=$1`, user)
	})

	service := NewConfigLeaseService(store, nil)
	service.ConfigureRollout("leased_writes", true, nil)
	service.clock = func() time.Time { return now }
	holderA := ConfigLeaseHolder{RepositoryID: repositoryID, AssignmentID: assignmentA, EnvironmentID: environmentA, HelperID: helperA, HelperGeneration: 1, BaseRemoteRevision: "head-1"}
	holderB := ConfigLeaseHolder{RepositoryID: repositoryID, AssignmentID: assignmentB, EnvironmentID: environmentB, HelperID: helperB, HelperGeneration: 1, BaseRemoteRevision: "head-1"}

	first, err := service.Acquire(ctx, "acquire-a", holderA, 30*time.Second)
	if err != nil || first.FencingToken != 1 {
		t.Fatalf("first lease = %#v, %v", first, err)
	}
	replayed, err := service.Acquire(ctx, "acquire-a", holderA, 30*time.Second)
	if err != nil || replayed.LeaseID != first.LeaseID || replayed.FencingToken != first.FencingToken {
		t.Fatalf("acquire replay = %#v, %v", replayed, err)
	}
	if _, err := service.Acquire(ctx, "acquire-b-busy", holderB, 30*time.Second); !errors.Is(err, ErrConfigLeaseBusy) {
		t.Fatalf("competing acquire error = %v", err)
	}
	renewed, err := service.Renew(ctx, "renew-a", holderA, first.LeaseID, first.FencingToken, time.Minute)
	if err != nil || !renewed.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("renewed lease = %#v, %v", renewed, err)
	}

	now = now.Add(2 * time.Minute)
	second, err := service.Acquire(ctx, "acquire-b", holderB, 30*time.Second)
	if err != nil || second.FencingToken != first.FencingToken+1 {
		t.Fatalf("second lease = %#v, %v", second, err)
	}
	if err := service.Release(ctx, "release-stale", holderA, first.LeaseID, first.FencingToken); !errors.Is(err, ErrConfigLeaseLost) {
		t.Fatalf("stale release error = %v", err)
	}

	assignments := NewConfigAssignmentService(store, nil, "warning-1")
	assignments.clock = func() time.Time { return now }
	if err := assignments.Clear(ctx, user, environmentB, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Renew(ctx, "renew-revoked", holderB, second.LeaseID, second.FencingToken, 30*time.Second); !errors.Is(err, ErrConfigLeaseLost) {
		t.Fatalf("revoked renew error = %v", err)
	}

	third, err := service.Acquire(ctx, "acquire-a-after-release", holderA, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_environments SET desired_state='suspended' WHERE id=$1`, environmentA); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Renew(ctx, "renew-after-environment-suspend", holderA, third.LeaseID, third.FencingToken, 30*time.Second); !errors.Is(err, ErrConfigLeaseLost) {
		t.Fatalf("environment lifecycle trigger did not revoke lease: %v", err)
	}
}

func TestConfigRepositoryLeaseRejectsUnsafeRequests(t *testing.T) {
	service := NewConfigLeaseService(nil, nil)
	holder := ConfigLeaseHolder{RepositoryID: "repo", AssignmentID: "assignment", EnvironmentID: "environment", HelperID: "helper", HelperGeneration: 1}
	for _, ttl := range []time.Duration{time.Second, 3 * time.Minute} {
		if _, err := service.Acquire(context.Background(), "operation", holder, ttl); !errors.Is(err, ErrConfigLeaseInvalid) {
			t.Fatalf("ttl %s error = %v", ttl, err)
		}
	}
}
