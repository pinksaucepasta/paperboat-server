package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConfigConflictResolutionRequiresCurrentAssignmentHeadAndConflictRevision(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_")
	user := "conflict_user_" + suffix
	environment := "conflict_env_" + suffix
	repository := "conflict_repo_" + suffix
	assignment := "conflict_assignment_" + suffix
	helper := "conflict_helper_" + suffix
	revision := strings.Repeat("a", 64)
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, []any{user, "workos_" + user, user + "@example.test"}},
		{`INSERT INTO paperboat.control_config_repositories (id,owner_user_id,provider,external_ref,display_name,state) VALUES ($1,$2,'github',$1,'owner/config','active')`, []any{repository, user}},
		{`INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$1,$2)`, []any{environment, user}},
		{`INSERT INTO paperboat.control_helpers (id,environment_id,state,generation) VALUES ($1,$2,'active',1)`, []any{helper, environment}},
		{`INSERT INTO paperboat.control_config_assignments (id,environment_id,repository_id,consent_state,warning_revision,version) VALUES ($1,$2,$3,'not_required','warning-1',3)`, []any{assignment, environment, repository}},
		{`INSERT INTO paperboat.control_config_sync_statuses
		  (environment_id,repository_id,assignment_id,helper_id,helper_generation,
		   warning_revision,policy_revision,key_version,sync_revision,state,remote_revision,
		   pending_path_count,conflicts,helper_updated_at,observed_at)
		  VALUES ($1,$2,$3,$4,1,'warning-1','policy-1',1,2,'conflict','head-2',0,
		          jsonb_build_array(jsonb_build_object('path','.config/tool','reason','concurrent_update','revision',$5::text)),$6,$6)`,
			[]any{environment, repository, assignment, helper, revision, now}},
	}
	for _, statement := range statements {
		if _, err := store.SQL().ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=$1`, user)
	})
	service := NewConfigConflictService(store, nil, nil)
	request := ConfigConflictResolution{
		Path: ".config/tool", ConflictRevision: revision,
		ExpectedRemoteRevision: "head-2", Action: "keep_local",
	}
	created, err := service.Request(ctx, user, environment, 3, request)
	if err != nil || created.ID == "" || created.Action != "keep_local" {
		t.Fatalf("resolution = %#v, %v", created, err)
	}
	request.ExpectedRemoteRevision = "head-stale"
	if _, err := service.Request(ctx, user, environment, 3, request); !errors.Is(err, ErrConfigConflictResolutionStale) {
		t.Fatalf("stale head error = %v", err)
	}
	request.ExpectedRemoteRevision = "head-2"
	request.ConflictRevision = strings.Repeat("b", 64)
	if _, err := service.Request(ctx, user, environment, 3, request); !errors.Is(err, ErrConfigConflictResolutionStale) {
		t.Fatalf("stale conflict error = %v", err)
	}
}
