package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPreviewLifecyclePreservesIdentityAndTombstonesRoute(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_") + time.Now().Format("150405.000000000")
	owner, environmentID := "preview_owner_"+suffix, "preview_env_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, owner, "workos_"+owner, owner+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3)`, environmentID, "workspace_"+suffix, owner); err != nil {
		t.Fatal(err)
	}
	service, err := NewPreviewService(store, nil, []byte("01234567890123456789012345678901"), "preview.example.test")
	if err != nil {
		t.Fatal(err)
	}
	helperHost := "helper-" + strings.ToLower(suffix) + ".example.test"
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_routes (id,environment_id,kind,public_host,target_host,target_port) VALUES ($1,$2,'helper_https_wss',$3,'127.0.0.1',38080)`, "route_helper_"+suffix, environmentID, helperHost); err != nil {
		t.Fatal(err)
	}
	if allowed, err := service.CanIssueCertificate(ctx, helperHost); err != nil || !allowed {
		t.Fatalf("helper certificate authorization allowed=%v err=%v", allowed, err)
	}
	if _, err := service.CreateOrUpdate(ctx, owner, "preview-no-ack-"+suffix, environmentID, "web", "127.0.0.1", 3000, false); !errors.Is(err, ErrPreviewAcknowledgment) {
		t.Fatalf("missing acknowledgement error = %v", err)
	}
	created, err := service.CreateOrUpdate(ctx, owner, "preview-create-"+suffix, environmentID, "web", "127.0.0.1", 3000, true)
	if err != nil || created.State != "registering" || !created.RouteID.Valid {
		t.Fatalf("created = %#v, err = %v", created, err)
	}
	if allowed, err := service.CanIssueCertificate(ctx, created.PublicHost); err != nil || !allowed {
		t.Fatalf("certificate authorization allowed=%v err=%v", allowed, err)
	}
	if allowed, err := service.CanIssueCertificate(ctx, strings.ToUpper(created.PublicHost)); err != nil || allowed {
		t.Fatalf("uppercase certificate authorization allowed=%v err=%v", allowed, err)
	}
	replay, err := service.CreateOrUpdate(ctx, owner, "preview-create-"+suffix, environmentID, "web", "127.0.0.1", 3000, true)
	if err != nil || replay.ID != created.ID || replay.Version != created.Version {
		t.Fatalf("replay = %#v, err = %v", replay, err)
	}
	updated, err := service.CreateOrUpdate(ctx, owner, "preview-update-"+suffix, environmentID, "web", "127.0.0.1", 4000, false)
	if err != nil || updated.PreviewKey != created.PreviewKey || updated.PublicHost != created.PublicHost || updated.TargetPort != 4000 {
		t.Fatalf("updated = %#v, err = %v", updated, err)
	}
	if _, err := service.ObserveForHelper(ctx, PreviewObservation{EnvironmentID: environmentID, PreviewKey: updated.PreviewKey, LogicalName: updated.LogicalName, TargetHost: updated.TargetHost, TargetPort: 3000, Revision: 1, HelperReady: true, TargetReady: true, ObservedAt: time.Now().UTC()}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("stale target observation = %v", err)
	}
	observed, err := service.ObserveForHelper(ctx, PreviewObservation{EnvironmentID: environmentID, PreviewKey: updated.PreviewKey, LogicalName: updated.LogicalName, TargetHost: updated.TargetHost, TargetPort: updated.TargetPort, Revision: 1, HelperReady: true, TargetReady: true, ObservedAt: time.Now().UTC()})
	if err != nil || observed.State != "degraded" || !observed.HelperReady || !observed.TargetReady {
		t.Fatalf("helper observation = %#v, err = %v", observed, err)
	}
	if _, err := service.ObserveForHelper(ctx, PreviewObservation{EnvironmentID: environmentID, PreviewKey: updated.PreviewKey, LogicalName: updated.LogicalName, TargetHost: updated.TargetHost, TargetPort: updated.TargetPort, Revision: 1, HelperReady: false, TargetReady: false, ObservedAt: time.Now().UTC()}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("stale helper observation = %v", err)
	}
	service.clock = func() time.Time { return observed.HelperObservedAt.Time.Add(2 * time.Minute) }
	if err := service.RefreshEdgeReadiness(ctx); err != nil {
		t.Fatal(err)
	}
	expiredReadiness, err := service.List(ctx, owner, environmentID)
	if err != nil || len(expiredReadiness) != 1 || expiredReadiness[0].State != "offline" || expiredReadiness[0].HelperReady || expiredReadiness[0].TargetReady {
		t.Fatalf("expired readiness = %#v, err = %v", expiredReadiness, err)
	}
	service.clock = func() time.Time { return time.Now().UTC() }
	owned, err := service.ListOwned(ctx, owner)
	if err != nil || len(owned) != 1 || owned[0].Preview.ID != created.ID || owned[0].OwnerEmail != owner+"@example.test" || owned[0].ProjectID != "workspace_"+suffix || !owned[0].UserID.Valid || owned[0].UserID.String != owner {
		t.Fatalf("owned = %#v, err = %v", owned, err)
	}
	if other, err := service.ListOwned(ctx, "another-user"); err != nil || len(other) != 0 {
		t.Fatalf("cross-owner list = %#v, err = %v", other, err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_environments SET desired_state='revoked', revoked_at=now() WHERE id=$1`, environmentID); err != nil {
		t.Fatal(err)
	}
	if inactive, err := service.ListOwned(ctx, owner); err != nil || len(inactive) != 0 {
		t.Fatalf("inactive environment previews = %#v, err = %v", inactive, err)
	}
	if allowed, err := service.CanIssueCertificate(ctx, created.PublicHost); err != nil || allowed {
		t.Fatalf("revoked environment certificate authorization allowed=%v err=%v", allowed, err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_environments SET desired_state='active', revoked_at=NULL WHERE id=$1`, environmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeOwned(ctx, "another-user", "preview-denied-"+suffix, created.ID); !errors.Is(err, ErrPreviewDenied) {
		t.Fatalf("cross-owner revoke error = %v", err)
	}
	removed, err := service.RevokeOwned(ctx, owner, "preview-remove-"+suffix, created.ID)
	if err != nil || removed.State != "removed" || !removed.RemovedAt.Valid || !removed.RetainedUntil.Valid || removed.RetainedUntil.Time.Sub(removed.RemovedAt.Time) < previewRetention {
		t.Fatalf("removed = %#v, err = %v", removed, err)
	}
	if allowed, err := service.CanIssueCertificate(ctx, created.PublicHost); err != nil || allowed {
		t.Fatalf("removed preview certificate authorization allowed=%v err=%v", allowed, err)
	}
	var routeState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT desired_state FROM paperboat.control_routes WHERE id=$1`, created.RouteID.String).Scan(&routeState); err != nil || routeState != "detached" {
		t.Fatalf("route state = %q, err = %v", routeState, err)
	}
	if _, err := service.CreateOrUpdate(ctx, owner, "preview-recreate-"+suffix, environmentID, "web", "127.0.0.1", 5000, true); !errors.Is(err, ErrPreviewRemoved) {
		t.Fatalf("recreate error = %v", err)
	}
}

func TestPreviewConcurrentExactRetryMutatesOnce(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_") + time.Now().Format("150405.000000000")
	owner, environmentID := "preview_concurrent_owner_"+suffix, "preview_concurrent_env_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, owner, "workos_"+owner, owner+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3)`, environmentID, "workspace_"+suffix, owner); err != nil {
		t.Fatal(err)
	}
	service, err := NewPreviewService(store, nil, []byte("01234567890123456789012345678901"), "preview.example.test")
	if err != nil {
		t.Fatal(err)
	}
	operationKey := "preview-concurrent-" + suffix
	results := make(chan string, 2)
	errs := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			preview, createErr := service.CreateOrUpdate(ctx, owner, operationKey, environmentID, "web", "127.0.0.1", 3000, true)
			results <- preview.ID
			errs <- createErr
		}()
	}
	group.Wait()
	close(results)
	close(errs)
	var first string
	for id := range results {
		if first == "" {
			first = id
		} else if id != first {
			t.Fatalf("preview IDs differ: %q / %q", first, id)
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var previewCount, routeCount int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.control_previews WHERE environment_id=$1`, environmentID).Scan(&previewCount); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.control_routes WHERE environment_id=$1 AND kind='preview_public_https_wss'`, environmentID).Scan(&routeCount); err != nil {
		t.Fatal(err)
	}
	if previewCount != 1 || routeCount != 1 {
		t.Fatalf("preview count=%d route count=%d", previewCount, routeCount)
	}
}

func TestHelperPreviewOperationsRejectOtherEnvironment(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_") + time.Now().Format("150405.000000000")
	owner := "preview_helper_owner_" + suffix
	assignedEnvironment := "preview_helper_assigned_" + suffix
	otherEnvironment := "preview_helper_other_" + suffix
	helperID := "preview_helper_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, owner, "workos_"+owner, owner+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3),($4,$5,$3)`, assignedEnvironment, "workspace_assigned_"+suffix, owner, otherEnvironment, "workspace_other_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,state) VALUES ($1,$2,'active')`, helperID, assignedEnvironment); err != nil {
		t.Fatal(err)
	}
	service, err := NewPreviewService(store, nil, []byte("01234567890123456789012345678901"), "preview.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListForHelper(ctx, helperID, otherEnvironment); !errors.Is(err, ErrPreviewDenied) {
		t.Fatalf("cross-environment list error = %v", err)
	}
	if _, err := service.CreateOrUpdateForHelper(ctx, helperID, "preview-helper-cross-create", otherEnvironment, "web", "127.0.0.1", 3000, true); !errors.Is(err, ErrPreviewDenied) {
		t.Fatalf("cross-environment create error = %v", err)
	}
	if _, err := service.RemoveForHelper(ctx, helperID, "preview-helper-cross-remove", otherEnvironment, "web"); !errors.Is(err, ErrPreviewDenied) {
		t.Fatalf("cross-environment remove error = %v", err)
	}
}
