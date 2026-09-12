package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

func TestTeamConfigLifecycleAuthorityCASAndAuditAtomicity(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_")
	owner := "cfg43_lifecycle_owner_" + suffix
	admin := "cfg43_lifecycle_admin_" + suffix
	member := "cfg43_lifecycle_member_" + suffix
	teamID := "cfg43_lifecycle_team_" + suffix
	cleanupConfigTeamLifecycleFixture(t, store, []string{owner, admin, member}, []string{teamID}, nil, nil)
	for _, user := range []string{owner, admin, member} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, user, "workos_"+user, user+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.teams (team_id,owner_account,generation) VALUES ($1,$2,1)`, teamID, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.team_members (team_id,account_id,membership_generation,role,active) VALUES ($1,$2,1,'admin',true),($1,$3,1,'member',true)`, teamID, admin, member); err != nil {
		t.Fatal(err)
	}
	service := NewConfigAssignmentService(store, nil, "warning")
	service.SetRepositoryResolver(testConfigRepositoryResolver())
	adminRepo, err := service.ConnectRepository(ctx, admin, "github", "lifecycle-repo", "Lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	memberRepo, err := service.ConnectRepository(ctx, member, "github", "lifecycle-repo", "Lifecycle")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.SetTeamDefault(ctx, member, teamID, memberRepo.ID, 0); !errors.Is(err, ErrAssignmentForbidden) {
		t.Fatalf("member set error = %v", err)
	}
	created, err := service.SetTeamDefault(ctx, admin, teamID, adminRepo.ID, 0)
	if err != nil || created.Version != 1 {
		t.Fatalf("created = %+v, error = %v", created, err)
	}
	if _, err := service.SetTeamDefault(ctx, admin, teamID, adminRepo.ID, 0); !errors.Is(err, ErrAssignmentConflict) {
		t.Fatalf("stale set error = %v", err)
	}
	assertConfigAudit(t, store, teamID, "team.config_default_changed", admin, 1, adminRepo.ID)
	if _, err := service.AdoptTeamDefault(ctx, member, teamID, 1); err != nil {
		t.Fatal(err)
	}
	assertConfigAudit(t, store, teamID, "team.config_default_adopted", member, 1, memberRepo.ID)
	if err := service.UnadoptTeamDefault(ctx, member); err != nil {
		t.Fatal(err)
	}
	assertConfigAudit(t, store, teamID, "team.config_default_unadopted", member, 1, memberRepo.ID)

	rollbackTime := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	service.clock = func() time.Time { return rollbackTime }
	triggerSuffix := strings.ToLower(suffix)
	functionName := "reject_cfg_audit_" + triggerSuffix
	triggerName := "reject_cfg_audit_trigger_" + triggerSuffix
	if _, err := store.SQL().ExecContext(ctx, fmt.Sprintf(`CREATE FUNCTION paperboat.%s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'intentional config audit failure'; END $$; CREATE TRIGGER %s BEFORE INSERT ON paperboat.audit_events FOR EACH ROW WHEN (NEW.resource_id = %s) EXECUTE FUNCTION paperboat.%s()`, functionName, triggerName, "'"+teamID+"'", functionName)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON paperboat.audit_events; DROP FUNCTION IF EXISTS paperboat.%s()`, triggerName, functionName))
	})
	if err := service.DeleteTeamDefault(ctx, admin, teamID, 1); err == nil {
		t.Fatal("delete unexpectedly committed when its audit insert failed")
	}
	if current, err := service.TeamDefault(ctx, member, teamID); err != nil || current.Version != 1 {
		t.Fatalf("default after audit rollback = %+v, error = %v", current, err)
	}
	if _, err := store.SQL().ExecContext(ctx, fmt.Sprintf(`DROP TRIGGER %s ON paperboat.audit_events`, triggerName)); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteTeamDefault(ctx, admin, teamID, 1); err != nil {
		t.Fatal(err)
	}
	assertConfigAudit(t, store, teamID, "team.config_default_deleted", admin, 1, "")
}

func TestTeamConfigPublicationAuditUsesAuthoritativeAdoptionAndCommitsAtomically(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_")
	owner, member := "cfg43_publish_owner_"+suffix, "cfg43_publish_member_"+suffix
	teamID, environmentID, machineID := "cfg43_publish_team_"+suffix, "cfg43_publish_env_"+suffix, "cfg43_publish_machine_"+suffix
	cleanupConfigTeamLifecycleFixture(t, store, []string{owner, member}, []string{teamID}, []string{environmentID}, []string{machineID})
	for _, user := range []string{owner, member} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, user, "workos_"+user, user+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.teams (team_id,owner_account,generation) VALUES ($1,$2,1)`, []any{teamID, owner}},
		{`INSERT INTO paperboat.team_members (team_id,account_id,membership_generation,role,active) VALUES ($1,$2,1,'member',true)`, []any{teamID, member}},
		{`INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3)`, []any{environmentID, "workspace_" + suffix, member}},
		{`INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,machine_kind) VALUES ($1,$2,$3,'Hosted','linux','unknown','/workspace','hosted')`, []any{machineID, member, environmentID}},
	}
	for _, statement := range statements {
		if _, err := store.SQL().ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 9, 12, 13, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", ed25519.SeedSize)))
	signer, err := mint.New([]mint.Key{{ID: "config-publish-test", PrivateKey: privateKey}}, "config-publish-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := NewEnrollmentService(store, signer, audit.NewWriter(store), "https://api.example.test", "config-publication-encryption-key")
	enrollment.clock = func() time.Time { return now }
	grant, err := enrollment.Issue(ctx, member, "publish-enrollment-01", environmentID, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	helperPrivate := enrollmentTestPrivateKey(environmentID)
	identity, err := enrollment.Exchange(ctx, grant.Credential, helperPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	assignments := NewConfigAssignmentService(store, audit.NewWriter(store), "warning-publish")
	assignments.SetRepositoryResolver(testConfigRepositoryResolver())
	ownerRepo, err := assignments.ConnectRepository(ctx, owner, "github", "publish-repository", "")
	if err != nil {
		t.Fatal(err)
	}
	memberRepo, err := assignments.ConnectRepository(ctx, member, "github", "publish-repository", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assignments.SetTeamDefault(ctx, owner, teamID, ownerRepo.ID, 0); err != nil {
		t.Fatal(err)
	}
	adoption, err := assignments.AdoptTeamDefault(ctx, member, teamID, 1)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := store.Queries().GetControlConfigAssignment(ctx, environmentID)
	if err != nil {
		t.Fatal(err)
	}
	statuses := NewConfigStatusService(store, enrollment, audit.NewWriter(store), 10)
	statuses.clock = func() time.Time { return now }
	report := ConfigStatusReport{State: "healthy", Mode: ConfigModePullOnly, RepositoryID: adoption.RepositoryID, AssignmentID: assignment.ID,
		EnvironmentID: environmentID, MachineID: identity.MachineID, InstallationGeneration: 1, WarningRevision: "hosted",
		PolicyRevision: "policy-1", SyncRevision: 1, LastPublishedRevision: "published-1", UpdatedAt: now}
	record := func(operation string) error {
		body := []byte(`{}`)
		digest := sha256.Sum256(body)
		claims := HelperProofClaims{HelperID: identity.HelperID, EnvironmentID: environmentID,
			OperationID: operation, Method: "POST", Path: "/v1/config/status", BodySHA256: base64.RawURLEncoding.EncodeToString(digest[:]), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
		payload, _ := json.Marshal(claims)
		proof, _ := json.Marshal(helperProofEnvelope{Algorithm: "EdDSA", Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(helperPrivate, payload))})
		return statuses.Record(ctx, identity.Credential, proof, body, "POST", "/v1/config/status", report)
	}
	if err := record("publish-status-01"); err != nil {
		t.Fatal(err)
	}
	assertTeamPublicationAudit(t, store, teamID, member, "published-1", 1)
	report.SyncRevision = 2
	if err := record("publish-status-02"); err != nil {
		t.Fatal(err)
	}
	assertTeamPublicationAudit(t, store, teamID, member, "published-1", 1)

	triggerTag := fmt.Sprintf("%x", sha256.Sum256([]byte(suffix)))[:12]
	functionName, triggerName := "reject_publish_audit_"+triggerTag, "reject_publish_audit_trigger_"+triggerTag
	if _, err := store.SQL().ExecContext(ctx, fmt.Sprintf(`CREATE FUNCTION paperboat.%s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'intentional publication audit failure'; END $$`, functionName)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON paperboat.audit_events`, triggerName))
		_, _ = store.SQL().ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS paperboat.%s()`, functionName))
	})
	if _, err := store.SQL().ExecContext(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON paperboat.audit_events FOR EACH ROW WHEN (NEW.resource_id = '%s' AND NEW.event_type = 'team.config_published') EXECUTE FUNCTION paperboat.%s()`, triggerName, teamID, functionName)); err != nil {
		t.Fatal(err)
	}
	report.SyncRevision, report.LastPublishedRevision = 3, "published-2"
	if err := record("publish-status-03"); err == nil {
		t.Fatal("publication status unexpectedly committed when team audit failed")
	}
	var persistedRevision int64
	if err := store.SQL().QueryRowContext(ctx, `SELECT sync_revision FROM paperboat.control_config_sync_statuses WHERE environment_id=$1`, environmentID).Scan(&persistedRevision); err != nil || persistedRevision != 2 {
		t.Fatalf("status after audit rollback revision=%d error=%v", persistedRevision, err)
	}
	if _, err := store.SQL().ExecContext(ctx, fmt.Sprintf(`DROP TRIGGER %s ON paperboat.audit_events`, triggerName)); err != nil {
		t.Fatal(err)
	}
	if err := record("publish-status-04"); err != nil {
		t.Fatal(err)
	}
	assertTeamPublicationAudit(t, store, teamID, member, "published-2", 2)

	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.team_members SET active=false WHERE team_id=$1 AND account_id=$2`, teamID, member); err != nil {
		t.Fatal(err)
	}
	report.SyncRevision, report.LastPublishedRevision = 4, "published-after-removal"
	if err := record("publish-status-05"); err != nil {
		t.Fatal(err)
	}
	assertTeamPublicationAudit(t, store, teamID, member, "published-2", 2)
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_config_assignments SET adopted_team_id=NULL,adopted_default_version=NULL WHERE id=$1`, assignment.ID); err != nil {
		t.Fatal(err)
	}
	report.SyncRevision, report.LastPublishedRevision = 5, "personal-publication"
	if err := record("publish-status-06"); err != nil {
		t.Fatal(err)
	}
	assertTeamPublicationAudit(t, store, teamID, member, "published-2", 2)
	// Replacement assignments retain the environment's monotonic history.
	replacement, err := assignments.Assign(ctx, member, machineID, memberRepo.ID, ConfigModePushOnly, "", assignment.Version)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := store.Queries().GetControlConfigSyncRevision(ctx, dbsqlc.GetControlConfigSyncRevisionParams{EnvironmentID: environmentID, AssignmentID: replacement.ID, MachineID: identity.MachineID, InstallationGeneration: 1})
	if err != nil || floor != report.SyncRevision {
		t.Fatalf("replacement sync revision floor=%d want=%d error=%v", floor, report.SyncRevision, err)
	}
	oldAssignment := report.AssignmentID
	report.AssignmentID, report.Mode, report.SyncRevision = replacement.ID, ConfigModePushOnly, floor+1
	report.LastPublishedRevision = "personal-replacement-publication"
	if err := record("publish-status-replacement"); err != nil {
		t.Fatalf("current replacement status rejected: %v", err)
	}
	report.AssignmentID = oldAssignment
	report.SyncRevision++
	if err := record("publish-status-old-assignment"); !errors.Is(err, ErrConfigStatusInvalid) {
		t.Fatalf("old assignment accepted: %v", err)
	}
	report.AssignmentID = replacement.ID
	report.SyncRevision = floor
	if err := record("publish-status-old-revision"); !errors.Is(err, ErrConfigStatusStale) {
		t.Fatalf("old sync revision accepted: %v", err)
	}
	report.SyncRevision = floor + 2
	report.InstallationGeneration = 2
	if err := record("publish-status-wrong-generation"); !errors.Is(err, ErrConfigStatusInvalid) {
		t.Fatalf("wrong installation accepted: %v", err)
	}
	var gotAssignment string
	var gotRevision int64
	if err := store.SQL().QueryRowContext(ctx, `SELECT assignment_id,sync_revision FROM paperboat.control_config_sync_statuses WHERE environment_id=$1`, environmentID).Scan(&gotAssignment, &gotRevision); err != nil || gotAssignment != replacement.ID || gotRevision != floor+1 {
		t.Fatalf("denied status changed current binding/revision: %v", err)
	}
	var history int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.control_config_sync_status_history WHERE environment_id=$1`, environmentID).Scan(&history); err != nil || history != int(floor+1) {
		t.Fatalf("replacement overwrote status history: count=%d error=%v", history, err)
	}
}

func cleanupConfigTeamLifecycleFixture(t *testing.T, store *db.DB, users, teams, environments, machines []string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, err := store.SQL().BeginTx(ctx, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer tx.Rollback()
		statements := []struct {
			query string
			args  []any
		}{
			{`ALTER TABLE paperboat.audit_events DISABLE TRIGGER audit_events_append_only`, nil},
			{`DELETE FROM paperboat.audit_events WHERE actor_user_id=ANY($1::text[]) OR resource_id=ANY($2::text[]) OR resource_id=ANY($3::text[]) OR resource_id=ANY($4::text[])`, []any{users, teams, environments, machines}},
			{`DELETE FROM paperboat.control_config_sync_status_history WHERE environment_id=ANY($1::text[])`, []any{environments}},
			{`DELETE FROM paperboat.control_config_sync_statuses WHERE environment_id=ANY($1::text[])`, []any{environments}},
			{`DELETE FROM paperboat.control_config_assignments WHERE environment_id=ANY($1::text[])`, []any{environments}},
			{`DELETE FROM paperboat.teams WHERE team_id=ANY($1::text[])`, []any{teams}},
			{`DELETE FROM paperboat.user_machines WHERE id=ANY($1::text[])`, []any{machines}},
			{`DELETE FROM paperboat.control_environments WHERE id=ANY($1::text[])`, []any{environments}},
			{`DELETE FROM paperboat.control_config_repositories WHERE owner_user_id=ANY($1::text[])`, []any{users}},
			{`DELETE FROM paperboat.team_operations WHERE account_id=ANY($1::text[])`, []any{users}},
			{`DELETE FROM paperboat.users WHERE id=ANY($1::text[])`, []any{users}},
			{`ALTER TABLE paperboat.audit_events ENABLE TRIGGER audit_events_append_only`, nil},
		}
		for _, statement := range statements {
			if _, err = tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
				t.Errorf("clean config team lifecycle fixture: %v", err)
				return
			}
		}
		if err = tx.Commit(); err != nil {
			t.Errorf("commit config team lifecycle cleanup: %v", err)
		}
	})
}

func assertTeamPublicationAudit(t *testing.T, store interface{ SQL() *sql.DB }, teamID, actor, revision string, count int) {
	t.Helper()
	var gotActor, gotRevision string
	var gotCount int
	err := store.SQL().QueryRowContext(context.Background(), `SELECT actor_user_id,metadata->>'published_revision',count(*) OVER () FROM paperboat.audit_events WHERE resource_type='team' AND resource_id=$1 AND event_type='team.config_published' ORDER BY created_at DESC LIMIT 1`, teamID).Scan(&gotActor, &gotRevision, &gotCount)
	if err != nil || gotActor != actor || gotRevision != revision || gotCount != count {
		t.Fatalf("publication audit actor=%q revision=%q count=%d error=%v", gotActor, gotRevision, gotCount, err)
	}
}

func assertConfigAudit(t *testing.T, store interface{ SQL() *sql.DB }, teamID, eventType, actor string, version int64, repositoryID string) {
	t.Helper()
	var gotActor string
	var raw []byte
	var count int
	err := store.SQL().QueryRowContext(context.Background(), `SELECT actor_user_id,metadata,count(*) OVER () FROM paperboat.audit_events WHERE resource_type='team' AND resource_id=$1 AND event_type=$2 ORDER BY created_at DESC LIMIT 1`, teamID, eventType).Scan(&gotActor, &raw, &count)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	if count != 1 || gotActor != actor || int64(metadata["version"].(float64)) != version {
		t.Fatalf("audit actor=%q metadata=%v", gotActor, metadata)
	}
	if repositoryID != "" && metadata["repository_id"] != repositoryID {
		t.Fatalf("audit repository ID = %v, want %q", metadata["repository_id"], repositoryID)
	}
	for _, forbidden := range []string{"display_name", "branch", "provider", "url", "content"} {
		if _, ok := metadata[forbidden]; ok {
			t.Fatalf("audit metadata contains %q: %v", forbidden, metadata)
		}
	}
}
