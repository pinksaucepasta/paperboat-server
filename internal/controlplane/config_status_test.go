package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

func TestMarshalConfigStatusListCanonicalizesNilAsArray(t *testing.T) {
	for _, encode := range []func() ([]byte, error){
		func() ([]byte, error) { return marshalConfigStatusList([]ConfigStatusPath(nil)) },
		func() ([]byte, error) { return marshalConfigStatusList([]string(nil)) },
	} {
		encoded, err := encode()
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err = json.Unmarshal(encoded, &value); err != nil {
			t.Fatal(err)
		}
		if _, ok := value.([]any); !ok {
			t.Fatalf("encoded value = %s, want JSON array", encoded)
		}
	}
}

func TestConfigStatusValidationRejectsStaleLeakingAndInconsistentReports(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	valid := ConfigStatusReport{
		State: "healthy", Mode: ConfigModeBidirectional, RepositoryID: "repository", AssignmentID: "assignment",
		EnvironmentID: "environment", MachineID: "helper", InstallationGeneration: 1,
		WarningRevision: "warning-1", PolicyRevision: "policy-1",
		SyncRevision: 1, RemoteRevision: "head", UpdatedAt: now,
	}
	if err := validateConfigStatus(valid, 10, now); err != nil {
		t.Fatalf("valid status error = %v", err)
	}
	tests := []ConfigStatusReport{
		func() ConfigStatusReport { value := valid; value.SyncRevision = 0; return value }(),
		func() ConfigStatusReport { value := valid; value.UpdatedAt = now.Add(-6 * time.Minute); return value }(),
		func() ConfigStatusReport {
			value := valid
			value.Skipped = []ConfigStatusPath{{Path: "/Users/alice/.secret", Reason: "excluded"}}
			return value
		}(),
		func() ConfigStatusReport { value := valid; value.FencingToken = 2; return value }(),
		func() ConfigStatusReport {
			value := valid
			value.State, value.ErrorCode = "sync_uncertain", "network_error"
			return value
		}(),
		func() ConfigStatusReport { value := valid; value.State = "conflict"; return value }(),
	}
	for i, report := range tests {
		if err := validateConfigStatus(report, 10, now); !errors.Is(err, ErrConfigStatusInvalid) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}

func TestConfigStatusValidationAcceptsHelperWarningWithSafeSkippedSpecialFiles(t *testing.T) {
	now := time.Date(2026, 7, 24, 7, 32, 39, 0, time.UTC)
	report := ConfigStatusReport{
		State: "revoked", Mode: ConfigModePullOnly, RepositoryID: "cfgrepo_fixture", AssignmentID: "cfgasn_fixture",
		EnvironmentID: "environment_fixture", MachineID: "helper_fixture", InstallationGeneration: 1,
		WarningRevision: "hosted", PolicyRevision: "1", SyncRevision: 12,
		RemoteRevision: "b08059618b070ee1673a0db2301c36ca7696e07a",
		LastAttemptAt:  &now, LastSuccessfulAt: &now, UpdatedAt: now,
		Skipped: []ConfigStatusPath{{
			Path: ".paperboat/helper/runtime/pts_fixture/client.sock", Reason: "special_file",
		}},
		ErrorCode: "credential_expired",
	}
	if err := validateConfigStatus(report, 50, now); err != nil {
		t.Fatalf("helper status rejected: %v", err)
	}
}

func TestConfigStatusRejectionClassIsBoundedAndNonSecret(t *testing.T) {
	tests := map[error]string{
		errors.Join(ErrConfigStatusInvalid, errConfigStatusReport):          "report",
		errors.Join(ErrConfigStatusInvalid, errConfigStatusIdentity):        "identity",
		errors.Join(ErrConfigStatusInvalid, errConfigStatusHelper):          "helper_binding",
		errors.Join(ErrConfigStatusInvalid, errConfigStatusAssign):          "assignment_binding",
		errors.Join(errors.New("database details"), errConfigStatusPersist): "persistence",
		ErrConfigStatusStale:                      "stale",
		errors.New("unexpected sensitive detail"): "unknown",
	}
	for err, want := range tests {
		if got := ConfigStatusRejectionClass(err); got != want {
			t.Fatalf("class(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestConfigAccountStatusUsesCanonicalAssignmentsConsentAndStatus(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_")
	user := "status_user_" + suffix
	hostedEnvironment := "status_hosted_" + suffix
	byodEnvironment := "status_byod_" + suffix
	repository := "status_repo_" + suffix
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	hostedHelper, byodHelper := "helper_hosted_"+suffix, "helper_byod_"+suffix
	hostedAssignment, byodAssignment := "assignment_hosted_"+suffix, "assignment_byod_"+suffix
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, []any{user, "workos_" + user, user + "@example.test"}},
		{`INSERT INTO paperboat.control_config_repositories (id,owner_user_id,provider,external_ref,display_name,state) VALUES ($1,$2,'github',$1,'owner/config','active')`, []any{repository, user}},
		{`INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$1,$3),($2,$2,$3)`, []any{hostedEnvironment, byodEnvironment, user}},
		{`INSERT INTO paperboat.control_helpers (id,environment_id,state,generation) VALUES ($1,$2,'active',1),($3,$4,'active',1)`, []any{hostedHelper, hostedEnvironment, byodHelper, byodEnvironment}},
		{`INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,machine_kind) VALUES ($1,$3,$4,'Hosted','linux','unknown','/workspace','online','hosted'),($2,$3,$5,'Laptop','darwin','arm64','/Users/test','online','personal')`, []any{"hosted_machine_" + suffix, "machine_" + suffix, user, hostedEnvironment, byodEnvironment}},
		{`INSERT INTO paperboat.control_config_assignments (id,machine_id,environment_id,repository_id,consent_state,warning_revision) VALUES ($1,$2,$3,$4,'not_required','warning-1'),($5,$6,$7,$4,'pending','warning-1')`, []any{hostedAssignment, "hosted_machine_" + suffix, hostedEnvironment, repository, byodAssignment, "machine_" + suffix, byodEnvironment}},
		{`INSERT INTO paperboat.control_config_sync_statuses
		  (environment_id,repository_id,assignment_id,machine_id,installation_generation,
		   warning_revision,policy_revision,sync_revision,state,
		   pending_clean_path_count,machine_updated_at,observed_at)
		  VALUES ($1,$2,$3,$4,1,'warning-1','policy-1',2,'healthy',0,$5,$5)`,
			[]any{hostedEnvironment, repository, hostedAssignment, "hosted_machine_" + suffix, now}},
	}
	for _, statement := range statements {
		if _, err := store.SQL().ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=$1`, user)
	})
	service := NewConfigStatusService(store, nil, nil, 10)
	service.clock = func() time.Time { return now }
	service.SetAccountPolicy(config.ConfigSync{
		Mode: "leased_writes", BYODEnabled: true,
		PolicyRevision: "policy-1", MaxFileBytes: 10, MaxBatchBytes: 20,
		ManifestContract: "paperboat-manifest-v1", ManifestMaxBytes: 1024,
		ManifestMaxLines: 10, ManifestMaxPatternBytes: 128,
		StaleHeartbeatAfter: time.Minute,
	})
	status, err := service.Account(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "consent_required" || len(status.Environments) != 2 {
		t.Fatalf("status = %#v", status)
	}
	states := map[string]string{}
	for _, environment := range status.Environments {
		states[environment.Profile] = environment.State
	}
	if states["hosted"] != "healthy" || states["byod"] != "consent_required" {
		t.Fatalf("states = %#v", states)
	}
}
