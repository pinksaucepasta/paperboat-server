package terminalsessions

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
)

func TestCatalogCreatesDefaultAndAllocatesMonotonicNames(t *testing.T) {
	store := newTerminalSessionTestDB(t)
	projectService, project := createTerminalSessionTestProject(t, store, "usr_terminal_sessions")
	service := New(store, projectService, 8, 1, 3)
	ctx := context.Background()

	sessions, err := service.List(ctx, "usr_terminal_sessions", project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || !sessions[0].IsDefault || sessions[0].Name != "default" {
		t.Fatalf("default catalog row = %#v", sessions)
	}

	first, err := service.Create(ctx, "usr_terminal_sessions", project.ID, "", "create-shell-2")
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != "shell-2" || first.ID == "" {
		t.Fatalf("first automatic session = %#v", first)
	}
	replay, err := service.Create(ctx, "usr_terminal_sessions", project.ID, "", "create-shell-2")
	if err != nil || replay.ID != first.ID {
		t.Fatalf("idempotency replay = %#v, %v", replay, err)
	}
	second, err := service.Create(ctx, "usr_terminal_sessions", project.ID, "", "create-shell-3")
	if err != nil || second.Name != "shell-3" {
		t.Fatalf("second automatic session = %#v, %v", second, err)
	}
	if _, err := service.Delete(ctx, "usr_terminal_sessions", project.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	third, err := service.Create(ctx, "usr_terminal_sessions", project.ID, "", "create-shell-4")
	if err != nil || third.Name != "shell-4" {
		t.Fatalf("automatic name was reused after deletion: %#v, %v", third, err)
	}
	if _, err := service.Delete(ctx, "usr_terminal_sessions", project.ID, sessions[0].ID); !errors.Is(err, ErrReserved) {
		t.Fatalf("delete default error = %v, want ErrReserved", err)
	}
}

func TestCatalogSerializesConcurrentAutomaticCreationAndEnforcesLimit(t *testing.T) {
	store := newTerminalSessionTestDB(t)
	projectService, project := createTerminalSessionTestProject(t, store, "usr_terminal_concurrency")
	service := New(store, projectService, 5, 1, 3) // default plus four named sessions
	ctx := context.Background()

	var wg sync.WaitGroup
	names := make(chan string, 4)
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			session, err := service.Create(ctx, "usr_terminal_concurrency", project.ID, "", "concurrent-"+string(rune('a'+i)))
			if err != nil {
				errs <- err
				return
			}
			names <- session.Name
		}(i)
	}
	wg.Wait()
	close(names)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	got := make([]string, 0, 4)
	for name := range names {
		got = append(got, name)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "shell-2,shell-3,shell-4,shell-5" {
		t.Fatalf("concurrent names = %v", got)
	}
	if _, err := service.Create(ctx, "usr_terminal_concurrency", project.ID, "overflow", "overflow-key"); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit error = %v, want ErrLimit", err)
	}
}

func TestProjectDeletionTombstonesSessionsAndQueuesHistoryPurges(t *testing.T) {
	store := newTerminalSessionTestDB(t)
	projectService, project := createTerminalSessionTestProject(t, store, "usr_terminal_project_delete")
	service := New(store, projectService, 8, 1, 3)
	ctx := context.Background()
	if _, err := service.Create(ctx, "usr_terminal_project_delete", project.ID, "api", "create-api"); err != nil {
		t.Fatal(err)
	}
	if _, err := projectService.Delete(ctx, "usr_terminal_project_delete", project.ID); err != nil {
		t.Fatal(err)
	}
	var active, purges int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.project_terminal_sessions WHERE project_id=$1 AND deleted_at IS NULL`, project.ID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.terminal_session_operations WHERE project_id=$1 AND operation='delete_history' AND state='pending'`, project.ID).Scan(&purges); err != nil {
		t.Fatal(err)
	}
	if active != 0 || purges != 2 {
		t.Fatalf("project deletion retained %d active sessions and queued %d purges", active, purges)
	}
}

func TestSnapshotProjectPersistsRuntimeStateAndWorkingDirectory(t *testing.T) {
	store := newTerminalSessionTestDB(t)
	projectService, project := createTerminalSessionTestProject(t, store, "usr_terminal_snapshot")
	signer, err := mint.NewEphemeral(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := New(store, projectService, 8, time.Second, 3)
	service.ConfigureControl(func(context.Context, string) (string, error) {
		return "https://terminal-control.example.test", nil
	}, signer, "https://paperboat.example.test", &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString(`{"operation":"snapshot","terminals":[{"terminalId":"term-1","state":"running","attachmentCount":1,"lastActivityAt":"2026-07-15T12:00:00Z","cwd":"/workspace/api","exitCode":null,"exitSignal":null,"sequence":42}]}`)),
		}, nil
	})})

	if err := service.SnapshotProject(context.Background(), project.ID); err != nil {
		t.Fatal(err)
	}
	var state, cwd string
	var sequence int64
	var syncedAt time.Time
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT runtime_state, launch_cwd, last_runtime_sequence, last_runtime_sync_at
FROM paperboat.project_terminal_sessions
WHERE project_id=$1 AND terminal_id='term-1'`, project.ID).Scan(&state, &cwd, &sequence, &syncedAt); err != nil {
		t.Fatal(err)
	}
	if state != "running" || cwd != "/workspace/api" || sequence != 42 || syncedAt.IsZero() {
		t.Fatalf("persisted terminal runtime = state=%q cwd=%q sequence=%d synced_at=%s", state, cwd, sequence, syncedAt)
	}
}

func TestCloseSnapshotsWorkingDirectoryBeforeTerminalShutdown(t *testing.T) {
	store := newTerminalSessionTestDB(t)
	projectService, project := createTerminalSessionTestProject(t, store, "usr_terminal_close_snapshot")
	signer, err := mint.NewEphemeral(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	service := New(store, projectService, 8, time.Second, 3)
	service.ConfigureControl(func(context.Context, string) (string, error) {
		return "https://terminal-control.example.test", nil
	}, signer, "https://paperboat.example.test", &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls++
		body := `{"operation":"close","terminals":[]}`
		if calls == 1 {
			body = `{"operation":"snapshot","terminals":[{"terminalId":"term-1","state":"running","attachmentCount":0,"lastActivityAt":"2026-07-15T12:00:00Z","cwd":"/workspace/api","exitCode":null,"exitSignal":null,"sequence":42}]}`
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(body))}, nil
	})})

	sessions, err := service.List(context.Background(), "usr_terminal_close_snapshot", project.ID)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("list sessions = %#v, %v", sessions, err)
	}
	applied, err := service.Close(context.Background(), "usr_terminal_close_snapshot", project.ID, sessions[0].ID)
	if err != nil || !applied {
		t.Fatalf("close applied=%v err=%v", applied, err)
	}
	var state, cwd string
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT runtime_state, launch_cwd FROM paperboat.project_terminal_sessions WHERE id=$1`, sessions[0].ID).Scan(&state, &cwd); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || state != "closed" || cwd != "/workspace/api" {
		t.Fatalf("close calls=%d state=%q cwd=%q", calls, state, cwd)
	}
	if applied, err = service.Close(context.Background(), "usr_terminal_close_snapshot", project.ID, sessions[0].ID); err != nil || !applied {
		t.Fatalf("repeat close applied=%v err=%v", applied, err)
	}
	if calls != 2 {
		t.Fatalf("repeat close performed %d control calls, want 2", calls)
	}
	if err := store.Queries().ReopenTerminalSession(context.Background(), dbsqlc.ReopenTerminalSessionParams{ProjectID: project.ID, ID: sessions[0].ID}); err != nil {
		t.Fatal(err)
	}
	if applied, err = service.Close(context.Background(), "usr_terminal_close_snapshot", project.ID, sessions[0].ID); err != nil || !applied {
		t.Fatalf("close after reopen applied=%v err=%v", applied, err)
	}
	if calls != 4 {
		t.Fatalf("close after reopen performed %d control calls, want 4", calls)
	}
}

func newTerminalSessionTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run terminal-session integration tests")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") && os.Getenv("PAPERBOAT_ALLOW_DESTRUCTIVE_TEST_DB_RESET") != "true" {
		t.Fatal("refusing to truncate an unsafe PAPERBOAT_TEST_DATABASE_DSN")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
DO $$ DECLARE tables text; BEGIN
  SELECT string_agg(format('%I.%I', schemaname, tablename), ', ') INTO tables
  FROM pg_tables WHERE schemaname = 'paperboat' AND tablename NOT IN ('schema_migrations', 'goose_db_version');
  IF tables IS NOT NULL THEN EXECUTE 'TRUNCATE TABLE ' || tables || ' CASCADE'; END IF;
END $$;`); err != nil {
		t.Fatal(err)
	}
	return store
}

func createTerminalSessionTestProject(t *testing.T, store *db.DB, userID string) (*projects.Service, projects.Project) {
	t.Helper()
	ctx := context.Background()
	seedTerminalSessionCatalog(t, store)
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1, $2, $3, 'active')`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.storage_accounts (id, user_id, included_gb) VALUES ($1, $2, 32)`, "stor_"+userID, userID); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Secrets.EncryptionKey = "terminal-session-test-encryption-key"
	service := projects.NewService(store, audit.NewWriter(store), cfg)
	project, _, err := service.Create(ctx, projects.CreateInput{UserID: userID, IdempotencyKey: "project-" + userID, RepositoryURL: "https://github.com/paperboat/terminal-sessions.git", StorageGB: 8, MachineTypeCode: "standard-1x", RegionCode: "iad", PresetCodes: []string{"codex"}, IdleTimeoutCode: "15m"})
	if err != nil {
		t.Fatal(err)
	}
	return service, project
}

func seedTerminalSessionCatalog(t *testing.T, store *db.DB) {
	t.Helper()
	ctx := context.Background()
	statements := []string{
		`INSERT INTO paperboat.machine_types (id, code, name, vcpu, memory_mb, credit_weight, active, current_version_id) VALUES ('mt_standard', 'standard-1x', 'Standard', 4, 8192, 1, true, 'mtv_standard')`,
		`INSERT INTO paperboat.machine_type_versions (id, machine_type_id, version_number, vcpu, memory_mb, credit_weight) VALUES ('mtv_standard', 'mt_standard', 1, 4, 8192, 1)`,
		`INSERT INTO paperboat.vm_presets (id, code, name, active, current_version_id) VALUES ('preset_codex', 'codex', 'Codex', true, 'presetv_codex')`,
		`INSERT INTO paperboat.vm_preset_versions (id, preset_id, version_number, manifest) VALUES ('presetv_codex', 'preset_codex', 1, '{}'::jsonb)`,
		`INSERT INTO paperboat.regions (id, code, name, enabled) VALUES ('region_iad', 'iad', 'Ashburn', true)`,
		`INSERT INTO paperboat.idle_timeout_options (id, code, duration_seconds, active) VALUES ('idle_15m', '15m', 900, true)`,
	}
	for _, statement := range statements {
		if _, err := store.SQL().ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
}
