package orchestrator

import (
	"context"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
)

// TestDeleteCompletesWhenSecretsAreUndecryptable proves that a project whose
// stored secrets were encrypted under an encryption key that is no longer
// configured (key drift) can still be deleted. Without tolerance for decryption
// failures the delete job errors on ProjectIntent and the project is stranded in
// "deleting" forever, never releasing its storage.
func TestDeleteCompletesWhenSecretsAreUndecryptable(t *testing.T) {
	store := newOrchestratorTestDB(t)
	ctx := context.Background()
	seedOrchestratorCatalogs(t, store)
	insertOrchestratorUser(t, store, "usr_orch_keydrift", 20)
	insertGitHubToken(t, store, "usr_orch_keydrift", "github-keydrift-token")

	// Provision under the original key.
	cfg := orchestratorTestConfig()
	cfg.Secrets.AgentunnelMachineToken = "agentunnel-keydrift-token"
	projectService := projects.NewService(store, audit.NewWriter(store), cfg)
	project, _, err := projectService.Create(ctx, projects.CreateInput{
		UserID:          "usr_orch_keydrift",
		IdempotencyKey:  "orch-keydrift",
		RepositoryURL:   "https://github.com/paperboat/example.git",
		StorageGB:       8,
		MachineTypeCode: "standard-1x",
		RegionCode:      "iad",
		PresetCodes:     []string{"codex"},
		IdleTimeoutCode: "15m",
	})
	if err != nil {
		t.Fatal(err)
	}
	fakeFly := fly.NewFakeClient()
	if err := NewService(store, fakeFly, cfg).RunOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// The encryption key changes: everything stored above is now undecryptable.
	rotated := cfg
	rotated.Secrets.EncryptionKey = "a-different-encryption-key-after-rotation"
	deleteService := NewService(store, fakeFly, rotated)

	if _, err := projectService.Delete(ctx, "usr_orch_keydrift", project.ID); err != nil {
		t.Fatal(err)
	}
	if err := deleteService.RunOnce(ctx); err != nil {
		t.Fatalf("delete run failed despite undecryptable secrets: %v", err)
	}

	var state string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.projects WHERE id = $1`, project.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "deleted" {
		t.Fatalf("project state = %q, want deleted", state)
	}
	var allocated int
	if err := store.SQL().QueryRowContext(ctx, `SELECT allocated_gb FROM paperboat.storage_accounts WHERE user_id = $1`, "usr_orch_keydrift").Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != 0 {
		t.Fatalf("allocated storage after delete = %d, want 0", allocated)
	}
	if len(fakeFly.Volumes) != 0 || len(fakeFly.Machines) != 0 {
		t.Fatalf("provider resources remain after delete: volumes=%d machines=%d", len(fakeFly.Volumes), len(fakeFly.Machines))
	}
}
