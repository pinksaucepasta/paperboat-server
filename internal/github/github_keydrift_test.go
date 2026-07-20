package github

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

// TestUndecryptableTokenIsDisconnected proves that when the stored GitHub token
// was encrypted under an encryption key that is no longer configured (key
// drift), token-dependent operations surface ErrNotConnected and status renders
// disconnected so the dashboard prompts the user to reconnect.
func TestUndecryptableTokenIsDisconnected(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_gh_keydrift_" + suffix
	if _, err := store.SQL().ExecContext(ctx,
		`INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
		 VALUES ($1, $2, $3, 'active')`,
		userID, "workos_gh_keydrift_"+suffix, "gh-keydrift-"+suffix+"@example.com"); err != nil {
		t.Fatal(err)
	}

	// Token encrypted under the original key.
	ciphertext, err := secrets.Encrypt("original-encryption-key", "gho_realtoken")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx,
		`INSERT INTO paperboat.github_oauth_tokens
		   (id, user_id, token_ciphertext, scopes, provider_account_login, last_validated_at, created_at, updated_at)
		 VALUES ($1, $2, $3, ARRAY['repo']::text[], $4, now(), now(), now())`,
		"ght_keydrift_"+suffix, userID, ciphertext, "octocat"); err != nil {
		t.Fatal(err)
	}

	// The server now runs with a different encryption key.
	cfg := config.Config{}
	cfg.Secrets.EncryptionKey = "a-different-encryption-key-after-rotation"
	cfg.GitHub.OAuthScopes = []string{"repo"}
	service := NewService(store, audit.NewWriter(store), &FakeClient{}, cfg)

	if _, err := service.ListRepos(ctx, userID); err != ErrNotConnected {
		t.Fatalf("ListRepos error = %v, want ErrNotConnected", err)
	}
	status, err := service.Status(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Connected || len(status.Scopes) != 0 || len(status.MissingScopes) != 0 {
		t.Fatalf("status = %#v, want disconnected empty status", status)
	}
}

type timeoutAfterCreateClient struct {
	FakeClient
	timedOut bool
}

func (c *timeoutAfterCreateClient) CreateRepo(ctx context.Context, token string, input RepoCreateInput) (Repo, error) {
	repo, err := c.FakeClient.CreateRepo(ctx, token, input)
	if err != nil {
		return Repo{}, err
	}
	if !c.timedOut {
		c.timedOut = true
		return Repo{}, context.DeadlineExceeded
	}
	return repo, nil
}

func TestProvisionConfigRepoReconcilesTimeoutAfterCreate(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_gh_uncertain_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "gh-uncertain-"+suffix+"@example.com"); err != nil {
		t.Fatal(err)
	}
	encryptionKey := "github-uncertain-test-key"
	token, err := secrets.Encrypt(encryptionKey, "gho_timeout_test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.github_oauth_tokens (id,user_id,token_ciphertext,scopes,provider_account_login,last_validated_at,created_at,updated_at) VALUES ($1,$2,$3,ARRAY['repo']::text[],$4,now(),now(),now())`, "ght_uncertain_"+suffix, userID, token, "octocat"); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{}
	cfg.Secrets.EncryptionKey = encryptionKey
	cfg.GitHub.OAuthScopes = []string{"repo"}
	cfg.GitHub.ConfigRepoName = "paperboat-config"
	cfg.GitHub.ConfigRepoBranch = "main"
	client := &timeoutAfterCreateClient{FakeClient: FakeClient{User: GitHubUser{Login: "octocat"}}}
	service := NewService(store, audit.NewWriter(store), client, cfg)
	key := "github-provision-" + suffix

	if _, err := service.ProvisionConfigRepo(ctx, userID, key); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first provision error = %v, want deadline exceeded", err)
	}
	var state string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.github_repo_provisioning_attempts WHERE idempotency_key=$1`, key).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "uncertain" {
		t.Fatalf("attempt state = %q, want uncertain", state)
	}
	repo, err := service.ProvisionConfigRepo(ctx, userID, key)
	if err != nil {
		t.Fatal(err)
	}
	if repo.Owner != "octocat" || repo.Name != "paperboat-config" || client.Created != 1 {
		t.Fatalf("repo = %#v, creates = %d", repo, client.Created)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.github_repo_provisioning_attempts WHERE idempotency_key=$1`, key).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "succeeded" {
		t.Fatalf("retry state = %q, want succeeded", state)
	}
}
