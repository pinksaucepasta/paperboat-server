package github

import (
	"context"
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
